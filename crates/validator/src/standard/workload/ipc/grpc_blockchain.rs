// Path: crates/validator/src/standard/workload/ipc/grpc_blockchain.rs

use crate::standard::workload::ipc::RpcContext;
use ioi_api::{
    chain::{ChainStateMachine, ChainView},
    commitment::CommitmentScheme,
    state::{StateAccess, StateManager, StateScanIter},
};
use ioi_execution::app::load_aft_auxiliary_raw_state_value;
use ioi_ipc::blockchain::{
    chain_control_server::ChainControl, contract_control_server::ContractControl,
    process_block_request::Payload as ProcessPayload, staking_control_server::StakingControl,
    state_query_server::StateQuery, system_control_server::SystemControl, BlockList,
    CallContractRequest, CallContractResponse, CheckAndTallyProposalsRequest,
    CheckAndTallyProposalsResponse, CheckResult, CheckTransactionsRequest,
    CheckTransactionsResponse, DebugPinHeightRequest, DebugTriggerGcResponse,
    DebugUnpinHeightRequest, DeployContractRequest, DeployContractResponse, GetBlocksRangeRequest,
    GetBlocksRangeResponse, GetExpectedModelHashResponse, GetGenesisStatusRequest,
    GetGenesisStatusResponse, GetNextStakedValidatorsRequest, GetNextStakedValidatorsResponse,
    GetStakedValidatorsRequest, GetStakedValidatorsResponse, GetStatusRequest, GetStatusResponse,
    KeyValuePair, PrefixScanRequest, PrefixScanResponse, ProcessBlockRequest, ProcessBlockResponse,
    QueryContractRequest, QueryContractResponse, QueryRawStateRequest, QueryRawStateResponse,
    QueryStateAtRequest, QueryStateAtResponse, UpdateBlockHeaderRequest, UpdateBlockHeaderResponse,
};
use ioi_types::{
    app::{Block, ChainTransaction, Membership, StateRoot},
    codec,
    config::ConsensusType,
    error::StateError,
};
use std::mem;
use std::sync::Arc;
use tonic::{Request, Response, Status};

// -----------------------------------------------------------------------------
// ChainControl Service
// -----------------------------------------------------------------------------

/// Implements the `ChainControl` gRPC service for blockchain lifecycle management.
pub struct ChainControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Shared RPC context containing the machine state and workload handle.
    pub ctx: Arc<RpcContext<CS, ST>>,
}

impl<CS, ST> ChainControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    fn header_execution_surface_matches(
        left: &ioi_types::app::BlockHeader,
        right: &ioi_types::app::BlockHeader,
    ) -> bool {
        left.parent_hash == right.parent_hash
            && left.parent_state_root == right.parent_state_root
            && left.state_root == right.state_root
            && left.transactions_root == right.transactions_root
            && left.timestamp_ms_or_legacy() == right.timestamp_ms_or_legacy()
            && left.gas_used == right.gas_used
    }
}

#[tonic::async_trait]
impl<CS, ST> ChainControl for ChainControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    async fn process_block(
        &self,
        request: Request<ProcessBlockRequest>,
    ) -> Result<Response<ProcessBlockResponse>, Status> {
        let req = request.into_inner();

        let block_bytes = match req.payload {
            Some(ProcessPayload::BlockBytesInline(bytes)) => bytes,
            Some(ProcessPayload::ShmemHandle(handle)) => {
                let dp = self.ctx.data_plane.as_ref().ok_or_else(|| {
                    Status::failed_precondition("Shared Memory Data Plane not initialized")
                })?;
                if handle.region_id != dp.id() {
                    return Err(Status::invalid_argument("Region ID mismatch"));
                }
                dp.read_raw(handle.offset, handle.length)
                    .map_err(|e| Status::internal(e.to_string()))?
                    .to_vec()
            }
            None => return Err(Status::invalid_argument("Missing payload")),
        };

        let block: Block<ChainTransaction> =
            codec::from_bytes_canonical(&block_bytes).map_err(|e| Status::invalid_argument(e))?;

        let prepared_block = {
            let machine = self.ctx.machine.lock().await;
            machine
                .prepare_block(block)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
        };

        let (processed_block, events) = {
            let mut machine = self.ctx.machine.lock().await;
            machine
                .commit_block(prepared_block)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
        };

        let block_bytes =
            codec::to_bytes_canonical(&processed_block).map_err(|e| Status::internal(e))?;

        Ok(Response::new(ProcessBlockResponse {
            block_bytes,
            events,
        }))
    }

    async fn get_blocks_range(
        &self,
        request: Request<GetBlocksRangeRequest>,
    ) -> Result<Response<GetBlocksRangeResponse>, Status> {
        let req = request.into_inner();
        let committed_height = {
            let machine = self.ctx.machine.lock().await;
            machine.state.status.height
        };
        let blocks = self
            .ctx
            .workload
            .store
            .get_blocks_range(req.since, req.max_blocks, req.max_bytes)
            .map_err(|e| Status::internal(e.to_string()))?;
        let blocks: Vec<_> = blocks
            .into_iter()
            .filter(|block| block.header.height <= committed_height)
            .collect();

        let mut encoded_blocks = Vec::new();
        for b in blocks {
            encoded_blocks.push(codec::to_bytes_canonical(&b).map_err(|e| Status::internal(e))?);
        }

        use ioi_ipc::blockchain::get_blocks_range_response::Data as BlocksData;
        Ok(Response::new(GetBlocksRangeResponse {
            data: Some(BlocksData::Inline(BlockList {
                blocks: encoded_blocks,
            })),
        }))
    }

    async fn update_block_header(
        &self,
        request: Request<UpdateBlockHeaderRequest>,
    ) -> Result<Response<UpdateBlockHeaderResponse>, Status> {
        let req = request.into_inner();
        let incoming_block: Block<ChainTransaction> = codec::from_bytes_canonical(&req.block_bytes)
            .map_err(|e| Status::invalid_argument(e))?;
        let mut machine = self.ctx.machine.lock().await;
        let mut block = incoming_block;
        let committed_height = machine.state.status.height;
        let recent_committed_height = machine
            .state
            .recent_blocks
            .last()
            .map(|candidate| candidate.header.height)
            .unwrap_or(0);

        if let Some(last) = machine.state.recent_blocks.last() {
            if last.header.height == block.header.height {
                if !Self::header_execution_surface_matches(&last.header, &block.header) {
                    return Err(Status::failed_precondition(format!(
                        "refusing to enrich block {} because execution fields diverged from the local committed state",
                        block.header.height
                    )));
                }

                let mut merged = last.clone();
                merged.header.signature = mem::take(&mut block.header.signature);
                merged.header.oracle_counter = block.header.oracle_counter;
                merged.header.oracle_trace_hash = block.header.oracle_trace_hash;
                merged.header.guardian_certificate = block.header.guardian_certificate.take();
                merged.header.sealed_finality_proof = block.header.sealed_finality_proof.take();
                merged.header.canonical_order_certificate =
                    block.header.canonical_order_certificate.take();
                merged.header.publication_frontier = block.header.publication_frontier.take();
                merged.header.timeout_certificate = block.header.timeout_certificate.take();
                merged.header.canonical_collapse_extension_certificate =
                    block.header.canonical_collapse_extension_certificate.take();
                block = merged;
            }
        }

        if block.header.height > committed_height && block.header.height > recent_committed_height {
            return Err(Status::failed_precondition(format!(
                "refusing to persist speculative header enrichment for height {} while local committed height is {}",
                block.header.height, committed_height
            )));
        }

        if block.header.height == machine.state.status.height
            && !machine.state.last_state_root.is_empty()
            && block.header.state_root.0 != machine.state.last_state_root
        {
            return Err(Status::failed_precondition(format!(
                "refusing to enrich block {} because header state_root does not match the local workload state root",
                block.header.height
            )));
        }

        let block_bytes = codec::to_bytes_canonical(&block).map_err(Status::internal)?;

        self.ctx
            .workload
            .store
            .put_block(block.header.height, &block_bytes)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Header enrichment must not mutate the live execution state tree.
        // Doing so can advance the in-memory root independently from the last
        // committed block, which breaks anchored state reads for the next
        // consensus round. AFT canonical collapse data is persisted on the
        // committed path and published through the normal registry/state flow.
        if let Err(error) =
            crate::standard::orchestration::aft_collapse::maybe_derive_persisted_canonical_collapse_object(&block)
        {
            tracing::debug!(
                height = block.header.height,
                error = %error,
                "Skipping best-effort canonical collapse derivation during header enrichment."
            );
        }

        if let Some(last) = machine.state.recent_blocks.last_mut() {
            if last.header.height == block.header.height {
                *last = block;
            }
        }
        Ok(Response::new(UpdateBlockHeaderResponse {}))
    }

    async fn get_genesis_status(
        &self,
        _request: Request<GetGenesisStatusRequest>,
    ) -> Result<Response<GetGenesisStatusResponse>, Status> {
        let machine = self.ctx.machine.lock().await;
        match &machine.state.genesis_state {
            ioi_execution::app::GenesisState::Ready { root, chain_id } => {
                Ok(Response::new(GetGenesisStatusResponse {
                    ready: true,
                    root: root.clone(),
                    chain_id: chain_id.to_string(),
                }))
            }
            ioi_execution::app::GenesisState::Pending => {
                Ok(Response::new(GetGenesisStatusResponse {
                    ready: false,
                    ..Default::default()
                }))
            }
        }
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let (status, consensus_type) = {
            let machine = self.ctx.machine.lock().await;
            (machine.status().clone(), machine.consensus_type())
        };
        let durable_status = if matches!(consensus_type, ConsensusType::Aft) {
            let mut candidates = Vec::new();
            for height in (1..=status.height).rev() {
                let Some(block) = self
                    .ctx
                    .workload
                    .store
                    .get_block_by_height(height)
                    .map_err(|e| Status::internal(e.to_string()))?
                else {
                    continue;
                };
                let is_durable = match crate::standard::orchestration::aft_collapse::maybe_derive_persisted_canonical_collapse_object(&block)
                {
                    Ok(collapse) => collapse.is_some(),
                    Err(error) => {
                        tracing::debug!(
                            height,
                            error = %error,
                            "Skipping non-durable AFT status candidate whose canonical collapse surface is not yet derivable."
                        );
                        false
                    }
                };
                candidates.push(block);
                if is_durable {
                    break;
                }
            }
            crate::standard::orchestration::aft_collapse::collapse_backed_aft_status(
                &status,
                candidates.iter(),
            )
        } else {
            status
        };
        Ok(Response::new(GetStatusResponse {
            height: durable_status.height,
            latest_timestamp: durable_status.latest_timestamp,
            total_transactions: durable_status.total_transactions,
            is_running: durable_status.is_running,
        }))
    }
}

// -----------------------------------------------------------------------------
// StateQuery Service
// -----------------------------------------------------------------------------

/// Implementation of the `StateQuery` gRPC service for state queries and pre-checks.
pub struct StateQueryImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Shared RPC context.
    pub ctx: Arc<RpcContext<CS, ST>>,
}

struct AnchoredReadState<'a, ST: StateManager> {
    state: &'a ST,
    anchor_commitment: ST::Commitment,
    anchor_is_live_head: bool,
}

impl<'a, ST: StateManager> AnchoredReadState<'a, ST> {
    fn new(
        state: &'a ST,
        anchor: [u8; 32],
        fallback_roots: &[Vec<u8>],
    ) -> Result<Self, StateError> {
        let anchor_commitment = Self::resolve_anchor_commitment(state, anchor, fallback_roots)?;
        let anchor_is_live_head = state.commitment_to_bytes(&anchor_commitment)
            == state.commitment_to_bytes(&state.root_commitment());
        Ok(Self {
            state,
            anchor_commitment,
            anchor_is_live_head,
        })
    }

    fn resolve_anchor_commitment(
        state: &ST,
        anchor: [u8; 32],
        fallback_roots: &[Vec<u8>],
    ) -> Result<ST::Commitment, StateError> {
        if let Some(commitment) = state.commitment_from_anchor(&anchor) {
            if state.version_exists_for_root(&commitment) {
                return Ok(commitment);
            }
        }

        let mut candidate_roots = Vec::with_capacity(fallback_roots.len() + 1);
        candidate_roots.push(state.commitment_to_bytes(&state.root_commitment()));
        for root in fallback_roots {
            if !root.is_empty() && !candidate_roots.iter().any(|candidate| candidate == root) {
                candidate_roots.push(root.clone());
            }
        }

        for root in candidate_roots {
            let root_anchor = StateRoot(root.clone()).to_anchor().map_err(|error| {
                StateError::Validation(format!("failed to derive fallback state anchor: {error}"))
            })?;
            if root_anchor.0 != anchor {
                continue;
            }

            let commitment = state.commitment_from_bytes(&root)?;
            if state.version_exists_for_root(&commitment) {
                return Ok(commitment);
            }
        }

        Err(StateError::UnknownAnchor(hex::encode(anchor)))
    }

    fn read_only_write_error() -> StateError {
        StateError::WriteError("anchored transaction precheck state is read-only".into())
    }
}

impl<ST: StateManager> StateAccess for AnchoredReadState<'_, ST> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        let (membership, _proof) = self.state.get_with_proof_at(&self.anchor_commitment, key)?;
        Ok(match membership {
            Membership::Present(value) => Some(value),
            Membership::Absent => None,
        })
    }

    fn insert(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), StateError> {
        Err(Self::read_only_write_error())
    }

    fn delete(&mut self, _key: &[u8]) -> Result<(), StateError> {
        Err(Self::read_only_write_error())
    }

    fn batch_set(&mut self, _updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        Err(Self::read_only_write_error())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.get(key)).collect()
    }

    fn batch_apply(
        &mut self,
        _inserts: &[(Vec<u8>, Vec<u8>)],
        _deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        Err(Self::read_only_write_error())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        if self.anchor_is_live_head {
            self.state.prefix_scan(prefix)
        } else {
            Err(StateError::Validation(
                "anchored prefix scans are unavailable for historical precheck roots".into(),
            ))
        }
    }
}

#[tonic::async_trait]
impl<CS, ST> StateQuery for StateQueryImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    async fn check_transactions(
        &self,
        request: Request<CheckTransactionsRequest>,
    ) -> Result<Response<CheckTransactionsResponse>, Status> {
        let req = request.into_inner();
        let anchor: [u8; 32] = req
            .anchor
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("expected 32-byte state anchor"))?;

        let (services, chain_id, height, fallback_roots) = {
            let chain_guard = self.ctx.machine.lock().await;
            let mut roots = Vec::new();
            if let ioi_execution::app::GenesisState::Ready { root, .. } =
                &chain_guard.state.genesis_state
            {
                roots.push(root.clone());
            }
            for block in chain_guard.state.recent_blocks.iter().rev() {
                let root = block.header.state_root.0.clone();
                if !root.is_empty() && !roots.iter().any(|candidate| candidate == &root) {
                    roots.push(root);
                }
            }
            (
                chain_guard.services.clone(),
                chain_guard.state.chain_id,
                chain_guard.status().height,
                roots,
            )
        };

        let mut txs = Vec::new();
        for tx_bytes in req.txs {
            txs.push(
                codec::from_bytes_canonical::<ChainTransaction>(&tx_bytes)
                    .map_err(|e| Status::invalid_argument(e))?,
            );
        }

        let base_state_tree = self.ctx.workload.state_tree();
        let base_state = base_state_tree.read().await;
        let anchored_state = AnchoredReadState::new(&*base_state, anchor, &fallback_roots)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        let mut results = Vec::with_capacity(txs.len());
        for tx in txs {
            // [FIX] Removed mut keyword here
            let ctx = ioi_api::transaction::context::TxContext {
                block_height: height + 1,
                // [FIX] Convert seconds to nanoseconds (u64)
                block_timestamp: req.expected_timestamp_secs.saturating_mul(1_000_000_000),
                chain_id,
                signer_account_id: ioi_types::app::AccountId::default(), // Will be set by apply/verify
                services: &services,
                simulation: true,
                is_internal: false,
            };

            // Use system validation helpers directly instead of full model execution for speed
            use ioi_tx::system::{nonce, validation};

            let check_result = (|| -> Result<(), ioi_types::error::TransactionError> {
                validation::verify_stateless_signature(&tx)?;
                validation::verify_stateful_authorization(&anchored_state, &services, &tx, &ctx)?;
                // Admission only needs to reject stale nonces. The mempool already
                // handles exact ordering by placing nonce gaps into the Future queue.
                nonce::assert_nonce_at_least(&anchored_state, &tx)?;
                Ok(())
            })();

            results.push(match check_result {
                Ok(_) => CheckResult {
                    success: true,
                    error: String::new(),
                },
                Err(e) => CheckResult {
                    success: false,
                    error: e.to_string(),
                },
            });
        }

        Ok(Response::new(CheckTransactionsResponse { results }))
    }

    // ... (rest of implementation remains the same)
    async fn query_state_at(
        &self,
        request: Request<QueryStateAtRequest>,
    ) -> Result<Response<QueryStateAtResponse>, Status> {
        let req = request.into_inner();
        let root = StateRoot(req.root);

        let state_tree = self.ctx.workload.state_tree();
        let state = state_tree.read().await;
        let root_commitment = state
            .commitment_from_bytes(&root.0)
            .map_err(|e| Status::internal(e.to_string()))?;
        let current_root = state.commitment_to_bytes(&state.root_commitment());
        let root_known_before_query = state.version_exists_for_root(&root_commitment);
        let (membership, proof) = match state.get_with_proof_at(&root_commitment, &req.key) {
            Ok(result) => result,
            Err(error) => {
                drop(state);
                let machine = self.ctx.machine.lock().await;
                let recent_block_root = machine
                    .state
                    .recent_blocks
                    .last()
                    .map(|block| block.header.state_root.0.clone())
                    .unwrap_or_default();
                tracing::error!(
                    target: "state_query",
                    requested_root = %hex::encode(&root.0),
                    requested_root_len = root.0.len(),
                    current_root = %hex::encode(&current_root),
                    current_root_len = current_root.len(),
                    root_known_before_query,
                    machine_height = machine.state.status.height,
                    machine_last_state_root = %hex::encode(&machine.state.last_state_root),
                    recent_block_height = machine.state.recent_blocks.last().map(|block| block.header.height).unwrap_or(0),
                    recent_block_root = %hex::encode(recent_block_root),
                    key = %hex::encode(&req.key),
                    error = %error,
                    "query_state_at failed because the requested root was not resolvable by the workload state backend"
                );
                return Err(Status::internal(error.to_string()));
            }
        };

        let proof_bytes = codec::to_bytes_canonical(&proof).map_err(|e| Status::internal(e))?;
        let resp_struct = ioi_api::chain::QueryStateResponse {
            msg_version: 1,
            scheme_id: 1,
            scheme_version: 1,
            membership,
            proof_bytes,
        };
        let response_bytes =
            codec::to_bytes_canonical(&resp_struct).map_err(|e| Status::internal(e))?;

        Ok(Response::new(QueryStateAtResponse { response_bytes }))
    }

    async fn query_raw_state(
        &self,
        request: Request<QueryRawStateRequest>,
    ) -> Result<Response<QueryRawStateResponse>, Status> {
        let req = request.into_inner();
        let state_tree = self.ctx.workload.state_tree();
        let state = state_tree.read().await;
        match state.get(&req.key) {
            Ok(Some(val)) => Ok(Response::new(QueryRawStateResponse {
                value: val,
                found: true,
            })),
            Ok(None) => {
                match load_aft_auxiliary_raw_state_value(self.ctx.workload.store.as_ref(), &req.key)
                {
                    Ok(Some(value)) => {
                        Ok(Response::new(QueryRawStateResponse { value, found: true }))
                    }
                    Ok(None) => Ok(Response::new(QueryRawStateResponse {
                        value: vec![],
                        found: false,
                    })),
                    Err(error) => Err(Status::internal(error.to_string())),
                }
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn prefix_scan(
        &self,
        request: Request<PrefixScanRequest>,
    ) -> Result<Response<PrefixScanResponse>, Status> {
        let req = request.into_inner();
        let state_tree = self.ctx.workload.state_tree();
        let state = state_tree.read().await;
        let iter = state
            .prefix_scan(&req.prefix)
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut pairs = Vec::new();
        for res in iter {
            let (k, v) = res.map_err(|e| Status::internal(e.to_string()))?;
            pairs.push(KeyValuePair {
                key: k.to_vec(),
                value: v.to_vec(),
            });
        }
        Ok(Response::new(PrefixScanResponse { pairs }))
    }
}

// -----------------------------------------------------------------------------
// ContractControl Service
// -----------------------------------------------------------------------------

/// Implementation of the `ContractControl` gRPC service for smart contracts.
pub struct ContractControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Shared RPC context.
    pub ctx: Arc<RpcContext<CS, ST>>,
}

#[tonic::async_trait]
impl<CS, ST> ContractControl for ContractControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    async fn deploy_contract(
        &self,
        req: Request<DeployContractRequest>,
    ) -> Result<Response<DeployContractResponse>, Status> {
        let r = req.into_inner();
        let (addr, changes) = self
            .ctx
            .workload
            .deploy_contract(r.code, r.sender)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let state_changes = changes
            .into_iter()
            .map(|(k, v)| KeyValuePair { key: k, value: v })
            .collect();
        Ok(Response::new(DeployContractResponse {
            address: addr,
            state_changes,
        }))
    }

    async fn call_contract(
        &self,
        req: Request<CallContractRequest>,
    ) -> Result<Response<CallContractResponse>, Status> {
        let r = req.into_inner();
        let exec_ctx = codec::from_bytes_canonical(&r.context_bytes)
            .map_err(|e| Status::invalid_argument(e))?;
        let (output, (inserts, deletions)) = self
            .ctx
            .workload
            .call_contract(r.address, r.input_data, exec_ctx)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let execution_output =
            codec::to_bytes_canonical(&output).map_err(|e| Status::internal(e))?;
        let state_changes = inserts
            .into_iter()
            .map(|(k, v)| KeyValuePair { key: k, value: v })
            .collect();
        Ok(Response::new(CallContractResponse {
            execution_output,
            state_changes,
            deletions,
        }))
    }

    async fn query_contract(
        &self,
        req: Request<QueryContractRequest>,
    ) -> Result<Response<QueryContractResponse>, Status> {
        let r = req.into_inner();
        let exec_ctx = codec::from_bytes_canonical(&r.context_bytes)
            .map_err(|e| Status::invalid_argument(e))?;
        let output = self
            .ctx
            .workload
            .query_contract(r.address, r.input_data, exec_ctx)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(QueryContractResponse {
            execution_output: codec::to_bytes_canonical(&output)
                .map_err(|e| Status::internal(e))?,
        }))
    }
}

// -----------------------------------------------------------------------------
// StakingControl Service
// -----------------------------------------------------------------------------

/// Implementation of the `StakingControl` gRPC service for validator sets.
pub struct StakingControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Shared RPC context.
    pub ctx: Arc<RpcContext<CS, ST>>,
}

#[tonic::async_trait]
impl<CS, ST> StakingControl for StakingControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    async fn get_staked_validators(
        &self,
        _: Request<GetStakedValidatorsRequest>,
    ) -> Result<Response<GetStakedValidatorsResponse>, Status> {
        let stakes = self
            .ctx
            .machine
            .lock()
            .await
            .get_staked_validators()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let validators = stakes
            .into_iter()
            .map(|(k, v)| (hex::encode(k.0), v))
            .collect();
        Ok(Response::new(GetStakedValidatorsResponse { validators }))
    }
    async fn get_next_staked_validators(
        &self,
        _: Request<GetNextStakedValidatorsRequest>,
    ) -> Result<Response<GetNextStakedValidatorsResponse>, Status> {
        let stakes = self
            .ctx
            .machine
            .lock()
            .await
            .get_next_staked_validators()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let validators = stakes
            .into_iter()
            .map(|(k, v)| (hex::encode(k.0), v))
            .collect();
        Ok(Response::new(GetNextStakedValidatorsResponse {
            validators,
        }))
    }
}

// -----------------------------------------------------------------------------
// SystemControl Service
// -----------------------------------------------------------------------------

/// Implementation of the `SystemControl` gRPC service for debug/system ops.
pub struct SystemControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    /// Shared RPC context.
    pub ctx: Arc<RpcContext<CS, ST>>,
}

#[tonic::async_trait]
impl<CS, ST> SystemControl for SystemControlImpl<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + AsRef<[u8]>
        + std::fmt::Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync + From<Vec<u8>>,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    async fn get_expected_model_hash(
        &self,
        _: Request<()>,
    ) -> Result<Response<GetExpectedModelHashResponse>, Status> {
        let state_tree = self.ctx.workload.state_tree();
        let json = {
            let state = state_tree.read().await;
            state
                .get(ioi_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH)
                .map_err(|e| Status::internal(e.to_string()))?
                .ok_or(Status::not_found("Model hash not set"))?
        };
        let hex: String =
            serde_json::from_slice(&json).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(GetExpectedModelHashResponse {
            hash: hex::decode(hex).unwrap(),
        }))
    }

    // [FIX] Corrected method name: check_And_tally_proposals -> check_and_tally_proposals
    async fn check_and_tally_proposals(
        &self,
        _: Request<CheckAndTallyProposalsRequest>,
    ) -> Result<Response<CheckAndTallyProposalsResponse>, Status> {
        Ok(Response::new(CheckAndTallyProposalsResponse {
            logs: vec![],
        }))
    }

    async fn debug_pin_height(
        &self,
        r: Request<DebugPinHeightRequest>,
    ) -> Result<Response<()>, Status> {
        self.ctx.workload.pins().pin(r.into_inner().height);
        Ok(Response::new(()))
    }

    async fn debug_unpin_height(
        &self,
        r: Request<DebugUnpinHeightRequest>,
    ) -> Result<Response<()>, Status> {
        self.ctx.workload.pins().unpin(r.into_inner().height);
        Ok(Response::new(()))
    }

    async fn debug_trigger_gc(
        &self,
        _: Request<()>,
    ) -> Result<Response<DebugTriggerGcResponse>, Status> {
        let h = self.ctx.machine.lock().await.status().height;
        let s = self
            .ctx
            .workload
            .run_gc_pass(h)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DebugTriggerGcResponse {
            heights_pruned: s.heights_pruned as u64,
            nodes_deleted: s.nodes_deleted as u64,
        }))
    }
}
