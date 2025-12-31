// Path: crates/validator/src/standard/workload/ipc/grpc_blockchain.rs

use crate::standard::workload::ipc::RpcContext;
use ioi_api::{chain::ChainStateMachine, commitment::CommitmentScheme, state::StateManager};
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
    app::{Block, ChainTransaction, StateRoot},
    codec,
};
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
        let blocks = self
            .ctx
            .workload
            .store
            .get_blocks_range(req.since, req.max_blocks, req.max_bytes)
            .map_err(|e| Status::internal(e.to_string()))?;

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
        let block: Block<ChainTransaction> = codec::from_bytes_canonical(&req.block_bytes)
            .map_err(|e| Status::invalid_argument(e))?;

        self.ctx
            .workload
            .store
            .put_block(block.header.height, &req.block_bytes)
            .await // Add await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut machine = self.ctx.machine.lock().await;
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
        let machine = self.ctx.machine.lock().await;
        let s = machine.status();
        Ok(Response::new(GetStatusResponse {
            height: s.height,
            latest_timestamp: s.latest_timestamp,
            total_transactions: s.total_transactions,
            is_running: s.is_running,
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

        let (services, chain_id, height) = {
            let chain_guard = self.ctx.machine.lock().await;
            (
                chain_guard.services.clone(),
                chain_guard.state.chain_id,
                chain_guard.status().height,
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
        let mut overlay = ioi_api::state::StateOverlay::new(&*base_state);

        let mut results = Vec::with_capacity(txs.len());
        for tx in txs {
            // [FIX] Updated import
            use crate::firewall::enforce_firewall;
            
            // [FIX] Use enforce_firewall instead of check_tx
            let check_result: Result<(), ioi_types::error::TransactionError> = enforce_firewall(
                &mut overlay,
                &services,
                &tx,
                chain_id,
                height + 1,
                req.expected_timestamp_secs,
                false,
                true, // is_simulation
            )
            .await;

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
        let (membership, proof) = state
            .get_with_proof_at(&root_commitment, &req.key)
            .map_err(|e| Status::internal(e.to_string()))?;

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
            Ok(None) => Ok(Response::new(QueryRawStateResponse {
                value: vec![],
                found: false,
            })),
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