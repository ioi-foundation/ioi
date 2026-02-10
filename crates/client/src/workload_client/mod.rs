// Path: crates/client/src/workload_client/mod.rs

use crate::shmem::DataPlane;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::chain::{QueryStateResponse, WorkloadClientApi};
use ioi_api::vm::{ExecutionContext, ExecutionOutput};
use ioi_types::{
    app::{AccountId, Block, ChainStatus, ChainTransaction, StateAnchor, StateRoot},
    codec,
    error::ChainError,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::Channel;

// Import generated gRPC clients
use ioi_ipc::blockchain::chain_control_client::ChainControlClient;
use ioi_ipc::blockchain::contract_control_client::ContractControlClient;
use ioi_ipc::blockchain::staking_control_client::StakingControlClient;
use ioi_ipc::blockchain::state_query_client::StateQueryClient;
use ioi_ipc::blockchain::system_control_client::SystemControlClient;

// Import request/response types and enums
use ioi_ipc::blockchain::{
    get_blocks_range_response::Data as BlocksData,
    process_block_request::Payload as ProcessPayload, CallContractRequest,
    CheckAndTallyProposalsRequest, CheckTransactionsRequest, DebugPinHeightRequest,
    DebugUnpinHeightRequest, DeployContractRequest, GetBlocksRangeRequest, GetGenesisStatusRequest,
    GetNextStakedValidatorsRequest, GetStakedValidatorsRequest, GetStatusRequest,
    PrefixScanRequest, ProcessBlockRequest, QueryContractRequest, QueryRawStateRequest,
    QueryStateAtRequest, SharedMemoryHandle, UpdateBlockHeaderRequest,
};

// Threshold (64KB) for switching to shared memory transfer
const BLOCK_SHMEM_THRESHOLD: usize = 64 * 1024;

/// Helper to distinguish logic errors (from the remote) vs transport errors (from tonic)
fn map_grpc_error(status: tonic::Status) -> ChainError {
    match status.code() {
        // If the server explicitly returns InvalidArgument, it likely processed it
        // and rejected it logically (e.g., bad signature, state conflict).
        tonic::Code::InvalidArgument => ChainError::Transaction(status.message().to_string()),
        tonic::Code::FailedPrecondition => ChainError::Transaction(status.message().to_string()),

        // Everything else (Unavailable, DeadlineExceeded, Internal, etc.)
        // suggests the infrastructure failed, not the logic.
        _ => ChainError::ExecutionClient(status.to_string()),
    }
}

/// A client for communicating with the Workload container via gRPC and Shared Memory.
pub struct WorkloadClient {
    // gRPC Clients
    chain: Mutex<ChainControlClient<Channel>>,
    state: Mutex<StateQueryClient<Channel>>,
    contract: Mutex<ContractControlClient<Channel>>,
    staking: Mutex<StakingControlClient<Channel>>,
    system: Mutex<SystemControlClient<Channel>>,

    // Data Plane (Shared Memory)
    data_plane: Option<Arc<DataPlane>>,

    // Stored address for logging/debugging
    addr: String,
}

// [FIX] Manual Debug impl
impl std::fmt::Debug for WorkloadClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadClient")
            .field("addr", &self.addr)
            .field("data_plane", &self.data_plane)
            .finish_non_exhaustive()
    }
}

impl WorkloadClient {
    /// Establishes a connection to the Workload container.
    pub async fn new(addr: &str, _ca: &str, _cert: &str, _key: &str) -> Result<Self> {
        let endpoint = if addr.starts_with("http") {
            addr.to_string()
        } else {
            format!("http://{}", addr)
        };

        // FIX: Use connect_lazy() to allow the client structure to be created
        // even if the server is not yet listening. This prevents the Orchestrator
        // from crashing during startup race conditions. Connection errors will be
        // surfaced when the first RPC is attempted (which is handled by the retry loop).
        let channel = Channel::from_shared(endpoint.clone())?.connect_lazy();

        let shmem_id =
            std::env::var("IOI_SHMEM_ID").unwrap_or_else(|_| "ioi_workload_shm_default".into());
        let data_plane = DataPlane::connect(&shmem_id).ok().map(Arc::new);

        if data_plane.is_none() {
            log::warn!(
                "WorkloadClient could not connect to Data Plane '{}'. Falling back to pure gRPC.",
                shmem_id
            );
        } else {
            log::info!("WorkloadClient connected to Data Plane '{}'.", shmem_id);
        }

        Ok(Self {
            chain: Mutex::new(ChainControlClient::new(channel.clone())),
            state: Mutex::new(StateQueryClient::new(channel.clone())),
            contract: Mutex::new(ContractControlClient::new(channel.clone())),
            staking: Mutex::new(StakingControlClient::new(channel.clone())),
            system: Mutex::new(SystemControlClient::new(channel)),
            data_plane,
            addr: addr.to_string(),
        })
    }

    pub fn destination_addr(&self) -> &str {
        &self.addr
    }

    pub async fn get_status(&self) -> Result<ChainStatus> {
        let mut client = self.chain.lock().await;
        let resp = client
            .get_status(GetStatusRequest {})
            .await
            .map_err(|e| anyhow!("gRPC get_status failed: {}", e))?
            .into_inner();

        Ok(ChainStatus {
            height: resp.height,
            latest_timestamp: resp.latest_timestamp,
            total_transactions: resp.total_transactions,
            is_running: resp.is_running,
        })
    }

    pub async fn get_genesis_status_details(
        &self,
    ) -> Result<ioi_ipc::blockchain::GetGenesisStatusResponse> {
        let mut client = self.chain.lock().await;
        let resp = client
            .get_genesis_status(GetGenesisStatusRequest {})
            .await
            .map_err(|e| anyhow!("gRPC get_genesis_status failed: {}", e))?
            .into_inner();
        Ok(resp)
    }

    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        sender: Vec<u8>,
    ) -> Result<(Vec<u8>, HashMap<Vec<u8>, Vec<u8>>)> {
        let req = DeployContractRequest { code, sender };
        let mut client = self.contract.lock().await;
        let resp = client
            .deploy_contract(req)
            .await
            .map_err(|e| anyhow!("gRPC deploy_contract failed: {}", e))?
            .into_inner();

        let mut changes = HashMap::new();
        for kv in resp.state_changes {
            changes.insert(kv.key, kv.value);
        }
        Ok((resp.address, changes))
    }

    pub async fn call_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<(ExecutionOutput, HashMap<Vec<u8>, Vec<u8>>)> {
        // [FIX] Map codec string error to anyhow
        let context_bytes = codec::to_bytes_canonical(&context).map_err(|e| anyhow!(e))?;
        let req = CallContractRequest {
            address,
            input_data,
            context_bytes,
        };
        let mut client = self.contract.lock().await;
        let resp = client
            .call_contract(req)
            .await
            .map_err(|e| anyhow!("gRPC call_contract failed: {}", e))?
            .into_inner();

        // [FIX] Map codec string error to anyhow
        let output = codec::from_bytes_canonical(&resp.execution_output).map_err(|e| anyhow!(e))?;
        let mut changes = HashMap::new();
        for kv in resp.state_changes {
            changes.insert(kv.key, kv.value);
        }
        Ok((output, changes))
    }

    pub async fn query_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<ExecutionOutput> {
        // [FIX] Map codec string error to anyhow
        let context_bytes = codec::to_bytes_canonical(&context).map_err(|e| anyhow!(e))?;
        let req = QueryContractRequest {
            address,
            input_data,
            context_bytes,
        };
        let mut client = self.contract.lock().await;
        let resp = client
            .query_contract(req)
            .await
            .map_err(|e| anyhow!("gRPC query_contract failed: {}", e))?
            .into_inner();

        // [FIX] Map codec string error to anyhow
        let output = codec::from_bytes_canonical(&resp.execution_output).map_err(|e| anyhow!(e))?;
        Ok(output)
    }

    pub async fn get_expected_model_hash(&self) -> Result<Vec<u8>> {
        let mut client = self.system.lock().await;
        let resp = client
            .get_expected_model_hash(())
            .await
            .map_err(|e| anyhow!("gRPC get_expected_model_hash failed: {}", e))?
            .into_inner();
        Ok(resp.hash)
    }

    pub async fn check_and_tally_proposals(&self, current_height: u64) -> Result<Vec<String>> {
        let mut client = self.system.lock().await;
        let resp = client
            .check_and_tally_proposals(CheckAndTallyProposalsRequest { current_height })
            .await
            .map_err(|e| anyhow!("gRPC check_and_tally_proposals failed: {}", e))?
            .into_inner();
        Ok(resp.logs)
    }

    pub async fn debug_pin_height(&self, height: u64) -> Result<()> {
        let mut client = self.system.lock().await;
        client
            .debug_pin_height(DebugPinHeightRequest { height })
            .await
            .map_err(|e| anyhow!("gRPC debug_pin_height failed: {}", e))?;
        Ok(())
    }

    pub async fn debug_unpin_height(&self, height: u64) -> Result<()> {
        let mut client = self.system.lock().await;
        client
            .debug_unpin_height(DebugUnpinHeightRequest { height })
            .await
            .map_err(|e| anyhow!("gRPC debug_unpin_height failed: {}", e))?;
        Ok(())
    }

    pub async fn debug_trigger_gc(&self) -> Result<ioi_types::app::DebugTriggerGcResponse> {
        let mut client = self.system.lock().await;
        let resp = client
            .debug_trigger_gc(())
            .await
            .map_err(|e| anyhow!("gRPC debug_trigger_gc failed: {}", e))?
            .into_inner();

        Ok(ioi_types::app::DebugTriggerGcResponse {
            heights_pruned: resp.heights_pruned as usize,
            nodes_deleted: resp.nodes_deleted as usize,
        })
    }

    pub async fn get_next_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>> {
        let mut client = self.staking.lock().await;
        let resp = client
            .get_next_staked_validators(GetNextStakedValidatorsRequest {})
            .await
            .map_err(|e| anyhow!("gRPC get_next_staked_validators failed: {}", e))?
            .into_inner();

        let mut result = BTreeMap::new();
        for (hex_key, stake) in resp.validators {
            let bytes = hex::decode(hex_key)?;
            let mut arr = [0u8; 32];
            if bytes.len() == 32 {
                arr.copy_from_slice(&bytes);
                result.insert(AccountId(arr), stake);
            }
        }
        Ok(result)
    }

    /// Retrieves the state root of the latest block.
    pub async fn get_state_root(&self) -> Result<StateRoot> {
        let status = self.get_status().await?;
        let block = self
            .get_block_by_height(status.height)
            .await?
            .ok_or_else(|| anyhow!("Head block not found"))?;
        Ok(block.header.state_root)
    }

    pub async fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<Block<ChainTransaction>>> {
        // Reusing get_blocks_range logic locally since there's no direct RPC in trait
        // Note: get_blocks_range logic below
        let req = GetBlocksRangeRequest {
            since: height,
            max_blocks: 1,
            max_bytes: 10 * 1024 * 1024,
        };

        let mut client = self.chain.lock().await;
        let response = client
            .get_blocks_range(req)
            .await
            .map_err(|e| anyhow!("gRPC get_blocks_range failed: {}", e))?
            .into_inner();

        // Process response logic copied from get_blocks_range to avoid &self borrow conflict
        let raw_blocks = match response.data {
            Some(BlocksData::Inline(list)) => list.blocks,
            Some(BlocksData::Shmem(handle)) => {
                if let Some(dp) = &self.data_plane {
                    if handle.region_id != dp.id() {
                        return Err(anyhow!("Shmem region ID mismatch"));
                    }
                    let bytes = dp.read_raw(handle.offset, handle.length)?;
                    use prost::Message;
                    let block_list = ioi_ipc::blockchain::BlockList::decode(bytes)
                        .map_err(|e| anyhow!("Failed to decode BlockList: {}", e))?;
                    block_list.blocks
                } else {
                    return Err(anyhow!(
                        "Received Shmem response but Data Plane not configured"
                    ));
                }
            }
            None => vec![],
        };

        if let Some(b_bytes) = raw_blocks.into_iter().next() {
            let b: Block<ChainTransaction> = codec::from_bytes_canonical(&b_bytes)
                .map_err(|e| anyhow!("Failed to decode block: {}", e))?;
            if b.header.height == height {
                return Ok(Some(b));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl WorkloadClientApi for WorkloadClient {
    async fn process_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> ioi_types::Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        // [FIX] Map codec string error to ChainError
        let block_bytes = codec::to_bytes_canonical(&block)
            .map_err(|e| ChainError::Transaction(e.to_string()))?;

        // Hybrid Data Plane Logic
        let payload = if block_bytes.len() > BLOCK_SHMEM_THRESHOLD {
            if let Some(dp) = &self.data_plane {
                // Write raw bytes to shared memory (Zero-Copy transfer)
                match dp.write_raw(&block_bytes, None) {
                    Ok(handle) => {
                        log::debug!(
                            "Transmitting block {} via Data Plane ({} bytes, offset {})",
                            block.header.height,
                            handle.length,
                            handle.offset
                        );
                        ProcessPayload::ShmemHandle(SharedMemoryHandle {
                            region_id: handle.region_id,
                            offset: handle.offset,
                            length: handle.length,
                        })
                    }
                    Err(e) => {
                        log::warn!("Data Plane write failed, falling back to inline: {}", e);
                        ProcessPayload::BlockBytesInline(block_bytes)
                    }
                }
            } else {
                ProcessPayload::BlockBytesInline(block_bytes)
            }
        } else {
            ProcessPayload::BlockBytesInline(block_bytes)
        };

        let req = ProcessBlockRequest {
            payload: Some(payload),
        };
        let mut client = self.chain.lock().await;
        let resp = client
            .process_block(req)
            .await
            .map_err(map_grpc_error)?
            .into_inner();

        let processed = codec::from_bytes_canonical(&resp.block_bytes).map_err(|e| {
            ChainError::Transaction(format!("Failed to decode processed block: {}", e))
        })?;

        Ok((processed, resp.events))
    }

    async fn get_blocks_range(
        &self,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
    ) -> ioi_types::Result<Vec<Block<ChainTransaction>>, ChainError> {
        let request = GetBlocksRangeRequest {
            since,
            max_blocks,
            max_bytes,
        };

        let mut client = self.chain.lock().await;
        let response = client
            .get_blocks_range(request)
            .await
            .map_err(map_grpc_error)?
            .into_inner();

        let raw_blocks = match response.data {
            Some(BlocksData::Inline(list)) => list.blocks,
            Some(BlocksData::Shmem(handle)) => {
                if let Some(dp) = &self.data_plane {
                    if handle.region_id != dp.id() {
                        return Err(ChainError::Transaction("Shmem region ID mismatch".into()));
                    }
                    let bytes = dp.read_raw(handle.offset, handle.length).map_err(|e| {
                        ChainError::Transaction(format!("Shmem read failed: {}", e))
                    })?;
                    use prost::Message;
                    let block_list =
                        ioi_ipc::blockchain::BlockList::decode(bytes).map_err(|e| {
                            ChainError::Transaction(format!(
                                "Failed to decode BlockList from shmem: {}",
                                e
                            ))
                        })?;
                    block_list.blocks
                } else {
                    return Err(ChainError::Transaction(
                        "Received Shmem response but Data Plane is not configured client-side"
                            .into(),
                    ));
                }
            }
            None => vec![],
        };

        let mut blocks = Vec::with_capacity(raw_blocks.len());
        for b_bytes in raw_blocks {
            let b = codec::from_bytes_canonical(&b_bytes)
                .map_err(|e| ChainError::Transaction(format!("Failed to decode block: {}", e)))?;
            blocks.push(b);
        }
        Ok(blocks)
    }

    async fn get_block_by_height(
        &self,
        height: u64,
    ) -> ioi_types::Result<Option<Block<ChainTransaction>>, ChainError> {
        let mut blocks = self.get_blocks_range(height, 1, 10 * 1024 * 1024).await?;
        Ok(blocks.pop())
    }

    async fn check_transactions_at(
        &self,
        anchor: StateAnchor,
        expected_timestamp_secs: u64,
        txs: Vec<ChainTransaction>,
    ) -> ioi_types::Result<Vec<std::result::Result<(), String>>, ChainError> {
        let mut encoded_txs = Vec::with_capacity(txs.len());
        for tx in txs {
            encoded_txs.push(
                codec::to_bytes_canonical(&tx)
                    .map_err(|e| ChainError::Transaction(e.to_string()))?,
            );
        }

        let request = CheckTransactionsRequest {
            anchor: anchor.0.to_vec(),
            expected_timestamp_secs,
            txs: encoded_txs,
        };

        let mut client = self.state.lock().await;
        let response = client
            .check_transactions(request)
            .await
            .map_err(map_grpc_error)?
            .into_inner();

        let results = response
            .results
            .into_iter()
            .map(|r| if r.success { Ok(()) } else { Err(r.error) })
            .collect();

        Ok(results)
    }

    async fn query_state_at(
        &self,
        root: StateRoot,
        key: &[u8],
    ) -> ioi_types::Result<QueryStateResponse, ChainError> {
        let request = QueryStateAtRequest {
            root: root.0,
            key: key.to_vec(),
        };

        let mut client = self.state.lock().await;
        let response = client
            .query_state_at(request)
            .await
            .map_err(map_grpc_error)?
            .into_inner();

        codec::from_bytes_canonical(&response.response_bytes).map_err(|e| {
            ChainError::Transaction(format!("Failed to decode QueryStateResponse: {}", e))
        })
    }

    async fn query_raw_state(&self, key: &[u8]) -> ioi_types::Result<Option<Vec<u8>>, ChainError> {
        let request = QueryRawStateRequest { key: key.to_vec() };

        let mut client = self.state.lock().await;
        let response = client
            .query_raw_state(request)
            .await
            .map_err(map_grpc_error)?
            .into_inner();

        if response.found {
            Ok(Some(response.value))
        } else {
            Ok(None)
        }
    }

    async fn prefix_scan(
        &self,
        prefix: &[u8],
    ) -> ioi_types::Result<Vec<(Vec<u8>, Vec<u8>)>, ChainError> {
        let request = PrefixScanRequest {
            prefix: prefix.to_vec(),
        };

        let mut client = self.state.lock().await;
        let response = client
            .prefix_scan(request)
            .await
            .map_err(map_grpc_error)?
            .into_inner();

        let pairs = response
            .pairs
            .into_iter()
            .map(|kv| (kv.key, kv.value))
            .collect();
        Ok(pairs)
    }

    async fn get_staked_validators(
        &self,
    ) -> ioi_types::Result<BTreeMap<AccountId, u64>, ChainError> {
        let request = GetStakedValidatorsRequest {};
        let mut client = self.staking.lock().await;
        let response = client
            .get_staked_validators(request)
            .await
            .map_err(map_grpc_error)?
            .into_inner();

        let mut result = BTreeMap::new();
        for (hex_key, stake) in response.validators {
            let bytes = hex::decode(&hex_key)
                .map_err(|e| ChainError::Transaction(format!("Invalid AccountId hex: {}", e)))?;
            if bytes.len() != 32 {
                return Err(ChainError::Transaction("Invalid AccountId length".into()));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            result.insert(AccountId(arr), stake);
        }
        Ok(result)
    }

    async fn get_genesis_status(&self) -> ioi_types::Result<bool, ChainError> {
        let request = GetGenesisStatusRequest {};
        let mut client = self.chain.lock().await;
        let response = client
            .get_genesis_status(request)
            .await
            .map_err(map_grpc_error)?
            .into_inner();
        Ok(response.ready)
    }

    async fn update_block_header(
        &self,
        block: Block<ChainTransaction>,
    ) -> ioi_types::Result<(), ChainError> {
        let block_bytes = codec::to_bytes_canonical(&block)
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        let request = UpdateBlockHeaderRequest { block_bytes };

        let mut client = self.chain.lock().await;
        client
            .update_block_header(request)
            .await
            .map_err(map_grpc_error)?;
        Ok(())
    }

    // [NEW] Implementation via delegation to inherent method
    async fn get_state_root(&self) -> std::result::Result<StateRoot, ChainError> {
        // We use the inherent method on the struct
        self.get_state_root()
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    // [NEW] Implementation via delegation to inherent method
    async fn get_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        // We use the inherent method on the struct
        self.get_status()
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
