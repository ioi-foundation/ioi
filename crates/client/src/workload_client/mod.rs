// Path: crates/client/src/workload_client/mod.rs

use crate::shmem::DataPlane;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::chain::{AdmissionWitness, QueryStateResponse, WorkloadClientApi};
use ioi_api::storage::AdmittedTip;
use ioi_api::vm::{ExecutionContext, ExecutionOutput};
use ioi_types::{
    app::{AccountId, Block, ChainStatus, ChainTransaction, StateAnchor, StateRoot},
    codec,
    error::ChainError,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
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
    QueryStateAtRequest, RecordAdmittedTipRequest, ReplaceUnfinalizedTipRequest,
    SharedMemoryHandle, UpdateBlockHeaderRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Threshold (64KB) for switching to shared memory transfer
const BLOCK_SHMEM_THRESHOLD: usize = 64 * 1024;
const WORKLOAD_GRPC_MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const SINGLE_BLOCK_FETCH_MAX_BYTES: u32 = 64 * 1024 * 1024;
const DEFAULT_WORKLOAD_GRPC_REQUEST_TIMEOUT_MS: u64 = 10_000;
pub const WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION: &str =
    "ioi.workload.step_module_dispatch.v1";
pub const WORKLOAD_STEP_MODULE_DISPATCH_EVIDENCE_REF: &str =
    "rust_workload_client_step_module_dispatch";
pub const WORKLOAD_STEP_MODULE_TRANSPORT_GRPC: &str = "workload_grpc";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadStepModuleDispatchRequest {
    pub schema_version: String,
    pub invocation_id: String,
    pub module_kind: String,
    pub module_ref: String,
    pub execution_backend: String,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub payload_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_plane_handle: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadStepModuleDispatchPlan {
    pub schema_version: String,
    pub invocation_id: String,
    pub module_ref: String,
    pub execution_backend: String,
    pub transport: String,
    pub data_plane_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_plane_handle: Option<Value>,
    pub artifact_refs: Vec<String>,
    pub payload_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadStepModuleDispatchError {
    InvalidSchemaVersion { actual: String },
    MissingField(&'static str),
    DaemonJsBackendRetired,
    UnsupportedExecutionBackend { backend: String },
    UnsupportedModuleKind { module_kind: String },
}

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

fn workload_grpc_request_timeout_ms() -> u64 {
    std::env::var("IOI_WORKLOAD_GRPC_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_WORKLOAD_GRPC_REQUEST_TIMEOUT_MS)
}

fn workload_grpc_request_timeout() -> Duration {
    Duration::from_millis(workload_grpc_request_timeout_ms())
}

fn workload_timeout_anyhow(label: &str) -> anyhow::Error {
    anyhow!(
        "gRPC {} timed out after {}ms",
        label,
        workload_grpc_request_timeout_ms()
    )
}

fn workload_timeout_chain(label: &str) -> ChainError {
    ChainError::ExecutionClient(format!(
        "gRPC {} timed out after {}ms",
        label,
        workload_grpc_request_timeout_ms()
    ))
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
    data_plane: Mutex<Option<Arc<DataPlane>>>,
    shmem_id: String,

    // Stored address for logging/debugging
    addr: String,
}

// [FIX] Manual Debug impl
impl std::fmt::Debug for WorkloadClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadClient")
            .field("addr", &self.addr)
            .field("shmem_id", &self.shmem_id)
            .finish_non_exhaustive()
    }
}

impl WorkloadClient {
    pub fn plan_step_module_dispatch(
        request: &WorkloadStepModuleDispatchRequest,
    ) -> std::result::Result<WorkloadStepModuleDispatchPlan, WorkloadStepModuleDispatchError> {
        if request.schema_version != WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION {
            return Err(WorkloadStepModuleDispatchError::InvalidSchemaVersion {
                actual: request.schema_version.clone(),
            });
        }
        require_workload_dispatch_field("invocation_id", &request.invocation_id)?;
        require_workload_dispatch_field("module_ref", &request.module_ref)?;
        require_workload_dispatch_field("module_kind", &request.module_kind)?;
        require_workload_dispatch_field("execution_backend", &request.execution_backend)?;
        if request.execution_backend == "daemon_js" {
            return Err(WorkloadStepModuleDispatchError::DaemonJsBackendRetired);
        }
        if request.execution_backend != WORKLOAD_STEP_MODULE_TRANSPORT_GRPC {
            return Err(
                WorkloadStepModuleDispatchError::UnsupportedExecutionBackend {
                    backend: request.execution_backend.clone(),
                },
            );
        }
        if request.module_kind != "workload_job"
            && request.module_kind != "rust_wasm_service_module"
        {
            return Err(WorkloadStepModuleDispatchError::UnsupportedModuleKind {
                module_kind: request.module_kind.clone(),
            });
        }
        Ok(WorkloadStepModuleDispatchPlan {
            schema_version: WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION.to_string(),
            invocation_id: request.invocation_id.clone(),
            module_ref: request.module_ref.clone(),
            execution_backend: request.execution_backend.clone(),
            transport: WORKLOAD_STEP_MODULE_TRANSPORT_GRPC.to_string(),
            data_plane_required: workload_dispatch_data_plane_required(
                request.data_plane_handle.as_ref(),
            ),
            data_plane_handle: request.data_plane_handle.clone(),
            artifact_refs: unique_workload_refs(&request.artifact_refs),
            payload_refs: unique_workload_refs(&request.payload_refs),
            evidence_refs: vec![WORKLOAD_STEP_MODULE_DISPATCH_EVIDENCE_REF.to_string()],
        })
    }

    async fn clone_chain_client(&self) -> ChainControlClient<Channel> {
        self.chain.lock().await.clone()
    }

    async fn clone_state_client(&self) -> StateQueryClient<Channel> {
        self.state.lock().await.clone()
    }

    async fn clone_staking_client(&self) -> StakingControlClient<Channel> {
        self.staking.lock().await.clone()
    }

    async fn clone_system_client(&self) -> SystemControlClient<Channel> {
        self.system.lock().await.clone()
    }

    async fn clone_contract_client(&self) -> ContractControlClient<Channel> {
        self.contract.lock().await.clone()
    }

    fn try_connect_data_plane(
        shmem_id: &str,
        connect_retries: u32,
        connect_backoff_ms: u64,
    ) -> Option<Arc<DataPlane>> {
        for attempt in 0..=connect_retries {
            match DataPlane::connect(shmem_id) {
                Ok(plane) => return Some(Arc::new(plane)),
                Err(_) if attempt < connect_retries => {
                    thread::sleep(Duration::from_millis(connect_backoff_ms));
                }
                Err(_) => {}
            }
        }
        None
    }

    async fn ensure_data_plane(&self) -> Option<Arc<DataPlane>> {
        {
            let guard = self.data_plane.lock().await;
            if let Some(existing) = guard.as_ref() {
                return Some(existing.clone());
            }
        }

        let connected = Self::try_connect_data_plane(&self.shmem_id, 0, 0);
        if let Some(plane) = connected {
            let mut guard = self.data_plane.lock().await;
            if guard.is_none() {
                log::info!(
                    "WorkloadClient attached to Data Plane '{}' after lazy retry.",
                    self.shmem_id
                );
                *guard = Some(plane.clone());
            }
            return guard.as_ref().cloned();
        }

        None
    }

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
        let connect_retries = std::env::var("IOI_SHMEM_CONNECT_RETRIES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(500);
        let connect_backoff_ms = std::env::var("IOI_SHMEM_CONNECT_BACKOFF_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(20);
        let data_plane =
            Self::try_connect_data_plane(&shmem_id, connect_retries, connect_backoff_ms);

        if data_plane.is_none() {
            log::warn!(
                "WorkloadClient could not connect to Data Plane '{}'. Falling back to pure gRPC.",
                shmem_id
            );
        } else {
            log::info!("WorkloadClient connected to Data Plane '{}'.", shmem_id);
        }

        Ok(Self {
            chain: Mutex::new(
                ChainControlClient::new(channel.clone())
                    .max_decoding_message_size(WORKLOAD_GRPC_MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(WORKLOAD_GRPC_MAX_MESSAGE_BYTES),
            ),
            state: Mutex::new(
                StateQueryClient::new(channel.clone())
                    .max_decoding_message_size(WORKLOAD_GRPC_MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(WORKLOAD_GRPC_MAX_MESSAGE_BYTES),
            ),
            contract: Mutex::new(ContractControlClient::new(channel.clone())),
            staking: Mutex::new(StakingControlClient::new(channel.clone())),
            system: Mutex::new(SystemControlClient::new(channel)),
            data_plane: Mutex::new(data_plane),
            shmem_id,
            addr: addr.to_string(),
        })
    }

    pub fn destination_addr(&self) -> &str {
        &self.addr
    }

    /// The COMMITTED chain status: the workload's Agentgres-admitted tip marker (height 0 with
    /// none), never the durable status.
    pub async fn get_committed_status(&self) -> Result<ChainStatus> {
        let mut client = self.clone_chain_client().await;
        let resp = timeout(
            workload_grpc_request_timeout(),
            client.get_committed_status(GetStatusRequest {}),
        )
        .await
        .map_err(|_| workload_timeout_anyhow("get_committed_status"))?
        .map_err(|e| anyhow!("gRPC get_committed_status failed: {}", e))?
        .into_inner();

        Ok(ChainStatus {
            height: resp.height,
            latest_timestamp: resp.latest_timestamp,
            total_transactions: resp.total_transactions,
            is_running: resp.is_running,
            latest_timestamp_ms: resp.latest_timestamp.saturating_mul(1000),
        })
    }

    /// The COMMITTED tip as the workload's admitted-tip marker holds it (FU-N11-DURABLE-STATUS-1
    /// D2a round 2): height, block hash and state root from the marker; `None` before the first
    /// admission.
    pub async fn get_committed_tip(&self) -> Result<Option<AdmittedTip>> {
        let mut client = self.clone_chain_client().await;
        let resp = timeout(
            workload_grpc_request_timeout(),
            client.get_committed_tip(GetStatusRequest {}),
        )
        .await
        .map_err(|_| workload_timeout_anyhow("get_committed_tip"))?
        .map_err(|e| anyhow!("gRPC get_committed_tip failed: {}", e))?
        .into_inner();
        if resp.block_hash.is_empty() {
            return Ok(None);
        }
        let block_hash: [u8; 32] = resp
            .block_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("the committed tip's block hash is not 32 bytes"))?;
        Ok(Some(AdmittedTip {
            height: resp.height,
            block_hash,
            state_root: resp.state_root,
        }))
    }

    /// Sends a RecordAdmittedTip presenting exactly `capability` (FU-N11-DURABLE-STATUS-1 D2a round
    /// 2, B2): the shared client stores no capability; only the orchestration's admitted-tip
    /// publisher holds one.
    async fn record_admitted_tip_ipc(&self, capability: &[u8; 32], tip: &AdmittedTip) -> Result<()> {
        let mut client = self.clone_chain_client().await;
        timeout(
            workload_grpc_request_timeout(),
            client.record_admitted_tip(RecordAdmittedTipRequest {
                height: tip.height,
                block_hash: tip.block_hash.to_vec(),
                state_root: tip.state_root.clone(),
                capability: capability.to_vec(),
            }),
        )
        .await
        .map_err(|_| workload_timeout_anyhow("record_admitted_tip"))?
        .map_err(|e| anyhow!("gRPC record_admitted_tip refused: {}", e))?;
        Ok(())
    }

    pub async fn get_status(&self) -> Result<ChainStatus> {
        let mut client = self.clone_chain_client().await;
        let resp = timeout(
            workload_grpc_request_timeout(),
            client.get_status(GetStatusRequest {}),
        )
        .await
        .map_err(|_| workload_timeout_anyhow("get_status"))?
        .map_err(|e| anyhow!("gRPC get_status failed: {}", e))?
        .into_inner();

        Ok(ChainStatus {
            height: resp.height,
            latest_timestamp: resp.latest_timestamp,
            total_transactions: resp.total_transactions,
            is_running: resp.is_running,
            latest_timestamp_ms: resp.latest_timestamp.saturating_mul(1000),
        })
    }

    /// Returns the data plane's raw executed cursor. This is an internal
    /// restart/reconciliation signal, not a finality statement.
    pub async fn get_execution_status(&self) -> Result<ChainStatus> {
        let mut client = self.clone_chain_client().await;
        let resp = timeout(
            workload_grpc_request_timeout(),
            client.get_execution_status(GetStatusRequest {}),
        )
        .await
        .map_err(|_| workload_timeout_anyhow("get_execution_status"))?
        .map_err(|e| anyhow!("gRPC get_execution_status failed: {}", e))?
        .into_inner();

        Ok(ChainStatus {
            height: resp.height,
            latest_timestamp: resp.latest_timestamp,
            total_transactions: resp.total_transactions,
            is_running: resp.is_running,
            latest_timestamp_ms: resp.latest_timestamp.saturating_mul(1000),
        })
    }

    pub async fn get_genesis_status_details(
        &self,
    ) -> Result<ioi_ipc::blockchain::GetGenesisStatusResponse> {
        let mut client = self.clone_chain_client().await;
        let resp = timeout(
            workload_grpc_request_timeout(),
            client.get_genesis_status(GetGenesisStatusRequest {}),
        )
        .await
        .map_err(|_| workload_timeout_anyhow("get_genesis_status"))?
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
        let mut client = self.clone_contract_client().await;
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
        let mut client = self.clone_contract_client().await;
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
        let mut client = self.clone_contract_client().await;
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
        let mut client = self.clone_system_client().await;
        let resp = client
            .get_expected_model_hash(())
            .await
            .map_err(|e| anyhow!("gRPC get_expected_model_hash failed: {}", e))?
            .into_inner();
        Ok(resp.hash)
    }

    pub async fn check_and_tally_proposals(&self, current_height: u64) -> Result<Vec<String>> {
        let mut client = self.clone_system_client().await;
        let resp = client
            .check_and_tally_proposals(CheckAndTallyProposalsRequest { current_height })
            .await
            .map_err(|e| anyhow!("gRPC check_and_tally_proposals failed: {}", e))?
            .into_inner();
        Ok(resp.logs)
    }

    pub async fn debug_pin_height(&self, height: u64) -> Result<()> {
        let mut client = self.clone_system_client().await;
        client
            .debug_pin_height(DebugPinHeightRequest { height })
            .await
            .map_err(|e| anyhow!("gRPC debug_pin_height failed: {}", e))?;
        Ok(())
    }

    pub async fn debug_unpin_height(&self, height: u64) -> Result<()> {
        let mut client = self.clone_system_client().await;
        client
            .debug_unpin_height(DebugUnpinHeightRequest { height })
            .await
            .map_err(|e| anyhow!("gRPC debug_unpin_height failed: {}", e))?;
        Ok(())
    }

    pub async fn debug_trigger_gc(&self) -> Result<ioi_types::app::DebugTriggerGcResponse> {
        let mut client = self.clone_system_client().await;
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
        let mut client = self.clone_staking_client().await;
        let resp = timeout(
            workload_grpc_request_timeout(),
            client.get_next_staked_validators(GetNextStakedValidatorsRequest {}),
        )
        .await
        .map_err(|_| workload_timeout_anyhow("get_next_staked_validators"))?
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

    /// Retrieves the state root of the latest COMMITTED (Agentgres-admitted) block, never of the
    /// durable tip, which may be uncommitted (FU-N11-DURABLE-STATUS-1 D2a, C7).
    pub async fn get_state_root(&self) -> Result<StateRoot> {
        Ok(ioi_api::chain::committed_state_root(self).await?)
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
            max_bytes: SINGLE_BLOCK_FETCH_MAX_BYTES,
        };

        let mut client = self.clone_chain_client().await;
        let response = timeout(
            workload_grpc_request_timeout(),
            client.get_blocks_range(req),
        )
        .await
        .map_err(|_| workload_timeout_anyhow("get_blocks_range"))?
        .map_err(|e| anyhow!("gRPC get_blocks_range failed: {}", e))?
        .into_inner();

        // Process response logic copied from get_blocks_range to avoid &self borrow conflict
        let raw_blocks = match response.data {
            Some(BlocksData::Inline(list)) => list.blocks,
            Some(BlocksData::Shmem(handle)) => {
                if let Some(dp) = self.ensure_data_plane().await {
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

fn require_workload_dispatch_field(
    field: &'static str,
    value: &str,
) -> std::result::Result<(), WorkloadStepModuleDispatchError> {
    if value.trim().is_empty() {
        return Err(WorkloadStepModuleDispatchError::MissingField(field));
    }
    Ok(())
}

fn workload_dispatch_data_plane_required(handle: Option<&Value>) -> bool {
    handle
        .and_then(|value| value.get("required"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn unique_workload_refs(values: &[String]) -> Vec<String> {
    values.iter().fold(Vec::new(), |mut refs, value| {
        let value = value.trim();
        if !value.is_empty() && !refs.iter().any(|existing| existing == value) {
            refs.push(value.to_string());
        }
        refs
    })
}

#[cfg(test)]
mod workload_step_module_dispatch_tests {
    use super::*;
    use serde_json::json;

    fn dispatch_request() -> WorkloadStepModuleDispatchRequest {
        WorkloadStepModuleDispatchRequest {
            schema_version: WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION.to_string(),
            invocation_id: "invocation://workspace-status".to_string(),
            module_kind: "workload_job".to_string(),
            module_ref: "workspace.status".to_string(),
            execution_backend: WORKLOAD_STEP_MODULE_TRANSPORT_GRPC.to_string(),
            artifact_refs: vec![
                "artifact://input".to_string(),
                "artifact://input".to_string(),
            ],
            payload_refs: vec!["payload://context".to_string()],
            data_plane_handle: Some(json!({
                "region_id": "ioi_workload_shm_default",
                "offset": 0,
                "length": 128,
                "codec": "rkyv",
                "required": true
            })),
        }
    }

    #[test]
    fn workload_client_plans_step_module_dispatch_contract() {
        let plan = WorkloadClient::plan_step_module_dispatch(&dispatch_request())
            .expect("workload dispatch should be planned");

        assert_eq!(
            plan.schema_version,
            WORKLOAD_STEP_MODULE_DISPATCH_SCHEMA_VERSION
        );
        assert_eq!(plan.invocation_id, "invocation://workspace-status");
        assert_eq!(plan.module_ref, "workspace.status");
        assert_eq!(plan.execution_backend, WORKLOAD_STEP_MODULE_TRANSPORT_GRPC);
        assert_eq!(plan.transport, WORKLOAD_STEP_MODULE_TRANSPORT_GRPC);
        assert!(plan.data_plane_required);
        assert_eq!(plan.artifact_refs, vec!["artifact://input"]);
        assert_eq!(plan.payload_refs, vec!["payload://context"]);
        assert!(plan
            .evidence_refs
            .contains(&WORKLOAD_STEP_MODULE_DISPATCH_EVIDENCE_REF.to_string()));
    }

    #[test]
    fn workload_client_rejects_daemon_js_dispatch() {
        let mut request = dispatch_request();
        request.execution_backend = "daemon_js".to_string();

        let error = WorkloadClient::plan_step_module_dispatch(&request)
            .expect_err("daemon_js dispatch must fail closed");

        assert_eq!(
            error,
            WorkloadStepModuleDispatchError::DaemonJsBackendRetired
        );
    }
}

#[async_trait]
impl WorkloadClientApi for WorkloadClient {
    async fn process_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> ioi_types::Result<
        (
            Block<ChainTransaction>,
            Vec<Vec<u8>>,
            Vec<ioi_api::chain::BlockExecutionReceipt>,
        ),
        ChainError,
    > {
        // Serialize the shmem write with the outbound RPC so a concurrent process_block()
        // call cannot overwrite the fixed shmem slot before the workload reads it.
        let mut client = self.chain.lock().await;

        // [FIX] Map codec string error to ChainError
        let block_bytes = codec::to_bytes_canonical(&block)
            .map_err(|e| ChainError::Transaction(e.to_string()))?;

        // Hybrid Data Plane Logic
        let payload = if block_bytes.len() > BLOCK_SHMEM_THRESHOLD {
            if let Some(dp) = self.ensure_data_plane().await {
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
        let resp = client
            .process_block(req)
            .await
            .map_err(map_grpc_error)?
            .into_inner();

        let processed = codec::from_bytes_canonical(&resp.block_bytes).map_err(|e| {
            ChainError::Transaction(format!("Failed to decode processed block: {}", e))
        })?;
        let execution_receipts = resp
            .execution_receipts
            .iter()
            .map(|bytes| {
                codec::from_bytes_canonical(bytes).map_err(|error| {
                    ChainError::Transaction(format!(
                        "Failed to decode block execution receipt: {error}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok((processed, resp.events, execution_receipts))
    }

    async fn replace_unfinalized_tip(
        &self,
        expected_target: Block<ChainTransaction>,
        expected_live_tip: Block<ChainTransaction>,
        replacement: Block<ChainTransaction>,
        recognized_height: u64,
    ) -> ioi_types::Result<
        (
            Block<ChainTransaction>,
            Vec<Vec<u8>>,
            Vec<ioi_api::chain::BlockExecutionReceipt>,
        ),
        ChainError,
    > {
        let request = ReplaceUnfinalizedTipRequest {
            replacement_block_bytes: codec::to_bytes_canonical(&replacement)
                .map_err(ChainError::Transaction)?,
            expected_tip_height: expected_target.header.height,
            expected_parent_state_root: expected_target.header.parent_state_root.0.clone(),
            expected_state_root: expected_target.header.state_root.0.clone(),
            expected_transactions_root: expected_target.header.transactions_root.clone(),
            recognized_height,
            expected_target_block_bytes: codec::to_bytes_canonical(&expected_target)
                .map_err(ChainError::Transaction)?,
            expected_live_tip_block_bytes: codec::to_bytes_canonical(&expected_live_tip)
                .map_err(ChainError::Transaction)?,
        };
        let mut client = self.chain.lock().await;
        let response = client
            .replace_unfinalized_tip(request)
            .await
            .map_err(map_grpc_error)?
            .into_inner();
        let processed = codec::from_bytes_canonical(&response.block_bytes).map_err(|error| {
            ChainError::Transaction(format!(
                "Failed to decode replacement block response: {error}"
            ))
        })?;
        let execution_receipts = response
            .execution_receipts
            .iter()
            .map(|bytes| {
                codec::from_bytes_canonical(bytes).map_err(|error| {
                    ChainError::Transaction(format!(
                        "Failed to decode replacement execution receipt: {error}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((processed, response.events, execution_receipts))
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

        let mut client = self.clone_chain_client().await;
        let response = timeout(
            workload_grpc_request_timeout(),
            client.get_blocks_range(request),
        )
        .await
        .map_err(|_| workload_timeout_chain("get_blocks_range"))?
        .map_err(map_grpc_error)?
        .into_inner();

        let raw_blocks = match response.data {
            Some(BlocksData::Inline(list)) => list.blocks,
            Some(BlocksData::Shmem(handle)) => {
                if let Some(dp) = self.ensure_data_plane().await {
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
        let mut blocks = self
            .get_blocks_range(height, 1, SINGLE_BLOCK_FETCH_MAX_BYTES)
            .await?;
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

        let mut client = self.clone_state_client().await;
        let response = timeout(
            workload_grpc_request_timeout(),
            client.check_transactions(request),
        )
        .await
        .map_err(|_| workload_timeout_chain("check_transactions"))?
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

        let mut client = self.clone_state_client().await;
        let response = timeout(
            workload_grpc_request_timeout(),
            client.query_state_at(request),
        )
        .await
        .map_err(|_| workload_timeout_chain("query_state_at"))?
        .map_err(map_grpc_error)?
        .into_inner();

        codec::from_bytes_canonical(&response.response_bytes).map_err(|e| {
            ChainError::Transaction(format!("Failed to decode QueryStateResponse: {}", e))
        })
    }

    async fn query_raw_state(&self, key: &[u8]) -> ioi_types::Result<Option<Vec<u8>>, ChainError> {
        let request = QueryRawStateRequest { key: key.to_vec() };

        let mut client = self.clone_state_client().await;
        let response = timeout(
            workload_grpc_request_timeout(),
            client.query_raw_state(request),
        )
        .await
        .map_err(|_| workload_timeout_chain("query_raw_state"))?
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

        let mut client = self.clone_state_client().await;
        let response = timeout(workload_grpc_request_timeout(), client.prefix_scan(request))
            .await
            .map_err(|_| workload_timeout_chain("prefix_scan"))?
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
        let mut client = self.clone_staking_client().await;
        let response = timeout(
            workload_grpc_request_timeout(),
            client.get_staked_validators(request),
        )
        .await
        .map_err(|_| workload_timeout_chain("get_staked_validators"))?
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
        let mut client = self.clone_chain_client().await;
        let response = timeout(
            workload_grpc_request_timeout(),
            client.get_genesis_status(request),
        )
        .await
        .map_err(|_| workload_timeout_chain("get_genesis_status"))?
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

    async fn get_execution_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        self.get_execution_status()
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn get_committed_status(&self) -> std::result::Result<ChainStatus, ChainError> {
        self.get_committed_status()
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    async fn get_committed_tip(&self) -> std::result::Result<Option<AdmittedTip>, ChainError> {
        self.get_committed_tip()
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    // FU-N11-DURABLE-STATUS-1 D2a round 2, B2: presents exactly the caller's capability.
    async fn record_admitted_tip_with_capability(
        &self,
        _witness: AdmissionWitness,
        capability: &[u8; 32],
        tip: AdmittedTip,
    ) -> std::result::Result<(), ChainError> {
        self.record_admitted_tip_ipc(capability, &tip)
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod admitted_tip_client_tests {
    //! FU-N11-DURABLE-STATUS-1 D2a round 2 (RED-3), B2: the SHARED workload client carries no
    //! admission capability. A record presents exactly the capability its caller passes, so a
    //! non-admission caller holding the shared client (even with a self-built witness) presents
    //! nothing the workload accepts. Driven through the REAL client against a ChainControl mock
    //! served over loopback gRPC.
    use super::WorkloadClient;
    use ioi_api::chain::{AdmissionWitness, WorkloadClientApi};
    use ioi_api::storage::AdmittedTip;
    use ioi_ipc::blockchain::chain_control_server::{ChainControl, ChainControlServer};
    use ioi_ipc::blockchain::{
        GetBlocksRangeRequest, GetBlocksRangeResponse, GetCommittedTipResponse,
        GetGenesisStatusRequest,
        GetGenesisStatusResponse, GetStatusRequest, GetStatusResponse, ProcessBlockRequest,
        ProcessBlockResponse, RecordAdmittedTipRequest, RecordAdmittedTipResponse,
        ReplaceUnfinalizedTipRequest, UpdateBlockHeaderRequest, UpdateBlockHeaderResponse,
    };
    use std::sync::{Arc, Mutex};
    use tonic::{Request, Response, Status};

    /// The admission gate's SECOND CANARY (ioi-client test code; FU-N11-DURABLE-STATUS-1 D2a
    /// round 2): the gate's clippy run over this crate's test target must flag exactly this one
    /// construction. The tests below take their witnesses from here.
    fn admission_gate_canary() -> AdmissionWitness {
        AdmissionWitness::from_agentgres_admission()
    }

    /// The workload's capability in this test (the publisher's, in production).
    const CAPABILITY: [u8; 32] = [0x5A; 32];

    /// A ChainControl that records every capability presented to RecordAdmittedTip and advances
    /// its marker only for `accepted`.
    struct MockWorkload {
        accepted: [u8; 32],
        presented: Mutex<Vec<Vec<u8>>>,
        marker: Mutex<Option<u64>>,
    }

    impl MockWorkload {
        fn presented(&self) -> Vec<Vec<u8>> {
            self.presented.lock().unwrap().clone()
        }
        fn marker(&self) -> Option<u64> {
            *self.marker.lock().unwrap()
        }
    }

    fn unimplemented_rpc<T>() -> Result<Response<T>, Status> {
        Err(Status::unimplemented("not served by the admitted-tip mock"))
    }

    #[tonic::async_trait]
    impl ChainControl for MockWorkload {
        async fn process_block(
            &self,
            _request: Request<ProcessBlockRequest>,
        ) -> Result<Response<ProcessBlockResponse>, Status> {
            unimplemented_rpc()
        }
        async fn replace_unfinalized_tip(
            &self,
            _request: Request<ReplaceUnfinalizedTipRequest>,
        ) -> Result<Response<ProcessBlockResponse>, Status> {
            unimplemented_rpc()
        }
        async fn get_blocks_range(
            &self,
            _request: Request<GetBlocksRangeRequest>,
        ) -> Result<Response<GetBlocksRangeResponse>, Status> {
            unimplemented_rpc()
        }
        async fn update_block_header(
            &self,
            _request: Request<UpdateBlockHeaderRequest>,
        ) -> Result<Response<UpdateBlockHeaderResponse>, Status> {
            unimplemented_rpc()
        }
        async fn get_genesis_status(
            &self,
            _request: Request<GetGenesisStatusRequest>,
        ) -> Result<Response<GetGenesisStatusResponse>, Status> {
            unimplemented_rpc()
        }
        async fn get_status(
            &self,
            _request: Request<GetStatusRequest>,
        ) -> Result<Response<GetStatusResponse>, Status> {
            unimplemented_rpc()
        }
        async fn get_execution_status(
            &self,
            _request: Request<GetStatusRequest>,
        ) -> Result<Response<GetStatusResponse>, Status> {
            unimplemented_rpc()
        }
        async fn get_committed_status(
            &self,
            _request: Request<GetStatusRequest>,
        ) -> Result<Response<GetStatusResponse>, Status> {
            Ok(Response::new(GetStatusResponse {
                height: self.marker().unwrap_or(0),
                latest_timestamp: 0,
                total_transactions: 0,
                is_running: true,
            }))
        }
        async fn record_admitted_tip(
            &self,
            request: Request<RecordAdmittedTipRequest>,
        ) -> Result<Response<RecordAdmittedTipResponse>, Status> {
            let request = request.into_inner();
            self.presented
                .lock()
                .unwrap()
                .push(request.capability.clone());
            if request.capability.as_slice() != self.accepted.as_slice() {
                return Err(Status::permission_denied(
                    "the workload capability does not match",
                ));
            }
            *self.marker.lock().unwrap() = Some(request.height);
            Ok(Response::new(RecordAdmittedTipResponse {}))
        }
        // GREEN-3 (the GetCommittedTip proto change): served from the mock's marker.
        async fn get_committed_tip(
            &self,
            _request: Request<GetStatusRequest>,
        ) -> Result<Response<GetCommittedTipResponse>, Status> {
            Ok(Response::new(match self.marker() {
                None => GetCommittedTipResponse::default(),
                Some(height) => GetCommittedTipResponse {
                    height,
                    block_hash: vec![height as u8; 32],
                    state_root: vec![height as u8; 32],
                    latest_timestamp: 0,
                },
            }))
        }
    }

    /// Serves `mock` on an ephemeral loopback port and returns its address.
    async fn serve(mock: Arc<MockWorkload>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let incoming = tonic::transport::server::TcpIncoming::from_listener(listener, true, None)
            .expect("incoming");
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(ChainControlServer::from_arc(mock))
                .serve_with_incoming(incoming)
                .await;
        });
        address.to_string()
    }

    /// A shared workload client as the node binaries build one (no data plane in this test).
    async fn shared_client(address: &str) -> WorkloadClient {
        std::env::set_var("IOI_SHMEM_ID", "ioi-d2a-red3-no-such-region");
        std::env::set_var("IOI_SHMEM_CONNECT_RETRIES", "0");
        WorkloadClient::new(address, "", "", "")
            .await
            .expect("workload client")
    }

    fn tip(height: u64) -> AdmittedTip {
        AdmittedTip {
            height,
            block_hash: [height as u8; 32],
            state_root: vec![height as u8; 32],
        }
    }

    /// RED-3 (fails at 079937616: the client presents only the capability ATTACHED to the shared
    /// client and ignores the caller's, workload_client/mod.rs:363-371 and :1138-1146; the RED-3
    /// scaffold keeps that). GREEN-3: the publisher's capability reaches the workload and records
    /// the tip; then a non-admission caller on the SAME shared client presents only what it has
    /// (here zeros), is refused, and the marker stays.
    #[tokio::test]
    async fn the_shared_client_presents_only_the_capability_its_caller_passes() {
        let mock = Arc::new(MockWorkload {
            accepted: CAPABILITY,
            presented: Mutex::new(Vec::new()),
            marker: Mutex::new(None),
        });
        let address = serve(mock.clone()).await;
        let client = shared_client(&address).await;
        // The harness control: the real client reaches the mock over loopback gRPC.
        assert_eq!(
            client
                .get_committed_status()
                .await
                .expect("the mock workload serves the committed status")
                .height,
            0
        );

        client
            .record_admitted_tip_with_capability(admission_gate_canary(), &CAPABILITY, tip(3))
            .await
            .expect("the publisher's capability records the admitted tip");
        assert_eq!(mock.marker(), Some(3));

        assert!(
            client
                .record_admitted_tip_with_capability(admission_gate_canary(), &[0u8; 32], tip(4))
                .await
                .is_err(),
            "a non-admission caller on the shared client is refused"
        );
        assert_eq!(
            mock.presented(),
            vec![CAPABILITY.to_vec(), vec![0u8; 32]],
            "each record presents exactly its caller's capability; the shared client keeps none"
        );
        assert_eq!(mock.marker(), Some(3), "the refused record leaves the marker unchanged");
    }

    /// GREEN-3 PIN (the GetCommittedTip proto surface did not exist at RED-3, so it has no RED):
    /// the shared client reads the committed tip FROM THE WORKLOAD'S MARKER, through the trait, and
    /// reports none before the first admission.
    #[tokio::test]
    async fn the_shared_client_reads_the_committed_tip_from_the_workload_marker() {
        let mock = Arc::new(MockWorkload {
            accepted: CAPABILITY,
            presented: Mutex::new(Vec::new()),
            marker: Mutex::new(None),
        });
        let address = serve(mock.clone()).await;
        let client = shared_client(&address).await;
        let api: &dyn WorkloadClientApi = &client;
        assert_eq!(
            api.get_committed_tip().await.expect("committed tip"),
            None,
            "no admission yet: no committed tip"
        );
        *mock.marker.lock().unwrap() = Some(3);
        assert_eq!(
            api.get_committed_tip().await.expect("committed tip"),
            Some(AdmittedTip {
                height: 3,
                block_hash: [3; 32],
                state_root: vec![3; 32],
            })
        );
    }
}
