use ioi_api::vm::inference::InferenceRuntime;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_memory::MemoryRuntime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::transport::Channel;

use super::capabilities::CapabilityGovernanceRequest;
use super::session::{AgentTask, GateResponse};
use super::session_compaction::SessionSummary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBlob {
    pub data_base64: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostInputEvent {
    pub device: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatLaunchReceipt {
    pub timestamp_ms: u64,
    pub stage: String,
    pub detail: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetAutopilotDataResult {
    pub data_dir: String,
    pub removed_paths: Vec<String>,
    pub identity_preserved: bool,
    pub remote_history_may_persist: bool,
}

#[derive(Default)]
pub struct AppState {
    pub current_task: Option<AgentTask>,
    pub gate_response: Option<GateResponse>,
    pub is_simulating: bool,
    pub rpc_client: Option<PublicApiClient<Channel>>,
    pub event_index: HashMap<String, Vec<String>>,
    pub artifact_index: HashMap<String, Vec<String>>,

    // Shared kernel-owned runtime for inference, embeddings, and adjacent
    // absorbed model/media capability calls.
    pub inference_runtime: Option<Arc<dyn InferenceRuntime>>,

    // Chat's typed outcome router may use a separate real runtime so
    // lightweight route planning does not stall behind heavier artifact generation.
    pub chat_routing_inference_runtime: Option<Arc<dyn InferenceRuntime>>,

    // Acceptance validation runtime kept distinct from the production artifact runtime
    // so Chat can surface separate provenance truthfully.
    pub acceptance_inference_runtime: Option<Arc<dyn InferenceRuntime>>,

    // Primary local runtime for checkpoints, memory, events, artifacts, and cache state.
    pub memory_runtime: Option<Arc<MemoryRuntime>>,

    // Cross-window chat launch intent survives a recreated Chat shell.
    pub pending_chat_launch_request: Option<Value>,

    // Recent launch receipts make Chat shell handoff failures inspectable.
    pub chat_launch_receipts: Vec<ChatLaunchReceipt>,

    // Active assistant workbench session is kernel-owned so shell recreation
    // does not drop reply/prep context.
    pub active_assistant_workbench_session: Option<Value>,

    // Cached full session history snapshot lets shell projections stay live
    // without falling back to frontend polling during active runs.
    pub session_history_projection: Vec<SessionSummary>,

    // Active capability governance request keeps lease widening / baseline
    // review durable across shell hops until the operator applies or dismisses it.
    pub capability_governance_request: Option<CapabilityGovernanceRequest>,

    // Coalesce kernel-owned session history refreshes so event-stream and
    // background monitor paths can keep projections fresh without piling up
    // duplicate RPC work.
    pub session_projection_refresh_in_flight: bool,
}
