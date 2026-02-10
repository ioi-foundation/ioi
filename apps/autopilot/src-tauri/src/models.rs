// apps/autopilot/src-tauri/src/models.rs
use ioi_api::vm::inference::InferenceRuntime;
use ioi_ipc::public::public_api_client::PublicApiClient;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tonic::transport::Channel;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentPhase {
    Idle,
    Running,
    Gate,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateInfo {
    pub title: String,
    pub description: String,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub duration: String,
    pub actions: u32,
    pub cost: Option<String>,
}

// Structured chat message for persistent history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "user", "agent", "system", "tool"

    // [NOTE] We map backend `content` to frontend `text` for compatibility with UI components
    #[serde(alias = "content")]
    pub text: String,

    pub timestamp: u64,
}

// Represents a node in the hierarchical swarm visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmAgent {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub role: String,
    pub status: String, // "running", "completed", "failed", "requisition"
    pub budget_used: f64,
    pub budget_cap: f64,
    pub current_thought: Option<String>,
    #[serde(default)]
    pub artifacts_produced: u32,
    #[serde(default)]
    pub estimated_cost: f64,
    #[serde(default)]
    pub policy_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: String,
    pub intent: String,
    pub agent: String,
    pub phase: AgentPhase,
    pub progress: u32,
    pub total_steps: u32,
    pub current_step: String,
    pub gate_info: Option<GateInfo>,
    pub receipt: Option<Receipt>,
    pub visual_hash: Option<String>,
    pub pending_request_hash: Option<String>,
    pub session_id: Option<String>,

    // History source of truth.
    // This is populated by hydrating from the blockchain state (Audit Log).
    #[serde(default)]
    pub history: Vec<ChatMessage>,

    // Track processed steps using a composite key "{step}:{tool}"
    #[serde(skip, default)]
    pub processed_steps: HashSet<String>,

    // The hierarchical swarm state for SwarmViz
    #[serde(default)]
    pub swarm_tree: Vec<SwarmAgent>,

    // [NEW] Evolutionary Metadata (Genetics)
    #[serde(default)]
    pub generation: u64,

    #[serde(default = "default_lineage")]
    pub lineage_id: String,

    #[serde(default)]
    pub fitness_score: f32,
}

fn default_lineage() -> String {
    "genesis".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResponse {
    pub responded: bool,
    pub approved: bool,
}

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

// Struct for persistent session history index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String, // Hex encoded
    pub title: String,
    pub timestamp: u64,
}

#[derive(Default)]
pub struct AppState {
    pub current_task: Option<AgentTask>,
    pub gate_response: Option<GateResponse>,
    pub is_simulating: bool,
    pub rpc_client: Option<PublicApiClient<Channel>>,

    // Persistent Store for Studio execution artifacts
    // Note: SovereignContextStore is imported but used inside Arc<Mutex> here
    // We don't need to import it if we don't name it in the struct field type explicitly if using fully qualified or alias,
    // but here we use ioi_scs::SovereignContextStore implicitly via the module if not imported?
    // Actually we need to import it to name it.
    // In lib.rs we imported it. Here we need it too.
    // The previous error was in ingestion.rs.
    pub studio_scs: Option<Arc<Mutex<ioi_scs::SovereignContextStore>>>,

    // Shared Inference Runtime for Embedding/Indexing commands
    pub inference_runtime: Option<Arc<dyn InferenceRuntime>>,
}
