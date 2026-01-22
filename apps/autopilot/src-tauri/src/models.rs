// apps/autopilot/src-tauri/src/models.rs
use serde::{Deserialize, Serialize};
use ioi_ipc::public::public_api_client::PublicApiClient;
use tonic::transport::Channel;
use std::collections::HashSet;

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

// [NEW] Structured chat message for persistent history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "user", "agent", "system", "tool"
    pub text: String,
    pub timestamp: u64,
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
    
    // [NEW] History source of truth. 
    // This is populated by hydrating from the blockchain state (Audit Log).
    #[serde(default)] 
    pub history: Vec<ChatMessage>,

    // [NEW] Track processed step indices to prevent duplicate logs
    // from overlapping 'Thought' and 'ActionResult' events.
    // Marked skip so it doesn't get sent to the frontend.
    #[serde(skip, default)]
    pub processed_steps: HashSet<u32>,
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

// [NEW] Struct for persistent session history index
// Used by the backend to display the sidebar list without hydrating full state
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
}