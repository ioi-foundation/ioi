// apps/autopilot/src-tauri/src/models.rs
use ioi_api::vm::inference::InferenceRuntime;
use ioi_ipc::public::public_api_client::PublicApiClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    CommandRun,
    CommandStream,
    CodeSearch,
    FileRead,
    FileEdit,
    DiffCreated,
    TestRun,
    BrowserNavigate,
    BrowserExtract,
    Receipt,
    InfoNote,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventStatus {
    Success,
    Failure,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactType {
    Diff,
    File,
    Web,
    RunBundle,
    Report,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub artifact_type: ArtifactType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptDigest {
    pub receipt_id: String,
    pub policy_hash: String,
    pub decision: String,
    pub tier: String,
    pub reason_code: String,
    pub tool_name: String,
    pub budgets: Value,
    pub step_index: u32,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub event_id: String,
    pub timestamp: String,
    pub thread_id: String,
    pub step_index: u32,
    pub event_type: EventType,
    pub title: String,
    pub digest: Value,
    pub details: Value,
    #[serde(default)]
    pub artifact_refs: Vec<ArtifactRef>,
    pub receipt_ref: Option<String>,
    #[serde(default)]
    pub input_refs: Vec<String>,
    pub status: EventStatus,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub artifact_id: String,
    pub created_at: String,
    pub thread_id: String,
    pub artifact_type: ArtifactType,
    pub title: String,
    pub description: String,
    pub content_ref: String,
    pub metadata: Value,
    pub version: Option<u32>,
    pub parent_artifact_id: Option<String>,
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

    // New immutable event stream (canonical for new runs).
    #[serde(default)]
    pub events: Vec<AgentEvent>,

    // Macro artifacts for this thread.
    #[serde(default)]
    pub artifacts: Vec<Artifact>,

    // Run bundle artifact pointer (if created).
    #[serde(default)]
    pub run_bundle_id: Option<String>,

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
    pub event_index: HashMap<String, Vec<String>>,
    pub artifact_index: HashMap<String, Vec<String>>,

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializes_agent_event_shape() {
        let event = AgentEvent {
            event_id: "evt-1".to_string(),
            timestamp: "2026-02-13T00:00:00Z".to_string(),
            thread_id: "thread-1".to_string(),
            step_index: 7,
            event_type: EventType::CommandRun,
            title: "Ran cargo test".to_string(),
            digest: json!({"tool":"cargo test"}),
            details: json!({"output":"ok"}),
            artifact_refs: vec![ArtifactRef {
                artifact_id: "art-1".to_string(),
                artifact_type: ArtifactType::Log,
            }],
            receipt_ref: Some("receipt-1".to_string()),
            input_refs: vec!["evt-0".to_string()],
            status: EventStatus::Success,
            duration_ms: Some(12),
        };

        let value = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(value["event_id"], "evt-1");
        assert_eq!(value["event_type"], "COMMAND_RUN");
        assert_eq!(value["status"], "SUCCESS");
        assert_eq!(value["artifact_refs"][0]["artifact_type"], "LOG");
    }

    #[test]
    fn serializes_artifact_shape() {
        let artifact = Artifact {
            artifact_id: "art-1".to_string(),
            created_at: "2026-02-13T00:00:00Z".to_string(),
            thread_id: "thread-1".to_string(),
            artifact_type: ArtifactType::Diff,
            title: "Large diff".to_string(),
            description: "Diff exceeded threshold".to_string(),
            content_ref: "scs://artifact/art-1".to_string(),
            metadata: json!({"files_touched": 4}),
            version: Some(1),
            parent_artifact_id: None,
        };
        let value = serde_json::to_value(&artifact).expect("serialize artifact");
        assert_eq!(value["artifact_type"], "DIFF");
        assert_eq!(value["metadata"]["files_touched"], 4);
    }
}
