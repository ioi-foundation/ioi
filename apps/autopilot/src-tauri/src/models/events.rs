use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub duration: String,
    pub actions: u32,
    pub cost: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
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
    BrowserSnapshot,
    Receipt,
    InfoNote,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventStatus {
    Success,
    Failure,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactType {
    Diff,
    File,
    Web,
    RunBundle,
    Report,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub artifact_type: ArtifactType,
}

#[allow(dead_code)]
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

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
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
#[serde(rename_all = "camelCase")]
pub struct AssistantWorkbenchActivityRecord {
    pub activity_id: String,
    pub session_kind: String,
    pub surface: String,
    pub action: String,
    pub status: String,
    pub message: String,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub source_notification_id: Option<String>,
    #[serde(default)]
    pub connector_id: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub evidence_thread_id: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
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
