//! Public thread, turn, item, and event-stream contracts for agent runtimes.
#![allow(missing_docs)]

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const RUNTIME_THREAD_SCHEMA_VERSION_V1: &str = "ioi.runtime.thread.v1";
pub const RUNTIME_TURN_SCHEMA_VERSION_V1: &str = "ioi.runtime.turn.v1";
pub const RUNTIME_ITEM_SCHEMA_VERSION_V1: &str = "ioi.runtime.item.v1";
pub const RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1: &str = "ioi.runtime.event.v1";
pub const RUNTIME_TTI_SCHEMA_VERSION_V1: &str = RUNTIME_THREAD_SCHEMA_VERSION_V1;

pub const RUNTIME_TTI_SCHEMA_VERSION_LITERALS: &[&str] = &[
    RUNTIME_THREAD_SCHEMA_VERSION_V1,
    RUNTIME_TURN_SCHEMA_VERSION_V1,
    RUNTIME_ITEM_SCHEMA_VERSION_V1,
    RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1,
];

pub const RUNTIME_THREAD_MODES: &[&str] = &["plan", "agent", "yolo", "custom"];
pub const RUNTIME_APPROVAL_MODES: &[&str] = &[
    "suggest",
    "auto_local",
    "never_prompt",
    "human_required",
    "policy_required",
];
pub const RUNTIME_THREAD_STATUSES: &[&str] = &[
    "active",
    "idle",
    "waiting",
    "interrupted",
    "completed",
    "failed",
    "archived",
];
pub const RUNTIME_TURN_STATUSES: &[&str] = &[
    "queued",
    "running",
    "waiting_for_approval",
    "waiting_for_input",
    "interrupted",
    "completed",
    "failed",
    "canceled",
];
pub const RUNTIME_ITEM_KINDS: &[&str] = &[
    "user_message",
    "agent_message",
    "reasoning_delta",
    "tool_call",
    "tool_result",
    "file_change",
    "command_execution",
    "approval_required",
    "approval_decision",
    "context_compaction",
    "lsp_diagnostics",
    "memory_update",
    "subagent_event",
    "rollback_snapshot",
    "status",
    "error",
];
pub const RUNTIME_ITEM_STATUSES: &[&str] = &[
    "pending",
    "running",
    "completed",
    "failed",
    "interrupted",
    "canceled",
    "blocked",
];
pub const RUNTIME_ITEM_ACTORS: &[&str] =
    &["user", "assistant", "tool", "runtime", "policy", "system"];
pub const RUNTIME_EVENT_SOURCES: &[&str] = &[
    "runtime_service",
    "daemon_bridge",
    "sdk_client",
    "cli_tui",
    "react_flow",
    "runtime_auto",
    "fixture",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeThreadMode {
    Plan,
    #[default]
    Agent,
    Yolo,
    Custom,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeApprovalMode {
    #[default]
    Suggest,
    AutoLocal,
    NeverPrompt,
    HumanRequired,
    PolicyRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeThreadStatus {
    #[default]
    Active,
    Idle,
    Waiting,
    Interrupted,
    Completed,
    Failed,
    Archived,
}

impl RuntimeThreadStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Archived)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTurnStatus {
    Queued,
    #[default]
    Running,
    WaitingForApproval,
    WaitingForInput,
    Interrupted,
    Completed,
    Failed,
    Canceled,
}

impl RuntimeTurnStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Interrupted | Self::Completed | Self::Failed | Self::Canceled
        )
    }
}

pub type RuntimeLifecycleStatus = RuntimeTurnStatus;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeItemKind {
    UserMessage,
    AgentMessage,
    ReasoningDelta,
    ToolCall,
    ToolResult,
    FileChange,
    CommandExecution,
    ApprovalRequired,
    ApprovalDecision,
    ContextCompaction,
    LspDiagnostics,
    MemoryUpdate,
    SubagentEvent,
    RollbackSnapshot,
    #[default]
    Status,
    Error,
}

impl RuntimeItemKind {
    pub fn is_side_effect_candidate(self) -> bool {
        matches!(
            self,
            Self::ToolCall
                | Self::FileChange
                | Self::CommandExecution
                | Self::ApprovalDecision
                | Self::MemoryUpdate
                | Self::SubagentEvent
                | Self::RollbackSnapshot
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeItemStatus {
    Pending,
    #[default]
    Running,
    Completed,
    Failed,
    Interrupted,
    Canceled,
    Blocked,
}

impl RuntimeItemStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Interrupted | Self::Canceled | Self::Blocked
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeItemActor {
    User,
    Assistant,
    Tool,
    #[default]
    Runtime,
    Policy,
    System,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventSource {
    #[default]
    RuntimeService,
    DaemonBridge,
    SdkClient,
    CliTui,
    ReactFlow,
    Fixture,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct RuntimeUsageRecord {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_tokens: u64,
    pub cached_input_tokens: u64,
    pub tool_result_tokens: u64,
    pub compacted_tokens: u64,
    pub estimated_cost_micros: u64,
    pub provider: String,
    pub model: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeThreadRecord {
    pub schema_version: String,
    pub thread_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub workspace_root: String,
    pub title: String,
    pub mode: RuntimeThreadMode,
    pub approval_mode: RuntimeApprovalMode,
    pub trust_profile: String,
    pub model_route: String,
    pub status: RuntimeThreadStatus,
    pub latest_turn_id: Option<String>,
    pub latest_seq: u64,
    pub event_stream_id: String,
    pub workflow_graph_id: Option<String>,
    pub harness_binding_id: Option<String>,
    pub agentgres_projection_ref: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub archived_at: Option<String>,
    pub fixture_profile: Option<String>,
}

impl Default for RuntimeThreadRecord {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_THREAD_SCHEMA_VERSION_V1.to_string(),
            thread_id: String::new(),
            session_id: String::new(),
            agent_id: String::new(),
            workspace_root: String::new(),
            title: String::new(),
            mode: RuntimeThreadMode::Agent,
            approval_mode: RuntimeApprovalMode::Suggest,
            trust_profile: "local_private".to_string(),
            model_route: String::new(),
            status: RuntimeThreadStatus::Active,
            latest_turn_id: None,
            latest_seq: 0,
            event_stream_id: String::new(),
            workflow_graph_id: None,
            harness_binding_id: None,
            agentgres_projection_ref: None,
            created_at: String::new(),
            updated_at: String::new(),
            archived_at: None,
            fixture_profile: None,
        }
    }
}

impl RuntimeThreadRecord {
    pub fn new(
        thread_id: impl Into<String>,
        session_id: impl Into<String>,
        workspace_root: impl Into<String>,
    ) -> Self {
        let thread_id = thread_id.into();
        Self {
            event_stream_id: format!("{thread_id}:events"),
            thread_id,
            session_id: session_id.into(),
            workspace_root: workspace_root.into(),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeTurnRecord {
    pub schema_version: String,
    pub turn_id: String,
    pub thread_id: String,
    pub parent_turn_id: Option<String>,
    pub request_id: String,
    pub status: RuntimeTurnStatus,
    pub input_item_ids: Vec<String>,
    pub output_item_ids: Vec<String>,
    pub seq_start: Option<u64>,
    pub seq_end: Option<u64>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub mode: RuntimeThreadMode,
    pub approval_mode: RuntimeApprovalMode,
    pub model_route_decision_id: Option<String>,
    pub usage: Option<RuntimeUsageRecord>,
    pub stop_reason: Option<String>,
    pub error: Option<String>,
    pub rollback_snapshot_id: Option<String>,
    pub quality_ledger_ref: Option<String>,
    pub workflow_execution_ref: Option<String>,
    pub fixture_profile: Option<String>,
}

impl Default for RuntimeTurnRecord {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_TURN_SCHEMA_VERSION_V1.to_string(),
            turn_id: String::new(),
            thread_id: String::new(),
            parent_turn_id: None,
            request_id: String::new(),
            status: RuntimeTurnStatus::Running,
            input_item_ids: Vec::new(),
            output_item_ids: Vec::new(),
            seq_start: None,
            seq_end: None,
            started_at: String::new(),
            completed_at: None,
            mode: RuntimeThreadMode::Agent,
            approval_mode: RuntimeApprovalMode::Suggest,
            model_route_decision_id: None,
            usage: None,
            stop_reason: None,
            error: None,
            rollback_snapshot_id: None,
            quality_ledger_ref: None,
            workflow_execution_ref: None,
            fixture_profile: None,
        }
    }
}

impl RuntimeTurnRecord {
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeItemRecord {
    pub schema_version: String,
    pub item_id: String,
    pub thread_id: String,
    pub turn_id: String,
    pub kind: RuntimeItemKind,
    pub status: RuntimeItemStatus,
    pub seq_start: Option<u64>,
    pub seq_end: Option<u64>,
    pub actor: RuntimeItemActor,
    pub summary: String,
    pub content_ref: Option<String>,
    pub tool_name: Option<String>,
    pub component_kind: Option<String>,
    pub workflow_node_id: Option<String>,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub approval_id: Option<String>,
    pub policy_decision_id: Option<String>,
    pub rollback_snapshot_id: Option<String>,
    pub redaction_profile: String,
    pub payload_schema_version: String,
}

impl Default for RuntimeItemRecord {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_ITEM_SCHEMA_VERSION_V1.to_string(),
            item_id: String::new(),
            thread_id: String::new(),
            turn_id: String::new(),
            kind: RuntimeItemKind::Status,
            status: RuntimeItemStatus::Running,
            seq_start: None,
            seq_end: None,
            actor: RuntimeItemActor::Runtime,
            summary: String::new(),
            content_ref: None,
            tool_name: None,
            component_kind: None,
            workflow_node_id: None,
            receipt_refs: Vec::new(),
            artifact_refs: Vec::new(),
            approval_id: None,
            policy_decision_id: None,
            rollback_snapshot_id: None,
            redaction_profile: "internal".to_string(),
            payload_schema_version: RUNTIME_ITEM_SCHEMA_VERSION_V1.to_string(),
        }
    }
}

impl RuntimeItemRecord {
    pub fn has_replay_coordinates(&self) -> bool {
        self.seq_start.is_some() && self.seq_end.is_some()
    }

    pub fn requires_side_effect_evidence(&self) -> bool {
        self.kind.is_side_effect_candidate()
            && (self.receipt_refs.is_empty() && self.artifact_refs.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct RuntimeEventEnvelope {
    pub schema_version: String,
    pub event_id: String,
    pub event_stream_id: String,
    pub thread_id: String,
    pub turn_id: String,
    pub item_id: String,
    pub seq: u64,
    pub parent_seq: Option<u64>,
    pub idempotency_key: String,
    pub source: RuntimeEventSource,
    pub source_event_kind: String,
    pub event_kind: String,
    pub status: String,
    pub actor: RuntimeItemActor,
    pub created_at: String,
    pub workspace_root: String,
    pub workflow_graph_id: Option<String>,
    pub workflow_node_id: Option<String>,
    pub component_kind: Option<String>,
    pub tool_call_id: Option<String>,
    pub approval_id: Option<String>,
    pub artifact_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub policy_decision_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub payload_schema_version: String,
    pub payload_ref: Option<String>,
    pub payload: BTreeMap<String, String>,
    pub redaction_profile: String,
    pub fixture_profile: Option<String>,
}

impl Default for RuntimeEventEnvelope {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1.to_string(),
            event_id: String::new(),
            event_stream_id: String::new(),
            thread_id: String::new(),
            turn_id: String::new(),
            item_id: String::new(),
            seq: 0,
            parent_seq: None,
            idempotency_key: String::new(),
            source: RuntimeEventSource::RuntimeService,
            source_event_kind: String::new(),
            event_kind: String::new(),
            status: "running".to_string(),
            actor: RuntimeItemActor::Runtime,
            created_at: String::new(),
            workspace_root: String::new(),
            workflow_graph_id: None,
            workflow_node_id: None,
            component_kind: None,
            tool_call_id: None,
            approval_id: None,
            artifact_refs: Vec::new(),
            receipt_refs: Vec::new(),
            policy_decision_refs: Vec::new(),
            rollback_refs: Vec::new(),
            payload_schema_version: RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1.to_string(),
            payload_ref: None,
            payload: BTreeMap::new(),
            redaction_profile: "internal".to_string(),
            fixture_profile: None,
        }
    }
}

impl RuntimeEventEnvelope {
    pub fn thread_scoped(
        seq: u64,
        thread_id: impl Into<String>,
        event_kind: impl Into<String>,
    ) -> Self {
        let thread_id = thread_id.into();
        Self {
            event_stream_id: format!("{thread_id}:events"),
            seq,
            parent_seq: (seq > 1).then_some(seq - 1),
            thread_id,
            event_kind: event_kind.into(),
            ..Self::default()
        }
    }

    pub fn is_thread_scoped(&self) -> bool {
        !self.thread_id.is_empty()
    }

    pub fn is_replayable_after(&self, since_seq: u64) -> bool {
        self.seq > since_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_turn_item_defaults_use_public_tti_schema_versions() {
        assert_eq!(
            RuntimeThreadRecord::default().schema_version,
            RUNTIME_THREAD_SCHEMA_VERSION_V1
        );
        assert_eq!(
            RuntimeTurnRecord::default().schema_version,
            RUNTIME_TURN_SCHEMA_VERSION_V1
        );
        assert_eq!(
            RuntimeItemRecord::default().schema_version,
            RUNTIME_ITEM_SCHEMA_VERSION_V1
        );
        assert_eq!(
            RuntimeEventEnvelope::default().schema_version,
            RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1
        );
    }

    #[test]
    fn terminal_statuses_are_explicit() {
        assert!(RuntimeThreadStatus::Completed.is_terminal());
        assert!(RuntimeThreadStatus::Archived.is_terminal());
        assert!(!RuntimeThreadStatus::Waiting.is_terminal());
        assert!(RuntimeTurnStatus::Completed.is_terminal());
        assert!(RuntimeTurnStatus::Interrupted.is_terminal());
        assert!(!RuntimeTurnStatus::Running.is_terminal());
        assert!(RuntimeItemStatus::Blocked.is_terminal());
        assert!(!RuntimeItemStatus::Running.is_terminal());
    }

    #[test]
    fn side_effect_items_require_receipts_or_artifacts() {
        let mut item = RuntimeItemRecord {
            kind: RuntimeItemKind::FileChange,
            ..RuntimeItemRecord::default()
        };
        assert!(item.requires_side_effect_evidence());
        item.receipt_refs.push("receipt:file-change".to_string());
        assert!(!item.requires_side_effect_evidence());
    }

    #[test]
    fn event_replay_cursor_filters_monotonic_sequence() {
        let event = RuntimeEventEnvelope::thread_scoped(42, "thread-a", "turn.started");
        assert!(event.is_thread_scoped());
        assert_eq!(event.parent_seq, Some(41));
        assert!(event.is_replayable_after(41));
        assert!(!event.is_replayable_after(42));
    }
}
