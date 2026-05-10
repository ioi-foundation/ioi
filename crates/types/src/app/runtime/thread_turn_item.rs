//! Public thread, turn, item, and event-stream contracts for agent runtimes.
#![allow(missing_docs)]

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::super::runtime_contracts::EvidenceRef;

pub const RUNTIME_TTI_SCHEMA_VERSION_V1: &str = "ioi.agent-runtime.tti.v1";
pub const RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1: &str = "ioi.agent-runtime.event-envelope.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeThreadMode {
    Plan,
    #[default]
    Agent,
    Yolo,
    Review,
    WorkflowDesign,
    Chat,
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
pub enum RuntimeLifecycleStatus {
    Queued,
    #[default]
    InProgress,
    Completed,
    Failed,
    Interrupted,
    Canceled,
    Archived,
}

impl RuntimeLifecycleStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Interrupted | Self::Canceled | Self::Archived
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeItemKind {
    #[default]
    Status,
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
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub workspace: String,
    pub title: String,
    pub mode: RuntimeThreadMode,
    pub approval_mode: RuntimeApprovalMode,
    pub model_route: String,
    pub latest_turn_id: Option<String>,
    pub latest_seq: u64,
    pub archived: bool,
    pub workflow_graph_id: Option<String>,
    pub harness_binding_id: Option<String>,
    pub agentgres_projection_ref: Option<String>,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl Default for RuntimeThreadRecord {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_TTI_SCHEMA_VERSION_V1.to_string(),
            thread_id: String::new(),
            session_id: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            workspace: String::new(),
            title: String::new(),
            mode: RuntimeThreadMode::Agent,
            approval_mode: RuntimeApprovalMode::Suggest,
            model_route: String::new(),
            latest_turn_id: None,
            latest_seq: 0,
            archived: false,
            workflow_graph_id: None,
            harness_binding_id: None,
            agentgres_projection_ref: None,
            evidence_refs: Vec::new(),
        }
    }
}

impl RuntimeThreadRecord {
    pub fn new(
        thread_id: impl Into<String>,
        session_id: impl Into<String>,
        workspace: impl Into<String>,
    ) -> Self {
        Self {
            thread_id: thread_id.into(),
            session_id: session_id.into(),
            workspace: workspace.into(),
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
    pub status: RuntimeLifecycleStatus,
    pub started_at_ms: u64,
    pub completed_at_ms: Option<u64>,
    pub usage: Option<RuntimeUsageRecord>,
    pub error_summary: Option<String>,
    pub stop_reason: Option<String>,
    pub rollback_snapshot_id: Option<String>,
    pub quality_ledger_ref: Option<String>,
    pub workflow_execution_ref: Option<String>,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl Default for RuntimeTurnRecord {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_TTI_SCHEMA_VERSION_V1.to_string(),
            turn_id: String::new(),
            thread_id: String::new(),
            status: RuntimeLifecycleStatus::InProgress,
            started_at_ms: 0,
            completed_at_ms: None,
            usage: None,
            error_summary: None,
            stop_reason: None,
            rollback_snapshot_id: None,
            quality_ledger_ref: None,
            workflow_execution_ref: None,
            evidence_refs: Vec::new(),
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
    pub turn_id: String,
    pub kind: RuntimeItemKind,
    pub status: RuntimeItemStatus,
    pub seq_start: Option<u64>,
    pub seq_end: Option<u64>,
    pub tool_name: Option<String>,
    pub component_kind: Option<String>,
    pub workflow_node_id: Option<String>,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub redaction_profile: String,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl Default for RuntimeItemRecord {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_TTI_SCHEMA_VERSION_V1.to_string(),
            item_id: String::new(),
            turn_id: String::new(),
            kind: RuntimeItemKind::Status,
            status: RuntimeItemStatus::Running,
            seq_start: None,
            seq_end: None,
            tool_name: None,
            component_kind: None,
            workflow_node_id: None,
            receipt_refs: Vec::new(),
            artifact_refs: Vec::new(),
            redaction_profile: "internal".to_string(),
            evidence_refs: Vec::new(),
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
    pub seq: u64,
    pub parent_seq: Option<u64>,
    pub timestamp_ms: u64,
    pub thread_id: String,
    pub turn_id: Option<String>,
    pub item_id: Option<String>,
    pub event: String,
    pub actor: String,
    pub component_kind: Option<String>,
    pub workflow_node_id: Option<String>,
    pub payload_schema_version: String,
    pub payload_summary: BTreeMap<String, String>,
    pub receipt_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub redaction_profile: String,
}

impl Default for RuntimeEventEnvelope {
    fn default() -> Self {
        Self {
            schema_version: RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION_V1.to_string(),
            event_id: String::new(),
            seq: 0,
            parent_seq: None,
            timestamp_ms: 0,
            thread_id: String::new(),
            turn_id: None,
            item_id: None,
            event: String::new(),
            actor: String::new(),
            component_kind: None,
            workflow_node_id: None,
            payload_schema_version: RUNTIME_TTI_SCHEMA_VERSION_V1.to_string(),
            payload_summary: BTreeMap::new(),
            receipt_refs: Vec::new(),
            artifact_refs: Vec::new(),
            redaction_profile: "internal".to_string(),
        }
    }
}

impl RuntimeEventEnvelope {
    pub fn thread_scoped(seq: u64, thread_id: impl Into<String>, event: impl Into<String>) -> Self {
        Self {
            seq,
            thread_id: thread_id.into(),
            event: event.into(),
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
    fn thread_turn_item_defaults_use_public_tti_schema() {
        assert_eq!(
            RuntimeThreadRecord::default().schema_version,
            RUNTIME_TTI_SCHEMA_VERSION_V1
        );
        assert_eq!(
            RuntimeTurnRecord::default().schema_version,
            RUNTIME_TTI_SCHEMA_VERSION_V1
        );
        assert_eq!(
            RuntimeItemRecord::default().schema_version,
            RUNTIME_TTI_SCHEMA_VERSION_V1
        );
    }

    #[test]
    fn terminal_statuses_are_explicit() {
        assert!(RuntimeLifecycleStatus::Completed.is_terminal());
        assert!(RuntimeLifecycleStatus::Interrupted.is_terminal());
        assert!(!RuntimeLifecycleStatus::InProgress.is_terminal());
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
        assert!(event.is_replayable_after(41));
        assert!(!event.is_replayable_after(42));
    }
}
