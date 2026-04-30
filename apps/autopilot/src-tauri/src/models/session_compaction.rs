use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::session::AgentPhase;

// Struct for persistent session history index
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSummary {
    pub session_id: String, // Hex encoded
    pub title: String,
    pub timestamp: u64,
    #[serde(default)]
    pub phase: Option<AgentPhase>,
    #[serde(default)]
    pub current_step: Option<String>,
    #[serde(default)]
    pub resume_hint: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum SessionMemoryClass {
    Ephemeral,
    CarryForward,
    Pinned,
    GovernanceCritical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum SessionCompactionMode {
    Manual,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionPolicy {
    #[serde(default)]
    pub carry_pinned_only: bool,
    #[serde(default = "session_compaction_policy_true")]
    pub preserve_checklist_state: bool,
    #[serde(default = "session_compaction_policy_true")]
    pub preserve_background_tasks: bool,
    #[serde(default = "session_compaction_policy_true")]
    pub preserve_latest_output_excerpt: bool,
    #[serde(default = "session_compaction_policy_true")]
    pub preserve_governance_blockers: bool,
    #[serde(default)]
    pub aggressive_transcript_pruning: bool,
}

fn session_compaction_policy_true() -> bool {
    true
}

impl Default for SessionCompactionPolicy {
    fn default() -> Self {
        Self {
            carry_pinned_only: false,
            preserve_checklist_state: true,
            preserve_background_tasks: true,
            preserve_latest_output_excerpt: true,
            preserve_governance_blockers: true,
            aggressive_transcript_pruning: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum SessionCompactionDisposition {
    CarryForward,
    RetainedSummary,
    Pruned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum SessionCompactionResumeSafetyStatus {
    Protected,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionResumeSafetyReceipt {
    pub status: SessionCompactionResumeSafetyStatus,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionMemoryItem {
    pub key: String,
    pub label: String,
    pub memory_class: SessionMemoryClass,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionPruneDecision {
    pub key: String,
    pub label: String,
    pub disposition: SessionCompactionDisposition,
    pub detail_count: usize,
    pub rationale: String,
    pub summary: String,
    #[serde(default)]
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionCarryForwardState {
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub pinned_files: Vec<String>,
    #[serde(default)]
    pub explicit_includes: Vec<String>,
    #[serde(default)]
    pub explicit_excludes: Vec<String>,
    #[serde(default)]
    pub checklist_labels: Vec<String>,
    #[serde(default)]
    pub background_task_labels: Vec<String>,
    #[serde(default)]
    pub blocked_on: Option<String>,
    #[serde(default)]
    pub pending_decision_context: Option<String>,
    #[serde(default)]
    pub latest_artifact_outcome: Option<String>,
    #[serde(default)]
    pub execution_targets: Vec<String>,
    #[serde(default)]
    pub latest_output_excerpt: Option<String>,
    #[serde(default)]
    pub memory_items: Vec<SessionCompactionMemoryItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionPreview {
    pub session_id: String,
    pub title: String,
    #[serde(default)]
    pub phase: Option<AgentPhase>,
    pub policy: SessionCompactionPolicy,
    pub pre_compaction_span: String,
    pub summary: String,
    pub resume_anchor: String,
    pub carried_forward_state: SessionCompactionCarryForwardState,
    pub resume_safety: SessionCompactionResumeSafetyReceipt,
    #[serde(default)]
    pub prune_decisions: Vec<SessionCompactionPruneDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionRecord {
    pub compaction_id: String,
    pub session_id: String,
    pub title: String,
    pub compacted_at_ms: u64,
    pub mode: SessionCompactionMode,
    #[serde(default)]
    pub phase: Option<AgentPhase>,
    #[serde(default)]
    pub policy: SessionCompactionPolicy,
    pub pre_compaction_span: String,
    pub summary: String,
    pub resume_anchor: String,
    pub carried_forward_state: SessionCompactionCarryForwardState,
    pub resume_safety: SessionCompactionResumeSafetyReceipt,
    #[serde(default)]
    pub prune_decisions: Vec<SessionCompactionPruneDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionRecommendation {
    pub should_compact: bool,
    #[serde(default)]
    pub reason_labels: Vec<String>,
    #[serde(default)]
    pub recommended_policy: SessionCompactionPolicy,
    #[serde(default)]
    pub recommended_policy_label: String,
    #[serde(default)]
    pub recommended_policy_reason_labels: Vec<String>,
    #[serde(default)]
    pub resume_safeguard_labels: Vec<String>,
    pub history_count: usize,
    pub event_count: usize,
    pub artifact_count: usize,
    pub pinned_file_count: usize,
    pub explicit_include_count: usize,
    pub idle_age_ms: u64,
    #[serde(default)]
    pub blocked_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionDurabilityPortfolio {
    pub retained_session_count: usize,
    pub compacted_session_count: usize,
    pub replay_ready_session_count: usize,
    pub uncompacted_session_count: usize,
    pub stale_compaction_count: usize,
    pub degraded_compaction_count: usize,
    pub recommended_compaction_count: usize,
    pub compacted_without_team_memory_count: usize,
    pub team_memory_entry_count: usize,
    pub team_memory_covered_session_count: usize,
    pub team_memory_redacted_session_count: usize,
    pub team_memory_review_required_session_count: usize,
    #[serde(default)]
    pub coverage_summary: String,
    #[serde(default)]
    pub team_memory_summary: String,
    #[serde(default)]
    pub attention_summary: String,
    #[serde(default)]
    pub attention_labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompactionSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub active_session_id: Option<String>,
    #[serde(default)]
    pub active_session_title: Option<String>,
    pub policy_for_active: SessionCompactionPolicy,
    pub record_count: usize,
    #[serde(default)]
    pub latest_for_active: Option<SessionCompactionRecord>,
    #[serde(default)]
    pub preview_for_active: Option<SessionCompactionPreview>,
    #[serde(default)]
    pub recommendation_for_active: Option<SessionCompactionRecommendation>,
    #[serde(default)]
    pub durability_portfolio: SessionDurabilityPortfolio,
    #[serde(default)]
    pub records: Vec<SessionCompactionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum TeamMemoryScopeKind {
    Workspace,
    Session,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum TeamMemorySyncStatus {
    Synced,
    Redacted,
    ReviewRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemoryRedactionSummary {
    pub redaction_count: usize,
    #[serde(default)]
    pub redacted_fields: Vec<String>,
    pub redaction_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemorySyncEntry {
    pub entry_id: String,
    pub session_id: String,
    pub session_title: String,
    pub synced_at_ms: u64,
    pub scope_kind: TeamMemoryScopeKind,
    pub scope_id: String,
    pub scope_label: String,
    pub actor_id: String,
    pub actor_label: String,
    pub actor_role: String,
    pub sync_status: TeamMemorySyncStatus,
    pub review_summary: String,
    pub omitted_governance_item_count: usize,
    pub resume_anchor: String,
    pub pre_compaction_span: String,
    pub summary: String,
    #[serde(default)]
    pub shared_memory_items: Vec<SessionCompactionMemoryItem>,
    pub redaction: TeamMemoryRedactionSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemorySyncSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub active_session_id: Option<String>,
    #[serde(default)]
    pub active_scope_id: Option<String>,
    #[serde(default)]
    pub active_scope_kind: Option<TeamMemoryScopeKind>,
    #[serde(default)]
    pub active_scope_label: Option<String>,
    pub entry_count: usize,
    pub redacted_entry_count: usize,
    pub review_required_count: usize,
    pub summary: String,
    #[serde(default)]
    pub entries: Vec<TeamMemorySyncEntry>,
}
