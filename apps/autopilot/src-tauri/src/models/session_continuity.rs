use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::session::{AgentPhase, AgentTask};
use super::session_compaction::SessionSummary;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionProjection {
    pub task: Option<AgentTask>,
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRewindCandidate {
    pub session_id: String,
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
    pub is_current: bool,
    pub is_last_stable: bool,
    pub action_label: String,
    pub preview_headline: String,
    pub preview_detail: String,
    pub discard_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRewindSnapshot {
    #[serde(default)]
    pub active_session_id: Option<String>,
    #[serde(default)]
    pub active_session_title: Option<String>,
    #[serde(default)]
    pub last_stable_session_id: Option<String>,
    pub candidates: Vec<SessionRewindCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHookReceiptSummary {
    pub title: String,
    pub timestamp_ms: u64,
    pub tool_name: String,
    pub status: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHookRecord {
    pub hook_id: String,
    #[serde(default)]
    pub entry_id: Option<String>,
    pub label: String,
    pub owner_label: String,
    pub source_label: String,
    pub source_kind: String,
    #[serde(default)]
    pub source_uri: Option<String>,
    #[serde(default)]
    pub contribution_path: Option<String>,
    pub trigger_label: String,
    pub enabled: bool,
    pub status_label: String,
    pub trust_posture: String,
    pub governed_profile: String,
    pub authority_tier_label: String,
    pub availability_label: String,
    pub session_scope_label: String,
    pub why_active: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHookSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub active_hook_count: usize,
    pub disabled_hook_count: usize,
    pub runtime_receipt_count: usize,
    pub approval_receipt_count: usize,
    pub hooks: Vec<SessionHookRecord>,
    #[serde(default)]
    pub recent_receipts: Vec<SessionHookReceiptSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionBranchRecord {
    pub branch_name: String,
    #[serde(default)]
    pub upstream_branch: Option<String>,
    pub is_current: bool,
    #[serde(default)]
    pub ahead_count: u32,
    #[serde(default)]
    pub behind_count: u32,
    #[serde(default)]
    pub last_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionWorktreeRecord {
    pub path: String,
    #[serde(default)]
    pub branch_name: Option<String>,
    #[serde(default)]
    pub head: Option<String>,
    #[serde(default)]
    pub last_commit: Option<String>,
    #[serde(default)]
    pub changed_file_count: usize,
    #[serde(default)]
    pub dirty: bool,
    #[serde(default)]
    pub is_current: bool,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub lock_reason: Option<String>,
    #[serde(default)]
    pub prunable: bool,
    #[serde(default)]
    pub prune_reason: Option<String>,
    pub status_label: String,
    pub status_detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionBranchSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub is_repo: bool,
    #[serde(default)]
    pub repo_label: Option<String>,
    #[serde(default)]
    pub current_branch: Option<String>,
    #[serde(default)]
    pub upstream_branch: Option<String>,
    #[serde(default)]
    pub last_commit: Option<String>,
    #[serde(default)]
    pub ahead_count: u32,
    #[serde(default)]
    pub behind_count: u32,
    #[serde(default)]
    pub changed_file_count: usize,
    #[serde(default)]
    pub dirty: bool,
    pub worktree_risk_label: String,
    pub worktree_risk_detail: String,
    #[serde(default)]
    pub recent_branches: Vec<SessionBranchRecord>,
    #[serde(default)]
    pub worktrees: Vec<SessionWorktreeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionRemoteEnvBinding {
    pub key: String,
    pub value_preview: String,
    pub source_label: String,
    pub scope_label: String,
    pub provenance_label: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionRemoteEnvSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub focused_scope_label: String,
    pub governing_source_label: String,
    pub posture_label: String,
    pub posture_detail: String,
    #[serde(default)]
    pub binding_count: usize,
    #[serde(default)]
    pub control_plane_binding_count: usize,
    #[serde(default)]
    pub process_binding_count: usize,
    #[serde(default)]
    pub overlapping_binding_count: usize,
    #[serde(default)]
    pub secret_binding_count: usize,
    #[serde(default)]
    pub redacted_binding_count: usize,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub bindings: Vec<SessionRemoteEnvBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionServerSessionRecord {
    pub session_id: String,
    pub title: String,
    pub timestamp: u64,
    pub source_label: String,
    #[serde(default)]
    pub presence_state: String,
    #[serde(default)]
    pub presence_label: String,
    #[serde(default)]
    pub resume_hint: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SessionServerSnapshot {
    pub generated_at_ms: u64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    pub rpc_url: String,
    pub rpc_source_label: String,
    pub continuity_mode_label: String,
    pub continuity_status_label: String,
    pub continuity_detail: String,
    pub kernel_connection_label: String,
    pub kernel_connection_detail: String,
    #[serde(default)]
    pub explicit_rpc_target: bool,
    #[serde(default)]
    pub remote_kernel_target: bool,
    #[serde(default)]
    pub kernel_reachable: bool,
    #[serde(default)]
    pub remote_history_available: bool,
    #[serde(default)]
    pub local_session_count: usize,
    #[serde(default)]
    pub remote_session_count: usize,
    #[serde(default)]
    pub merged_session_count: usize,
    #[serde(default)]
    pub remote_only_session_count: usize,
    #[serde(default)]
    pub overlapping_session_count: usize,
    #[serde(default)]
    pub remote_attachable_session_count: usize,
    #[serde(default)]
    pub remote_history_only_session_count: usize,
    #[serde(default)]
    pub current_session_visible_remotely: bool,
    #[serde(default)]
    pub current_session_continuity_state: String,
    #[serde(default)]
    pub current_session_continuity_label: String,
    #[serde(default)]
    pub current_session_continuity_detail: String,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub recent_remote_sessions: Vec<SessionServerSessionRecord>,
}
