use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_restore_preview_operations_request.v1";
pub const WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_restore_apply_operations_request.v1";
pub const WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_snapshot_capture_request.v1";
pub const WORKSPACE_SNAPSHOT_CAPTURE_RESULT_SCHEMA_VERSION: &str =
    "ioi.workspace_snapshot_capture_result.v1";
pub const WORKSPACE_SNAPSHOT_RECORD_SCHEMA_VERSION: &str = "ioi.runtime.workspace-snapshot.v1";
pub const WORKSPACE_SNAPSHOT_EVENT_SCHEMA_VERSION: &str = "ioi.runtime.workspace-snapshot.event.v1";
pub const WORKSPACE_SNAPSHOT_ARTIFACT_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace_snapshot_artifact.v1";
pub const WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_snapshot_list_request.v1";
pub const WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_snapshot_content_package_request.v1";
pub const WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_snapshot_restore_preview_request.v1";
pub const WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_snapshot_restore_apply_request.v1";
pub const WORKSPACE_SNAPSHOT_LIST_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.workspace_snapshot.v1";
pub const WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace_snapshot_content_package.v1";
pub const WORKSPACE_RESTORE_PREVIEW_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace_restore_preview.v1";
pub const WORKSPACE_RESTORE_APPLY_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace_restore_apply.v1";
pub const WORKSPACE_RESTORE_ARTIFACT_SCHEMA_VERSION: &str =
    "ioi.runtime.workspace_restore_artifact.v1";
pub const WORKSPACE_RESTORE_EVENT_SCHEMA_VERSION: &str = "ioi.runtime.workspace_restore.event.v1";
pub const WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_restore_apply_policy_request.v1";
pub const WORKSPACE_RESTORE_APPLY_POLICY_PLAN_SCHEMA_VERSION: &str =
    "ioi.workspace_restore_apply_policy_plan.v1";
pub const WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES: u64 = 256 * 1024;
pub const WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES: u64 = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRestoreProtocolError {
    code: &'static str,
    message: String,
}

impl WorkspaceRestoreProtocolError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotCaptureRequest {
    pub schema_version: String,
    #[serde(default)]
    pub changed_files: Vec<WorkspaceSnapshotChangedFile>,
    #[serde(default)]
    pub content_drafts: Vec<WorkspaceSnapshotContentDraft>,
    #[serde(default)]
    pub max_content_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotChangedFile {
    pub path: String,
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub before_hash: Option<String>,
    #[serde(default)]
    pub after_hash: Option<String>,
    #[serde(default)]
    pub before_exists: bool,
    #[serde(default)]
    pub after_exists: Option<bool>,
    #[serde(default)]
    pub before_size_bytes: Option<u64>,
    #[serde(default)]
    pub after_size_bytes: Option<u64>,
    #[serde(default)]
    pub before_mtime_ms: Option<Value>,
    #[serde(default)]
    pub after_mtime_ms: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotContentDraft {
    pub path: String,
    #[serde(default)]
    pub before_content: Option<String>,
    #[serde(default)]
    pub after_content: Option<String>,
    #[serde(default)]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotCaptureResult {
    pub schema_version: String,
    #[serde(default)]
    pub files: Vec<WorkspaceSnapshotCapturedFile>,
    #[serde(default)]
    pub content_files: Vec<WorkspaceSnapshotCapturedFile>,
    pub captured_file_count: u64,
    pub omitted_file_count: u64,
    pub content_captured: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotCapturedFile {
    pub path: String,
    pub created: bool,
    pub deleted: bool,
    pub changed: bool,
    pub before: WorkspaceSnapshotCapturedSide,
    pub after: WorkspaceSnapshotCapturedSide,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotCapturedSide {
    pub exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_ms: Option<Value>,
    pub content_captured: bool,
    pub content_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct WorkspaceSnapshotCaptureRecord {
    public_file: WorkspaceSnapshotCapturedFile,
    content_file: WorkspaceSnapshotCapturedFile,
    content_captured: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct WorkspaceSnapshotCaptureSideRecord {
    public_side: WorkspaceSnapshotCapturedSide,
    content_side: WorkspaceSnapshotCapturedSide,
    captured: bool,
}

#[derive(Debug, Default, Clone)]
pub struct WorkspaceSnapshotCaptureCore;

impl WorkspaceSnapshotCaptureCore {
    pub fn capture_files(
        &self,
        request: &WorkspaceSnapshotCaptureRequest,
    ) -> Result<WorkspaceSnapshotCaptureResult, WorkspaceRestoreOperationError> {
        request.validate()?;
        let max_content_bytes = request
            .max_content_bytes
            .unwrap_or(WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES);
        let captures = request
            .changed_files
            .iter()
            .filter(|entry| !entry.path.trim().is_empty())
            .map(|entry| {
                capture_snapshot_file(
                    entry,
                    content_draft_for_path(&request.content_drafts, &entry.path),
                    max_content_bytes,
                )
            })
            .collect::<Vec<_>>();
        let captured_file_count = captures
            .iter()
            .filter(|capture| capture.content_captured)
            .count() as u64;
        let omitted_file_count = captures.len() as u64 - captured_file_count;
        Ok(WorkspaceSnapshotCaptureResult {
            schema_version: WORKSPACE_SNAPSHOT_CAPTURE_RESULT_SCHEMA_VERSION.to_string(),
            files: captures
                .iter()
                .map(|capture| capture.public_file.clone())
                .collect(),
            content_files: captures
                .iter()
                .map(|capture| capture.content_file.clone())
                .collect(),
            captured_file_count,
            omitted_file_count,
            content_captured: omitted_file_count == 0,
        })
    }
}

impl WorkspaceSnapshotCaptureRequest {
    fn validate(&self) -> Result<(), WorkspaceRestoreOperationError> {
        if self.schema_version != WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION {
            return Err(WorkspaceRestoreOperationError::InvalidSchemaVersion {
                expected: WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreOperationsRequest {
    pub schema_version: String,
    pub workspace_root: String,
    #[serde(default)]
    pub files: Vec<WorkspaceRestoreFile>,
    #[serde(default)]
    pub max_diff_bytes: Option<u64>,
    #[serde(default)]
    pub allow_conflicts: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreFile {
    pub path: String,
    #[serde(default)]
    pub before: WorkspaceRestoreFileSide,
    #[serde(default)]
    pub after: WorkspaceRestoreFileSide,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreFileSide {
    #[serde(default)]
    pub exists: bool,
    #[serde(default)]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreOperationRecord {
    pub path: String,
    pub operation: String,
    pub status: String,
    pub current_exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_hash: Option<String>,
    pub current_bytes: u64,
    pub target_exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_hash: Option<String>,
    pub snapshot_after_exists: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_after_hash: Option<String>,
    pub current_matches_snapshot_post: bool,
    pub current_matches_restore_target: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    pub diff: String,
    pub diff_bytes: u64,
    pub diff_hash: String,
    pub diff_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_exists: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_matches_target: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceRestoreCurrent {
    exists: bool,
    content: String,
    content_hash: Option<String>,
    content_bytes: u64,
    blocked: bool,
    blocked_reason: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct WorkspaceRestoreOperationsCore;

impl WorkspaceRestoreOperationsCore {
    pub fn preview_operations(
        &self,
        request: &WorkspaceRestoreOperationsRequest,
    ) -> Result<Vec<WorkspaceRestoreOperationRecord>, WorkspaceRestoreOperationError> {
        request.validate(WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION)?;
        request
            .files
            .iter()
            .map(|file| {
                preview_operation(
                    &request.workspace_root,
                    file,
                    request
                        .max_diff_bytes
                        .unwrap_or(WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES),
                )
            })
            .collect()
    }

    pub fn apply_operations(
        &self,
        request: &WorkspaceRestoreOperationsRequest,
    ) -> Result<Vec<WorkspaceRestoreOperationRecord>, WorkspaceRestoreOperationError> {
        request.validate(WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION)?;
        let allow_conflicts = request.allow_conflicts.unwrap_or(false);
        let plans = request
            .files
            .iter()
            .map(|file| {
                preview_operation(
                    &request.workspace_root,
                    file,
                    request
                        .max_diff_bytes
                        .unwrap_or(WORKSPACE_RESTORE_PREVIEW_DIFF_MAX_BYTES),
                )
                .map(|preview| (file, preview))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let blocked_preflight = plans.iter().any(|(_, preview)| {
            preview.status == "blocked" || (preview.status == "conflict" && !allow_conflicts)
        });
        if blocked_preflight {
            return Ok(plans
                .into_iter()
                .map(|(_, preview)| blocked_apply_operation(preview, allow_conflicts))
                .collect());
        }
        plans
            .into_iter()
            .map(|(file, preview)| {
                apply_operation(&request.workspace_root, file, preview, allow_conflicts)
            })
            .collect()
    }
}

impl WorkspaceRestoreOperationsRequest {
    fn validate(&self, expected: &'static str) -> Result<(), WorkspaceRestoreOperationError> {
        if self.schema_version != expected {
            return Err(WorkspaceRestoreOperationError::InvalidSchemaVersion {
                expected,
                actual: self.schema_version.clone(),
            });
        }
        if self.workspace_root.trim().is_empty() {
            return Err(WorkspaceRestoreOperationError::MissingWorkspaceRoot);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreApplyPolicyRequest {
    pub schema_version: String,
    pub snapshot_id: String,
    #[serde(default)]
    pub approval: Option<String>,
    #[serde(default)]
    pub approval_decision: Option<String>,
    #[serde(default)]
    pub policy_decision: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub confirm: Option<Value>,
    #[serde(default)]
    pub confirmed: Option<Value>,
    #[serde(default)]
    pub confirm_restore_apply: Option<Value>,
    #[serde(default)]
    pub apply_confirmed: Option<Value>,
    #[serde(default)]
    pub approval_granted: Option<Value>,
    #[serde(default)]
    pub approved: Option<Value>,
    #[serde(default)]
    pub restore_conflict_policy: Option<String>,
    #[serde(default)]
    pub conflict_policy: Option<String>,
    #[serde(default)]
    pub restore_policy: Option<String>,
    #[serde(default)]
    pub allow_conflicts: Option<Value>,
    #[serde(default)]
    pub override_conflicts: Option<Value>,
    #[serde(default)]
    pub operations: Vec<WorkspaceRestoreOperationPolicyInput>,
    #[serde(default)]
    pub counts: Option<WorkspaceRestoreApplyCounts>,
    #[serde(default)]
    pub hard_blocked: Option<bool>,
    #[serde(default)]
    pub conflict_blocked: Option<bool>,
    #[serde(default)]
    pub apply_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreApplyPolicyPlan {
    pub schema_version: String,
    pub snapshot_id: String,
    pub approval: WorkspaceRestoreApplyApproval,
    pub allow_conflicts: bool,
    pub conflict_policy: String,
    pub hard_blocked: bool,
    pub conflict_blocked: bool,
    pub policy_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_status: Option<String>,
    #[serde(default)]
    pub policy_decision_refs: Vec<String>,
    #[serde(default)]
    pub operation_policies: Vec<WorkspaceRestoreOperationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreApplyApproval {
    pub required: bool,
    pub satisfied: bool,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreOperationPolicyInput {
    pub path: String,
    pub status: String,
    #[serde(default)]
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreOperationPolicy {
    pub path: String,
    pub apply_reason: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRestoreApplyCounts {
    #[serde(default)]
    pub file_count: u64,
    #[serde(default)]
    pub ready_count: u64,
    #[serde(default)]
    pub noop_count: u64,
    #[serde(default)]
    pub conflict_count: u64,
    #[serde(default)]
    pub blocked_count: u64,
    #[serde(default)]
    pub applied_count: u64,
    #[serde(default)]
    pub apply_noop_count: u64,
    #[serde(default)]
    pub apply_blocked_count: u64,
    #[serde(default)]
    pub failed_count: u64,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceRestoreApplyPolicyProtocolRequest {
    pub request: WorkspaceRestoreApplyPolicyRequest,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceRestoreOperationsProtocolRequest {
    pub request: WorkspaceRestoreOperationsRequest,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceSnapshotCaptureProtocolRequest {
    pub request: WorkspaceSnapshotCaptureRequest,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotListRequest {
    pub schema_version: String,
    pub thread_id: String,
    #[serde(default)]
    pub snapshots: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotContentPackageRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub snapshot_id: String,
    #[serde(default)]
    pub snapshot_record: Option<Value>,
    #[serde(default)]
    pub content_package: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSnapshotRestoreRequest {
    pub schema_version: String,
    pub thread_id: String,
    pub snapshot_id: String,
    pub workspace_root: String,
    #[serde(default)]
    pub workflow_graph_id: Option<String>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub approval: Option<String>,
    #[serde(default)]
    pub approval_decision: Option<String>,
    #[serde(default)]
    pub policy_decision: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub confirm: Option<Value>,
    #[serde(default)]
    pub confirmed: Option<Value>,
    #[serde(default)]
    pub confirm_restore_apply: Option<Value>,
    #[serde(default)]
    pub apply_confirmed: Option<Value>,
    #[serde(default)]
    pub approval_granted: Option<Value>,
    #[serde(default)]
    pub approved: Option<Value>,
    #[serde(default)]
    pub restore_conflict_policy: Option<String>,
    #[serde(default)]
    pub conflict_policy: Option<String>,
    #[serde(default)]
    pub restore_policy: Option<String>,
    #[serde(default)]
    pub allow_conflicts: Option<Value>,
    #[serde(default)]
    pub override_conflicts: Option<Value>,
    #[serde(default)]
    pub max_diff_bytes: Option<u64>,
    #[serde(default)]
    pub snapshot_record: Option<Value>,
    #[serde(default)]
    pub content_package: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceSnapshotListProtocolRequest {
    pub request: WorkspaceSnapshotListRequest,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceSnapshotContentPackageProtocolRequest {
    pub request: WorkspaceSnapshotContentPackageRequest,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceSnapshotRestoreProtocolRequest {
    pub request: WorkspaceSnapshotRestoreRequest,
}

#[derive(Debug, Default, Clone)]
pub struct WorkspaceRestoreApplyPolicyCore;

impl WorkspaceRestoreApplyPolicyCore {
    pub fn plan_apply_policy(
        &self,
        request: &WorkspaceRestoreApplyPolicyRequest,
    ) -> Result<WorkspaceRestoreApplyPolicyPlan, WorkspaceRestoreApplyPolicyError> {
        request.validate()?;
        let approval = request.approval();
        let allow_conflicts = request.allows_conflicts();
        let conflict_policy = if allow_conflicts {
            "override_conflicts"
        } else {
            "clean_preview_only"
        }
        .to_string();
        let operation_counts = WorkspaceRestoreApplyCounts::from_operations(&request.operations);
        let hard_blocked = request
            .hard_blocked
            .unwrap_or(operation_counts.blocked_count > 0);
        let conflict_blocked = request
            .conflict_blocked
            .unwrap_or(operation_counts.conflict_count > 0 && !allow_conflicts);
        let operation_policies = request
            .operations
            .iter()
            .map(|operation| WorkspaceRestoreOperationPolicy {
                path: operation.path.clone(),
                apply_reason: operation_apply_blocked_reason(
                    operation,
                    &approval,
                    allow_conflicts,
                    hard_blocked,
                    conflict_blocked,
                ),
            })
            .collect::<Vec<_>>();
        let counts = request.counts.as_ref();
        let apply_status = request
            .apply_status
            .as_ref()
            .and_then(|status| normalize_apply_status(status))
            .or_else(|| counts.map(WorkspaceRestoreApplyCounts::apply_status));
        let policy_decision_refs = policy_decision_refs(
            &request.snapshot_id,
            &approval,
            allow_conflicts,
            hard_blocked,
            conflict_blocked,
            apply_status.as_deref(),
        );
        let policy_status = if apply_status.as_deref() == Some("blocked")
            || !approval.satisfied
            || hard_blocked
            || conflict_blocked
        {
            "blocked"
        } else {
            "allowed"
        }
        .to_string();
        let summary = apply_status.as_deref().and_then(|status| {
            counts.map(|counts| {
                apply_summary(
                    &request.snapshot_id,
                    status,
                    counts,
                    &approval,
                    allow_conflicts,
                )
            })
        });

        Ok(WorkspaceRestoreApplyPolicyPlan {
            schema_version: WORKSPACE_RESTORE_APPLY_POLICY_PLAN_SCHEMA_VERSION.to_string(),
            snapshot_id: request.snapshot_id.clone(),
            approval,
            allow_conflicts,
            conflict_policy,
            hard_blocked,
            conflict_blocked,
            policy_status,
            apply_status,
            policy_decision_refs,
            operation_policies,
            summary,
        })
    }
}

pub fn plan_workspace_restore_apply_policy_protocol_response(
    request: WorkspaceRestoreApplyPolicyProtocolRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    let plan = WorkspaceRestoreApplyPolicyCore
        .plan_apply_policy(&request.request)
        .map_err(|error| {
            WorkspaceRestoreProtocolError::new(
                "workspace_restore_apply_policy_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_policy_protocol",
        "backend": "rust_workspace_restore",
        "plan": plan.clone(),
        "approval": plan.approval.clone(),
        "allow_conflicts": plan.allow_conflicts,
        "conflict_policy": plan.conflict_policy.clone(),
        "hard_blocked": plan.hard_blocked,
        "conflict_blocked": plan.conflict_blocked,
        "policy_status": plan.policy_status.clone(),
        "apply_status": plan.apply_status.clone(),
        "policy_decision_refs": plan.policy_decision_refs.clone(),
        "operation_policies": plan.operation_policies.clone(),
        "summary": plan.summary.clone(),
    }))
}

pub fn preview_workspace_restore_operations_protocol_response(
    request: WorkspaceRestoreOperationsProtocolRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    let operations = WorkspaceRestoreOperationsCore
        .preview_operations(&request.request)
        .map_err(|error| {
            WorkspaceRestoreProtocolError::new(
                "workspace_restore_operations_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_operations_protocol",
        "backend": "rust_workspace_restore",
        "operation": "preview_workspace_restore_operations",
        "operations": operations,
    }))
}

pub fn apply_workspace_restore_operations_protocol_response(
    request: WorkspaceRestoreOperationsProtocolRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    let operations = WorkspaceRestoreOperationsCore
        .apply_operations(&request.request)
        .map_err(|error| {
            WorkspaceRestoreProtocolError::new(
                "workspace_restore_operations_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_workspace_restore_operations_protocol",
        "backend": "rust_workspace_restore",
        "operation": "apply_workspace_restore_operations",
        "operations": operations,
    }))
}

pub fn capture_workspace_snapshot_files_protocol_response(
    request: WorkspaceSnapshotCaptureProtocolRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    let capture = WorkspaceSnapshotCaptureCore
        .capture_files(&request.request)
        .map_err(|error| {
            WorkspaceRestoreProtocolError::new(
                "workspace_snapshot_capture_invalid",
                format!("{error:?}"),
            )
        })?;
    let snapshot_record = workspace_snapshot_capture_record(&request, &capture);
    let snapshot_artifact = workspace_snapshot_capture_artifact(&request, &snapshot_record);
    let snapshot_event =
        workspace_snapshot_capture_event(&request, &snapshot_record, &snapshot_artifact);
    Ok(json!({
        "source": "rust_workspace_snapshot_capture_protocol",
        "backend": "rust_workspace_restore",
        "capture": capture.clone(),
        "snapshot_record": snapshot_record,
        "snapshot_artifact": snapshot_artifact,
        "snapshot_event": snapshot_event,
        "files": capture.files.clone(),
        "content_files": capture.content_files.clone(),
        "captured_file_count": capture.captured_file_count,
        "omitted_file_count": capture.omitted_file_count,
        "content_captured": capture.content_captured,
    }))
}

pub fn project_workspace_snapshot_list_protocol_response(
    request: WorkspaceSnapshotListProtocolRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    validate_workspace_snapshot_list_request(&request.request)?;
    let projection = workspace_snapshot_list_projection(&request.request);
    Ok(json!({
        "source": "rust_workspace_snapshot_projection_protocol",
        "backend": "rust_workspace_restore",
        "projection_kind": "workspace_snapshot.list",
        "projection": projection,
        "evidence_refs": workspace_snapshot_projection_evidence_refs(),
    }))
}

pub fn project_workspace_snapshot_content_package_protocol_response(
    request: WorkspaceSnapshotContentPackageProtocolRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    validate_workspace_snapshot_content_package_request(&request.request)?;
    let projection = workspace_snapshot_content_package_projection(&request.request)?;
    Ok(json!({
        "source": "rust_workspace_snapshot_projection_protocol",
        "backend": "rust_workspace_restore",
        "projection_kind": "workspace_snapshot.content_package",
        "projection": projection,
        "evidence_refs": workspace_snapshot_projection_evidence_refs(),
    }))
}

pub fn preview_workspace_snapshot_restore_protocol_response(
    request: WorkspaceSnapshotRestoreProtocolRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    validate_workspace_snapshot_restore_request(
        &request.request,
        WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_REQUEST_SCHEMA_VERSION,
    )?;
    let files = workspace_restore_files_from_content_package(
        request.request.content_package.as_ref(),
        &request.request.snapshot_id,
    )?;
    let operations_request = WorkspaceRestoreOperationsRequest {
        schema_version: WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION.to_string(),
        workspace_root: request.request.workspace_root.clone(),
        files,
        max_diff_bytes: request.request.max_diff_bytes,
        allow_conflicts: None,
    };
    let operations = WorkspaceRestoreOperationsCore
        .preview_operations(&operations_request)
        .map_err(|error| {
            WorkspaceRestoreProtocolError::new(
                "workspace_snapshot_restore_invalid",
                format!("{error:?}"),
            )
        })?;
    let result = workspace_restore_preview_result(&request.request, &operations);
    Ok(json!({
        "source": "rust_workspace_snapshot_restore_protocol",
        "backend": "rust_workspace_restore",
        "projection_kind": "workspace_restore.preview",
        "restore_preview": result,
        "evidence_refs": workspace_snapshot_restore_evidence_refs(),
    }))
}

pub fn apply_workspace_snapshot_restore_protocol_response(
    request: WorkspaceSnapshotRestoreProtocolRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    validate_workspace_snapshot_restore_request(
        &request.request,
        WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION,
    )?;
    let files = workspace_restore_files_from_content_package(
        request.request.content_package.as_ref(),
        &request.request.snapshot_id,
    )?;
    let preview_request = WorkspaceRestoreOperationsRequest {
        schema_version: WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION.to_string(),
        workspace_root: request.request.workspace_root.clone(),
        files: files.clone(),
        max_diff_bytes: request.request.max_diff_bytes,
        allow_conflicts: None,
    };
    let preview_operations = WorkspaceRestoreOperationsCore
        .preview_operations(&preview_request)
        .map_err(|error| {
            WorkspaceRestoreProtocolError::new(
                "workspace_snapshot_restore_invalid",
                format!("{error:?}"),
            )
        })?;
    let preview_counts = workspace_restore_operation_counts(&preview_operations);
    let preview_status = workspace_restore_preview_status(&preview_counts);
    let apply_status = if preview_status == "blocked" || preview_status == "conflict" {
        "blocked"
    } else {
        "applied"
    };
    let policy_request = workspace_restore_apply_policy_request_from_restore(
        &request.request,
        &preview_operations,
        {
            let mut counts = preview_counts.clone();
            if apply_status == "blocked" {
                counts.apply_blocked_count = counts.file_count;
            } else if counts.file_count > 0 {
                counts.applied_count = counts.ready_count + counts.conflict_count;
                counts.apply_noop_count = counts.noop_count;
            }
            counts
        },
        apply_status,
    );
    let policy = WorkspaceRestoreApplyPolicyCore
        .plan_apply_policy(&policy_request)
        .map_err(|error| {
            WorkspaceRestoreProtocolError::new(
                "workspace_snapshot_restore_invalid",
                format!("{error:?}"),
            )
        })?;
    let operations = if policy.policy_status == "allowed" {
        let apply_request = WorkspaceRestoreOperationsRequest {
            schema_version: WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION.to_string(),
            workspace_root: request.request.workspace_root.clone(),
            files,
            max_diff_bytes: request.request.max_diff_bytes,
            allow_conflicts: Some(policy.allow_conflicts),
        };
        WorkspaceRestoreOperationsCore
            .apply_operations(&apply_request)
            .map_err(|error| {
                WorkspaceRestoreProtocolError::new(
                    "workspace_snapshot_restore_invalid",
                    format!("{error:?}"),
                )
            })?
    } else {
        workspace_restore_policy_blocked_operations(&preview_operations, &policy)
    };
    let result =
        workspace_restore_apply_result(&request.request, &preview_status, &operations, &policy);
    Ok(json!({
        "source": "rust_workspace_snapshot_restore_protocol",
        "backend": "rust_workspace_restore",
        "projection_kind": "workspace_restore.apply",
        "restore_apply": result,
        "evidence_refs": workspace_snapshot_restore_evidence_refs(),
    }))
}

impl WorkspaceRestoreApplyPolicyRequest {
    pub fn validate(&self) -> Result<(), WorkspaceRestoreApplyPolicyError> {
        if self.schema_version != WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION {
            return Err(WorkspaceRestoreApplyPolicyError::InvalidSchemaVersion {
                expected: WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.snapshot_id.trim().is_empty() {
            return Err(WorkspaceRestoreApplyPolicyError::MissingSnapshotId);
        }
        Ok(())
    }

    fn approval(&self) -> WorkspaceRestoreApplyApproval {
        let text = first_non_empty([
            self.approval.as_deref(),
            self.approval_decision.as_deref(),
            self.policy_decision.as_deref(),
            self.decision.as_deref(),
            self.status.as_deref(),
        ])
        .map(|value| value.to_ascii_lowercase());
        let approved_boolean = [
            &self.confirm,
            &self.confirmed,
            &self.confirm_restore_apply,
            &self.apply_confirmed,
            &self.approval_granted,
            &self.approved,
        ]
        .iter()
        .any(|value| json_value_is_true(value));
        let approved_text = text
            .as_deref()
            .map(|value| APPROVED_TEXT.contains(&value))
            .unwrap_or(false);

        WorkspaceRestoreApplyApproval {
            required: true,
            satisfied: approved_boolean || approved_text,
            source: if approved_boolean {
                "boolean_confirmation".to_string()
            } else if approved_text {
                text.unwrap_or_else(|| "approved".to_string())
            } else {
                "missing".to_string()
            },
        }
    }

    fn allows_conflicts(&self) -> bool {
        let policy = first_non_empty([
            self.restore_conflict_policy.as_deref(),
            self.conflict_policy.as_deref(),
            self.restore_policy.as_deref(),
        ])
        .map(|value| value.to_ascii_lowercase());
        json_value_is_true(&self.allow_conflicts)
            || json_value_is_true(&self.override_conflicts)
            || policy
                .as_deref()
                .map(|value| CONFLICT_OVERRIDE_POLICIES.contains(&value))
                .unwrap_or(false)
    }
}

impl WorkspaceRestoreApplyCounts {
    fn from_operations(operations: &[WorkspaceRestoreOperationPolicyInput]) -> Self {
        let mut counts = Self {
            file_count: operations.len() as u64,
            ..Default::default()
        };
        for operation in operations {
            match operation.status.as_str() {
                "ready" => counts.ready_count += 1,
                "noop" => counts.noop_count += 1,
                "conflict" => counts.conflict_count += 1,
                "blocked" => counts.blocked_count += 1,
                "applied" | "applied_with_override" => counts.applied_count += 1,
                "failed" => counts.failed_count += 1,
                _ => {}
            }
        }
        counts
    }

    fn apply_status(&self) -> String {
        if self.apply_blocked_count > 0 {
            return "blocked".to_string();
        }
        if self.failed_count > 0 {
            return "failed".to_string();
        }
        if self.applied_count == 0
            && self.file_count > 0
            && self.apply_noop_count == self.file_count
        {
            return "noop".to_string();
        }
        "applied".to_string()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceRestoreApplyPolicyError {
    #[error(
        "workspace restore apply policy schema is invalid: expected {expected}, received {actual}"
    )]
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("workspace restore apply policy requires snapshot_id")]
    MissingSnapshotId,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceRestoreOperationError {
    #[error(
        "workspace restore operation schema is invalid: expected {expected}, received {actual}"
    )]
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("workspace restore operation requires workspace_root")]
    MissingWorkspaceRoot,
    #[error("workspace restore path must be workspace-relative: {0}")]
    UnsafePath(String),
    #[error("workspace restore path escaped workspace root: {0}")]
    PathEscapedWorkspace(String),
    #[error("workspace restore IO failed: {0}")]
    Io(String),
}

const APPROVED_TEXT: [&str; 8] = [
    "approve",
    "approved",
    "allow",
    "allowed",
    "accept",
    "accepted",
    "confirm",
    "confirmed",
];

const CONFLICT_OVERRIDE_POLICIES: [&str; 6] = [
    "allow_override",
    "override",
    "override_conflicts",
    "force",
    "force_apply",
    "apply_with_conflicts",
];

fn capture_snapshot_file(
    entry: &WorkspaceSnapshotChangedFile,
    draft: Option<&WorkspaceSnapshotContentDraft>,
    max_content_bytes: u64,
) -> WorkspaceSnapshotCaptureRecord {
    let path = entry.path.trim().to_string();
    let before_hash = trim_optional_string(entry.before_hash.as_deref());
    let after_hash = trim_optional_string(entry.after_hash.as_deref());
    let before_exists = entry.before_exists;
    let after_exists = entry.after_exists.unwrap_or(true);
    let before = capture_snapshot_side(
        before_exists,
        before_hash.clone(),
        entry.before_size_bytes.unwrap_or(0),
        entry.before_mtime_ms.clone(),
        draft.and_then(|draft| draft.before_content.clone()),
        max_content_bytes,
    );
    let after = capture_snapshot_side(
        after_exists,
        after_hash.clone(),
        if after_exists {
            entry.after_size_bytes.unwrap_or(0)
        } else {
            0
        },
        entry.after_mtime_ms.clone(),
        draft.and_then(|draft| draft.after_content.clone()),
        max_content_bytes,
    );
    let common = WorkspaceSnapshotCapturedFile {
        path,
        created: entry.created,
        deleted: before_exists && !after_exists,
        changed: before_hash != after_hash,
        before: before.public_side.clone(),
        after: after.public_side.clone(),
        receipt_refs: Vec::new(),
        artifact_refs: Vec::new(),
        encoding: None,
    };
    let content_file = WorkspaceSnapshotCapturedFile {
        before: before.content_side.clone(),
        after: after.content_side.clone(),
        encoding: Some(
            trim_optional_string(draft.and_then(|draft| draft.encoding.as_deref()))
                .unwrap_or_else(|| "utf8".to_string()),
        ),
        ..common.clone()
    };
    WorkspaceSnapshotCaptureRecord {
        public_file: common,
        content_file,
        content_captured: before.captured && after.captured,
    }
}

fn capture_snapshot_side(
    exists: bool,
    content_hash: Option<String>,
    size_bytes: u64,
    mtime_ms: Option<Value>,
    content: Option<String>,
    max_content_bytes: u64,
) -> WorkspaceSnapshotCaptureSideRecord {
    if !exists {
        let side = WorkspaceSnapshotCapturedSide {
            exists,
            content_hash,
            size_bytes: 0,
            mtime_ms,
            content_captured: true,
            content_bytes: 0,
            omitted_reason: None,
            content: None,
        };
        return WorkspaceSnapshotCaptureSideRecord {
            public_side: side.clone(),
            content_side: side,
            captured: true,
        };
    }
    let Some(content) = content else {
        let side = WorkspaceSnapshotCapturedSide {
            exists,
            content_hash,
            size_bytes,
            mtime_ms,
            content_captured: false,
            content_bytes: 0,
            omitted_reason: Some("snapshot_content_missing".to_string()),
            content: None,
        };
        return WorkspaceSnapshotCaptureSideRecord {
            public_side: side.clone(),
            content_side: side,
            captured: false,
        };
    };
    let content_bytes = content.as_bytes().len() as u64;
    if content_bytes > max_content_bytes {
        let side = WorkspaceSnapshotCapturedSide {
            exists,
            content_hash,
            size_bytes,
            mtime_ms,
            content_captured: false,
            content_bytes,
            omitted_reason: Some("snapshot_content_size_limit_exceeded".to_string()),
            content: None,
        };
        return WorkspaceSnapshotCaptureSideRecord {
            public_side: side.clone(),
            content_side: side,
            captured: false,
        };
    }
    if content_hash
        .as_deref()
        .map(|hash| sha256_hex(&content) != hash)
        .unwrap_or(false)
    {
        let side = WorkspaceSnapshotCapturedSide {
            exists,
            content_hash,
            size_bytes,
            mtime_ms,
            content_captured: false,
            content_bytes,
            omitted_reason: Some("snapshot_content_hash_mismatch".to_string()),
            content: None,
        };
        return WorkspaceSnapshotCaptureSideRecord {
            public_side: side.clone(),
            content_side: side,
            captured: false,
        };
    }
    let public_side = WorkspaceSnapshotCapturedSide {
        exists,
        content_hash: content_hash.clone(),
        size_bytes,
        mtime_ms: mtime_ms.clone(),
        content_captured: true,
        content_bytes,
        omitted_reason: None,
        content: None,
    };
    let content_side = WorkspaceSnapshotCapturedSide {
        content: Some(content),
        ..public_side.clone()
    };
    WorkspaceSnapshotCaptureSideRecord {
        public_side,
        content_side,
        captured: true,
    }
}

fn content_draft_for_path<'a>(
    drafts: &'a [WorkspaceSnapshotContentDraft],
    path: &str,
) -> Option<&'a WorkspaceSnapshotContentDraft> {
    let target = path.trim();
    drafts
        .iter()
        .find(|draft| draft.path.trim() == target && !target.is_empty())
}

fn preview_operation(
    workspace_root: &str,
    file: &WorkspaceRestoreFile,
    max_diff_bytes: u64,
) -> Result<WorkspaceRestoreOperationRecord, WorkspaceRestoreOperationError> {
    let target = resolve_workspace_restore_path(workspace_root, &file.path)?;
    let current = read_workspace_restore_current(&target.absolute_path);
    let before_exists = file.before.exists;
    let after_exists = file.after.exists;
    let desired_content = if before_exists {
        file.before.content.as_deref().unwrap_or("")
    } else {
        ""
    };
    let desired_hash = if before_exists {
        trim_optional_string(file.before.content_hash.as_deref())
    } else {
        None
    };
    let after_hash = if after_exists {
        trim_optional_string(file.after.content_hash.as_deref())
    } else {
        None
    };
    let current_matches_snapshot_post =
        current.exists == after_exists && (!after_exists || current.content_hash == after_hash);
    let current_matches_restore_target =
        current.exists == before_exists && (!before_exists || current.content_hash == desired_hash);
    let content_available = !before_exists || file.before.content.is_some();
    let operation = if current_matches_restore_target {
        "noop"
    } else if before_exists {
        if current.exists {
            "replace"
        } else {
            "create"
        }
    } else {
        "delete"
    }
    .to_string();
    let status = if current_matches_restore_target {
        "noop"
    } else if !content_available || current.blocked {
        "blocked"
    } else if current_matches_snapshot_post {
        "ready"
    } else {
        "conflict"
    }
    .to_string();
    let diff = if status == "ready" {
        workspace_restore_diff_preview(
            &target.relative_path,
            if current.exists { &current.content } else { "" },
            if before_exists { desired_content } else { "" },
            max_diff_bytes,
        )
    } else {
        WorkspaceRestoreDiff {
            text: String::new(),
            bytes: 0,
            truncated: false,
        }
    };
    Ok(WorkspaceRestoreOperationRecord {
        path: target.relative_path,
        operation,
        status,
        current_exists: current.exists,
        current_hash: current.content_hash,
        current_bytes: current.content_bytes,
        target_exists: before_exists,
        target_hash: desired_hash,
        snapshot_after_exists: after_exists,
        snapshot_after_hash: after_hash,
        current_matches_snapshot_post,
        current_matches_restore_target,
        blocked_reason: current.blocked_reason.or_else(|| {
            if !content_available {
                Some("snapshot_restore_target_content_missing".to_string())
            } else {
                None
            }
        }),
        diff_hash: sha256_hex(&diff.text),
        diff: diff.text,
        diff_bytes: diff.bytes,
        diff_truncated: diff.truncated,
        apply_status: None,
        apply_reason: None,
        applied_exists: None,
        applied_hash: None,
        applied_bytes: None,
        applied_matches_target: None,
        error_message: None,
    })
}

fn blocked_apply_operation(
    mut preview: WorkspaceRestoreOperationRecord,
    allow_conflicts: bool,
) -> WorkspaceRestoreOperationRecord {
    preview.apply_status = Some("blocked".to_string());
    preview.apply_reason = workspace_restore_apply_block_reason(&preview, allow_conflicts);
    preview
}

fn apply_operation(
    workspace_root: &str,
    file: &WorkspaceRestoreFile,
    preview: WorkspaceRestoreOperationRecord,
    allow_conflicts: bool,
) -> Result<WorkspaceRestoreOperationRecord, WorkspaceRestoreOperationError> {
    let target = resolve_workspace_restore_path(workspace_root, &file.path)?;
    let target_exists = file.before.exists;
    if preview.status == "noop" {
        let current = read_workspace_restore_current(&target.absolute_path);
        return Ok(applied_operation(preview, current, "noop"));
    }
    let write_result = if !target_exists {
        if target.absolute_path.exists() {
            fs::remove_file(&target.absolute_path)
        } else {
            Ok(())
        }
    } else if let Some(content) = &file.before.content {
        if let Some(parent) = target.absolute_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target.absolute_path, content)
    } else {
        let mut failed = preview;
        failed.apply_status = Some("failed".to_string());
        failed.apply_reason = Some("snapshot_restore_target_content_missing".to_string());
        return Ok(failed);
    };
    if let Err(error) = write_result {
        let mut failed = preview;
        failed.apply_status = Some("failed".to_string());
        failed.apply_reason = Some("workspace_restore_write_failed".to_string());
        failed.error_message = Some(error.to_string());
        return Ok(failed);
    }
    let current = read_workspace_restore_current(&target.absolute_path);
    let apply_status = if preview.status == "conflict" && allow_conflicts {
        "applied_with_override"
    } else {
        "applied"
    };
    Ok(applied_operation(preview, current, apply_status))
}

fn applied_operation(
    mut preview: WorkspaceRestoreOperationRecord,
    current: WorkspaceRestoreCurrent,
    apply_status: &str,
) -> WorkspaceRestoreOperationRecord {
    preview.apply_status = Some(apply_status.to_string());
    preview.applied_exists = Some(current.exists);
    preview.applied_hash = current.content_hash.clone();
    preview.applied_bytes = Some(current.content_bytes);
    preview.applied_matches_target = Some(
        current.exists == preview.target_exists
            && (!current.exists || current.content_hash == preview.target_hash),
    );
    preview
}

fn workspace_restore_apply_block_reason(
    preview: &WorkspaceRestoreOperationRecord,
    allow_conflicts: bool,
) -> Option<String> {
    if preview.status == "blocked" {
        return Some(
            preview
                .blocked_reason
                .clone()
                .unwrap_or_else(|| "workspace_restore_preview_blocked".to_string()),
        );
    }
    if preview.status == "conflict" && !allow_conflicts {
        return Some("workspace_restore_conflict_requires_override".to_string());
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceRestorePath {
    absolute_path: PathBuf,
    relative_path: String,
}

fn resolve_workspace_restore_path(
    workspace_root: &str,
    selected_path: &str,
) -> Result<WorkspaceRestorePath, WorkspaceRestoreOperationError> {
    let relative_input = selected_path.trim();
    if relative_input.is_empty()
        || relative_input.contains('\0')
        || Path::new(relative_input).is_absolute()
    {
        return Err(WorkspaceRestoreOperationError::UnsafePath(
            selected_path.to_string(),
        ));
    }
    let root = normalize_path(&absolute_path(workspace_root)?);
    let candidate = normalize_path(&root.join(relative_input));
    if !path_inside(&root, &candidate) {
        return Err(WorkspaceRestoreOperationError::PathEscapedWorkspace(
            selected_path.to_string(),
        ));
    }
    // Lexical normalization alone does not stop a SYMLINKED parent from escaping the
    // workspace (e.g. <root>/sub -> /etc). Canonicalize the deepest existing ancestor of
    // the target and re-check it is still inside the canonicalized root before any write.
    if let Ok(canonical_root) = fs::canonicalize(&root) {
        let mut ancestor = candidate.as_path();
        let existing = loop {
            if ancestor.exists() {
                break Some(ancestor.to_path_buf());
            }
            match ancestor.parent() {
                Some(parent) => ancestor = parent,
                None => break None,
            }
        };
        if let Some(existing) = existing {
            if let Ok(canonical_existing) = fs::canonicalize(&existing) {
                if !path_inside(&canonical_root, &canonical_existing) {
                    return Err(WorkspaceRestoreOperationError::PathEscapedWorkspace(
                        selected_path.to_string(),
                    ));
                }
            }
        }
    }
    let relative_path = candidate
        .strip_prefix(&root)
        .unwrap_or(candidate.as_path())
        .to_string_lossy()
        .replace('\\', "/");
    Ok(WorkspaceRestorePath {
        absolute_path: candidate,
        relative_path: if relative_path.is_empty() {
            ".".to_string()
        } else {
            relative_path
        },
    })
}

fn read_workspace_restore_current(path: &Path) -> WorkspaceRestoreCurrent {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return WorkspaceRestoreCurrent {
                exists: false,
                content: String::new(),
                content_hash: None,
                content_bytes: 0,
                blocked: false,
                blocked_reason: None,
            };
        }
        Err(error) => {
            return WorkspaceRestoreCurrent {
                exists: true,
                content: String::new(),
                content_hash: None,
                content_bytes: 0,
                blocked: true,
                blocked_reason: Some(format!("current_path_metadata_failed:{error}")),
            };
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return WorkspaceRestoreCurrent {
            exists: true,
            content: String::new(),
            content_hash: None,
            content_bytes: metadata.len(),
            blocked: true,
            blocked_reason: Some(
                if metadata.file_type().is_symlink() {
                    "current_path_is_symbolic_link"
                } else {
                    "current_path_not_regular_file"
                }
                .to_string(),
            ),
        };
    }
    if metadata.len() > WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES {
        return WorkspaceRestoreCurrent {
            exists: true,
            content: String::new(),
            content_hash: None,
            content_bytes: metadata.len(),
            blocked: true,
            blocked_reason: Some("current_content_size_limit_exceeded".to_string()),
        };
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return WorkspaceRestoreCurrent {
                exists: true,
                content: String::new(),
                content_hash: None,
                content_bytes: metadata.len(),
                blocked: true,
                blocked_reason: Some(format!("current_content_read_failed:{error}")),
            };
        }
    };
    let content = String::from_utf8_lossy(&bytes).to_string();
    WorkspaceRestoreCurrent {
        exists: true,
        content_hash: Some(sha256_hex(&content)),
        content,
        content_bytes: bytes.len() as u64,
        blocked: false,
        blocked_reason: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceRestoreDiff {
    text: String,
    bytes: u64,
    truncated: bool,
}

fn workspace_restore_diff_preview(
    relative_path: &str,
    before: &str,
    after: &str,
    max_bytes: u64,
) -> WorkspaceRestoreDiff {
    if before == after {
        return WorkspaceRestoreDiff {
            text: String::new(),
            bytes: 0,
            truncated: false,
        };
    }
    let tmp_root = std::env::temp_dir().join(format!(
        "ioi-workspace-restore-diff-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let before_path = tmp_root.join("current");
    let after_path = tmp_root.join("restore");
    let diff_text = (|| -> Result<String, WorkspaceRestoreOperationError> {
        fs::create_dir_all(&tmp_root)?;
        fs::write(&before_path, before)?;
        fs::write(&after_path, after)?;
        let output = Command::new("git")
            .args([
                "diff",
                "--no-index",
                "--no-color",
                "--",
                &before_path.to_string_lossy(),
                &after_path.to_string_lossy(),
            ])
            .output();
        let raw = match output {
            Ok(output) => {
                if !output.stdout.is_empty() {
                    String::from_utf8_lossy(&output.stdout).to_string()
                } else {
                    String::from_utf8_lossy(&output.stderr).to_string()
                }
            }
            Err(_) => format!(
                "diff --git a/{relative_path} b/{relative_path}\n--- a/{relative_path}\n+++ b/{relative_path}\n@@ restore preview unavailable @@\n"
            ),
        };
        Ok(raw
            .replace(&before_path.to_string_lossy().to_string(), &format!("a/{relative_path}"))
            .replace(&after_path.to_string_lossy().to_string(), &format!("b/{relative_path}")))
    })()
    .unwrap_or_else(|error| format!("workspace restore diff unavailable: {error}"));
    let _ = fs::remove_dir_all(&tmp_root);
    let bytes = diff_text.as_bytes();
    let limit = max_bytes.max(1);
    let truncated = bytes.len() as u64 > limit;
    let full_len = bytes.len() as u64;
    let text = if truncated {
        String::from_utf8_lossy(&bytes[..limit as usize]).to_string()
    } else {
        diff_text
    };
    WorkspaceRestoreDiff {
        text,
        bytes: full_len,
        truncated,
    }
}

fn absolute_path(value: &str) -> Result<PathBuf, WorkspaceRestoreOperationError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .map_err(WorkspaceRestoreOperationError::from)?
            .join(path))
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn path_inside(root: &Path, candidate: &Path) -> bool {
    candidate == root || candidate.starts_with(root)
}

impl From<std::io::Error> for WorkspaceRestoreOperationError {
    fn from(error: std::io::Error) -> Self {
        WorkspaceRestoreOperationError::Io(error.to_string())
    }
}

fn operation_apply_blocked_reason(
    operation: &WorkspaceRestoreOperationPolicyInput,
    approval: &WorkspaceRestoreApplyApproval,
    allow_conflicts: bool,
    hard_blocked: bool,
    conflict_blocked: bool,
) -> String {
    if !approval.satisfied {
        return "workspace_restore_apply_requires_approval".to_string();
    }
    if operation.status == "blocked" {
        return first_non_empty([operation.blocked_reason.as_deref()])
            .unwrap_or("workspace_restore_preview_blocked")
            .to_string();
    }
    if operation.status == "conflict" && !allow_conflicts {
        return "workspace_restore_conflict_requires_override".to_string();
    }
    if hard_blocked {
        return "workspace_restore_apply_blocked_by_file".to_string();
    }
    if conflict_blocked {
        return "workspace_restore_apply_blocked_by_conflict".to_string();
    }
    "workspace_restore_apply_blocked_by_policy".to_string()
}

fn policy_decision_refs(
    snapshot_id: &str,
    approval: &WorkspaceRestoreApplyApproval,
    allow_conflicts: bool,
    hard_blocked: bool,
    conflict_blocked: bool,
    apply_status: Option<&str>,
) -> Vec<String> {
    let safe_snapshot_id = safe_id(snapshot_id);
    let mut refs = vec![format!(
        "policy_workspace_restore_apply_{}_{}",
        safe_snapshot_id,
        if approval.satisfied {
            "approval_satisfied"
        } else {
            "approval_required"
        }
    )];
    if allow_conflicts {
        refs.push(format!(
            "policy_workspace_restore_apply_{}_conflict_override",
            safe_snapshot_id
        ));
    }
    if hard_blocked {
        refs.push(format!(
            "policy_workspace_restore_apply_{}_blocked_file",
            safe_snapshot_id
        ));
    }
    if conflict_blocked {
        refs.push(format!(
            "policy_workspace_restore_apply_{}_conflict_blocked",
            safe_snapshot_id
        ));
    }
    if apply_status == Some("failed") {
        refs.push(format!(
            "policy_workspace_restore_apply_{}_write_failed",
            safe_snapshot_id
        ));
    }
    unique_strings(refs)
}

fn apply_summary(
    snapshot_id: &str,
    apply_status: &str,
    counts: &WorkspaceRestoreApplyCounts,
    approval: &WorkspaceRestoreApplyApproval,
    allow_conflicts: bool,
) -> String {
    if !approval.satisfied {
        return format!("Restore apply blocked for {snapshot_id}: operator approval is required.");
    }
    match apply_status {
        "blocked" => format!(
            "Restore apply blocked for {snapshot_id}: {} conflict(s), {} blocked file(s).",
            counts.conflict_count, counts.blocked_count
        ),
        "failed" => format!(
            "Restore apply failed for {snapshot_id}: {} file write(s) failed.",
            counts.failed_count
        ),
        "noop" => format!(
            "Restore apply found {} file(s) already restored for {snapshot_id}.",
            counts.file_count
        ),
        _ => format!(
            "Restore apply restored {} file(s) from {snapshot_id}{}.",
            counts.applied_count,
            if allow_conflicts {
                " with conflict override"
            } else {
                ""
            }
        ),
    }
}

fn workspace_snapshot_capture_record(
    request: &WorkspaceSnapshotCaptureProtocolRequest,
    capture: &WorkspaceSnapshotCaptureResult,
) -> Value {
    let thread_id = trim_optional_string(request.thread_id.as_deref());
    let turn_id = trim_optional_string(request.turn_id.as_deref());
    let workspace_root = trim_optional_string(request.workspace_root.as_deref());
    let tool_call_id = trim_optional_string(request.tool_call_id.as_deref());
    let workflow_graph_id = trim_optional_string(request.workflow_graph_id.as_deref());
    let workflow_node_id = trim_optional_string(request.workflow_node_id.as_deref());
    let changed_file_count = capture.files.iter().filter(|file| file.changed).count() as u64;
    let created_file_count = capture.files.iter().filter(|file| file.created).count() as u64;
    let deleted_file_count = capture.files.iter().filter(|file| file.deleted).count() as u64;
    let snapshot_seed = json!({
        "schema_version": WORKSPACE_SNAPSHOT_RECORD_SCHEMA_VERSION,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "workspace_root": workspace_root,
        "tool_call_id": tool_call_id,
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
        "files": capture.files,
        "content_files": capture.content_files,
    });
    let seed_text = serde_json::to_string(&snapshot_seed).unwrap_or_else(|_| "{}".to_string());
    let snapshot_hash = format!("sha256:{}", sha256_hex(&seed_text));
    let snapshot_hash_id = snapshot_hash
        .strip_prefix("sha256:")
        .unwrap_or(&snapshot_hash)
        .chars()
        .take(24)
        .collect::<String>();
    let snapshot_id = format!("workspace_snapshot_{snapshot_hash_id}");
    let safe_snapshot_id = safe_id(&snapshot_id);
    let receipt_refs = unique_strings(vec![format!(
        "receipt://runtime.workspace_snapshot/{safe_snapshot_id}"
    )]);
    let artifact_refs = unique_strings(vec![format!(
        "artifact://runtime.workspace_snapshot/{safe_snapshot_id}"
    )]);
    let restore_status = if capture.content_captured {
        "content_captured"
    } else {
        "content_partial"
    };
    json!({
        "schema_version": WORKSPACE_SNAPSHOT_RECORD_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "snapshot_hash": snapshot_hash,
        "snapshot_kind": "pre_post_touched_files",
        "file_count": capture.files.len() as u64,
        "changed_file_count": changed_file_count,
        "created_file_count": created_file_count,
        "deleted_file_count": deleted_file_count,
        "restore": {
            "status": restore_status,
            "preview_supported": true,
            "apply_supported": true,
        },
        "trigger": {
            "thread_id": thread_id,
            "turn_id": turn_id,
            "workspace_root": workspace_root,
            "tool_call_id": tool_call_id,
            "workflow_graph_id": workflow_graph_id,
            "workflow_node_id": workflow_node_id,
        },
        "files": capture.files,
        "content_files": capture.content_files,
        "receipt_refs": receipt_refs,
        "artifact_refs": artifact_refs,
        "summary": format!(
            "Captured {} workspace snapshot file(s); {} file content payload(s) captured, {} omitted.",
            capture.files.len(),
            capture.captured_file_count,
            capture.omitted_file_count
        ),
    })
}

fn workspace_snapshot_capture_artifact(
    request: &WorkspaceSnapshotCaptureProtocolRequest,
    snapshot_record: &Value,
) -> Value {
    let thread_id = trim_optional_string(request.thread_id.as_deref());
    let turn_id = trim_optional_string(request.turn_id.as_deref());
    let workspace_root = trim_optional_string(request.workspace_root.as_deref());
    let tool_call_id = trim_optional_string(request.tool_call_id.as_deref());
    let workflow_graph_id = trim_optional_string(request.workflow_graph_id.as_deref());
    let workflow_node_id = trim_optional_string(request.workflow_node_id.as_deref());
    let snapshot_id = snapshot_record
        .get("snapshot_id")
        .and_then(Value::as_str)
        .unwrap_or("workspace_snapshot_unknown");
    let snapshot_hash = snapshot_record
        .get("snapshot_hash")
        .and_then(Value::as_str)
        .unwrap_or("sha256:unknown");
    let artifact_refs = string_array_from_value(snapshot_record.get("artifact_refs"));
    let artifact_id = artifact_refs.first().cloned().unwrap_or_else(|| {
        format!(
            "artifact://runtime.workspace_snapshot/{}",
            safe_id(snapshot_id)
        )
    });
    let receipt_refs = string_array_from_value(snapshot_record.get("receipt_refs"));
    let receipt_id = receipt_refs.first().cloned().unwrap_or_else(|| {
        format!(
            "receipt://runtime.workspace_snapshot/{}",
            safe_id(snapshot_id)
        )
    });
    let content = snapshot_record.clone();
    let content_text = serde_json::to_string(&content).unwrap_or_else(|_| "{}".to_string());
    json!({
        "schema_version": WORKSPACE_SNAPSHOT_ARTIFACT_SCHEMA_VERSION,
        "id": artifact_id,
        "artifact_id": artifact_id,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "tool_name": "workspace.snapshot_capture",
        "tool_call_id": tool_call_id,
        "workspace_root": workspace_root,
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
        "channel": "workspace-snapshot",
        "name": format!("{snapshot_id}.json"),
        "media_type": "application/json",
        "redaction": "workspace_snapshot",
        "snapshot_id": snapshot_id,
        "snapshot_hash": snapshot_hash,
        "snapshot_kind": snapshot_record.get("snapshot_kind").cloned().unwrap_or(Value::Null),
        "receipt_id": receipt_id,
        "receipt_refs": receipt_refs,
        "artifact_refs": artifact_refs,
        "content": content,
        "content_bytes": content_text.as_bytes().len() as u64,
        "content_hash": format!("sha256:{}", sha256_hex(&content_text)),
        "evidence_refs": workspace_snapshot_capture_artifact_evidence_refs(),
    })
}

fn workspace_snapshot_capture_event(
    request: &WorkspaceSnapshotCaptureProtocolRequest,
    snapshot_record: &Value,
    snapshot_artifact: &Value,
) -> Value {
    let thread_id = trim_optional_string(request.thread_id.as_deref());
    let turn_id = trim_optional_string(request.turn_id.as_deref());
    let workspace_root = trim_optional_string(request.workspace_root.as_deref());
    let tool_call_id = trim_optional_string(request.tool_call_id.as_deref());
    let workflow_graph_id = trim_optional_string(request.workflow_graph_id.as_deref());
    let workflow_node_id = trim_optional_string(request.workflow_node_id.as_deref());
    let snapshot_id = snapshot_record
        .get("snapshot_id")
        .and_then(Value::as_str)
        .unwrap_or("workspace_snapshot_unknown");
    let snapshot_hash = snapshot_record
        .get("snapshot_hash")
        .and_then(Value::as_str)
        .unwrap_or("sha256:unknown");
    let event_seed = json!({
        "schema_version": WORKSPACE_SNAPSHOT_EVENT_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "snapshot_hash": snapshot_hash,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "tool_call_id": tool_call_id,
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
    });
    let event_hash =
        sha256_hex(&serde_json::to_string(&event_seed).unwrap_or_else(|_| snapshot_id.to_string()));
    let event_id = format!(
        "event_workspace_snapshot_{}",
        event_hash.chars().take(24).collect::<String>()
    );
    let payload_summary = json!({
        "schema_version": WORKSPACE_SNAPSHOT_RECORD_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "snapshot_hash": snapshot_hash,
        "snapshot_kind": snapshot_record.get("snapshot_kind").cloned().unwrap_or(Value::Null),
        "file_count": snapshot_record.get("file_count").cloned().unwrap_or(Value::Null),
        "changed_file_count": snapshot_record.get("changed_file_count").cloned().unwrap_or(Value::Null),
        "created_file_count": snapshot_record.get("created_file_count").cloned().unwrap_or(Value::Null),
        "deleted_file_count": snapshot_record.get("deleted_file_count").cloned().unwrap_or(Value::Null),
        "restore": snapshot_record.get("restore").cloned().unwrap_or(Value::Null),
        "trigger": snapshot_record.get("trigger").cloned().unwrap_or(Value::Null),
        "summary": snapshot_record.get("summary").cloned().unwrap_or(Value::Null),
        "receipt_refs": snapshot_record.get("receipt_refs").cloned().unwrap_or(json!([])),
        "artifact_refs": snapshot_record.get("artifact_refs").cloned().unwrap_or(json!([])),
    });
    let idempotency_key = format!(
        "workspace_snapshot:capture:{}:{}",
        safe_id(snapshot_id),
        tool_call_id
            .as_deref()
            .map(safe_id)
            .unwrap_or_else(|| "no_tool_call".to_string())
    );
    let payload_hash = json_value_hash(&payload_summary);
    json!({
        "schema_version": WORKSPACE_SNAPSHOT_EVENT_SCHEMA_VERSION,
        "event_id": event_id,
        "event_stream_id": thread_id
            .as_ref()
            .map(|thread_id| format!("{thread_id}:events"))
            .unwrap_or_else(|| format!("{snapshot_id}:events")),
        "event_kind": "workspace_snapshot.captured",
        "status": "completed",
        "actor": "runtime",
        "component_kind": "workspace_snapshot",
        "item_id": format!(
            "thread:{}:workspace_snapshot:{}",
            thread_id.as_deref().map(safe_id).unwrap_or_else(|| "unknown_thread".to_string()),
            safe_id(snapshot_id)
        ),
        "idempotency_key": idempotency_key,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "workspace_root": workspace_root,
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
        "tool_call_id": tool_call_id,
        "snapshot_id": snapshot_id,
        "artifact_refs": snapshot_record.get("artifact_refs").cloned().unwrap_or(json!([])),
        "receipt_refs": snapshot_record.get("receipt_refs").cloned().unwrap_or(json!([])),
        "payload_schema_version": WORKSPACE_SNAPSHOT_RECORD_SCHEMA_VERSION,
        "payload_hash": payload_hash,
        "payload_summary": payload_summary,
        "snapshot_artifact": snapshot_artifact,
        "evidence_refs": workspace_snapshot_capture_event_evidence_refs(),
    })
}

fn validate_workspace_snapshot_list_request(
    request: &WorkspaceSnapshotListRequest,
) -> Result<(), WorkspaceRestoreProtocolError> {
    if request.schema_version != WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION {
        return Err(WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_list_invalid",
            format!(
                "workspace snapshot list schema is invalid: expected {}, received {}",
                WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.thread_id.trim().is_empty() {
        return Err(WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_list_invalid",
            "workspace snapshot list requires thread_id".to_string(),
        ));
    }
    Ok(())
}

fn validate_workspace_snapshot_content_package_request(
    request: &WorkspaceSnapshotContentPackageRequest,
) -> Result<(), WorkspaceRestoreProtocolError> {
    if request.schema_version != WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION {
        return Err(WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_content_package_invalid",
            format!(
                "workspace snapshot content package schema is invalid: expected {}, received {}",
                WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION, request.schema_version
            ),
        ));
    }
    if request.thread_id.trim().is_empty() || request.snapshot_id.trim().is_empty() {
        return Err(WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_content_package_invalid",
            "workspace snapshot content package requires thread_id and snapshot_id".to_string(),
        ));
    }
    Ok(())
}

fn validate_workspace_snapshot_restore_request(
    request: &WorkspaceSnapshotRestoreRequest,
    expected_schema: &'static str,
) -> Result<(), WorkspaceRestoreProtocolError> {
    if request.schema_version != expected_schema {
        return Err(WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_restore_invalid",
            format!(
                "workspace snapshot restore schema is invalid: expected {}, received {}",
                expected_schema, request.schema_version
            ),
        ));
    }
    if request.thread_id.trim().is_empty()
        || request.snapshot_id.trim().is_empty()
        || request.workspace_root.trim().is_empty()
    {
        return Err(WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_restore_invalid",
            "workspace snapshot restore requires thread_id, snapshot_id, and workspace_root"
                .to_string(),
        ));
    }
    Ok(())
}

fn workspace_snapshot_list_projection(request: &WorkspaceSnapshotListRequest) -> Value {
    let snapshots = request
        .snapshots
        .iter()
        .filter_map(normalize_workspace_snapshot_projection_record)
        .collect::<Vec<_>>();
    json!({
        "schema_version": WORKSPACE_SNAPSHOT_LIST_RESULT_SCHEMA_VERSION,
        "object": "ioi.runtime_workspace_snapshot_list",
        "thread_id": request.thread_id.trim(),
        "snapshot_count": snapshots.len() as u64,
        "snapshots": snapshots,
        "evidence_refs": workspace_snapshot_projection_evidence_refs(),
    })
}

fn workspace_snapshot_content_package_projection(
    request: &WorkspaceSnapshotContentPackageRequest,
) -> Result<Value, WorkspaceRestoreProtocolError> {
    let content_package = request.content_package.as_ref().ok_or_else(|| {
        WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_content_package_required",
            format!(
                "workspace snapshot {} requires Rust-owned content package projection input",
                request.snapshot_id
            ),
        )
    })?;
    let content_files = workspace_snapshot_content_files_from_package(content_package)?;
    let snapshot_record = request
        .snapshot_record
        .as_ref()
        .and_then(normalize_workspace_snapshot_projection_record)
        .unwrap_or_else(|| {
            json!({
                "schema_version": WORKSPACE_SNAPSHOT_RECORD_SCHEMA_VERSION,
                "snapshot_id": request.snapshot_id.trim(),
                "restore": {
                    "status": "content_captured",
                    "preview_supported": true,
                    "apply_supported": true,
                },
                "receipt_refs": [],
                "artifact_refs": [],
            })
        });
    let receipt_refs = unique_strings(
        [
            string_array_from_value(snapshot_record.get("receipt_refs")),
            string_array_from_value(content_package.get("receipt_refs")),
        ]
        .concat(),
    );
    let artifact_refs = unique_strings(
        [
            string_array_from_value(snapshot_record.get("artifact_refs")),
            string_array_from_value(content_package.get("artifact_refs")),
        ]
        .concat(),
    );
    let file_count = content_files.len() as u64;
    let restore = content_package
        .get("restore")
        .cloned()
        .or_else(|| snapshot_record.get("restore").cloned())
        .unwrap_or(Value::Null);
    Ok(json!({
        "schema_version": WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_SCHEMA_VERSION,
        "object": "ioi.runtime_workspace_snapshot_content_package",
        "thread_id": request.thread_id.trim(),
        "snapshot_id": request.snapshot_id.trim(),
        "snapshot": snapshot_record,
        "content_files": content_files,
        "file_count": file_count,
        "receipt_refs": receipt_refs,
        "artifact_refs": artifact_refs,
        "restore": restore,
        "evidence_refs": workspace_snapshot_projection_evidence_refs(),
    }))
}

fn normalize_workspace_snapshot_projection_record(value: &Value) -> Option<Value> {
    let snapshot_id = value
        .get("snapshot_id")
        .and_then(Value::as_str)
        .and_then(|value| trim_optional_string(Some(value)))?;
    Some(json!({
        "schema_version": value
            .get("schema_version")
            .and_then(Value::as_str)
            .unwrap_or(WORKSPACE_SNAPSHOT_RECORD_SCHEMA_VERSION),
        "snapshot_id": snapshot_id,
        "snapshot_hash": value.get("snapshot_hash").cloned().unwrap_or(Value::Null),
        "snapshot_kind": value.get("snapshot_kind").cloned().unwrap_or(Value::Null),
        "file_count": value.get("file_count").cloned().unwrap_or(json!(0)),
        "changed_file_count": value.get("changed_file_count").cloned().unwrap_or(json!(0)),
        "created_file_count": value.get("created_file_count").cloned().unwrap_or(json!(0)),
        "deleted_file_count": value.get("deleted_file_count").cloned().unwrap_or(json!(0)),
        "restore": value.get("restore").cloned().unwrap_or(Value::Null),
        "trigger": value.get("trigger").cloned().unwrap_or(Value::Null),
        "files": value.get("files").cloned().unwrap_or(json!([])),
        "content_files": value.get("content_files").cloned().unwrap_or(json!([])),
        "receipt_refs": string_array_from_value(value.get("receipt_refs")),
        "artifact_refs": string_array_from_value(value.get("artifact_refs")),
        "summary": value.get("summary").cloned().unwrap_or(Value::Null),
    }))
}

fn workspace_restore_files_from_content_package(
    content_package: Option<&Value>,
    snapshot_id: &str,
) -> Result<Vec<WorkspaceRestoreFile>, WorkspaceRestoreProtocolError> {
    let content_package = content_package.ok_or_else(|| {
        WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_content_package_required",
            format!(
                "workspace restore for {snapshot_id} requires Rust-owned content package projection input"
            ),
        )
    })?;
    let content_files = workspace_snapshot_content_files_from_package(content_package)?;
    if content_files.is_empty() {
        return Err(WorkspaceRestoreProtocolError::new(
            "workspace_snapshot_content_package_empty",
            format!("workspace snapshot {snapshot_id} has no content files to restore"),
        ));
    }
    Ok(content_files
        .into_iter()
        .map(|file| WorkspaceRestoreFile {
            path: file.path,
            before: WorkspaceRestoreFileSide {
                exists: file.before.exists,
                content_hash: file.before.content_hash,
                content: file.before.content,
            },
            after: WorkspaceRestoreFileSide {
                exists: file.after.exists,
                content_hash: file.after.content_hash,
                content: None,
            },
        })
        .collect())
}

fn workspace_snapshot_content_files_from_package(
    content_package: &Value,
) -> Result<Vec<WorkspaceSnapshotCapturedFile>, WorkspaceRestoreProtocolError> {
    let files_value = content_package
        .get("content_files")
        .or_else(|| content_package.get("files"))
        .cloned()
        .unwrap_or_else(|| json!([]));
    let files: Vec<WorkspaceSnapshotCapturedFile> =
        serde_json::from_value(files_value).map_err(|error| {
            WorkspaceRestoreProtocolError::new(
                "workspace_snapshot_content_package_invalid",
                format!("workspace snapshot content package files are invalid: {error}"),
            )
        })?;
    Ok(files)
}

fn workspace_restore_preview_result(
    request: &WorkspaceSnapshotRestoreRequest,
    operations: &[WorkspaceRestoreOperationRecord],
) -> Value {
    let counts = workspace_restore_operation_counts(operations);
    let preview_status = workspace_restore_preview_status(&counts);
    let mut result = json!({
        "schema_version": WORKSPACE_RESTORE_PREVIEW_RESULT_SCHEMA_VERSION,
        "object": "ioi.runtime_workspace_restore_preview",
        "thread_id": request.thread_id.trim(),
        "snapshot_id": request.snapshot_id.trim(),
        "preview_status": preview_status,
        "preview_supported": true,
        "apply_supported": true,
        "file_count": counts.file_count,
        "ready_count": counts.ready_count,
        "noop_count": counts.noop_count,
        "conflict_count": counts.conflict_count,
        "blocked_count": counts.blocked_count,
        "operations": operations,
        "receipt_refs": workspace_restore_receipt_refs("preview", &request.snapshot_id),
        "artifact_refs": workspace_restore_artifact_refs("preview", &request.snapshot_id),
        "rollback_refs": vec![request.snapshot_id.trim().to_string()],
        "summary": workspace_restore_preview_summary(&request.snapshot_id, &preview_status, &counts),
        "evidence_refs": workspace_snapshot_restore_evidence_refs(),
    });
    let artifact = workspace_restore_artifact_record("preview", request, &result);
    let event = workspace_restore_event_record("preview", request, &result, &artifact);
    if let Some(object) = result.as_object_mut() {
        object.insert("restore_preview_artifact".to_string(), artifact);
        object.insert("restore_preview_event".to_string(), event);
    }
    result
}

fn workspace_restore_apply_result(
    request: &WorkspaceSnapshotRestoreRequest,
    preview_status: &str,
    operations: &[WorkspaceRestoreOperationRecord],
    policy: &WorkspaceRestoreApplyPolicyPlan,
) -> Value {
    let counts = workspace_restore_operation_counts(operations);
    let apply_status = workspace_restore_apply_status(&counts);
    let mut result = json!({
        "schema_version": WORKSPACE_RESTORE_APPLY_RESULT_SCHEMA_VERSION,
        "object": "ioi.runtime_workspace_restore_apply",
        "thread_id": request.thread_id.trim(),
        "snapshot_id": request.snapshot_id.trim(),
        "preview_status": preview_status,
        "apply_status": apply_status,
        "apply_supported": true,
        "approval_required": policy.approval.required,
        "approval_satisfied": policy.approval.satisfied,
        "file_count": counts.file_count,
        "applied_count": counts.applied_count,
        "apply_noop_count": counts.apply_noop_count,
        "apply_blocked_count": counts.apply_blocked_count,
        "failed_count": counts.failed_count,
        "operations": operations,
        "policy_decision_refs": policy.policy_decision_refs.clone(),
        "receipt_refs": workspace_restore_receipt_refs("apply", &request.snapshot_id),
        "artifact_refs": workspace_restore_artifact_refs("apply", &request.snapshot_id),
        "rollback_refs": vec![request.snapshot_id.trim().to_string()],
        "summary": policy.summary.clone().unwrap_or_else(|| {
            apply_summary(
                &request.snapshot_id,
                &apply_status,
                &counts,
                &policy.approval,
                policy.allow_conflicts,
            )
        }),
        "evidence_refs": workspace_snapshot_restore_evidence_refs(),
    });
    let artifact = workspace_restore_artifact_record("apply", request, &result);
    let event = workspace_restore_event_record("apply", request, &result, &artifact);
    if let Some(object) = result.as_object_mut() {
        object.insert("restore_apply_artifact".to_string(), artifact);
        object.insert("restore_apply_event".to_string(), event);
    }
    result
}

fn workspace_restore_apply_policy_request_from_restore(
    request: &WorkspaceSnapshotRestoreRequest,
    operations: &[WorkspaceRestoreOperationRecord],
    counts: WorkspaceRestoreApplyCounts,
    apply_status: &str,
) -> WorkspaceRestoreApplyPolicyRequest {
    WorkspaceRestoreApplyPolicyRequest {
        schema_version: WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION.to_string(),
        snapshot_id: request.snapshot_id.clone(),
        approval: request.approval.clone(),
        approval_decision: request.approval_decision.clone(),
        policy_decision: request.policy_decision.clone(),
        decision: request.decision.clone(),
        status: request.status.clone(),
        confirm: request.confirm.clone(),
        confirmed: request.confirmed.clone(),
        confirm_restore_apply: request.confirm_restore_apply.clone(),
        apply_confirmed: request.apply_confirmed.clone(),
        approval_granted: request.approval_granted.clone(),
        approved: request.approved.clone(),
        restore_conflict_policy: request.restore_conflict_policy.clone(),
        conflict_policy: request.conflict_policy.clone(),
        restore_policy: request.restore_policy.clone(),
        allow_conflicts: request.allow_conflicts.clone(),
        override_conflicts: request.override_conflicts.clone(),
        operations: operations
            .iter()
            .map(|operation| WorkspaceRestoreOperationPolicyInput {
                path: operation.path.clone(),
                status: operation.status.clone(),
                blocked_reason: operation.blocked_reason.clone(),
            })
            .collect(),
        counts: Some(counts),
        hard_blocked: None,
        conflict_blocked: None,
        apply_status: Some(apply_status.to_string()),
    }
}

fn workspace_restore_policy_blocked_operations(
    operations: &[WorkspaceRestoreOperationRecord],
    policy: &WorkspaceRestoreApplyPolicyPlan,
) -> Vec<WorkspaceRestoreOperationRecord> {
    operations
        .iter()
        .map(|operation| {
            let mut blocked = operation.clone();
            blocked.apply_status = Some("blocked".to_string());
            blocked.apply_reason = policy
                .operation_policies
                .iter()
                .find(|entry| entry.path == operation.path)
                .map(|entry| entry.apply_reason.clone())
                .or_else(|| operation.blocked_reason.clone())
                .or_else(|| Some("workspace_restore_apply_blocked_by_policy".to_string()));
            blocked
        })
        .collect()
}

fn workspace_restore_operation_counts(
    operations: &[WorkspaceRestoreOperationRecord],
) -> WorkspaceRestoreApplyCounts {
    let mut counts = WorkspaceRestoreApplyCounts {
        file_count: operations.len() as u64,
        ..Default::default()
    };
    for operation in operations {
        match operation.status.as_str() {
            "ready" => counts.ready_count += 1,
            "noop" => counts.noop_count += 1,
            "conflict" => counts.conflict_count += 1,
            "blocked" => counts.blocked_count += 1,
            _ => {}
        }
        match operation.apply_status.as_deref() {
            Some("applied") | Some("applied_with_override") => counts.applied_count += 1,
            Some("noop") => counts.apply_noop_count += 1,
            Some("blocked") => counts.apply_blocked_count += 1,
            Some("failed") => counts.failed_count += 1,
            _ => {}
        }
    }
    counts
}

fn workspace_restore_preview_status(counts: &WorkspaceRestoreApplyCounts) -> String {
    if counts.blocked_count > 0 {
        "blocked".to_string()
    } else if counts.conflict_count > 0 {
        "conflict".to_string()
    } else if counts.file_count > 0 && counts.noop_count == counts.file_count {
        "noop".to_string()
    } else {
        "ready".to_string()
    }
}

fn workspace_restore_apply_status(counts: &WorkspaceRestoreApplyCounts) -> String {
    if counts.failed_count > 0 {
        "failed".to_string()
    } else if counts.apply_blocked_count > 0 {
        "blocked".to_string()
    } else if counts.file_count > 0 && counts.apply_noop_count == counts.file_count {
        "noop".to_string()
    } else {
        "applied".to_string()
    }
}

fn workspace_restore_preview_summary(
    snapshot_id: &str,
    preview_status: &str,
    counts: &WorkspaceRestoreApplyCounts,
) -> String {
    match preview_status {
        "blocked" => format!(
            "Restore preview blocked for {snapshot_id}: {} blocked file(s).",
            counts.blocked_count
        ),
        "conflict" => format!(
            "Restore preview found {} conflict(s) for {snapshot_id}.",
            counts.conflict_count
        ),
        "noop" => format!(
            "Restore preview found {} file(s) already restored for {snapshot_id}.",
            counts.file_count
        ),
        _ => format!(
            "Restore preview ready for {} file(s) from {snapshot_id}.",
            counts.ready_count
        ),
    }
}

fn workspace_restore_receipt_refs(kind: &str, snapshot_id: &str) -> Vec<String> {
    vec![format!(
        "receipt://runtime.workspace_restore/{kind}/{}",
        safe_id(snapshot_id)
    )]
}

fn workspace_restore_artifact_refs(kind: &str, snapshot_id: &str) -> Vec<String> {
    vec![format!(
        "artifact://runtime.workspace_restore/{kind}/{}",
        safe_id(snapshot_id)
    )]
}

fn workspace_restore_artifact_record(
    kind: &str,
    request: &WorkspaceSnapshotRestoreRequest,
    value: &Value,
) -> Value {
    let artifact_refs = string_array_from_value(value.get("artifact_refs"));
    let artifact_id = artifact_refs.first().cloned().unwrap_or_else(|| {
        format!(
            "artifact://runtime.workspace_restore/{kind}/{}",
            safe_id(&request.snapshot_id)
        )
    });
    let receipt_refs = string_array_from_value(value.get("receipt_refs"));
    let receipt_id = receipt_refs.first().cloned().unwrap_or_else(|| {
        format!(
            "receipt://runtime.workspace_restore/{kind}/{}",
            safe_id(&request.snapshot_id)
        )
    });
    let content =
        serde_json::to_string(value).unwrap_or_else(|_| "{\"error\":\"hash_failed\"}".to_string());
    let channel = format!("restore-{kind}");
    json!({
        "schema_version": WORKSPACE_RESTORE_ARTIFACT_SCHEMA_VERSION,
        "id": artifact_id,
        "artifact_id": artifact_id,
        "thread_id": request.thread_id.trim(),
        "tool_name": format!("workspace.restore_{kind}"),
        "channel": channel,
        "name": format!("workspace-restore-{kind}.json"),
        "media_type": "application/json",
        "redaction": format!("workspace_restore_{kind}"),
        "snapshot_id": request.snapshot_id.trim(),
        "workflow_graph_id": trim_optional_string(request.workflow_graph_id.as_deref()),
        "workflow_node_id": trim_optional_string(request.workflow_node_id.as_deref()),
        "receipt_id": receipt_id,
        "receipt_refs": receipt_refs,
        "artifact_refs": artifact_refs,
        "rollback_refs": string_array_from_value(value.get("rollback_refs")),
        "content": value,
        "content_bytes": content.as_bytes().len() as u64,
        "content_hash": json_value_hash(value),
        "evidence_refs": workspace_snapshot_restore_artifact_evidence_refs(),
    })
}

fn workspace_restore_event_record(
    kind: &str,
    request: &WorkspaceSnapshotRestoreRequest,
    value: &Value,
    artifact: &Value,
) -> Value {
    let status_field = if kind == "apply" {
        "apply_status"
    } else {
        "preview_status"
    };
    let status = value
        .get(status_field)
        .and_then(Value::as_str)
        .unwrap_or("planned");
    let idempotency_key = trim_optional_string(request.idempotency_key.as_deref())
        .unwrap_or_else(|| format!("workspace_restore:{kind}:{}", safe_id(&request.snapshot_id)));
    let receipt_refs = string_array_from_value(value.get("receipt_refs"));
    let artifact_refs = string_array_from_value(value.get("artifact_refs"));
    let rollback_refs = string_array_from_value(value.get("rollback_refs"));
    let payload_summary = workspace_restore_event_payload_summary(kind, value);
    let payload_hash = json_value_hash(&payload_summary);
    let event_id = format!(
        "event_workspace_restore_{}_{}",
        kind,
        safe_id(&format!("{}:{idempotency_key}", request.snapshot_id))
    );
    json!({
        "schema_version": WORKSPACE_RESTORE_EVENT_SCHEMA_VERSION,
        "event_id": event_id,
        "event_stream_id": format!("{}:events", request.thread_id.trim()),
        "thread_id": request.thread_id.trim(),
        "turn_id": Value::Null,
        "item_id": format!(
            "thread:{}:workspace_restore:{kind}:{}",
            safe_id(&request.thread_id),
            safe_id(&request.snapshot_id)
        ),
        "event_kind": format!("workspace_restore.{kind}"),
        "status": status,
        "actor": "daemon",
        "component_kind": "workspace_restore",
        "workflow_graph_id": trim_optional_string(request.workflow_graph_id.as_deref()),
        "workflow_node_id": trim_optional_string(request.workflow_node_id.as_deref()),
        "snapshot_id": request.snapshot_id.trim(),
        "idempotency_key": idempotency_key,
        "receipt_refs": receipt_refs,
        "artifact_refs": artifact_refs,
        "rollback_refs": rollback_refs,
        "payload_schema_version": value.get("schema_version").cloned().unwrap_or(Value::Null),
        "payload_hash": payload_hash,
        "payload_summary": payload_summary,
        "restore_artifact": artifact,
        "evidence_refs": workspace_snapshot_restore_event_evidence_refs(),
    })
}

fn workspace_restore_event_payload_summary(kind: &str, value: &Value) -> Value {
    let mut summary = serde_json::Map::new();
    summary.insert(
        "operation_kind".to_string(),
        json!(format!("workspace_restore.{kind}")),
    );
    for field in [
        "thread_id",
        "snapshot_id",
        "preview_status",
        "apply_status",
        "file_count",
        "ready_count",
        "noop_count",
        "conflict_count",
        "blocked_count",
        "applied_count",
        "apply_noop_count",
        "apply_blocked_count",
        "failed_count",
        "receipt_refs",
        "artifact_refs",
        "rollback_refs",
        "policy_decision_refs",
        "summary",
    ] {
        if let Some(field_value) = value.get(field) {
            summary.insert(field.to_string(), field_value.clone());
        }
    }
    Value::Object(summary)
}

fn workspace_snapshot_restore_artifact_evidence_refs() -> Vec<&'static str> {
    vec![
        "rust_daemon_core_workspace_restore_artifact",
        "agentgres_workspace_restore_artifact_truth",
        "workspace_restore_artifact_js_materializer_retired",
    ]
}

fn workspace_snapshot_restore_event_evidence_refs() -> Vec<&'static str> {
    vec![
        "rust_daemon_core_workspace_restore_event",
        "agentgres_workspace_restore_event_truth",
        "workspace_restore_event_js_append_retired",
    ]
}

fn workspace_snapshot_capture_artifact_evidence_refs() -> Vec<&'static str> {
    vec![
        "rust_daemon_core_workspace_snapshot_artifact",
        "agentgres_workspace_snapshot_artifact_truth",
        "workspace_snapshot_artifact_js_materializer_retired",
    ]
}

fn workspace_snapshot_capture_event_evidence_refs() -> Vec<&'static str> {
    vec![
        "rust_daemon_core_workspace_snapshot_event",
        "agentgres_workspace_snapshot_event_truth",
        "workspace_snapshot_event_js_append_retired",
    ]
}

fn workspace_snapshot_projection_evidence_refs() -> Vec<&'static str> {
    vec![
        "rust_daemon_core_workspace_snapshot_projection",
        "agentgres_workspace_snapshot_projection_truth",
        "workspace_snapshot_js_projection_retired",
    ]
}

fn workspace_snapshot_restore_evidence_refs() -> Vec<&'static str> {
    vec![
        "rust_daemon_core_workspace_restore_api",
        "agentgres_workspace_restore_truth",
        "workspace_restore_js_facade_retired",
    ]
}

fn string_array_from_value(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|value| trim_optional_string(Some(value)))
                .collect()
        })
        .unwrap_or_default()
}

fn normalize_apply_status(status: &str) -> Option<String> {
    let normalized = status.trim().to_ascii_lowercase();
    if ["blocked", "failed", "noop", "applied"].contains(&normalized.as_str()) {
        Some(normalized)
    } else {
        None
    }
}

fn json_value_is_true(value: &Option<Value>) -> bool {
    match value {
        Some(Value::Bool(true)) => true,
        Some(Value::String(text)) => text.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn trim_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn first_non_empty<'a, I>(values: I) -> Option<&'a str>
where
    I: IntoIterator<Item = Option<&'a str>>,
{
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn json_value_hash(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if !value.is_empty() && !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::fs;
    use std::path::PathBuf;

    fn temp_workspace(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ioi-workspace-restore-kernel-test-{}-{}",
            name,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).expect("workspace dir");
        path
    }

    fn restore_file(path: &str, before: &str, after: &str) -> WorkspaceRestoreFile {
        WorkspaceRestoreFile {
            path: path.to_string(),
            before: WorkspaceRestoreFileSide {
                exists: true,
                content_hash: Some(sha256_hex(before)),
                content: Some(before.to_string()),
            },
            after: WorkspaceRestoreFileSide {
                exists: true,
                content_hash: Some(sha256_hex(after)),
                content: None,
            },
        }
    }

    #[test]
    fn workspace_snapshot_capture_records_public_and_content_files_from_rust_core() {
        let request = WorkspaceSnapshotCaptureRequest {
            schema_version: WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION.to_string(),
            changed_files: vec![WorkspaceSnapshotChangedFile {
                path: "src/app.js".to_string(),
                created: false,
                before_hash: Some(sha256_hex("old")),
                after_hash: Some(sha256_hex("new")),
                before_exists: true,
                after_exists: Some(true),
                before_size_bytes: Some(3),
                after_size_bytes: Some(3),
                before_mtime_ms: None,
                after_mtime_ms: None,
            }],
            content_drafts: vec![WorkspaceSnapshotContentDraft {
                path: "src/app.js".to_string(),
                before_content: Some("old".to_string()),
                after_content: Some("new".to_string()),
                encoding: None,
            }],
            max_content_bytes: Some(WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES),
        };

        let capture = WorkspaceSnapshotCaptureCore
            .capture_files(&request)
            .expect("snapshot capture");

        assert_eq!(capture.files.len(), 1);
        assert_eq!(capture.captured_file_count, 1);
        assert_eq!(capture.omitted_file_count, 0);
        assert_eq!(capture.files[0].path, "src/app.js");
        assert_eq!(capture.files[0].before.content, None);
        assert_eq!(
            capture.content_files[0].before.content.as_deref(),
            Some("old")
        );
        assert!(capture.content_captured);
    }

    #[test]
    fn rust_core_shapes_workspace_snapshot_capture_protocol_response() {
        let old_hash = sha256_hex("old");
        let new_hash = sha256_hex("new");
        let response = capture_workspace_snapshot_files_protocol_response(
            WorkspaceSnapshotCaptureProtocolRequest {
                thread_id: Some("thread_alpha".to_string()),
                turn_id: Some("turn_alpha".to_string()),
                workspace_root: Some("/workspace".to_string()),
                tool_call_id: Some("tool_call_alpha".to_string()),
                workflow_graph_id: Some("graph_alpha".to_string()),
                workflow_node_id: Some("node_alpha".to_string()),
                request: WorkspaceSnapshotCaptureRequest {
                    schema_version: WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION.to_string(),
                    max_content_bytes: Some(WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES),
                    changed_files: vec![WorkspaceSnapshotChangedFile {
                        path: "src/app.js".to_string(),
                        created: false,
                        before_hash: Some(old_hash),
                        after_hash: Some(new_hash),
                        before_exists: true,
                        after_exists: Some(true),
                        before_size_bytes: Some(3),
                        after_size_bytes: Some(3),
                        before_mtime_ms: None,
                        after_mtime_ms: None,
                    }],
                    content_drafts: vec![WorkspaceSnapshotContentDraft {
                        path: "src/app.js".to_string(),
                        before_content: Some("old".to_string()),
                        after_content: Some("new".to_string()),
                        encoding: None,
                    }],
                },
            },
        )
        .expect("workspace snapshot capture protocol response");

        assert_eq!(
            response["source"],
            "rust_workspace_snapshot_capture_protocol"
        );
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["captured_file_count"], 1);
        assert_eq!(response["omitted_file_count"], 0);
        assert_eq!(response["files"][0]["path"], "src/app.js");
        assert_eq!(response["files"][0]["before"]["content"], Value::Null);
        assert_eq!(response["content_files"][0]["before"]["content"], "old");
        assert_eq!(
            response["snapshot_record"]["schema_version"],
            WORKSPACE_SNAPSHOT_RECORD_SCHEMA_VERSION
        );
        assert_eq!(
            response["snapshot_record"]["snapshot_kind"],
            "pre_post_touched_files"
        );
        assert_eq!(response["snapshot_record"]["file_count"], 1);
        assert_eq!(response["snapshot_record"]["changed_file_count"], 1);
        assert_eq!(
            response["snapshot_record"]["trigger"]["tool_call_id"],
            "tool_call_alpha"
        );
        assert_eq!(
            response["snapshot_record"]["restore"]["status"],
            "content_captured"
        );
        assert_eq!(
            response["snapshot_artifact"]["schema_version"],
            WORKSPACE_SNAPSHOT_ARTIFACT_SCHEMA_VERSION
        );
        assert_eq!(
            response["snapshot_artifact"]["id"],
            response["snapshot_record"]["artifact_refs"][0]
        );
        assert_eq!(
            response["snapshot_artifact"]["receipt_refs"],
            response["snapshot_record"]["receipt_refs"]
        );
        assert_eq!(
            response["snapshot_event"]["schema_version"],
            WORKSPACE_SNAPSHOT_EVENT_SCHEMA_VERSION
        );
        assert_eq!(
            response["snapshot_event"]["event_kind"],
            "workspace_snapshot.captured"
        );
        assert_eq!(response["snapshot_event"]["thread_id"], "thread_alpha");
        assert_eq!(
            response["snapshot_event"]["idempotency_key"],
            format!(
                "workspace_snapshot:capture:{}:tool_call_alpha",
                safe_id(
                    response["snapshot_record"]["snapshot_id"]
                        .as_str()
                        .expect("snapshot id")
                )
            )
        );
        assert_eq!(
            response["snapshot_event"]["snapshot_id"],
            response["snapshot_record"]["snapshot_id"]
        );
        assert_eq!(
            response["snapshot_event"]["receipt_refs"],
            response["snapshot_record"]["receipt_refs"]
        );
        assert_eq!(
            response["snapshot_event"]["artifact_refs"],
            response["snapshot_record"]["artifact_refs"]
        );
        assert_eq!(
            response["snapshot_event"]["payload_summary"]["snapshot_id"],
            response["snapshot_record"]["snapshot_id"]
        );
        assert_eq!(
            response["snapshot_event"]["snapshot_artifact"]["id"],
            response["snapshot_artifact"]["id"]
        );
    }

    #[test]
    fn workspace_restore_operations_preview_ready_file_from_rust_core() {
        let workspace = temp_workspace("preview");
        let file_path = workspace.join("src/app.js");
        fs::create_dir_all(file_path.parent().expect("parent")).expect("mkdir");
        fs::write(&file_path, "new").expect("write current");
        let request = WorkspaceRestoreOperationsRequest {
            schema_version: WORKSPACE_RESTORE_PREVIEW_OPERATIONS_REQUEST_SCHEMA_VERSION.to_string(),
            workspace_root: workspace.to_string_lossy().to_string(),
            files: vec![restore_file("src/app.js", "old", "new")],
            max_diff_bytes: Some(4096),
            allow_conflicts: None,
        };

        let operations = WorkspaceRestoreOperationsCore
            .preview_operations(&request)
            .expect("preview operations");

        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].path, "src/app.js");
        assert_eq!(operations[0].operation, "replace");
        assert_eq!(operations[0].status, "ready");
        assert!(operations[0].current_matches_snapshot_post);
        assert!(!operations[0].diff.is_empty());
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn workspace_restore_operations_apply_restores_file_from_rust_core() {
        let workspace = temp_workspace("apply");
        let file_path = workspace.join("src/app.js");
        fs::create_dir_all(file_path.parent().expect("parent")).expect("mkdir");
        fs::write(&file_path, "new").expect("write current");
        let request = WorkspaceRestoreOperationsRequest {
            schema_version: WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION.to_string(),
            workspace_root: workspace.to_string_lossy().to_string(),
            files: vec![restore_file("src/app.js", "old", "new")],
            max_diff_bytes: Some(4096),
            allow_conflicts: Some(false),
        };

        let operations = WorkspaceRestoreOperationsCore
            .apply_operations(&request)
            .expect("apply operations");

        assert_eq!(operations[0].status, "ready");
        assert_eq!(operations[0].apply_status.as_deref(), Some("applied"));
        assert_eq!(
            fs::read_to_string(&file_path).expect("restored file"),
            "old"
        );
        assert_eq!(operations[0].applied_matches_target, Some(true));
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn rust_core_shapes_workspace_restore_apply_operations_protocol_response() {
        let workspace = temp_workspace("apply-response");
        let target = workspace.join("src/app.js");
        fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        fs::write(&target, "new").expect("write current");
        let response = apply_workspace_restore_operations_protocol_response(
            WorkspaceRestoreOperationsProtocolRequest {
                request: WorkspaceRestoreOperationsRequest {
                    schema_version: WORKSPACE_RESTORE_APPLY_OPERATIONS_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    workspace_root: workspace.to_string_lossy().to_string(),
                    files: vec![restore_file("src/app.js", "old", "new")],
                    max_diff_bytes: Some(4096),
                    allow_conflicts: Some(false),
                },
            },
        )
        .expect("workspace restore apply operations protocol response");

        assert_eq!(
            response["source"],
            "rust_workspace_restore_operations_protocol"
        );
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["operation"], "apply_workspace_restore_operations");
        assert_eq!(response["operations"][0]["status"], "ready");
        assert_eq!(response["operations"][0]["apply_status"], "applied");
        assert_eq!(fs::read_to_string(&target).expect("restored"), "old");
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn workspace_restore_apply_policy_requires_approval_by_default() {
        let request = WorkspaceRestoreApplyPolicyRequest {
            schema_version: WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION.to_string(),
            snapshot_id: "workspace_snapshot_alpha".to_string(),
            approval: None,
            approval_decision: None,
            policy_decision: None,
            decision: None,
            status: None,
            confirm: None,
            confirmed: None,
            confirm_restore_apply: None,
            apply_confirmed: None,
            approval_granted: None,
            approved: None,
            restore_conflict_policy: None,
            conflict_policy: None,
            restore_policy: None,
            allow_conflicts: None,
            override_conflicts: None,
            operations: vec![WorkspaceRestoreOperationPolicyInput {
                path: "src/app.js".to_string(),
                status: "ready".to_string(),
                blocked_reason: None,
            }],
            counts: Some(WorkspaceRestoreApplyCounts {
                file_count: 1,
                apply_blocked_count: 1,
                ..Default::default()
            }),
            hard_blocked: None,
            conflict_blocked: None,
            apply_status: None,
        };

        let plan = WorkspaceRestoreApplyPolicyCore
            .plan_apply_policy(&request)
            .expect("policy planned");

        assert!(!plan.approval.satisfied);
        assert_eq!(plan.policy_status, "blocked");
        assert_eq!(plan.apply_status.as_deref(), Some("blocked"));
        assert_eq!(
            plan.operation_policies[0].apply_reason,
            "workspace_restore_apply_requires_approval"
        );
        assert_eq!(
            plan.policy_decision_refs[0],
            "policy_workspace_restore_apply_workspace_snapshot_alpha_approval_required"
        );
    }

    #[test]
    fn workspace_restore_apply_policy_allows_confirmed_conflict_override() {
        let request: WorkspaceRestoreApplyPolicyRequest = serde_json::from_value(json!({
            "schema_version": WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION,
            "snapshot_id": "workspace/snapshot beta",
            "confirm_restore_apply": "true",
            "restore_conflict_policy": "override_conflicts",
            "operations": [
                {
                    "path": "src/app.js",
                    "status": "conflict"
                }
            ],
            "counts": {
                "file_count": 1,
                "conflict_count": 1,
                "applied_count": 1
            }
        }))
        .expect("request");

        let plan = WorkspaceRestoreApplyPolicyCore
            .plan_apply_policy(&request)
            .expect("policy planned");

        assert!(plan.approval.satisfied);
        assert!(plan.allow_conflicts);
        assert!(!plan.conflict_blocked);
        assert_eq!(plan.conflict_policy, "override_conflicts");
        assert_eq!(plan.apply_status.as_deref(), Some("applied"));
        assert!(plan.policy_decision_refs.contains(
            &"policy_workspace_restore_apply_workspace_snapshot_beta_conflict_override".to_string()
        ));
        assert_eq!(
            plan.summary.as_deref(),
            Some("Restore apply restored 1 file(s) from workspace/snapshot beta with conflict override.")
        );
    }

    #[test]
    fn rust_core_shapes_workspace_restore_apply_policy_protocol_response() {
        let response = plan_workspace_restore_apply_policy_protocol_response(
            WorkspaceRestoreApplyPolicyProtocolRequest {
                request: WorkspaceRestoreApplyPolicyRequest {
                    schema_version: WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    snapshot_id: "workspace_snapshot_alpha".to_string(),
                    confirm_restore_apply: Some(Value::Bool(true)),
                    restore_conflict_policy: Some("override_conflicts".to_string()),
                    operations: vec![WorkspaceRestoreOperationPolicyInput {
                        path: "src/app.js".to_string(),
                        status: "conflict".to_string(),
                        blocked_reason: None,
                    }],
                    counts: Some(WorkspaceRestoreApplyCounts {
                        file_count: 1,
                        conflict_count: 1,
                        applied_count: 1,
                        ..Default::default()
                    }),
                    approval: None,
                    approval_decision: None,
                    policy_decision: None,
                    decision: None,
                    status: None,
                    confirm: None,
                    confirmed: None,
                    apply_confirmed: None,
                    approval_granted: None,
                    approved: None,
                    conflict_policy: None,
                    restore_policy: None,
                    allow_conflicts: None,
                    override_conflicts: None,
                    hard_blocked: None,
                    conflict_blocked: None,
                    apply_status: None,
                },
            },
        )
        .expect("workspace restore apply policy protocol response");

        assert_eq!(response["source"], "rust_workspace_restore_policy_protocol");
        assert_eq!(response["backend"], "rust_workspace_restore");
        assert_eq!(response["approval"]["satisfied"], true);
        assert_eq!(response["allow_conflicts"], true);
        assert_eq!(response["conflict_policy"], "override_conflicts");
        assert_eq!(response["apply_status"], "applied");
        assert_eq!(
            response["policy_decision_refs"][1],
            "policy_workspace_restore_apply_workspace_snapshot_alpha_conflict_override"
        );
        assert_eq!(
            response["summary"],
            "Restore apply restored 1 file(s) from workspace_snapshot_alpha with conflict override."
        );
    }

    fn snapshot_record_and_content_package() -> (Value, Value) {
        let old_hash = sha256_hex("old");
        let new_hash = sha256_hex("new");
        let response = capture_workspace_snapshot_files_protocol_response(
            WorkspaceSnapshotCaptureProtocolRequest {
                thread_id: Some("thread_alpha".to_string()),
                turn_id: Some("turn_alpha".to_string()),
                workspace_root: Some("/workspace".to_string()),
                tool_call_id: Some("tool_call_alpha".to_string()),
                workflow_graph_id: Some("graph_alpha".to_string()),
                workflow_node_id: Some("node_alpha".to_string()),
                request: WorkspaceSnapshotCaptureRequest {
                    schema_version: WORKSPACE_SNAPSHOT_CAPTURE_REQUEST_SCHEMA_VERSION.to_string(),
                    max_content_bytes: Some(WORKSPACE_SNAPSHOT_MAX_CAPTURE_BYTES),
                    changed_files: vec![WorkspaceSnapshotChangedFile {
                        path: "src/app.js".to_string(),
                        created: false,
                        before_hash: Some(old_hash),
                        after_hash: Some(new_hash),
                        before_exists: true,
                        after_exists: Some(true),
                        before_size_bytes: Some(3),
                        after_size_bytes: Some(3),
                        before_mtime_ms: None,
                        after_mtime_ms: None,
                    }],
                    content_drafts: vec![WorkspaceSnapshotContentDraft {
                        path: "src/app.js".to_string(),
                        before_content: Some("old".to_string()),
                        after_content: Some("new".to_string()),
                        encoding: None,
                    }],
                },
            },
        )
        .expect("snapshot capture response");
        let snapshot_record = response["snapshot_record"].clone();
        let content_package = json!({
            "schema_version": WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_SCHEMA_VERSION,
            "snapshot_id": snapshot_record["snapshot_id"].clone(),
            "restore": snapshot_record["restore"].clone(),
            "content_files": response["content_files"].clone(),
            "receipt_refs": snapshot_record["receipt_refs"].clone(),
            "artifact_refs": snapshot_record["artifact_refs"].clone(),
        });
        (snapshot_record, content_package)
    }

    #[test]
    fn rust_core_shapes_workspace_snapshot_public_projection_responses() {
        let (snapshot_record, content_package) = snapshot_record_and_content_package();
        let snapshot_id = snapshot_record["snapshot_id"]
            .as_str()
            .expect("snapshot id")
            .to_string();
        let list = project_workspace_snapshot_list_protocol_response(
            WorkspaceSnapshotListProtocolRequest {
                request: WorkspaceSnapshotListRequest {
                    schema_version: WORKSPACE_SNAPSHOT_LIST_REQUEST_SCHEMA_VERSION.to_string(),
                    thread_id: "thread_alpha".to_string(),
                    snapshots: vec![snapshot_record.clone()],
                },
            },
        )
        .expect("snapshot list response");

        assert_eq!(
            list["source"],
            "rust_workspace_snapshot_projection_protocol"
        );
        assert_eq!(
            list["projection"]["schema_version"],
            WORKSPACE_SNAPSHOT_LIST_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            list["projection"]["object"],
            "ioi.runtime_workspace_snapshot_list"
        );
        assert_eq!(list["projection"]["thread_id"], "thread_alpha");
        assert_eq!(list["projection"]["snapshot_count"], 1);
        assert_eq!(
            list["projection"]["snapshots"][0]["snapshot_id"],
            snapshot_id
        );
        assert!(list["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "rust_daemon_core_workspace_snapshot_projection"));

        let package = project_workspace_snapshot_content_package_protocol_response(
            WorkspaceSnapshotContentPackageProtocolRequest {
                request: WorkspaceSnapshotContentPackageRequest {
                    schema_version: WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    thread_id: "thread_alpha".to_string(),
                    snapshot_id: snapshot_id.clone(),
                    snapshot_record: Some(snapshot_record),
                    content_package: Some(content_package),
                },
            },
        )
        .expect("snapshot content package response");

        assert_eq!(
            package["source"],
            "rust_workspace_snapshot_projection_protocol"
        );
        assert_eq!(
            package["projection"]["schema_version"],
            WORKSPACE_SNAPSHOT_CONTENT_PACKAGE_SCHEMA_VERSION
        );
        assert_eq!(package["projection"]["snapshot_id"], snapshot_id);
        assert_eq!(package["projection"]["file_count"], 1);
        assert_eq!(
            package["projection"]["content_files"][0]["before"]["content"],
            "old"
        );
    }

    #[test]
    fn rust_core_shapes_workspace_snapshot_restore_preview_and_apply_responses() {
        let workspace = temp_workspace("public-restore");
        let file_path = workspace.join("src/app.js");
        fs::create_dir_all(file_path.parent().expect("parent")).expect("mkdir");
        fs::write(&file_path, "new").expect("write current");
        let (snapshot_record, content_package) = snapshot_record_and_content_package();
        let snapshot_id = snapshot_record["snapshot_id"]
            .as_str()
            .expect("snapshot id")
            .to_string();

        let preview = preview_workspace_snapshot_restore_protocol_response(
            WorkspaceSnapshotRestoreProtocolRequest {
                request: WorkspaceSnapshotRestoreRequest {
                    schema_version: WORKSPACE_SNAPSHOT_RESTORE_PREVIEW_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    thread_id: "thread_alpha".to_string(),
                    snapshot_id: snapshot_id.clone(),
                    workspace_root: workspace.to_string_lossy().to_string(),
                    workflow_graph_id: Some("graph_alpha".to_string()),
                    workflow_node_id: Some("restore_preview".to_string()),
                    idempotency_key: Some("idem-preview".to_string()),
                    source: Some("sdk_client".to_string()),
                    snapshot_record: Some(snapshot_record.clone()),
                    content_package: Some(content_package.clone()),
                    max_diff_bytes: Some(4096),
                    approval: None,
                    approval_decision: None,
                    policy_decision: None,
                    decision: None,
                    status: None,
                    confirm: None,
                    confirmed: None,
                    confirm_restore_apply: None,
                    apply_confirmed: None,
                    approval_granted: None,
                    approved: None,
                    restore_conflict_policy: None,
                    conflict_policy: None,
                    restore_policy: None,
                    allow_conflicts: None,
                    override_conflicts: None,
                },
            },
        )
        .expect("restore preview response");

        assert_eq!(
            preview["source"],
            "rust_workspace_snapshot_restore_protocol"
        );
        assert_eq!(
            preview["restore_preview"]["schema_version"],
            WORKSPACE_RESTORE_PREVIEW_RESULT_SCHEMA_VERSION
        );
        assert_eq!(preview["restore_preview"]["preview_status"], "ready");
        assert_eq!(preview["restore_preview"]["ready_count"], 1);
        assert_eq!(
            preview["restore_preview"]["operations"][0]["status"],
            "ready"
        );
        assert_eq!(
            preview["restore_preview"]["restore_preview_artifact"]["schema_version"],
            WORKSPACE_RESTORE_ARTIFACT_SCHEMA_VERSION
        );
        assert_eq!(
            preview["restore_preview"]["restore_preview_event"]["event_kind"],
            "workspace_restore.preview"
        );
        assert_eq!(
            preview["restore_preview"]["restore_preview_event"]["payload_summary"]["receipt_refs"],
            preview["restore_preview"]["receipt_refs"]
        );

        let blocked_apply = apply_workspace_snapshot_restore_protocol_response(
            WorkspaceSnapshotRestoreProtocolRequest {
                request: WorkspaceSnapshotRestoreRequest {
                    schema_version: WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    thread_id: "thread_alpha".to_string(),
                    snapshot_id: snapshot_id.clone(),
                    workspace_root: workspace.to_string_lossy().to_string(),
                    workflow_graph_id: Some("graph_alpha".to_string()),
                    workflow_node_id: Some("restore_apply".to_string()),
                    idempotency_key: Some("idem-apply".to_string()),
                    source: Some("sdk_client".to_string()),
                    snapshot_record: Some(snapshot_record.clone()),
                    content_package: Some(content_package.clone()),
                    max_diff_bytes: Some(4096),
                    approval: None,
                    approval_decision: None,
                    policy_decision: None,
                    decision: None,
                    status: None,
                    confirm: None,
                    confirmed: None,
                    confirm_restore_apply: None,
                    apply_confirmed: None,
                    approval_granted: None,
                    approved: None,
                    restore_conflict_policy: None,
                    conflict_policy: None,
                    restore_policy: None,
                    allow_conflicts: None,
                    override_conflicts: None,
                },
            },
        )
        .expect("blocked restore apply response");

        assert_eq!(blocked_apply["restore_apply"]["apply_status"], "blocked");
        assert_eq!(blocked_apply["restore_apply"]["approval_satisfied"], false);
        assert_eq!(fs::read_to_string(&file_path).expect("current"), "new");

        let applied = apply_workspace_snapshot_restore_protocol_response(
            WorkspaceSnapshotRestoreProtocolRequest {
                request: WorkspaceSnapshotRestoreRequest {
                    schema_version: WORKSPACE_SNAPSHOT_RESTORE_APPLY_REQUEST_SCHEMA_VERSION
                        .to_string(),
                    thread_id: "thread_alpha".to_string(),
                    snapshot_id: snapshot_id.clone(),
                    workspace_root: workspace.to_string_lossy().to_string(),
                    workflow_graph_id: Some("graph_alpha".to_string()),
                    workflow_node_id: Some("restore_apply".to_string()),
                    idempotency_key: Some("idem-apply-approved".to_string()),
                    source: Some("sdk_client".to_string()),
                    snapshot_record: Some(snapshot_record),
                    content_package: Some(content_package),
                    max_diff_bytes: Some(4096),
                    approval_granted: Some(Value::Bool(true)),
                    approval: None,
                    approval_decision: None,
                    policy_decision: None,
                    decision: None,
                    status: None,
                    confirm: None,
                    confirmed: None,
                    confirm_restore_apply: None,
                    apply_confirmed: None,
                    approved: None,
                    restore_conflict_policy: None,
                    conflict_policy: None,
                    restore_policy: None,
                    allow_conflicts: None,
                    override_conflicts: None,
                },
            },
        )
        .expect("approved restore apply response");

        assert_eq!(applied["restore_apply"]["apply_status"], "applied");
        assert_eq!(applied["restore_apply"]["approval_satisfied"], true);
        assert_eq!(applied["restore_apply"]["applied_count"], 1);
        assert_eq!(
            applied["restore_apply"]["restore_apply_artifact"]["schema_version"],
            WORKSPACE_RESTORE_ARTIFACT_SCHEMA_VERSION
        );
        assert_eq!(
            applied["restore_apply"]["restore_apply_event"]["event_kind"],
            "workspace_restore.apply"
        );
        assert_eq!(
            applied["restore_apply"]["restore_apply_event"]["payload_summary"]
                ["policy_decision_refs"],
            applied["restore_apply"]["policy_decision_refs"]
        );
        assert_eq!(fs::read_to_string(&file_path).expect("restored"), "old");
        let _ = fs::remove_dir_all(workspace);
    }
}
