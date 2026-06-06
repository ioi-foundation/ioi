use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const WORKSPACE_RESTORE_APPLY_POLICY_REQUEST_SCHEMA_VERSION: &str =
    "ioi.workspace_restore_apply_policy_request.v1";
pub const WORKSPACE_RESTORE_APPLY_POLICY_PLAN_SCHEMA_VERSION: &str =
    "ioi.workspace_restore_apply_policy_plan.v1";

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
    use serde_json::json;

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
}
