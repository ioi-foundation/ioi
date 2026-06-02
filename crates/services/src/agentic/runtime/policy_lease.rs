use crate::agentic::rules::{ActionRules, DefaultPolicy};
use crate::agentic::runtime::keys::{get_approval_authority_key, get_approval_grant_key};
use crate::agentic::runtime::types::{AgentStatus, PendingActionState};
use ioi_api::state::StateAccess;
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};

pub const RUNTIME_POLICY_LEASE_SCHEMA_VERSION: &str = "ioi.runtime.policy_lease.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyLeaseSnapshot {
    pub schema_version: String,
    pub session_id: String,
    pub policy_id: String,
    pub default_policy: String,
    pub permission_mode: String,
    pub leases: Vec<RuntimePolicyLeaseEntry>,
    pub pending_gate: Option<RuntimePolicyPendingGate>,
    pub sandbox: RuntimeSandboxSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyLeaseEntry {
    pub lease_id: String,
    pub kind: String,
    pub status: String,
    pub source: String,
    pub scope: String,
    pub expires_at_ms: Option<u64>,
    pub remaining_ms: Option<u64>,
    pub max_usages: Option<u32>,
    pub authority_status: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyPendingGate {
    pub status: String,
    pub pause_reason: Option<String>,
    pub pending_tool_present: bool,
    pub pending_tool_hash_ref: Option<String>,
    pub pending_request_nonce: Option<u64>,
    pub approval_grant_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSandboxSnapshot {
    pub workspace_root: String,
    pub filesystem_boundary: String,
    pub symlink_policy: String,
    pub ignored_file_policy: String,
    pub network_policy: String,
    pub env_log_policy: String,
    pub timeout_policy: String,
    pub output_policy: String,
}

pub fn policy_lease_snapshot_for_state(
    state: &dyn StateAccess,
    session_id: [u8; 32],
    rules: &ActionRules,
    status: &AgentStatus,
    working_directory: &str,
    pending: &PendingActionState,
    now_ms: u64,
) -> Result<RuntimePolicyLeaseSnapshot, TransactionError> {
    let grant = load_approval_grant(state, &session_id)?;
    let authority = grant
        .as_ref()
        .map(|grant| load_approval_authority(state, &grant.authority_id))
        .transpose()?
        .flatten();
    Ok(policy_lease_snapshot_from_parts(
        session_id,
        rules,
        status,
        working_directory,
        pending,
        grant.as_ref(),
        authority.as_ref(),
        now_ms,
    ))
}

pub fn policy_lease_snapshot_from_parts(
    session_id: [u8; 32],
    rules: &ActionRules,
    status: &AgentStatus,
    working_directory: &str,
    pending: &PendingActionState,
    grant: Option<&ApprovalGrant>,
    authority: Option<&ApprovalAuthority>,
    now_ms: u64,
) -> RuntimePolicyLeaseSnapshot {
    let session_hex = hex::encode(session_id);
    let mut leases = vec![base_policy_lease(&session_hex, rules)];
    if let Some(grant) = grant {
        leases.push(approval_grant_lease(&session_hex, grant, authority, now_ms));
    }

    RuntimePolicyLeaseSnapshot {
        schema_version: RUNTIME_POLICY_LEASE_SCHEMA_VERSION.to_string(),
        session_id: session_hex,
        policy_id: rules.policy_id.clone(),
        default_policy: default_policy_label(rules.defaults).to_string(),
        permission_mode: permission_mode_for_policy(rules).to_string(),
        leases,
        pending_gate: pending_gate(status, pending, grant.is_some()),
        sandbox: sandbox_snapshot(rules, working_directory),
    }
}

fn load_approval_grant(
    state: &dyn StateAccess,
    session_id: &[u8; 32],
) -> Result<Option<ApprovalGrant>, TransactionError> {
    state
        .get(&get_approval_grant_key(session_id))?
        .map(|bytes| {
            codec::from_bytes_canonical::<ApprovalGrant>(&bytes).map_err(|error| {
                TransactionError::Invalid(format!("Invalid approval grant: {error}"))
            })
        })
        .transpose()
}

fn load_approval_authority(
    state: &dyn StateAccess,
    authority_id: &[u8; 32],
) -> Result<Option<ApprovalAuthority>, TransactionError> {
    state
        .get(&get_approval_authority_key(authority_id))?
        .map(|bytes| {
            codec::from_bytes_canonical::<ApprovalAuthority>(&bytes).map_err(|error| {
                TransactionError::Invalid(format!("Invalid approval authority: {error}"))
            })
        })
        .transpose()
}

fn base_policy_lease(session_hex: &str, rules: &ActionRules) -> RuntimePolicyLeaseEntry {
    RuntimePolicyLeaseEntry {
        lease_id: format!("policy:{}:{}", session_hex, rules.policy_id),
        kind: permission_mode_for_policy(rules).to_string(),
        status: "active".to_string(),
        source: "action_rules".to_string(),
        scope: "session_effective_policy".to_string(),
        expires_at_ms: None,
        remaining_ms: None,
        max_usages: None,
        authority_status: None,
        notes: vec![format!(
            "default_policy={}",
            default_policy_label(rules.defaults)
        )],
    }
}

fn approval_grant_lease(
    session_hex: &str,
    grant: &ApprovalGrant,
    authority: Option<&ApprovalAuthority>,
    now_ms: u64,
) -> RuntimePolicyLeaseEntry {
    let authority_status = authority_status(authority, now_ms);
    let status = if now_ms > grant.expires_at {
        "expired"
    } else if authority_status == "revoked" {
        "revoked"
    } else if authority_status == "expired" {
        "expired_authority"
    } else if authority_status == "missing" {
        "missing_authority"
    } else {
        "active"
    };
    let kind = if grant.max_usages == Some(1) {
        "allow_once"
    } else {
        "approval_grant"
    };
    RuntimePolicyLeaseEntry {
        lease_id: format!(
            "approval:{}:{}",
            session_hex,
            short_hash(&grant.request_hash)
        ),
        kind: kind.to_string(),
        status: status.to_string(),
        source: "approval_grant".to_string(),
        scope: "exact_request_policy_binding".to_string(),
        expires_at_ms: Some(grant.expires_at),
        remaining_ms: grant.expires_at.checked_sub(now_ms),
        max_usages: grant.max_usages,
        authority_status: Some(authority_status),
        notes: vec![
            format!("request_hash_ref={}", short_hash(&grant.request_hash)),
            format!("policy_hash_ref={}", short_hash(&grant.policy_hash)),
        ],
    }
}

fn pending_gate(
    status: &AgentStatus,
    pending: &PendingActionState,
    approval_grant_present: bool,
) -> Option<RuntimePolicyPendingGate> {
    if pending.tool_call.is_none()
        && pending.tool_jcs.is_none()
        && pending.tool_hash.is_none()
        && pending.approval.is_none()
        && !approval_grant_present
    {
        return None;
    }
    Some(RuntimePolicyPendingGate {
        status: match status {
            AgentStatus::Idle => "idle",
            AgentStatus::Paused(_) => "waiting_for_operator",
            AgentStatus::Running => "resumable_or_executing",
            AgentStatus::Completed(_) => "completed",
            AgentStatus::Terminated => "terminated",
            AgentStatus::Failed(_) => "failed",
        }
        .to_string(),
        pause_reason: match status {
            AgentStatus::Paused(reason) => Some(reason.clone()),
            _ => None,
        },
        pending_tool_present: pending.tool_call.is_some() || pending.tool_jcs.is_some(),
        pending_tool_hash_ref: pending.tool_hash.as_ref().map(short_hash),
        pending_request_nonce: pending.request_nonce,
        approval_grant_present,
    })
}

fn sandbox_snapshot(rules: &ActionRules, working_directory: &str) -> RuntimeSandboxSnapshot {
    let network_policy = match rules.defaults {
        DefaultPolicy::AllowAll => "allow_by_default",
        DefaultPolicy::DenyAll => "deny_by_default",
        DefaultPolicy::RequireApproval => "approval_required_by_default",
    };
    RuntimeSandboxSnapshot {
        workspace_root: working_directory.trim().to_string(),
        filesystem_boundary: if working_directory.trim().is_empty() {
            "unbound"
        } else {
            "workspace_scoped"
        }
        .to_string(),
        symlink_policy: "reject_escape".to_string(),
        ignored_file_policy: "protect_ignored_files".to_string(),
        network_policy: network_policy.to_string(),
        env_log_policy: "redact_sensitive_values".to_string(),
        timeout_policy: "bounded_action_timeout".to_string(),
        output_policy: "bounded_and_redacted_output".to_string(),
    }
}

fn authority_status(authority: Option<&ApprovalAuthority>, now_ms: u64) -> String {
    match authority {
        None => "missing".to_string(),
        Some(authority) if authority.revoked => "revoked".to_string(),
        Some(authority) if now_ms > authority.expires_at => "expired".to_string(),
        Some(_) => "active".to_string(),
    }
}

fn permission_mode_for_policy(rules: &ActionRules) -> &'static str {
    let policy_id = rules.policy_id.to_ascii_lowercase();
    if policy_id.contains("full-access") {
        return "full_access";
    }
    if policy_id.contains("auto-review") || policy_id.contains("autoreview") {
        return "auto_review";
    }
    match rules.defaults {
        DefaultPolicy::AllowAll => "full_access",
        DefaultPolicy::DenyAll => "locked_down",
        DefaultPolicy::RequireApproval => "default_permissions",
    }
}

fn default_policy_label(policy: DefaultPolicy) -> &'static str {
    match policy {
        DefaultPolicy::AllowAll => "allow_all",
        DefaultPolicy::DenyAll => "deny_all",
        DefaultPolicy::RequireApproval => "require_approval",
    }
}

fn short_hash(hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(&hash[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::rules::{ActionRules, Verdict};
    use ioi_types::app::SignatureSuite;

    fn rules(policy_id: &str, default_policy: DefaultPolicy) -> ActionRules {
        ActionRules {
            policy_id: policy_id.to_string(),
            defaults: default_policy,
            rules: vec![crate::agentic::rules::Rule {
                rule_id: Some("allow-complete".to_string()),
                target: "agent__complete".to_string(),
                conditions: Default::default(),
                action: Verdict::Allow,
            }],
            ..ActionRules::default()
        }
    }

    fn grant(expires_at: u64, max_usages: Option<u32>) -> ApprovalGrant {
        ApprovalGrant {
            schema_version: 1,
            authority_id: [7u8; 32],
            request_hash: [1u8; 32],
            policy_hash: [2u8; 32],
            audience: [3u8; 32],
            nonce: [4u8; 32],
            counter: 1,
            expires_at,
            max_usages,
            window_id: None,
            pii_action: None,
            scoped_exception: None,
            review_request_hash: None,
            approver_public_key: vec![9],
            approver_sig: vec![8],
            approver_suite: SignatureSuite::ED25519,
        }
    }

    fn authority(expires_at: u64, revoked: bool) -> ApprovalAuthority {
        ApprovalAuthority {
            schema_version: 1,
            authority_id: [7u8; 32],
            public_key: vec![9],
            signature_suite: SignatureSuite::ED25519,
            expires_at,
            revoked,
            scope_allowlist: vec!["desktop_agent.resume".to_string()],
        }
    }

    #[test]
    fn policy_lease_snapshot_classifies_permission_modes() {
        let snapshot = policy_lease_snapshot_from_parts(
            [5u8; 32],
            &rules("runtime-bridge-full-access", DefaultPolicy::AllowAll),
            &AgentStatus::Running,
            "/tmp/workspace",
            &PendingActionState::default(),
            None,
            None,
            10,
        );

        assert_eq!(snapshot.permission_mode, "full_access");
        assert_eq!(snapshot.leases[0].kind, "full_access");
        assert_eq!(snapshot.sandbox.filesystem_boundary, "workspace_scoped");
        assert_eq!(snapshot.sandbox.network_policy, "allow_by_default");
    }

    #[test]
    fn policy_lease_snapshot_projects_pending_allow_once_and_revocation() {
        let mut pending = PendingActionState::default();
        pending.tool_call = Some("tool".to_string());
        pending.tool_hash = Some([6u8; 32]);
        pending.request_nonce = Some(42);
        let grant = grant(2_000, Some(1));
        let authority = authority(3_000, true);
        let snapshot = policy_lease_snapshot_from_parts(
            [5u8; 32],
            &rules("runtime-bridge-auto-review", DefaultPolicy::RequireApproval),
            &AgentStatus::Paused("Waiting for approval".to_string()),
            "/tmp/workspace",
            &pending,
            Some(&grant),
            Some(&authority),
            1_000,
        );

        assert_eq!(snapshot.permission_mode, "auto_review");
        assert_eq!(snapshot.leases[1].kind, "allow_once");
        assert_eq!(snapshot.leases[1].status, "revoked");
        assert_eq!(
            snapshot
                .pending_gate
                .as_ref()
                .map(|gate| gate.status.as_str()),
            Some("waiting_for_operator")
        );
        assert_eq!(
            snapshot
                .pending_gate
                .as_ref()
                .and_then(|gate| gate.pending_tool_hash_ref.as_deref()),
            Some("sha256:0606060606060606")
        );
    }
}
