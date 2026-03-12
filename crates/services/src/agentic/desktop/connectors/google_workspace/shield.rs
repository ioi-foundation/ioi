use super::types::{
    ResolvedShieldPolicy, ShieldAutomationMode, ShieldDecisionMode, ShieldPolicyState,
};
use super::*;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::AgentState;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::KernelEvent;
use ioi_types::error::TransactionError;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

const SHIELD_POLICY_PATH_ENV: &str = "IOI_SHIELD_POLICY_PATH";

pub fn matches_google_connector_id(connector_id: &str) -> bool {
    matches!(
        connector_id.trim().to_ascii_lowercase().as_str(),
        "google.workspace" | "google_workspace" | "google"
    )
}

fn shield_policy_path(service: Option<&DesktopAgentService>) -> Option<PathBuf> {
    service
        .and_then(|svc| svc.shield_policy_path.clone())
        .or_else(|| std::env::var_os(SHIELD_POLICY_PATH_ENV).map(PathBuf::from))
}

fn load_shield_policy_state(service: Option<&DesktopAgentService>) -> ShieldPolicyState {
    let Some(path) = shield_policy_path(service) else {
        return ShieldPolicyState::default();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return ShieldPolicyState::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn resolve_google_shield_policy(service: Option<&DesktopAgentService>) -> ResolvedShieldPolicy {
    let state = load_shield_policy_state(service);
    let defaults = state.global;
    if let Some(override_state) = state.overrides.get(GOOGLE_CONNECTOR_ID) {
        if !override_state.inherit_global {
            return ResolvedShieldPolicy {
                reads: override_state.reads.clone(),
                writes: override_state.writes.clone(),
                admin: override_state.admin.clone(),
                expert: override_state.expert.clone(),
                automations: override_state.automations.clone(),
            };
        }
    }

    ResolvedShieldPolicy {
        reads: defaults.reads,
        writes: defaults.writes,
        admin: defaults.admin,
        expert: defaults.expert,
        automations: defaults.automations,
    }
}

fn is_automation_action_id(action_id: &str) -> bool {
    matches!(
        action_id,
        "gmail.watch_emails" | "events.subscribe" | "events.renew"
    )
}

fn shield_decision_for_action(
    policy: &ResolvedShieldPolicy,
    spec: &GoogleConnectorActionSpec,
) -> Result<bool, String> {
    match spec.kind {
        "read" => match policy.reads {
            ShieldDecisionMode::Auto => Ok(false),
            ShieldDecisionMode::Confirm => Ok(true),
            ShieldDecisionMode::Block => Err(format!(
                "Blocked by Shield policy: {} is disabled for this connector.",
                spec.label
            )),
        },
        "write" | "workflow" => match policy.writes {
            ShieldDecisionMode::Auto => Ok(false),
            ShieldDecisionMode::Confirm => Ok(true),
            ShieldDecisionMode::Block => Err(format!(
                "Blocked by Shield policy: {} is disabled for this connector.",
                spec.label
            )),
        },
        "expert" => match policy.expert {
            ShieldDecisionMode::Auto => Ok(false),
            ShieldDecisionMode::Confirm => Ok(true),
            ShieldDecisionMode::Block => Err(
                "Blocked by Shield policy: expert Google actions are disabled for this connector."
                    .to_string(),
            ),
        },
        "admin" if is_automation_action_id(spec.id) => match policy.automations {
            ShieldAutomationMode::ConfirmOnCreate
            | ShieldAutomationMode::ConfirmOnRun
            | ShieldAutomationMode::ManualOnly => Ok(true),
        },
        "admin" => match policy.admin {
            ShieldDecisionMode::Auto => Ok(false),
            ShieldDecisionMode::Confirm => Ok(true),
            ShieldDecisionMode::Block => Err(format!(
                "Blocked by Shield policy: {} is disabled for this connector.",
                spec.label
            )),
        },
        _ => Ok(false),
    }
}

pub(super) fn compute_google_shield_request_hash(
    spec: &GoogleConnectorActionSpec,
    input: &Value,
) -> Result<[u8; 32], TransactionError> {
    let canonical = serde_jcs::to_vec(&json!({
        "connectorId": GOOGLE_CONNECTOR_ID,
        "actionId": spec.id,
        "toolName": spec.tool_name,
        "input": input,
    }))
    .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let digest = sha256(&canonical).map_err(|error| {
        TransactionError::Invalid(format!("Failed to hash Shield request: {}", error))
    })?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    Ok(hash)
}

fn emit_google_shield_interception(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    spec: &GoogleConnectorActionSpec,
    request_hash: [u8; 32],
    verdict: &str,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let _ = tx.send(KernelEvent::FirewallInterception {
        verdict: verdict.to_string(),
        target: spec.tool_name.to_string(),
        request_hash,
        session_id: Some(session_id),
    });
}

pub(super) fn runtime_resume_already_authorizes_google_tool(
    agent_state: &AgentState,
    raw_tool_json: &Value,
) -> bool {
    if agent_state.pending_approval.is_none() {
        return false;
    }

    let Some(pending_tool_jcs) = agent_state.pending_tool_jcs.as_ref() else {
        return false;
    };

    match serde_jcs::to_vec(raw_tool_json) {
        Ok(current_tool_jcs) => &current_tool_jcs == pending_tool_jcs,
        Err(_) => false,
    }
}

pub(super) fn enforce_google_tool_shield_policy(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    spec: &GoogleConnectorActionSpec,
    input: &Value,
    runtime_resume_approval: bool,
) -> Result<(), TransactionError> {
    let policy = resolve_google_shield_policy(Some(service));
    let requires_confirmation = match shield_decision_for_action(&policy, spec) {
        Ok(value) => value,
        Err(message) => {
            let request_hash = compute_google_shield_request_hash(spec, input)?;
            emit_google_shield_interception(service, session_id, spec, request_hash, "BLOCK");
            return Err(TransactionError::Invalid(message));
        }
    };
    if !requires_confirmation {
        return Ok(());
    }

    let request_hash = compute_google_shield_request_hash(spec, input)?;
    let already_approved = agent_state
        .pending_approval
        .as_ref()
        .map(|token| token.request_hash == request_hash)
        .unwrap_or(false)
        || runtime_resume_approval;

    if already_approved {
        return Ok(());
    }

    emit_google_shield_interception(service, session_id, spec, request_hash, "REQUIRE_APPROVAL");
    Err(TransactionError::PendingApproval(hex::encode(request_hash)))
}
