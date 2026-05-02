use crate::agentic::runtime::service::tool_execution::{
    emit_execution_contract_receipt_event_with_observation, execution_evidence_key,
    record_execution_evidence, record_execution_evidence_with_value, record_success_condition,
    success_condition_key,
};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::AgentState;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::AgentTool;

fn install_resolution_receipt_evidence(verification_checks: &[String]) -> Option<String> {
    let mut fields = verification_checks
        .iter()
        .map(|check| check.trim())
        .filter_map(|check| check.strip_prefix("software_install."))
        .filter(|field| !field.trim().is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    (!fields.is_empty()).then(|| fields.join(";"))
}

fn install_resolution_value<'a>(
    verification_checks: &'a [String],
    field_name: &str,
) -> Option<&'a str> {
    let prefix = format!("software_install.{field_name}=");
    verification_checks
        .iter()
        .map(|check| check.trim())
        .find_map(|check| check.strip_prefix(prefix.as_str()))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn install_approval_receipt_evidence(agent_state: &AgentState) -> Option<String> {
    let grant = agent_state.pending_approval.as_ref()?;
    let grant_ref = grant
        .artifact_hash()
        .map(|hash| format!("sha256:{}", hex::encode(hash)))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());
    Some(format!(
        "approval_grant_ref={};request_hash=sha256:{};policy_hash=sha256:{};authority_id=sha256:{}",
        grant_ref,
        hex::encode(grant.request_hash),
        hex::encode(grant.policy_hash),
        hex::encode(grant.authority_id)
    ))
}

fn verification_commit_from_resolution(verification_checks: &[String]) -> Option<String> {
    let verification = install_resolution_value(verification_checks, "verification")?;
    let digest = sha256(verification.as_bytes()).ok()?;
    Some(format!("sha256:{}", hex::encode(digest.as_ref())))
}

pub(super) fn record_queue_install_success_receipts(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    verification_checks: &mut Vec<String>,
    output: Option<&str>,
) {
    if !matches!(tool, AgentTool::SoftwareInstallExecutePlan { .. }) {
        return;
    }

    if let Some(evidence) = install_resolution_receipt_evidence(verification_checks) {
        record_execution_evidence_with_value(
            &mut agent_state.tool_execution_log,
            "software_install_resolution",
            evidence.clone(),
        );
        verification_checks.push(execution_evidence_key("software_install_resolution"));
        emit_execution_contract_receipt_event_with_observation(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "resolution",
            "software_install_resolution",
            true,
            &evidence,
            Some("install_resolver"),
            Some("resolved"),
            Some("software_install_resolution"),
            None,
            Some("software.install.execute".to_string()),
            None,
        );
    }

    if let Some(evidence) = install_approval_receipt_evidence(agent_state) {
        record_execution_evidence_with_value(
            &mut agent_state.tool_execution_log,
            "approval",
            evidence.clone(),
        );
        verification_checks.push(execution_evidence_key("approval"));
        emit_execution_contract_receipt_event_with_observation(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "approval",
            "approval",
            true,
            &evidence,
            Some("approval_grant"),
            Some("approved"),
            Some("signed_approval"),
            None,
            Some("agency_firewall".to_string()),
            None,
        );
    }

    record_execution_evidence(&mut agent_state.tool_execution_log, "execution");
    verification_checks.push(execution_evidence_key("execution"));
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        "execution",
        true,
        "execution_invocation_completed=true",
        Some("software_install__execute_plan"),
        Some("completed"),
        Some("tool_execution"),
        None,
        Some("software.install.execute".to_string()),
        None,
    );

    record_execution_evidence(&mut agent_state.tool_execution_log, "verification");
    verification_checks.push(execution_evidence_key("verification"));
    let verification_commit = verification_commit_from_resolution(verification_checks);
    if let Some(commit) = verification_commit.as_ref() {
        record_execution_evidence_with_value(
            &mut agent_state.tool_execution_log,
            "verification_commit",
            commit.clone(),
        );
        verification_checks.push(execution_evidence_key("verification_commit"));
    }
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        "verification",
        true,
        "verification_receipt_recorded=true",
        Some("install_verifier"),
        Some("passed"),
        Some("tool_verification"),
        verification_commit.clone(),
        Some("software.install.execute".to_string()),
        None,
    );
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        "verification_commit",
        verification_commit.is_some(),
        verification_commit
            .as_deref()
            .unwrap_or("verification_commit=missing"),
        Some("install_verifier"),
        verification_commit.as_deref(),
        Some("sha256"),
        verification_commit.clone(),
        Some("software.install.execute".to_string()),
        None,
    );

    record_success_condition(
        &mut agent_state.tool_execution_log,
        "verified_local_app_available",
    );
    verification_checks.push(success_condition_key("verified_local_app_available"));
    let evidence = format!(
        "verified_local_app_available=true;tool_output_chars={}",
        output.map(|entry| entry.chars().count()).unwrap_or(0)
    );
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        "verified_local_app_available",
        true,
        &evidence,
        Some("install_verifier"),
        Some("true"),
        Some("bool"),
        None,
        Some("software.install.execute".to_string()),
        None,
    );
}
