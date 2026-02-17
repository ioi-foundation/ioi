use super::super::refusal_eval::handle_refusal;
use super::super::support::canonical_intent_hash;
use crate::agentic::desktop::service::step::anti_loop::{
    build_post_state_summary, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, tier_as_str,
    to_routing_failure_class, FailureClass, TierRoutingDecision,
};
use crate::agentic::desktop::service::step::incident::{
    incident_receipt_fields, load_incident_state,
};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_types::app::{RoutingReceiptEvent, RoutingStateSummary};
use ioi_types::error::TransactionError;
use serde_json::json;

pub(super) async fn intercept_raw_refusal(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    key: &[u8],
    session_id: [u8; 32],
    final_visual_phash: [u8; 32],
    tool_call_result: &str,
    routing_decision: &TierRoutingDecision,
    pre_state_summary: &RoutingStateSummary,
    tool_version: &str,
) -> Result<bool, TransactionError> {
    if !tool_call_result.contains("\"name\":\"system::refusal\"") {
        return Ok(false);
    }

    let reason = if let Ok(val) = serde_json::from_str::<serde_json::Value>(tool_call_result) {
        val.get("arguments")
            .and_then(|a| a.get("reason"))
            .and_then(|m| m.as_str())
            .unwrap_or("Refused")
            .to_string()
    } else {
        "Refused".to_string()
    };

    let refusal_tool_name = "system::refusal".to_string();
    let refusal_args = json!({
        "reason": reason
    });
    let refusal_action_payload = json!({
        "name": refusal_tool_name,
        "arguments": refusal_args
    });
    let refusal_intent_hash = canonical_intent_hash(
        &refusal_tool_name,
        &refusal_args,
        routing_decision.tier,
        pre_state_summary.step_index,
        tool_version,
    );
    let refusal_policy_decision = "denied".to_string();
    let refusal_failure_class = FailureClass::UserInterventionNeeded;
    let refusal_stop_condition_hit = true;
    let refusal_escalation_path =
        Some(escalation_path_for_failure(refusal_failure_class).to_string());

    handle_refusal(
        service,
        state,
        agent_state,
        key,
        session_id,
        final_visual_phash,
        &reason,
    )
    .await?;

    let verification_checks = vec![
        format!("policy_decision={}", refusal_policy_decision),
        "was_refusal=true".to_string(),
        format!("stop_condition_hit={}", refusal_stop_condition_hit),
        format!(
            "routing_tier_selected={}",
            tier_as_str(routing_decision.tier)
        ),
        format!("routing_reason_code={}", routing_decision.reason_code),
        format!(
            "routing_source_failure={}",
            routing_decision
                .source_failure
                .map(|class| class.as_str().to_string())
                .unwrap_or_else(|| "None".to_string())
        ),
        format!(
            "routing_tier_matches_pre_state={}",
            pre_state_summary.tier == tier_as_str(routing_decision.tier)
        ),
        format!("failure_class={}", refusal_failure_class.as_str()),
    ];
    let mut artifacts = extract_artifacts(
        Some("ERROR_CLASS=HumanChallengeRequired"),
        Some(tool_call_result),
    );
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));
    let post_state = build_post_state_summary(agent_state, false, verification_checks);
    let policy_binding = policy_binding_hash(&refusal_intent_hash, &refusal_policy_decision);
    let incident_fields =
        incident_receipt_fields(load_incident_state(state, &session_id)?.as_ref());
    let receipt = RoutingReceiptEvent {
        session_id,
        step_index: pre_state_summary.step_index,
        intent_hash: refusal_intent_hash,
        policy_decision: refusal_policy_decision,
        tool_name: "system::refusal".to_string(),
        tool_version: tool_version.to_string(),
        pre_state: pre_state_summary.clone(),
        action_json: serde_json::to_string(&refusal_action_payload)
            .unwrap_or_else(|_| "{}".to_string()),
        post_state,
        artifacts,
        failure_class: Some(to_routing_failure_class(refusal_failure_class)),
        failure_class_name: refusal_failure_class.as_str().to_string(),
        intent_class: incident_fields.intent_class,
        incident_id: incident_fields.incident_id,
        incident_stage: incident_fields.incident_stage,
        strategy_name: incident_fields.strategy_name,
        strategy_node: incident_fields.strategy_node,
        gate_state: incident_fields.gate_state,
        resolution_action: incident_fields.resolution_action,
        stop_condition_hit: refusal_stop_condition_hit,
        escalation_path: refusal_escalation_path,
        scs_lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    emit_routing_receipt(service.event_sender.as_ref(), receipt);
    Ok(true)
}
