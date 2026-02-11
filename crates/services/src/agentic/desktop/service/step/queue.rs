// Path: crates/services/src/agentic/desktop/service/step/queue.rs

use self::super::helpers::default_safe_policy;
use super::action::{canonical_intent_hash, canonical_tool_identity};
use super::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, choose_routing_tier,
    classify_failure, emit_routing_receipt, escalation_path_for_failure, extract_artifacts,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    retry_budget_remaining, should_block_retry_without_change, should_trip_retry_guard,
    tier_as_str, to_routing_failure_class, FailureClass, TierRoutingDecision,
};
use crate::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus, StepAgentParams};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{RoutingReceiptEvent, RoutingStateSummary};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;

/// Applies parity routing for queued actions and snapshots the pre-state after
/// tier selection so receipts and executor context stay coherent.
pub fn resolve_queue_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    let routing_decision = choose_routing_tier(agent_state);
    agent_state.current_tier = routing_decision.tier;
    let pre_state_summary = build_state_summary(agent_state);
    (routing_decision, pre_state_summary)
}

pub async fn process_queue_item(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
) -> Result<(), TransactionError> {
    log::info!(
        "Draining execution queue for session {} (Pending: {})",
        hex::encode(&p.session_id[..4]),
        agent_state.execution_queue.len()
    );

    let key = get_state_key(&p.session_id);
    let policy_key = [AGENT_POLICY_PREFIX, p.session_id.as_slice()].concat();
    let rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let (routing_decision, pre_state_summary) = resolve_queue_routing_context(agent_state);
    let mut policy_decision = "allowed".to_string();

    // Pop the first action
    let action_request = agent_state.execution_queue.remove(0);

    // [NEW] Capture the active skill hash for attribution
    let active_skill = agent_state.active_skill_hash;

    // [FIX] Removed manual ToolExecutor construction.
    // The service method now handles it internally.

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    // Re-construct AgentTool from ActionRequest to reuse execution logic
    let tool_wrapper = match action_request.target {
        ioi_types::app::ActionTarget::Custom(ref name) => {
            let args: serde_json::Value =
                serde_json::from_slice(&action_request.params).unwrap_or(json!({}));
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("name".to_string(), json!(name));
            wrapper.insert("arguments".to_string(), args);
            AgentTool::Dynamic(serde_json::Value::Object(wrapper))
        }
        _ => {
            // For native targets (e.g. BrowserNavigate), we need to reconstruct the specific enum
            let name = match action_request.target {
                ioi_types::app::ActionTarget::BrowserNavigateHermetic => "browser__navigate",
                ioi_types::app::ActionTarget::BrowserNavigateLocal => "browser__navigate",
                ioi_types::app::ActionTarget::GuiType => "gui__type",
                ioi_types::app::ActionTarget::GuiClick => "gui__click",
                ioi_types::app::ActionTarget::SysExec => "sys__exec",
                _ => {
                    return Err(TransactionError::Invalid(
                        "Queue execution for this target type pending refactor".into(),
                    ))
                }
            };

            let args: serde_json::Value =
                serde_json::from_slice(&action_request.params).unwrap_or(json!({}));
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("name".to_string(), json!(name));
            wrapper.insert("arguments".to_string(), args);
            AgentTool::Dynamic(serde_json::Value::Object(wrapper))
        }
    };
    let (tool_name, intent_args) = canonical_tool_identity(&tool_wrapper);
    let action_json = serde_json::to_string(&tool_wrapper).unwrap_or_else(|_| "{}".to_string());
    let intent_hash = canonical_intent_hash(
        &tool_name,
        &intent_args,
        routing_decision.tier,
        pre_state_summary.step_index,
        env!("CARGO_PKG_VERSION"),
    );

    // Execute
    // [FIX] Updated call: removed executor arg
    let result_tuple = service
        .handle_action_execution(
            // &executor,  <-- REMOVED
            tool_wrapper,
            p.session_id,
            agent_state.step_count,
            [0u8; 32],
            &rules,
            &agent_state,
            &os_driver,
        )
        .await;

    let (success, out, err): (bool, Option<String>, Option<String>) = match result_tuple {
        Ok(tuple) => tuple,
        Err(e) => {
            let msg = e.to_string();
            if msg.to_lowercase().contains("blocked by policy") {
                policy_decision = "denied".to_string();
            }
            (false, None, Some(msg))
        }
    };

    let output_str = out.clone().unwrap_or_default();
    let error_str = err.clone();

    // Log Trace with Provenance
    goto_trace_log(
        agent_state,
        state,
        &key,
        p.session_id,
        [0u8; 32],
        format!("[Macro Step] Executing queued action"),
        output_str,
        success,
        error_str,
        "macro_step".to_string(),
        service.event_sender.clone(),
        active_skill, // [NEW] Pass the skill hash
    )?;

    let mut failure_class: Option<FailureClass> = None;
    let mut stop_condition_hit = false;
    let mut escalation_path: Option<String> = None;
    let mut verification_checks = Vec::new();
    if success {
        agent_state.recent_actions.clear();
    } else {
        failure_class = classify_failure(err.as_deref(), &policy_decision);
        if let Some(class) = failure_class {
            let target_id = agent_state.target.as_ref().and_then(|target| {
                target
                    .app_hint
                    .as_deref()
                    .filter(|v| !v.trim().is_empty())
                    .or_else(|| {
                        target
                            .title_pattern
                            .as_deref()
                            .filter(|v| !v.trim().is_empty())
                    })
            });
            let window_fingerprint = agent_state
                .last_screen_phash
                .filter(|hash| *hash != [0u8; 32])
                .map(hex::encode);
            let attempt_key = build_attempt_key(
                &intent_hash,
                routing_decision.tier,
                &tool_name,
                target_id,
                window_fingerprint.as_deref(),
            );
            let (repeat_count, attempt_key_hash) =
                register_failure_attempt(agent_state, class, &attempt_key);
            let budget_remaining = retry_budget_remaining(repeat_count);
            let blocked_without_change = should_block_retry_without_change(class, repeat_count);
            verification_checks.push(format!("attempt_repeat_count={}", repeat_count));
            verification_checks.push(format!("attempt_key_hash={}", attempt_key_hash));
            verification_checks.push(format!(
                "attempt_retry_budget_remaining={}",
                budget_remaining
            ));
            verification_checks.push(format!(
                "attempt_retry_blocked_without_change={}",
                blocked_without_change
            ));
            if matches!(class, FailureClass::UserInterventionNeeded) {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                agent_state.status = AgentStatus::Paused(
                    "Waiting for user intervention: complete the required human verification in Local Browser, then resume.".to_string(),
                );
            } else if blocked_without_change {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                agent_state.status = AgentStatus::Paused(format!(
                    "Retry blocked: unchanged AttemptKey for {}",
                    class.as_str()
                ));
                if matches!(
                    class,
                    FailureClass::FocusMismatch
                        | FailureClass::TargetNotFound
                        | FailureClass::VisionTargetNotFound
                        | FailureClass::NoEffectAfterAction
                        | FailureClass::TierViolation
                        | FailureClass::MissingDependency
                        | FailureClass::ContextDrift
                        | FailureClass::ToolUnavailable
                        | FailureClass::NonDeterministicUI
                        | FailureClass::TimeoutOrHang
                        | FailureClass::UnexpectedState
                ) {
                    agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                }
            } else if should_trip_retry_guard(class, repeat_count) {
                stop_condition_hit = true;
                escalation_path = Some(escalation_path_for_failure(class).to_string());
                agent_state.status = AgentStatus::Paused(format!(
                    "Retry guard tripped after repeated {} failures",
                    class.as_str()
                ));
                if matches!(
                    class,
                    FailureClass::FocusMismatch
                        | FailureClass::TargetNotFound
                        | FailureClass::VisionTargetNotFound
                        | FailureClass::NoEffectAfterAction
                        | FailureClass::TierViolation
                        | FailureClass::MissingDependency
                        | FailureClass::ContextDrift
                        | FailureClass::ToolUnavailable
                        | FailureClass::NonDeterministicUI
                        | FailureClass::TimeoutOrHang
                        | FailureClass::UnexpectedState
                ) {
                    agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                }
            }
        }
    }

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push("was_queue=true".to_string());
    verification_checks.push(format!("stop_condition_hit={}", stop_condition_hit));
    verification_checks.push(format!(
        "routing_tier_selected={}",
        tier_as_str(routing_decision.tier)
    ));
    verification_checks.push(format!(
        "routing_reason_code={}",
        routing_decision.reason_code
    ));
    verification_checks.push(format!(
        "routing_source_failure={}",
        routing_decision
            .source_failure
            .map(|class| class.as_str().to_string())
            .unwrap_or_else(|| "None".to_string())
    ));
    verification_checks.push(format!(
        "routing_tier_matches_pre_state={}",
        pre_state_summary.tier == tier_as_str(routing_decision.tier)
    ));
    if let Some(class) = failure_class {
        verification_checks.push(format!("failure_class={}", class.as_str()));
    }

    agent_state.step_count += 1;

    if success && !stop_condition_hit {
        agent_state.consecutive_failures = 0;
    }

    let mut artifacts = extract_artifacts(err.as_deref(), out.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!(
        "trace://session/{}",
        hex::encode(&p.session_id[..4])
    ));
    let post_state = build_post_state_summary(agent_state, success, verification_checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);
    let receipt = RoutingReceiptEvent {
        session_id: p.session_id,
        step_index: pre_state_summary.step_index,
        intent_hash,
        policy_decision,
        tool_name,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        pre_state: pre_state_summary,
        action_json,
        post_state,
        artifacts,
        failure_class: failure_class.map(to_routing_failure_class),
        stop_condition_hit,
        escalation_path,
        scs_lineage_ptr: lineage_pointer(active_skill),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &p.session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    // [NEW] If queue is empty, clear the active skill hash to reset context
    if agent_state.execution_queue.is_empty() {
        agent_state.active_skill_hash = None;
    }

    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}
