use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::keys::{get_mutation_receipt_ptr_key, get_state_key, get_trace_key};
use crate::agentic::runtime::service::planning::planner;
use crate::agentic::runtime::service::planning::playbook::{
    queue_parent_playbook_await_request, queue_root_playbook_delegate_request,
};
use crate::agentic::runtime::service::policy::load_action_rules_for_session;
use crate::agentic::runtime::service::queue;
use crate::agentic::runtime::service::recovery::anti_loop::{
    mutation_receipt_artifact_id, mutation_receipt_pointer_for_artifact_id,
};
use crate::agentic::runtime::service::tool_execution as action;
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{AgentState, AgentStatus, StepAgentParams};
use crate::agentic::runtime::utils::{persist_agent_state, timestamp_ms_now};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::StepTrace;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, KernelEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;

pub(super) async fn emit_planner_fallback_evidence(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    block_height: u64,
    reason: &str,
) -> Result<(), TransactionError> {
    let normalized = reason.trim();
    if normalized.is_empty() {
        return Ok(());
    }

    let msg = ioi_types::app::agentic::ChatMessage {
        role: "system".to_string(),
        content: format!(
            "Planner fallback engaged (reason: {}). Switching to direct step cognition.",
            normalized
        ),
        timestamp: timestamp_ms_now(),
        trace_hash: None,
    };
    let _ = service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;

    if let Some(tx) = service.event_sender.as_ref() {
        let _ = tx.send(KernelEvent::AgentActionResult {
            session_id,
            step_index,
            tool_name: "system::planner_fallback".to_string(),
            output: normalized.to_string(),
            error_class: Some("PlannerFallback".to_string()),
            agent_status: "Running".to_string(),
        });
    }
    Ok(())
}

pub(super) fn hydrate_step_state(
    state: &dyn StateAccess,
    session_id: [u8; 32],
) -> Result<(Vec<u8>, AgentState), TransactionError> {
    let key = get_state_key(&session_id);
    let bytes = state
        .get(&key)?
        .ok_or(TransactionError::Invalid("Session not found".into()))?;
    let agent_state = codec::from_bytes_canonical(&bytes)?;
    Ok((key, agent_state))
}

pub(super) fn ensure_agent_running_or_resume_retry_pause(
    agent_state: &mut AgentState,
) -> Result<(), TransactionError> {
    if agent_state.status != AgentStatus::Running {
        let auto_resume_retry_pause = matches!(
            &agent_state.status,
            AgentStatus::Paused(reason)
                if reason.starts_with("Retry blocked: unchanged AttemptKey for")
                    || reason.starts_with("Retry guard tripped after repeated")
        );

        if auto_resume_retry_pause {
            // Keep web-research flows autonomous under transient model/tool instability.
            agent_state.status = AgentStatus::Running;
            agent_state.recent_actions.clear();
        } else {
            return Err(TransactionError::Invalid(format!(
                "Agent not running: {:?}",
                agent_state.status
            )));
        }
    }

    Ok(())
}

pub(super) async fn maybe_run_optimizer_recovery(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    key: &[u8],
    block_height: u64,
) -> Result<bool, TransactionError> {
    if !(agent_state.consecutive_failures >= 3 && agent_state.consecutive_failures < 5) {
        return Ok(false);
    }
    let Some(optimizer) = &service.optimizer else {
        return Ok(false);
    };

    log::warn!(
        "Agent stuck ({} failures). Triggering Optimizer intervention...",
        agent_state.consecutive_failures
    );

    let trace_key = get_trace_key(&session_id, agent_state.step_count.saturating_sub(1));
    let Some(bytes) = state.get(&trace_key)? else {
        return Ok(false);
    };
    let Ok(last_trace) = codec::from_bytes_canonical::<StepTrace>(&bytes) else {
        return Ok(false);
    };

    match optimizer
        .synthesize_recovery_skill(state, session_id, &last_trace)
        .await
    {
        Ok(record) => {
            log::info!(
                "Recovery successful. Injected skill: {}",
                record.macro_body.definition.name
            );

            let parent_skill_hash = agent_state.active_skill_hash;
            let child_skill_hash = record.skill_hash;
            agent_state.active_skill_hash = Some(child_skill_hash);
            agent_state.consecutive_failures = 0;

            let msg = format!(
                "SYSTEM: I noticed you are stuck. I have synthesized a new tool '{}' to help you. Try using it.",
                record.macro_body.definition.name
            );
            let sys_msg = ioi_types::app::agentic::ChatMessage {
                role: "system".to_string(),
                content: msg,
                timestamp: timestamp_ms_now(),
                trace_hash: None,
            };
            service
                .append_chat_to_scs(session_id, &sys_msg, block_height)
                .await?;

            let trace_hash_bytes = sha256(&codec::to_bytes_canonical(&last_trace)?)
                .map_err(|e| TransactionError::Invalid(format!("Trace hash failed: {}", e)))?;
            let mut trace_hash = [0u8; 32];
            trace_hash.copy_from_slice(trace_hash_bytes.as_ref());

            let mutation_payload = serde_json::to_string(&json!({
                "kind": "MutationReceipt",
                "strategy": "Hotfix",
                "session_id": hex::encode(session_id),
                "step_index": agent_state.step_count,
                "block_height": block_height,
                "parent_skill_hash": parent_skill_hash.map(hex::encode),
                "child_skill_hash": hex::encode(child_skill_hash),
                "source_trace_hash": hex::encode(trace_hash),
                "rationale": format!(
                    "Auto-synthesized recovery skill '{}'",
                    record.macro_body.definition.name
                ),
            }))
            .map_err(|e| TransactionError::Serialization(e.to_string()))?;

            let mutation_ptr_key = get_mutation_receipt_ptr_key(&session_id);
            if let Some(memory_runtime) = service.memory_runtime.as_ref() {
                let artifact_id = mutation_receipt_artifact_id(&trace_hash);
                memory_runtime
                    .upsert_artifact_json(session_id, &artifact_id, &mutation_payload)
                    .map_err(|error| {
                        TransactionError::Invalid(format!(
                            "Failed to persist mutation receipt artifact: {}",
                            error
                        ))
                    })?;
                let mutation_ptr = mutation_receipt_pointer_for_artifact_id(&artifact_id);
                state.insert(&mutation_ptr_key, mutation_ptr.as_bytes())?;
            } else {
                state.delete(&mutation_ptr_key)?;
            }

            persist_agent_state(state, key, agent_state, service.memory_runtime.as_ref())?;
            Ok(true)
        }
        Err(error) => {
            log::error!("Optimizer failed to synthesize recovery: {}", error);
            Ok(false)
        }
    }
}

pub(super) fn maybe_fail_step_resource_limits(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    key: &[u8],
) -> Result<bool, TransactionError> {
    if agent_state.budget != 0 && agent_state.consecutive_failures < 5 {
        return Ok(false);
    }

    agent_state.status = AgentStatus::Failed("Resources/Retry limit exceeded".into());
    persist_agent_state(state, key, agent_state, service.memory_runtime.as_ref())?;
    Ok(true)
}

pub(super) fn load_action_rules(
    state: &dyn StateAccess,
    session_id: [u8; 32],
) -> Result<ActionRules, TransactionError> {
    load_action_rules_for_session(state, session_id)
}

pub(super) async fn apply_planner_fallback_guards(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    rules: &ActionRules,
) -> Result<bool, TransactionError> {
    let planning_disabled =
        planner::planner_runtime_disabled_for_policy(rules.ontology_policy.planning_enabled);
    let mut planner_degradation_reason: Option<String> = None;
    let resolved_intent_snapshot = agent_state.resolved_intent.clone();
    if let Some(planner_state) = agent_state.planner_state.as_mut() {
        if planning_disabled {
            if planner::mark_planner_fallback(
                planner_state,
                planner::PLANNER_FALLBACK_REASON_PLANNING_DISABLED,
                resolved_intent_snapshot.as_ref(),
            ) {
                planner_degradation_reason =
                    Some(planner::PLANNER_FALLBACK_REASON_PLANNING_DISABLED.to_string());
            }
        } else if let Err(err) = planner::validate_and_hash_planner_state(
            planner_state,
            resolved_intent_snapshot.as_ref(),
        ) {
            let reason = format!(
                "{}: {}",
                planner::PLANNER_FALLBACK_REASON_VALIDATION_FAILED,
                err
            );
            if planner::mark_planner_fallback(
                planner_state,
                reason.as_str(),
                resolved_intent_snapshot.as_ref(),
            ) {
                planner_degradation_reason = Some(reason);
            }
        }
    }
    if let Some(reason) = planner_degradation_reason.as_deref() {
        emit_planner_fallback_evidence(
            service,
            session_id,
            agent_state.step_count,
            block_height,
            reason,
        )
        .await?;
    }

    Ok(planning_disabled)
}

fn enqueue_deterministic_screenshot_capture(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let params = serde_jcs::to_vec(&json!({}))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    agent_state.execution_queue.push(ActionRequest {
        target: ActionTarget::GuiScreenshot,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64,
    });
    Ok(())
}

pub(super) async fn maybe_bootstrap_execution_queue(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    block_height: u64,
    block_timestamp: u64,
    call_context: ServiceCallContext<'_>,
    planning_disabled: bool,
) -> Result<bool, TransactionError> {
    if !(agent_state.execution_queue.is_empty() && !agent_state.has_canonical_pending_action()) {
        return Ok(false);
    }

    if queue_root_playbook_delegate_request(state, agent_state, p.session_id)? {
        Box::pin(queue::process_queue_item(
            service,
            state,
            agent_state,
            p,
            block_height,
            block_timestamp,
            call_context,
        ))
        .await?;
        return Ok(true);
    }
    if queue_parent_playbook_await_request(state, agent_state, p.session_id)? {
        Box::pin(queue::process_queue_item(
            service,
            state,
            agent_state,
            p,
            block_height,
            block_timestamp,
            call_context,
        ))
        .await?;
        return Ok(true);
    }
    if planning_disabled {
        return Ok(false);
    }

    let (planner_has_open_work, unmet_discovery_requirements) = agent_state
        .planner_state
        .as_ref()
        .map(|planner_state| {
            (
                planner::planner_has_open_work(planner_state),
                planner::planner_unmet_discovery_requirements(planner_state, agent_state),
            )
        })
        .unwrap_or((false, Vec::new()));
    if planner_has_open_work && !unmet_discovery_requirements.is_empty() {
        let reason = format!(
            "{}: {}",
            planner::PLANNER_FALLBACK_REASON_DISCOVERY_REQUIREMENTS_UNSATISFIED,
            unmet_discovery_requirements.join(",")
        );
        if let Some(planner_state) = agent_state.planner_state.as_mut() {
            planner::mark_planner_fallback(
                planner_state,
                reason.as_str(),
                agent_state.resolved_intent.as_ref(),
            );
        }
        emit_planner_fallback_evidence(
            service,
            p.session_id,
            agent_state.step_count,
            block_height,
            reason.as_str(),
        )
        .await?;
        return Ok(false);
    }

    let resolved_intent_snapshot = agent_state.resolved_intent.clone();
    let planner_nonce = agent_state.step_count as u64 + 1;
    match planner::dispatch_next_planner_action(
        agent_state,
        p.session_id,
        planner_nonce,
        resolved_intent_snapshot.as_ref(),
    ) {
        Ok(Some(step_id)) => {
            log::info!(
                "Planner dispatched step '{}' for session {}.",
                step_id,
                hex::encode(&p.session_id[..4])
            );
        }
        Ok(None) => {
            if let Some(planner_state) = agent_state.planner_state.as_mut() {
                if planner::planner_has_open_work(planner_state)
                    && planner::mark_planner_fallback(
                        planner_state,
                        planner::PLANNER_FALLBACK_REASON_NO_DISPATCHABLE_STEP,
                        resolved_intent_snapshot.as_ref(),
                    )
                {
                    emit_planner_fallback_evidence(
                        service,
                        p.session_id,
                        agent_state.step_count,
                        block_height,
                        planner::PLANNER_FALLBACK_REASON_NO_DISPATCHABLE_STEP,
                    )
                    .await?;
                }
            }
        }
        Err(err) => {
            let reason = format!(
                "{}: {}",
                planner::PLANNER_FALLBACK_REASON_DISPATCH_FAILED,
                err
            );
            if let Some(planner_state) = agent_state.planner_state.as_mut() {
                planner::mark_planner_fallback(
                    planner_state,
                    reason.as_str(),
                    resolved_intent_snapshot.as_ref(),
                );
            }
            emit_planner_fallback_evidence(
                service,
                p.session_id,
                agent_state.step_count,
                block_height,
                reason.as_str(),
            )
            .await?;
        }
    }

    Ok(false)
}

pub(super) async fn maybe_process_ready_work(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    block_height: u64,
    block_timestamp: u64,
    call_context: ServiceCallContext<'_>,
) -> Result<bool, TransactionError> {
    if !agent_state.execution_queue.is_empty() {
        Box::pin(queue::process_queue_item(
            service,
            state,
            agent_state,
            p,
            block_height,
            block_timestamp,
            call_context,
        ))
        .await?;
        return Ok(true);
    }

    if action::is_ui_capture_screenshot_intent(agent_state.resolved_intent.as_ref()) {
        enqueue_deterministic_screenshot_capture(agent_state, p.session_id)?;
        Box::pin(queue::process_queue_item(
            service,
            state,
            agent_state,
            p,
            block_height,
            block_timestamp,
            call_context,
        ))
        .await?;
        return Ok(true);
    }

    Ok(false)
}
