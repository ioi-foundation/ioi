use super::intent_resolver;
use super::queue;
use super::{STEP_ACTIVE_WINDOW_QUERY_TIMEOUT, WAIT_FOR_INTENT_CLARIFICATION_PROMPT};
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::service::lifecycle::maybe_seed_runtime_locality_context;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{AgentPauseReason, AgentState};
use crate::agentic::runtime::utils::{persist_agent_state, timestamp_ms_now};
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::IntentScopeProfile;
use ioi_types::app::KernelEvent;
use ioi_types::error::TransactionError;

fn is_web_research_intent(resolved_scope: IntentScopeProfile) -> bool {
    matches!(resolved_scope, IntentScopeProfile::WebResearch)
}

async fn active_window_title_for_step(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
) -> String {
    let Some(os_driver) = service.os_driver.as_ref() else {
        return "Unknown".to_string();
    };

    match tokio::time::timeout(
        STEP_ACTIVE_WINDOW_QUERY_TIMEOUT,
        os_driver.get_active_window_info(),
    )
    .await
    {
        Ok(Ok(Some(win))) => format!("{} ({})", win.title, win.app_name),
        Ok(Ok(None)) => "Unknown".to_string(),
        Ok(Err(_)) => "Unknown".to_string(),
        Err(_) => {
            log::warn!(
                "Step active-window query timed out after {:?} for session {}.",
                STEP_ACTIVE_WINDOW_QUERY_TIMEOUT,
                hex::encode(&session_id[..4])
            );
            "Unknown".to_string()
        }
    }
}

pub(super) async fn resolve_step_intent_and_maybe_pause(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    key: &[u8],
    rules: &ActionRules,
    block_height: u64,
) -> Result<bool, TransactionError> {
    let active_window_title = active_window_title_for_step(service, session_id).await;
    let resolved_intent = if let Some(existing) = agent_state.resolved_intent.clone() {
        if existing.intent_id != "resolver.unclassified"
            && !agent_state.awaiting_intent_clarification
        {
            existing
        } else {
            intent_resolver::resolve_step_intent_with_state(
                service,
                Some(state),
                agent_state,
                rules,
                &active_window_title,
            )
            .await?
        }
    } else {
        intent_resolver::resolve_step_intent_with_state(
            service,
            Some(state),
            agent_state,
            rules,
            &active_window_title,
        )
        .await?
    };

    let locality_scope_required =
        queue::web_pipeline::query_requires_runtime_locality_scope(&agent_state.goal);
    if locality_scope_required && is_web_research_intent(resolved_intent.scope) {
        maybe_seed_runtime_locality_context(&agent_state.goal).await;
    }
    let runtime_locality_scope = queue::web_pipeline::effective_locality_scope_hint(None);
    let locality_scope_missing = locality_scope_required
        && is_web_research_intent(resolved_intent.scope)
        && runtime_locality_scope.is_none();
    let defer_intent_pause_for_runtime_locality = locality_scope_required
        && is_web_research_intent(resolved_intent.scope)
        && runtime_locality_scope.is_some();
    let was_waiting_intent = agent_state.awaiting_intent_clarification;
    let should_pause_for_intent = intent_resolver::should_pause_for_clarification(
        &resolved_intent,
        &rules.ontology_policy.intent_routing,
    );
    let should_wait_for_clarification = !agent_state.has_canonical_pending_action()
        && (locality_scope_missing
            || (should_pause_for_intent && !defer_intent_pause_for_runtime_locality));
    agent_state.resolved_intent = Some(resolved_intent);
    agent_state.awaiting_intent_clarification = should_wait_for_clarification;
    if !should_wait_for_clarification {
        return Ok(false);
    }

    let clarification_output = if locality_scope_missing {
        "System: WAIT_FOR_INTENT_CLARIFICATION. More context is needed to resolve locality for this request. Please clarify the requested outcome."
    } else {
        WAIT_FOR_INTENT_CLARIFICATION_PROMPT
    };
    agent_state.set_pause_reason(AgentPauseReason::WaitingForIntentClarification);
    if !was_waiting_intent {
        let msg = ioi_types::app::agentic::ChatMessage {
            role: "assistant".to_string(),
            content: "I need a quick clarification before continuing. Please tell me exactly what outcome you want."
                .to_string(),
            timestamp: timestamp_ms_now(),
            trace_hash: None,
        };
        let _ = service
            .append_chat_to_scs(session_id, &msg, block_height)
            .await?;
        if let Some(tx) = service.event_sender.as_ref() {
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: agent_state.step_count,
                tool_name: "system::intent_clarification".to_string(),
                output: clarification_output.to_string(),
                error_class: None,
                agent_status: "Paused".to_string(),
            });
        }
    }

    persist_agent_state(state, key, agent_state, service.memory_runtime.as_ref())?;
    Ok(true)
}
