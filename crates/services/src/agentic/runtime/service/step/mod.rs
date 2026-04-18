// Path: crates/services/src/agentic/runtime/service/step/mod.rs

pub mod action;
pub mod anti_loop;
pub mod browser_completion;
mod clarification;
pub mod cognition;
mod direct_inline;
pub mod helpers;
pub mod incident;
pub mod intent_resolver;
pub mod ontology;
mod orchestration;
mod pending_resume;
pub mod perception;
pub mod planner;
mod playbook;
pub mod queue;
pub mod route_projection;
pub mod signals;
pub mod text_tokens;
pub mod visual;
pub mod worker;

#[cfg(test)]
mod tests;

use super::{RuntimeAgentService, ServiceCallContext};
// [FIX] Import actions module from parent service directory
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::service::step::anti_loop::choose_routing_tier;
use crate::agentic::runtime::types::{AgentState, ExecutionTier, StepAgentParams};
use crate::agentic::runtime::utils::persist_agent_state;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::error::TransactionError;
use std::time::Duration;

const STEP_ACTIVE_WINDOW_QUERY_TIMEOUT: Duration = Duration::from_millis(300);
const WAIT_FOR_INTENT_CLARIFICATION_PROMPT: &str =
    "System: WAIT_FOR_INTENT_CLARIFICATION. Intent confidence is too low to proceed safely. Please clarify the requested outcome.";
async fn maybe_direct_inline_author_tool_call(
    service: &RuntimeAgentService,
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    target_tier: ExecutionTier,
) -> Result<Option<String>, TransactionError> {
    direct_inline::maybe_direct_inline_author_tool_call(
        service,
        state,
        agent_state,
        session_id,
        target_tier,
    )
    .await
}

fn hydrate_step_state(
    state: &dyn StateAccess,
    session_id: [u8; 32],
) -> Result<(Vec<u8>, AgentState), TransactionError> {
    orchestration::hydrate_step_state(state, session_id)
}

fn ensure_agent_running_or_resume_retry_pause(
    agent_state: &mut AgentState,
) -> Result<(), TransactionError> {
    orchestration::ensure_agent_running_or_resume_retry_pause(agent_state)
}

async fn maybe_run_optimizer_recovery(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    key: &[u8],
    block_height: u64,
) -> Result<bool, TransactionError> {
    orchestration::maybe_run_optimizer_recovery(
        service,
        state,
        agent_state,
        session_id,
        key,
        block_height,
    )
    .await
}

fn maybe_fail_step_resource_limits(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    key: &[u8],
) -> Result<bool, TransactionError> {
    orchestration::maybe_fail_step_resource_limits(service, state, agent_state, key)
}

fn load_action_rules(
    state: &dyn StateAccess,
    session_id: [u8; 32],
) -> Result<ActionRules, TransactionError> {
    orchestration::load_action_rules(state, session_id)
}

async fn resolve_step_intent_and_maybe_pause(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    key: &[u8],
    rules: &ActionRules,
    block_height: u64,
) -> Result<bool, TransactionError> {
    clarification::resolve_step_intent_and_maybe_pause(
        service,
        state,
        agent_state,
        session_id,
        key,
        rules,
        block_height,
    )
    .await
}

async fn apply_planner_fallback_guards(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    rules: &ActionRules,
) -> Result<bool, TransactionError> {
    orchestration::apply_planner_fallback_guards(
        service,
        agent_state,
        session_id,
        block_height,
        rules,
    )
    .await
}

fn queue_root_playbook_delegate_request(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    playbook::queue_root_playbook_delegate_request(state, agent_state, session_id)
}

fn queue_parent_playbook_await_request(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    playbook::queue_parent_playbook_await_request(state, agent_state, session_id)
}

fn maybe_enable_browser_lease_for_pending_action(
    service: &RuntimeAgentService,
    agent_state: &AgentState,
) {
    pending_resume::maybe_enable_browser_lease_for_pending_action(service, agent_state);
}

async fn maybe_resume_pending_action_or_clear_stale(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    key: &[u8],
    block_height: u64,
    block_timestamp: u64,
    call_context: ServiceCallContext<'_>,
) -> Result<bool, TransactionError> {
    pending_resume::maybe_resume_pending_action_or_clear_stale(
        service,
        state,
        agent_state,
        session_id,
        key,
        block_height,
        block_timestamp,
        call_context,
    )
    .await
}

fn should_clear_stale_canonical_pending(
    agent_state: &AgentState,
    allow_runtime_secret_retry: bool,
) -> bool {
    pending_resume::should_clear_stale_canonical_pending(agent_state, allow_runtime_secret_retry)
}

async fn maybe_bootstrap_execution_queue(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    block_height: u64,
    block_timestamp: u64,
    call_context: ServiceCallContext<'_>,
    planning_disabled: bool,
) -> Result<bool, TransactionError> {
    orchestration::maybe_bootstrap_execution_queue(
        service,
        state,
        agent_state,
        p,
        block_height,
        block_timestamp,
        call_context,
        planning_disabled,
    )
    .await
}

async fn maybe_process_ready_work(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    block_height: u64,
    block_timestamp: u64,
    call_context: ServiceCallContext<'_>,
) -> Result<bool, TransactionError> {
    orchestration::maybe_process_ready_work(
        service,
        state,
        agent_state,
        p,
        block_height,
        block_timestamp,
        call_context,
    )
    .await
}

async fn run_step_cognitive_loop(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    ctx: &TxContext<'_>,
    call_context: ServiceCallContext<'_>,
) -> Result<(), TransactionError> {
    let routing_decision = choose_routing_tier(agent_state);
    let target_tier = routing_decision.tier;
    log::info!(
        "Parity router selected tier={} reason={} source_failure={:?}",
        crate::agentic::runtime::service::step::anti_loop::tier_as_str(target_tier),
        routing_decision.reason_code,
        routing_decision.source_failure
    );

    agent_state.current_tier = target_tier;

    if let Some(direct_inline_tool_call) =
        maybe_direct_inline_author_tool_call(service, state, agent_state, p.session_id, target_tier)
            .await?
    {
        let final_visual_phash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
        Box::pin(action::process_tool_output(
            service,
            state,
            agent_state,
            direct_inline_tool_call,
            final_visual_phash,
            "DirectInlineAuthor".to_string(),
            p.session_id,
            ctx.block_height,
            ctx.block_timestamp,
            call_context,
        ))
        .await?;
        return Ok(());
    }

    let perception = Box::pin(perception::gather_context(
        service,
        state,
        agent_state,
        Some(target_tier),
    ))
    .await?;
    let cognition_result = Box::pin(cognition::think(
        service,
        agent_state,
        &perception,
        p.session_id,
    ))
    .await?;

    Box::pin(action::process_tool_output(
        service,
        state,
        agent_state,
        cognition_result.raw_output,
        perception.visual_phash,
        cognition_result.strategy_used,
        p.session_id,
        ctx.block_height,
        ctx.block_timestamp,
        call_context,
    ))
    .await?;

    Ok(())
}

pub async fn handle_step(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    p: StepAgentParams,
    ctx: &mut TxContext<'_>,
) -> Result<(), TransactionError> {
    let call_context = ServiceCallContext::from_tx(ctx);
    let (key, mut agent_state) = hydrate_step_state(state, p.session_id)?;

    ensure_agent_running_or_resume_retry_pause(&mut agent_state)?;
    if Box::pin(maybe_run_optimizer_recovery(
        service,
        state,
        &mut agent_state,
        p.session_id,
        &key,
        ctx.block_height,
    ))
    .await?
    {
        return Ok(());
    }
    if maybe_fail_step_resource_limits(service, state, &mut agent_state, &key)? {
        return Ok(());
    }

    let rules = load_action_rules(state, p.session_id)?;
    if Box::pin(resolve_step_intent_and_maybe_pause(
        service,
        state,
        &mut agent_state,
        p.session_id,
        &key,
        &rules,
        ctx.block_height,
    ))
    .await?
    {
        return Ok(());
    }

    let planning_disabled = Box::pin(apply_planner_fallback_guards(
        service,
        &mut agent_state,
        p.session_id,
        ctx.block_height,
        &rules,
    ))
    .await?;
    maybe_enable_browser_lease_for_pending_action(service, &agent_state);

    if Box::pin(maybe_resume_pending_action_or_clear_stale(
        service,
        state,
        &mut agent_state,
        p.session_id,
        &key,
        ctx.block_height,
        ctx.block_timestamp,
        call_context,
    ))
    .await?
    {
        return Ok(());
    }

    if Box::pin(maybe_bootstrap_execution_queue(
        service,
        state,
        &mut agent_state,
        &p,
        ctx.block_height,
        ctx.block_timestamp,
        call_context,
        planning_disabled,
    ))
    .await?
    {
        return Ok(());
    }
    if Box::pin(maybe_process_ready_work(
        service,
        state,
        &mut agent_state,
        &p,
        ctx.block_height,
        ctx.block_timestamp,
        call_context,
    ))
    .await?
    {
        return Ok(());
    }

    Box::pin(run_step_cognitive_loop(
        service,
        state,
        &mut agent_state,
        &p,
        ctx,
        call_context,
    ))
    .await?;
    persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
    Ok(())
}
