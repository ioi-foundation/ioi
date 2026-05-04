// Path: crates/services/src/agentic/runtime/service/decision_loop/mod.rs

mod clarification;
pub mod cognition;
pub mod helpers;
pub mod intent_resolver;
pub mod ontology;
mod orchestration;
mod pending_resume;
pub mod route_projection;
pub mod signals;
pub mod worker;

#[cfg(test)]
mod tests;

use super::{RuntimeAgentService, ServiceCallContext};
// [FIX] Import actions module from parent service directory
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::service::recovery::anti_loop::choose_routing_tier;
use crate::agentic::runtime::service::tool_execution;
use crate::agentic::runtime::service::visual_loop::perception;
use crate::agentic::runtime::types::{AgentState, ExecutionTier, StepAgentParams};
use crate::agentic::runtime::utils::persist_agent_state;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::agentic::{
    CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState, RuntimeRouteFrame,
};
use ioi_types::error::TransactionError;
use serde_json::json;
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
    crate::agentic::runtime::service::output::direct_inline::maybe_direct_inline_author_tool_call(
        service,
        state,
        agent_state,
        session_id,
        target_tier,
    )
    .await
}

const RUNTIME_ROUTE_INSTALL_RESOLVE_MARKER: &str =
    "runtime_route_frame_dispatch:software_install__resolve";
const RUNTIME_ROUTE_BROWSER_NAVIGATE_MARKER: &str =
    "runtime_route_frame_dispatch:browser__navigate";
const RUNTIME_ROUTE_SHELL_RUN_MARKER: &str = "runtime_route_frame_dispatch:shell__run";

fn maybe_typed_runtime_install_resolve_tool_call(agent_state: &mut AgentState) -> Option<String> {
    if agent_state
        .pending_tool_call
        .as_deref()
        .is_some_and(|raw| raw.contains("software_install__"))
    {
        return None;
    }
    if agent_state
        .recent_actions
        .iter()
        .any(|action| action.starts_with(RUNTIME_ROUTE_INSTALL_RESOLVE_MARKER))
    {
        return None;
    }

    let frame = agent_state.runtime_route_frame.clone()?;
    if !frame.route_family.eq_ignore_ascii_case("command_execution")
        || !frame.output_intent.eq_ignore_ascii_case("tool_execution")
        || frame.direct_answer_allowed
        || !frame.host_mutation
    {
        return None;
    }
    let request = frame.install_request?;
    let target = request.target_text.clone();
    log::info!(
        "TypedRuntimeInstallResolve dispatching software install resolver target={} session={}",
        target,
        hex::encode(&agent_state.session_id[..4])
    );
    agent_state
        .recent_actions
        .push(format!("{RUNTIME_ROUTE_INSTALL_RESOLVE_MARKER}:{target}"));

    serde_json::to_string(&json!({
        "name": "software_install__resolve",
        "arguments": {
            "request": request,
        }
    }))
    .ok()
}

fn maybe_typed_runtime_browser_navigate_tool_call(agent_state: &mut AgentState) -> Option<String> {
    if agent_state
        .pending_tool_call
        .as_deref()
        .is_some_and(|raw| raw.contains("browser__"))
    {
        return None;
    }
    if agent_state
        .recent_actions
        .iter()
        .any(|action| action.starts_with(RUNTIME_ROUTE_BROWSER_NAVIGATE_MARKER))
    {
        return None;
    }

    let frame = agent_state.runtime_route_frame.clone()?;
    if frame.direct_answer_allowed
        || !frame.output_intent.eq_ignore_ascii_case("tool_execution")
        || !frame.intent_id.eq_ignore_ascii_case("browser.interact")
    {
        return None;
    }
    let runtime_action = frame.runtime_action.as_ref()?;
    let browser_plan = runtime_action.browser_plan.as_ref()?;
    if !browser_plan.action.eq_ignore_ascii_case("navigate") {
        return None;
    }
    let url = browser_plan.url.clone();
    log::info!(
        "TypedRuntimeBrowserNavigate dispatching browser navigation url={} session={}",
        url,
        hex::encode(&agent_state.session_id[..4])
    );
    agent_state
        .recent_actions
        .push(format!("{RUNTIME_ROUTE_BROWSER_NAVIGATE_MARKER}:{url}"));

    serde_json::to_string(&json!({
        "name": "browser__navigate",
        "arguments": {
            "url": url,
        }
    }))
    .ok()
}

fn maybe_typed_runtime_shell_run_tool_call(agent_state: &mut AgentState) -> Option<String> {
    if agent_state
        .pending_tool_call
        .as_deref()
        .is_some_and(|raw| raw.contains("shell__run") || raw.contains("shell__start"))
    {
        return None;
    }
    if agent_state
        .recent_actions
        .iter()
        .any(|action| action.starts_with(RUNTIME_ROUTE_SHELL_RUN_MARKER))
    {
        return None;
    }

    let frame = agent_state.runtime_route_frame.clone()?;
    if frame.direct_answer_allowed
        || !frame.output_intent.eq_ignore_ascii_case("tool_execution")
        || !frame.intent_id.eq_ignore_ascii_case("command.exec")
    {
        return None;
    }
    let runtime_action = frame.runtime_action.as_ref()?;
    let command_plan = runtime_action.command_plan.as_ref()?;
    let (command, args) = command_plan.argv.split_first()?;
    if command.trim().is_empty() {
        return None;
    }
    log::info!(
        "TypedRuntimeShellRun dispatching shell command plan_ref={} session={}",
        command_plan.plan_ref,
        hex::encode(&agent_state.session_id[..4])
    );
    agent_state.recent_actions.push(format!(
        "{RUNTIME_ROUTE_SHELL_RUN_MARKER}:{}",
        command_plan.plan_ref
    ));

    serde_json::to_string(&json!({
        "name": "shell__run",
        "arguments": {
            "command": command,
            "args": args,
            "wait_ms_before_async": 30000u64,
            "detach": false,
        }
    }))
    .ok()
}

fn typed_runtime_local_install_resolved_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "software.install.desktop_app".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("software.install.execute")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "host_mutation".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "typed-runtime-route-frame".to_string(),
        embedding_model_id: "typed-runtime-route-frame".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "typed_runtime_route_frame".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "typed-runtime-route-frame-v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: true,
    }
}

fn typed_runtime_browser_action_resolved_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "browser.interact".to_string(),
        scope: IntentScopeProfile::UiInteraction,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("conversation.reply"),
            CapabilityId::from("browser.interact"),
            CapabilityId::from("browser.inspect"),
            CapabilityId::from("ui.interact"),
        ],
        required_evidence: vec!["execution".to_string(), "verification".to_string()],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "typed-runtime-route-frame".to_string(),
        embedding_model_id: "typed-runtime-route-frame".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "typed_runtime_route_frame".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "typed-runtime-route-frame-v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: true,
    }
}

fn typed_runtime_shell_command_resolved_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "command.exec".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![
            CapabilityId::from("agent.lifecycle"),
            CapabilityId::from("conversation.reply"),
            CapabilityId::from("command.exec"),
        ],
        required_evidence: vec!["execution".to_string(), "verification".to_string()],
        success_conditions: vec!["execution_artifact".to_string()],
        risk_class: "high".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "typed-runtime-route-frame".to_string(),
        embedding_model_id: "typed-runtime-route-frame".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "typed_runtime_route_frame".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "typed-runtime-route-frame-v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: true,
    }
}

fn typed_runtime_route_resolved_intent(frame: &RuntimeRouteFrame) -> Option<ResolvedIntentState> {
    if frame.direct_answer_allowed || !frame.output_intent.eq_ignore_ascii_case("tool_execution") {
        return None;
    }
    match frame.intent_id.trim().to_ascii_lowercase().as_str() {
        "software.install" | "software.install.desktop_app" => {
            Some(typed_runtime_local_install_resolved_intent())
        }
        "browser.interact" => Some(typed_runtime_browser_action_resolved_intent()),
        "command.exec" => Some(typed_runtime_shell_command_resolved_intent()),
        _ => None,
    }
}

fn ensure_typed_runtime_route_intent(agent_state: &mut AgentState) {
    let should_seed = agent_state
        .resolved_intent
        .as_ref()
        .map(|intent| intent.intent_id == "resolver.unclassified")
        .unwrap_or(true);
    if should_seed {
        let Some(frame) = agent_state.runtime_route_frame.as_ref() else {
            return;
        };
        let Some(resolved) = typed_runtime_route_resolved_intent(frame) else {
            return;
        };
        agent_state.resolved_intent = Some(resolved);
        agent_state.awaiting_intent_clarification = false;
    }
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

#[allow(dead_code)]
fn queue_root_playbook_delegate_request(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    crate::agentic::runtime::service::planning::playbook::queue_root_playbook_delegate_request(
        state,
        agent_state,
        session_id,
    )
}

#[allow(dead_code)]
fn queue_parent_playbook_await_request(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    crate::agentic::runtime::service::planning::playbook::queue_parent_playbook_await_request(
        state,
        agent_state,
        session_id,
    )
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

#[allow(dead_code)]
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
        crate::agentic::runtime::service::recovery::anti_loop::tier_as_str(target_tier),
        routing_decision.reason_code,
        routing_decision.source_failure
    );

    agent_state.current_tier = target_tier;

    if let Some(install_tool_call) = maybe_typed_runtime_install_resolve_tool_call(agent_state) {
        let final_visual_phash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
        Box::pin(
            crate::agentic::runtime::service::tool_execution::process_tool_output(
                service,
                state,
                agent_state,
                install_tool_call,
                final_visual_phash,
                "TypedRuntimeInstallResolve".to_string(),
                p.session_id,
                ctx.block_height,
                ctx.block_timestamp,
                call_context,
            ),
        )
        .await?;
        return Ok(());
    }

    if let Some(direct_inline_tool_call) =
        maybe_direct_inline_author_tool_call(service, state, agent_state, p.session_id, target_tier)
            .await?
    {
        let final_visual_phash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
        Box::pin(
            crate::agentic::runtime::service::tool_execution::process_tool_output(
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
            ),
        )
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

    Box::pin(tool_execution::process_tool_output(
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

async fn maybe_process_runtime_route_frame_dispatch(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    p: &StepAgentParams,
    ctx: &TxContext<'_>,
    call_context: ServiceCallContext<'_>,
) -> Result<bool, TransactionError> {
    let Some(tool_call) = maybe_typed_runtime_install_resolve_tool_call(agent_state)
        .or_else(|| maybe_typed_runtime_browser_navigate_tool_call(agent_state))
        .or_else(|| maybe_typed_runtime_shell_run_tool_call(agent_state))
    else {
        return Ok(false);
    };
    ensure_typed_runtime_route_intent(agent_state);

    let final_visual_phash = agent_state.last_screen_phash.unwrap_or([0u8; 32]);
    Box::pin(
        crate::agentic::runtime::service::tool_execution::process_tool_output(
            service,
            state,
            agent_state,
            tool_call,
            final_visual_phash,
            "TypedRuntimeRouteFrameDispatch".to_string(),
            p.session_id,
            ctx.block_height,
            ctx.block_timestamp,
            call_context,
        ),
    )
    .await?;
    Ok(true)
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
    ensure_typed_runtime_route_intent(&mut agent_state);
    if Box::pin(maybe_process_runtime_route_frame_dispatch(
        service,
        state,
        &mut agent_state,
        &p,
        ctx,
        call_context,
    ))
    .await?
    {
        persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
        return Ok(());
    }
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

    if Box::pin(maybe_process_runtime_route_frame_dispatch(
        service,
        state,
        &mut agent_state,
        &p,
        ctx,
        call_context,
    ))
    .await?
    {
        persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;
        return Ok(());
    }

    let rules = load_action_rules(state, p.session_id)?;
    if !agent_state.execution_queue.is_empty()
        && Box::pin(maybe_bootstrap_execution_queue(
            service,
            state,
            &mut agent_state,
            &p,
            ctx.block_height,
            ctx.block_timestamp,
            call_context,
            false,
        ))
        .await?
    {
        return Ok(());
    }
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
