// Path: crates/services/src/agentic/runtime/service/step/mod.rs

pub mod action;
pub mod anti_loop;
pub mod browser_completion;
pub mod cognition;
pub mod helpers;
pub mod incident;
pub mod intent_resolver;
pub mod ontology;
pub mod perception;
pub mod planner;
pub mod queue;
pub mod signals;
pub mod text_tokens;
pub mod visual;
pub mod worker;

use super::{RuntimeAgentService, ServiceCallContext};
// [FIX] Import actions module from parent service directory
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::agent_playbooks::builtin_agent_playbook;
use crate::agentic::runtime::keys::{
    get_mutation_receipt_ptr_key, get_parent_playbook_run_key, get_state_key, AGENT_POLICY_PREFIX,
};
use crate::agentic::runtime::runtime_secret;
use crate::agentic::runtime::service::actions;
use crate::agentic::runtime::service::lifecycle::maybe_seed_runtime_locality_context;
use crate::agentic::runtime::service::step::anti_loop::{
    choose_routing_tier, mutation_receipt_artifact_id, mutation_receipt_pointer_for_artifact_id,
};
use crate::agentic::runtime::service::step::helpers::default_safe_policy;
use crate::agentic::runtime::types::{AgentState, AgentStatus, ParentPlaybookRun, StepAgentParams};
use crate::agentic::runtime::utils::persist_agent_state;
use hex;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, ResolvedIntentState, StepTrace};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, KernelEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::json;
use std::time::Duration;

const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";
const STEP_ACTIVE_WINDOW_QUERY_TIMEOUT: Duration = Duration::from_millis(300);
const WAIT_FOR_INTENT_CLARIFICATION_PROMPT: &str =
    "System: WAIT_FOR_INTENT_CLARIFICATION. Intent confidence is too low to proceed safely. Please clarify the requested outcome.";

async fn emit_planner_fallback_evidence(
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
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
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

fn should_clear_stale_canonical_pending(
    agent_state: &AgentState,
    allow_runtime_secret_retry: bool,
) -> bool {
    agent_state.pending_tool_jcs.is_some()
        && agent_state.pending_approval.is_none()
        && !allow_runtime_secret_retry
}

fn pending_tool_is_browser_action(agent_state: &AgentState) -> bool {
    let Some(raw) = agent_state.pending_tool_jcs.as_ref() else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return false;
    };
    value
        .get("name")
        .and_then(|name| name.as_str())
        .map(|name| name.starts_with("browser__"))
        .unwrap_or(false)
}

fn is_web_research_intent(resolved_scope: IntentScopeProfile) -> bool {
    matches!(resolved_scope, IntentScopeProfile::WebResearch)
}

fn instruction_contract_slot_value<'a>(
    resolved: &'a ResolvedIntentState,
    slot_name: &str,
) -> Option<&'a str> {
    resolved
        .instruction_contract
        .as_ref()?
        .slot_bindings
        .iter()
        .find(|binding| binding.slot.trim().eq_ignore_ascii_case(slot_name))
        .and_then(|binding| binding.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn root_playbook_run_exists(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    resolved: &ResolvedIntentState,
) -> bool {
    let Some(playbook_id) = instruction_contract_slot_value(resolved, "playbook_id") else {
        return false;
    };
    let key = get_parent_playbook_run_key(&agent_state.session_id, playbook_id);
    state.get(&key).ok().flatten().is_some()
}

fn latest_root_playbook_child_session_id(
    state: &dyn StateAccess,
    agent_state: &AgentState,
) -> Option<[u8; 32]> {
    agent_state
        .child_session_ids
        .iter()
        .rev()
        .copied()
        .find(|child_session_id| {
            let key = get_state_key(child_session_id);
            state
                .get(&key)
                .ok()
                .flatten()
                .and_then(|bytes| codec::from_bytes_canonical::<AgentState>(&bytes).ok())
                .map(|child_state| {
                    child_state.parent_session_id == Some(agent_state.session_id)
                        && child_state.status == AgentStatus::Running
                })
                .unwrap_or(false)
        })
}

fn queue_root_playbook_delegate_request(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    let Some(resolved) = agent_state.resolved_intent.as_ref() else {
        return Ok(false);
    };
    if resolved
        .intent_id
        .trim()
        .eq_ignore_ascii_case("delegation.task")
        || agent_state.parent_session_id.is_some()
    {
        return Ok(false);
    }

    let Some(playbook_id) = instruction_contract_slot_value(resolved, "playbook_id") else {
        return Ok(false);
    };
    if builtin_agent_playbook(Some(playbook_id)).is_none()
        || root_playbook_run_exists(state, agent_state, resolved)
        || latest_root_playbook_child_session_id(state, agent_state).is_some()
    {
        return Ok(false);
    }

    let params = serde_jcs::to_vec(&json!({
        "goal": agent_state.goal,
        "budget": 0,
        "playbook_id": playbook_id,
        "template_id": instruction_contract_slot_value(resolved, "template_id"),
        "workflow_id": instruction_contract_slot_value(resolved, "workflow_id"),
        "role": serde_json::Value::Null,
        "success_criteria": serde_json::Value::Null,
        "merge_mode": serde_json::Value::Null,
        "expected_output": serde_json::Value::Null,
    }))
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::Custom("agent__delegate".to_string()),
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };
    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.push(request);
    Ok(true)
}

fn active_parent_playbook_child_session_id(
    state: &dyn StateAccess,
    agent_state: &AgentState,
) -> Option<[u8; 32]> {
    let resolved = agent_state.resolved_intent.as_ref()?;
    if resolved
        .intent_id
        .trim()
        .eq_ignore_ascii_case("delegation.task")
    {
        return None;
    }

    let playbook_id = instruction_contract_slot_value(resolved, "playbook_id")?;
    let key = get_parent_playbook_run_key(&agent_state.session_id, playbook_id);
    state
        .get(&key)
        .ok()
        .flatten()
        .and_then(|bytes| codec::from_bytes_canonical::<ParentPlaybookRun>(&bytes).ok())
        .and_then(|run| run.active_child_session_id)
        .or_else(|| latest_root_playbook_child_session_id(state, agent_state))
}

fn child_immediate_progress_await_eligible(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
) -> bool {
    let key = get_state_key(&child_session_id);
    state
        .get(&key)
        .ok()
        .flatten()
        .and_then(|bytes| codec::from_bytes_canonical::<AgentState>(&bytes).ok())
        .map(|_| true)
        .unwrap_or(false)
}

fn queue_parent_playbook_await_request(
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
) -> Result<bool, TransactionError> {
    let Some(child_session_id) = active_parent_playbook_child_session_id(state, agent_state) else {
        return Ok(false);
    };
    if !child_immediate_progress_await_eligible(state, child_session_id) {
        return Ok(false);
    }

    let params = serde_jcs::to_vec(&json!({
        "child_session_id_hex": hex::encode(child_session_id),
    }))
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::Custom("agent__await".to_string()),
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };
    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.push(request);
    Ok(true)
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

fn hydrate_step_state(
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

fn ensure_agent_running_or_resume_retry_pause(
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

async fn maybe_run_optimizer_recovery(
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

    let trace_key = crate::agentic::runtime::keys::get_trace_key(
        &session_id,
        agent_state.step_count.saturating_sub(1),
    );

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
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
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
        Err(e) => {
            log::error!("Optimizer failed to synthesize recovery: {}", e);
            Ok(false)
        }
    }
}

fn maybe_fail_step_resource_limits(
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

fn load_action_rules(
    state: &dyn StateAccess,
    session_id: [u8; 32],
) -> Result<ActionRules, TransactionError> {
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    Ok(state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy))
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

async fn resolve_step_intent_and_maybe_pause(
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
    let has_canonical_pending_resume = agent_state.pending_tool_jcs.is_some();
    let should_wait_for_clarification = !has_canonical_pending_resume
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
    agent_state.status = AgentStatus::Paused("Waiting for intent clarification".to_string());
    if !was_waiting_intent {
        let msg = ioi_types::app::agentic::ChatMessage {
            role: "assistant".to_string(),
            content: "I need a quick clarification before continuing. Please tell me exactly what outcome you want."
                .to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
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

async fn apply_planner_fallback_guards(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    rules: &ActionRules,
) -> Result<bool, TransactionError> {
    let planning_disabled =
        planner::planner_runtime_disabled_for_policy(rules.ontology_policy.planning_enabled);
    let mut planner_fallback_reason: Option<String> = None;
    let resolved_intent_snapshot = agent_state.resolved_intent.clone();
    if let Some(planner_state) = agent_state.planner_state.as_mut() {
        if planning_disabled {
            if planner::mark_planner_fallback(
                planner_state,
                planner::PLANNER_FALLBACK_REASON_PLANNING_DISABLED,
                resolved_intent_snapshot.as_ref(),
            ) {
                planner_fallback_reason =
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
                planner_fallback_reason = Some(reason);
            }
        }
    }
    if let Some(reason) = planner_fallback_reason.as_deref() {
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

fn maybe_enable_browser_lease_for_pending_action(
    service: &RuntimeAgentService,
    agent_state: &AgentState,
) {
    if pending_tool_is_browser_action(agent_state) {
        service.browser.set_lease(true);
    }
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
    let Some(raw_pending) = agent_state.pending_tool_jcs.as_ref() else {
        return Ok(false);
    };

    let allow_runtime_secret_retry = serde_json::from_slice::<AgentTool>(raw_pending)
        .ok()
        .map(|tool| matches!(tool, AgentTool::SysInstallPackage { .. }))
        .unwrap_or(false);
    if allow_runtime_secret_retry && agent_state.pending_approval.is_none() {
        let session_id_hex = hex::encode(session_id);
        if !runtime_secret::has_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD) {
            if !matches!(
                &agent_state.status,
                AgentStatus::Paused(reason)
                    if reason.eq_ignore_ascii_case("Waiting for sudo password")
            ) {
                log::warn!(
                    "Pending install retry without runtime secret for session {}; forcing pause.",
                    hex::encode(&session_id[..4])
                );
                agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
                persist_agent_state(state, key, agent_state, service.memory_runtime.as_ref())?;
            }
            return Ok(true);
        }
    }
    if agent_state.pending_approval.is_some() || allow_runtime_secret_retry {
        log::info!("Resuming canonical pending action.");
        actions::resume_pending_action(
            service,
            state,
            agent_state,
            session_id,
            block_height,
            block_timestamp,
            call_context,
        )
        .await?;
        return Ok(true);
    }
    if should_clear_stale_canonical_pending(agent_state, allow_runtime_secret_retry) {
        log::warn!(
            "Clearing stale canonical pending tool metadata for session {} (missing approval/runtime-secret resume context).",
            hex::encode(&session_id[..4])
        );
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_request_nonce = None;
        agent_state.pending_visual_hash = None;
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = None;
    }

    Ok(false)
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
    if !(agent_state.execution_queue.is_empty() && agent_state.pending_tool_jcs.is_none()) {
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

async fn maybe_process_ready_work(
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

#[cfg(test)]
mod tests {
    use super::{
        ensure_agent_running_or_resume_retry_pause, maybe_run_optimizer_recovery,
        queue_parent_playbook_await_request, queue_root_playbook_delegate_request,
        should_clear_stale_canonical_pending,
    };
    use crate::agentic::runtime::keys::{get_parent_playbook_run_key, get_state_key};
    use crate::agentic::runtime::service::RuntimeAgentService;
    use crate::agentic::runtime::types::{
        AgentMode, AgentState, AgentStatus, ExecutionTier, ParentPlaybookRun, ParentPlaybookStatus,
    };
    use async_trait::async_trait;
    use ioi_api::state::{StateAccess, StateScanIter};
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_types::app::agentic::{
        ArgumentOrigin, InstructionBindingKind, InstructionContract, InstructionSlotBinding,
        IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };
    use ioi_types::app::{ActionContext, ActionRequest, ActionTarget, ContextSlice};
    use ioi_types::codec;
    use ioi_types::error::{StateError, VmError};
    use std::collections::{BTreeMap, HashMap};
    use std::io::Cursor;
    use std::sync::Arc;

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "test".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: Default::default(),
            active_lens: None,
        }
    }

    #[derive(Default)]
    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let rows: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect();
            Ok(Box::new(rows.into_iter()))
        }
    }

    #[derive(Clone)]
    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            let mut img = image::ImageBuffer::<image::Rgba<u8>, Vec<u8>>::new(1, 1);
            img.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
            let mut bytes = Vec::new();
            img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
                .map_err(|error| VmError::HostError(format!("mock PNG encode failed: {error}")))?;
            Ok(bytes)
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            self.capture_screen(None).await
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Ok("<root/>".to_string())
        }

        async fn capture_context(
            &self,
            _intent: &ioi_types::app::ActionRequest,
        ) -> Result<ContextSlice, VmError> {
            Ok(ContextSlice {
                slice_id: [0u8; 32],
                frame_id: 0,
                chunks: vec![b"<root/>".to_vec()],
                mhnsw_root: [0u8; 32],
                traversal_proof: None,
                intent_id: [0u8; 32],
            })
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Ok(())
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn build_test_service() -> RuntimeAgentService {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let runtime = Arc::new(MockInferenceRuntime);
        RuntimeAgentService::new(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            runtime,
        )
    }

    fn resolved_web_intent_with_playbook(playbook_id: &str) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "web.research".to_string(),
            scope: IntentScopeProfile::WebResearch,
            band: IntentConfidenceBand::High,
            score: 0.99,
            top_k: vec![],
            required_capabilities: vec![],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "intent-matrix-test".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "v1".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [1u8; 32],
            tool_registry_hash: [2u8; 32],
            capability_ontology_hash: [3u8; 32],
            query_normalization_version: "intent-query-norm-v1".to_string(),
            matrix_source_hash: [4u8; 32],
            receipt_hash: [5u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: "web.research".to_string(),
                side_effect_mode: Default::default(),
                slot_bindings: vec![InstructionSlotBinding {
                    slot: "playbook_id".to_string(),
                    binding_kind: InstructionBindingKind::UserLiteral,
                    value: Some(playbook_id.to_string()),
                    origin: ArgumentOrigin::default(),
                    protected_slot_kind: Default::default(),
                }],
                negative_constraints: vec![],
                success_criteria: vec![],
            }),
            constrained: false,
        }
    }

    #[test]
    fn stale_canonical_pending_requires_cleanup_without_approval_or_runtime_retry() {
        let mut state = test_agent_state();
        state.pending_tool_jcs = Some(vec![1, 2, 3]);
        assert!(should_clear_stale_canonical_pending(&state, false));
    }

    #[test]
    fn canonical_pending_is_not_stale_when_runtime_retry_is_expected() {
        let mut state = test_agent_state();
        state.pending_tool_jcs = Some(vec![1, 2, 3]);
        assert!(!should_clear_stale_canonical_pending(&state, true));
    }

    #[test]
    fn retry_blocked_pause_auto_resumes_and_clears_recent_actions() {
        let mut state = test_agent_state();
        state.status = AgentStatus::Paused(
            "Retry blocked: unchanged AttemptKey for UnexpectedState".to_string(),
        );
        state.recent_actions = vec!["file__read".to_string()];

        ensure_agent_running_or_resume_retry_pause(&mut state).expect("retry pause should resume");

        assert_eq!(state.status, AgentStatus::Running);
        assert!(state.recent_actions.is_empty());
    }

    #[test]
    fn non_retry_pause_is_rejected_by_step_resumption_gate() {
        let mut state = test_agent_state();
        state.status = AgentStatus::Paused("Waiting for human approval".to_string());

        let error = ensure_agent_running_or_resume_retry_pause(&mut state)
            .expect_err("non-retry pause should not auto-resume");

        assert!(error
            .to_string()
            .contains("Agent not running: Paused(\"Waiting for human approval\")"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn optimizer_recovery_is_skipped_without_optimizer_configuration() {
        let service = build_test_service();
        let mut state = MockState::default();
        let mut agent_state = test_agent_state();
        agent_state.session_id = [0x44; 32];
        agent_state.consecutive_failures = 3;
        let session_id = agent_state.session_id;
        let key = get_state_key(&session_id);

        let triggered = maybe_run_optimizer_recovery(
            &service,
            &mut state,
            &mut agent_state,
            session_id,
            &key,
            7,
        )
        .await
        .expect("optimizer gate should evaluate");

        assert!(!triggered);
        assert_eq!(agent_state.consecutive_failures, 3);
        assert!(agent_state.active_skill_hash.is_none());
    }

    #[test]
    fn root_playbook_delegate_is_queued_without_cognition() {
        let session_id = [6u8; 32];
        let playbook_id = "citation_grounded_brief";
        let mut state = MockState::default();
        let mut agent_state = test_agent_state();
        agent_state.session_id = session_id;
        agent_state.goal = "Research the latest NIST PQC standards.".to_string();
        agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));

        let queued = queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
            .expect("queue delegate request");

        assert!(queued);
        assert_eq!(agent_state.execution_queue.len(), 1);
        assert_eq!(
            agent_state.execution_queue[0].target,
            ActionTarget::Custom("agent__delegate".to_string())
        );
        let args: serde_json::Value =
            serde_json::from_slice(&agent_state.execution_queue[0].params)
                .expect("delegate params should decode");
        assert_eq!(
            args.get("goal").and_then(|value| value.as_str()),
            Some("Research the latest NIST PQC standards.")
        );
        assert_eq!(
            args.get("playbook_id").and_then(|value| value.as_str()),
            Some(playbook_id)
        );

        let run = ParentPlaybookRun {
            parent_session_id: session_id,
            playbook_id: playbook_id.to_string(),
            playbook_label: "Citation-Grounded Brief".to_string(),
            topic: "latest NIST PQC standards".to_string(),
            status: ParentPlaybookStatus::Running,
            current_step_index: 0,
            active_child_session_id: Some([9u8; 32]),
            started_at_ms: 1,
            updated_at_ms: 1,
            completed_at_ms: None,
            steps: vec![],
        };
        state
            .insert(
                &get_parent_playbook_run_key(&session_id, playbook_id),
                &codec::to_bytes_canonical(&run).expect("playbook bytes"),
            )
            .expect("persist playbook run");
        agent_state.execution_queue.clear();

        let queued_again =
            queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
                .expect("queue delegate request after kickoff");

        assert!(!queued_again);
        assert!(agent_state.execution_queue.is_empty());
        state
            .delete(&get_parent_playbook_run_key(&session_id, playbook_id))
            .expect("delete playbook run");

        let child_session_id = [10u8; 32];
        let mut child_state = test_agent_state();
        child_state.session_id = child_session_id;
        child_state.parent_session_id = Some(session_id);
        state
            .insert(
                &get_state_key(&child_session_id),
                &codec::to_bytes_canonical(&child_state).expect("child bytes"),
            )
            .expect("persist child state");
        agent_state.child_session_ids.push(child_session_id);

        let queued_with_child =
            queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
                .expect("queue delegate request after child spawn");

        assert!(!queued_with_child);
        assert!(agent_state.execution_queue.is_empty());
    }

    #[test]
    fn active_parent_playbook_child_gets_single_startup_await_without_cognition() {
        let session_id = [7u8; 32];
        let child_session_id = [8u8; 32];
        let playbook_id = "citation_grounded_brief";
        let mut state = MockState::default();
        let run = ParentPlaybookRun {
            parent_session_id: session_id,
            playbook_id: playbook_id.to_string(),
            playbook_label: "Citation-Grounded Brief".to_string(),
            topic: "latest NIST PQC standards".to_string(),
            status: ParentPlaybookStatus::Running,
            current_step_index: 0,
            active_child_session_id: Some(child_session_id),
            started_at_ms: 1,
            updated_at_ms: 1,
            completed_at_ms: None,
            steps: vec![],
        };
        state
            .insert(
                &get_parent_playbook_run_key(&session_id, playbook_id),
                &codec::to_bytes_canonical(&run).expect("playbook bytes"),
            )
            .expect("persist playbook run");

        let mut agent_state = test_agent_state();
        agent_state.session_id = session_id;
        agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));
        let mut child_state = test_agent_state();
        child_state.session_id = child_session_id;
        state
            .insert(
                &get_state_key(&child_session_id),
                &codec::to_bytes_canonical(&child_state).expect("child bytes"),
            )
            .expect("persist child state");

        let queued = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
            .expect("queue await request");

        assert!(queued);
        assert_eq!(agent_state.execution_queue.len(), 1);
        assert_eq!(
            agent_state.execution_queue[0].target,
            ActionTarget::Custom("agent__await".to_string())
        );
        let args: serde_json::Value =
            serde_json::from_slice(&agent_state.execution_queue[0].params)
                .expect("await params should decode");
        assert_eq!(
            args.get("child_session_id_hex")
                .and_then(|value| value.as_str()),
            Some(hex::encode(child_session_id).as_str())
        );

        child_state.step_count = 1;
        state
            .insert(
                &get_state_key(&child_session_id),
                &codec::to_bytes_canonical(&child_state).expect("child bytes"),
            )
            .expect("persist updated child state");
        agent_state.execution_queue.clear();

        let queued_again =
            queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
                .expect("queue await request after child start");

        assert!(queued_again);
        assert_eq!(agent_state.execution_queue.len(), 1);
        agent_state.execution_queue.clear();

        child_state.status = AgentStatus::Completed(Some(
            "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)".to_string(),
        ));
        state
            .insert(
                &get_state_key(&child_session_id),
                &codec::to_bytes_canonical(&child_state).expect("child bytes"),
            )
            .expect("persist completed child state");

        let queued_terminal =
            queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
                .expect("queue await request after child completion");

        assert!(queued_terminal);
        assert_eq!(agent_state.execution_queue.len(), 1);
        agent_state.execution_queue.clear();
        child_state.status = AgentStatus::Running;
        child_state.pending_tool_call =
            Some("{\"name\":\"agent__complete\",\"arguments\":{\"result\":\"done\"}}".to_string());
        state
            .insert(
                &get_state_key(&child_session_id),
                &codec::to_bytes_canonical(&child_state).expect("child bytes"),
            )
            .expect("persist pending child state");

        let queued_pending =
            queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
                .expect("queue await request after child pending tool");

        assert!(queued_pending);
        assert_eq!(agent_state.execution_queue.len(), 1);
        agent_state.execution_queue.clear();
        child_state.pending_tool_call = None;

        child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::Custom("web__read".to_string()),
            params: serde_jcs::to_vec(&serde_json::json!({
                "url": "https://csrc.nist.gov/projects/post-quantum-cryptography"
            }))
            .expect("queued child params"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(child_session_id),
                window_id: None,
            },
            nonce: 1,
        });
        state
            .insert(
                &get_state_key(&child_session_id),
                &codec::to_bytes_canonical(&child_state).expect("child bytes"),
            )
            .expect("persist queued child state");

        let queued_followup =
            queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
                .expect("queue await request for queued child follow-up");

        assert!(queued_followup);
        assert_eq!(agent_state.execution_queue.len(), 1);
        state
            .delete(&get_parent_playbook_run_key(&session_id, playbook_id))
            .expect("delete playbook run");

        let fallback_child_session_id = [9u8; 32];
        let mut fallback_agent_state = test_agent_state();
        fallback_agent_state.session_id = session_id;
        fallback_agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));
        fallback_agent_state
            .child_session_ids
            .push(fallback_child_session_id);
        let mut fallback_child_state = test_agent_state();
        fallback_child_state.session_id = fallback_child_session_id;
        fallback_child_state.parent_session_id = Some(session_id);
        state
            .insert(
                &get_state_key(&fallback_child_session_id),
                &codec::to_bytes_canonical(&fallback_child_state).expect("fallback child bytes"),
            )
            .expect("persist fallback child state");

        let fallback_queued =
            queue_parent_playbook_await_request(&state, &mut fallback_agent_state, session_id)
                .expect("queue await request from child fallback");

        assert!(fallback_queued);
        assert_eq!(fallback_agent_state.execution_queue.len(), 1);
        let fallback_args: serde_json::Value =
            serde_json::from_slice(&fallback_agent_state.execution_queue[0].params)
                .expect("fallback await params should decode");
        assert_eq!(
            fallback_args
                .get("child_session_id_hex")
                .and_then(|value| value.as_str()),
            Some(hex::encode(fallback_child_session_id).as_str())
        );
    }
}
