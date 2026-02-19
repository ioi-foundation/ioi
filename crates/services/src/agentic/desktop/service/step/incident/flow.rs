use super::core::{
    action_fingerprint_from_tool_jcs, canonical_tool_name, now_millis, tool_fingerprint,
    ApprovalDirective, IncidentDirective, IncidentReceiptFields, IncidentState, PendingGate,
};
use super::recovery::{
    build_planner_prompt, deterministic_recovery_tool, effective_forbidden_tools,
    is_recoverable_failure, policy_max_transitions, policy_strategy_override,
    queue_recovery_action, queue_root_retry, validate_recovery_tool,
};
use super::store::{clear_incident_state, load_incident_state, persist_incident_state};
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::step::anti_loop::FailureClass;
use crate::agentic::desktop::service::step::ontology::{
    classify_intent_from_resolved, default_strategy_for, GateState, IncidentStage, IntentClass,
    ResolutionAction, StrategyNode,
};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::tools::discover_tools;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use crate::agentic::rules::{ActionRules, ApprovalMode};
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{InferenceOptions, LlmToolDefinition};
use ioi_types::error::TransactionError;
use serde_json::json;
use std::collections::BTreeSet;

pub fn should_enter_incident_recovery(
    failure_class: Option<FailureClass>,
    policy_decision: &str,
    stop_condition_hit: bool,
    incident_state: Option<&IncidentState>,
) -> bool {
    if stop_condition_hit {
        return false;
    }
    if matches!(policy_decision, "require_approval" | "denied") {
        return false;
    }
    let Some(class) = failure_class else {
        return false;
    };
    if !is_recoverable_failure(class) {
        return false;
    }
    if let Some(incident) = incident_state {
        if incident.active && incident.transitions_used >= incident.max_transitions {
            return false;
        }
    }
    true
}

pub async fn emit_incident_chat_progress(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    block_height: u64,
    content: impl Into<String>,
) -> Result<(), TransactionError> {
    let msg = ioi_types::app::agentic::ChatMessage {
        role: "system".to_string(),
        content: content.into(),
        timestamp: now_millis(),
        trace_hash: None,
    };
    let _ = service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;
    Ok(())
}

pub fn incident_receipt_fields(incident_state: Option<&IncidentState>) -> IncidentReceiptFields {
    let Some(incident) = incident_state else {
        return IncidentReceiptFields::default();
    };
    IncidentReceiptFields {
        intent_class: incident.intent_class.clone(),
        incident_id: incident.incident_id.clone(),
        incident_stage: incident.stage.clone(),
        strategy_name: incident.strategy_name.clone(),
        strategy_node: incident.strategy_cursor.clone(),
        gate_state: incident.gate_state.clone(),
        resolution_action: incident.resolution_action.clone(),
    }
}

pub async fn advance_incident_after_action_outcome(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    executed_retry_hash: &str,
    executed_tool_jcs: &[u8],
    success: bool,
    block_height: u64,
    error_msg: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> Result<IncidentDirective, TransactionError> {
    let Some(mut incident_state) = load_incident_state(state, &session_id)? else {
        verification_checks.push("incident_active=false".to_string());
        return Ok(IncidentDirective::Noop);
    };

    if !incident_state.active {
        verification_checks.push("incident_active=false".to_string());
        return Ok(IncidentDirective::Noop);
    }

    let stage_before = incident_state.stage.clone();
    let executed_fingerprint = action_fingerprint_from_tool_jcs(executed_tool_jcs);
    let is_pending_remedy = incident_state
        .pending_remedy_fingerprint
        .as_deref()
        .map(|fp| fp == executed_fingerprint.as_str())
        .unwrap_or(false);

    if is_pending_remedy {
        if success {
            incident_state.pending_remedy_fingerprint = None;
            incident_state.pending_remedy_tool_jcs = None;
            incident_state.stage = IncidentStage::RetryRoot.as_str().to_string();
            incident_state.strategy_cursor = StrategyNode::RetryRootAction.as_str().to_string();
            incident_state.gate_state = GateState::Cleared.as_str().to_string();
            incident_state.resolution_action = ResolutionAction::RetryRoot.as_str().to_string();
            let queued_retry = if incident_state.retry_enqueued {
                false
            } else {
                queue_root_retry(agent_state, session_id, &incident_state.root_tool_jcs)?
            };
            incident_state.retry_enqueued = incident_state.retry_enqueued || queued_retry;
            let stage_after = incident_state.stage.clone();
            persist_incident_state(state, &session_id, &incident_state)?;
            emit_incident_chat_progress(
                service,
                session_id,
                block_height,
                if queued_retry {
                    format!(
                        "System: Remedy succeeded for incident '{}'; queued root retry.",
                        incident_state.incident_id
                    )
                } else {
                    format!(
                        "System: Remedy succeeded for incident '{}'; root retry already queued.",
                        incident_state.incident_id
                    )
                },
            )
            .await?;
            verification_checks.push("incident_active=true".to_string());
            verification_checks.push(format!("incident_id={}", incident_state.incident_id));
            verification_checks.push(format!("incident_stage_before={}", stage_before));
            verification_checks.push(format!("incident_stage_after={}", stage_after));
            verification_checks.push(format!(
                "incident_transitions_used={}",
                incident_state.transitions_used
            ));
            verification_checks.push(format!(
                "incident_budget_remaining={}",
                incident_state
                    .max_transitions
                    .saturating_sub(incident_state.transitions_used)
            ));
            verification_checks.push(format!(
                "queued_retry_after_remedy_success={}",
                queued_retry
            ));
            return Ok(if queued_retry {
                IncidentDirective::QueueActions
            } else {
                IncidentDirective::Noop
            });
        }

        incident_state.pending_remedy_fingerprint = None;
        incident_state.pending_remedy_tool_jcs = None;
        incident_state.retry_enqueued = false;
        incident_state.stage = IncidentStage::Diagnose.as_str().to_string();
        incident_state.strategy_cursor = StrategyNode::DiagnoseFailure.as_str().to_string();
        incident_state.gate_state = GateState::Cleared.as_str().to_string();
        incident_state.resolution_action = ResolutionAction::ExecuteRemedy.as_str().to_string();
        incident_state.root_error = error_msg.map(|v| v.to_string());
        let stage_after = incident_state.stage.clone();
        persist_incident_state(state, &session_id, &incident_state)?;
        emit_incident_chat_progress(
            service,
            session_id,
            block_height,
            format!(
                "System: Remedy failed for incident '{}'; selecting next strategy node.",
                incident_state.incident_id
            ),
        )
        .await?;
        verification_checks.push("incident_active=true".to_string());
        verification_checks.push(format!("incident_id={}", incident_state.incident_id));
        verification_checks.push(format!("incident_stage_before={}", stage_before));
        verification_checks.push(format!("incident_stage_after={}", stage_after));
        verification_checks.push("queued_retry_after_remedy_success=false".to_string());
        return Ok(IncidentDirective::Noop);
    }

    if success && incident_state.root_retry_hash == executed_retry_hash {
        incident_state.stage = IncidentStage::Resolved.as_str().to_string();
        incident_state.gate_state = GateState::Cleared.as_str().to_string();
        incident_state.resolution_action = ResolutionAction::MarkResolved.as_str().to_string();
        emit_incident_chat_progress(
            service,
            session_id,
            block_height,
            format!(
                "System: Incident '{}' resolved after {} transition(s).",
                incident_state.incident_id, incident_state.transitions_used
            ),
        )
        .await?;
        clear_incident_state(state, &session_id)?;
        verification_checks.push("incident_active=false".to_string());
        verification_checks.push("incident_resolved=true".to_string());
        verification_checks.push(format!("incident_stage_before={}", stage_before));
        verification_checks.push(format!(
            "incident_stage_after={}",
            IncidentStage::Resolved.as_str()
        ));
        return Ok(IncidentDirective::MarkResolved);
    }

    let stage_after = incident_state.stage.clone();
    persist_incident_state(state, &session_id, &incident_state)?;
    verification_checks.push("incident_active=true".to_string());
    verification_checks.push(format!("incident_id={}", incident_state.incident_id));
    verification_checks.push(format!("incident_stage_before={}", stage_before));
    verification_checks.push(format!("incident_stage_after={}", stage_after));
    verification_checks.push(format!(
        "incident_transitions_used={}",
        incident_state.transitions_used
    ));
    verification_checks.push(format!(
        "incident_budget_remaining={}",
        incident_state
            .max_transitions
            .saturating_sub(incident_state.transitions_used)
    ));
    Ok(IncidentDirective::Noop)
}

pub fn register_pending_approval(
    state: &mut dyn StateAccess,
    rules: &ActionRules,
    agent_state: &AgentState,
    session_id: [u8; 32],
    root_retry_hash: &str,
    root_tool_name: &str,
    root_tool_jcs: &[u8],
    action_fingerprint: &str,
    request_hash: &str,
) -> Result<ApprovalDirective, TransactionError> {
    let intent = classify_intent_from_resolved(
        agent_state.resolved_intent.as_ref(),
        &agent_state.goal,
        root_tool_name,
        agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.as_deref()),
    );
    let failure = FailureClass::PermissionOrApprovalRequired;
    let (mut strategy_name, strategy_node) = default_strategy_for(intent, failure);
    if let Some(ov) = policy_strategy_override(rules, intent, failure) {
        strategy_name = ov;
    }
    let max_transitions = policy_max_transitions(rules, intent, failure);
    let loaded_incident = load_incident_state(state, &session_id)?;
    let mut incident = match loaded_incident {
        Some(current) if current.active => current,
        _ => IncidentState::new(
            root_retry_hash,
            root_tool_jcs,
            root_tool_name,
            intent,
            failure,
            None,
            strategy_name,
            strategy_node,
            max_transitions,
            agent_state.step_count,
        ),
    };

    // Preserve root incident identity across queued remedy/retry approval interceptions.
    incident.max_transitions = max_transitions;
    if incident.root_retry_hash.is_empty() {
        incident.root_retry_hash = root_retry_hash.to_string();
    }
    if incident.root_tool_name.is_empty() {
        incident.root_tool_name = root_tool_name.to_string();
    }
    if incident.root_tool_jcs.is_empty() {
        incident.root_tool_jcs = root_tool_jcs.to_vec();
    }
    if incident.intent_class.is_empty() {
        incident.intent_class = intent.as_str().to_string();
    }
    if incident.root_failure_class.is_empty() {
        incident.root_failure_class = failure.as_str().to_string();
    }

    let mut prompted_count = incident
        .pending_gate
        .as_ref()
        .filter(|pending| {
            pending.request_hash == request_hash && pending.action_fingerprint == action_fingerprint
        })
        .map(|pending| pending.prompted_count)
        .unwrap_or(0);

    let approval_mode = rules.ontology_policy.approval_mode;
    let bounded_limit = rules
        .ontology_policy
        .tool_preferences
        .bounded_reprompt_limit
        .max(1);

    let directive = match approval_mode {
        ApprovalMode::SinglePending => {
            if prompted_count > 0 {
                ApprovalDirective::SuppressDuplicatePrompt
            } else {
                ApprovalDirective::PromptUser
            }
        }
        ApprovalMode::BoundedReprompt => {
            if prompted_count >= bounded_limit {
                ApprovalDirective::PauseLoop
            } else {
                ApprovalDirective::PromptUser
            }
        }
        ApprovalMode::AlwaysPrompt => ApprovalDirective::PromptUser,
    };

    if matches!(directive, ApprovalDirective::PromptUser) {
        prompted_count = prompted_count.saturating_add(1);
        incident.transitions_used = incident.transitions_used.saturating_add(1);
    }

    incident.stage = IncidentStage::AwaitApproval.as_str().to_string();
    if incident.strategy_name.is_empty() {
        incident.strategy_name = strategy_name.as_str().to_string();
    }
    if incident.strategy_cursor.is_empty() {
        incident.strategy_cursor = strategy_node.as_str().to_string();
    }
    incident.gate_state = GateState::Pending.as_str().to_string();
    incident.resolution_action = ResolutionAction::WaitForUser.as_str().to_string();
    incident.pending_gate = Some(PendingGate {
        request_hash: request_hash.to_string(),
        action_fingerprint: action_fingerprint.to_string(),
        prompted_count,
        updated_at_ms: now_millis(),
    });

    if matches!(directive, ApprovalDirective::PauseLoop) {
        incident.stage = IncidentStage::PausedForUser.as_str().to_string();
        incident.gate_state = GateState::Denied.as_str().to_string();
        incident.resolution_action = ResolutionAction::Pause.as_str().to_string();
    }

    persist_incident_state(state, &session_id, &incident)?;
    Ok(directive)
}

pub fn mark_gate_approved(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let Some(mut incident) = load_incident_state(state, &session_id)? else {
        return Ok(());
    };
    incident.gate_state = GateState::Approved.as_str().to_string();
    incident.pending_gate = None;
    incident.resolution_action = ResolutionAction::RetryRoot.as_str().to_string();
    incident.stage = IncidentStage::RetryRoot.as_str().to_string();
    persist_incident_state(state, &session_id, &incident)?;
    Ok(())
}

pub fn mark_gate_denied(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let Some(mut incident) = load_incident_state(state, &session_id)? else {
        return Ok(());
    };
    incident.gate_state = GateState::Denied.as_str().to_string();
    incident.pending_gate = None;
    incident.resolution_action = ResolutionAction::Pause.as_str().to_string();
    incident.stage = IncidentStage::PausedForUser.as_str().to_string();
    persist_incident_state(state, &session_id, &incident)?;
    Ok(())
}

pub fn mark_incident_retry_root(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
) -> Result<(), TransactionError> {
    let Some(mut incident) = load_incident_state(state, &session_id)? else {
        return Ok(());
    };
    incident.active = true;
    incident.stage = IncidentStage::RetryRoot.as_str().to_string();
    incident.strategy_cursor = StrategyNode::RetryRootAction.as_str().to_string();
    incident.gate_state = GateState::Cleared.as_str().to_string();
    incident.resolution_action = ResolutionAction::RetryRoot.as_str().to_string();
    incident.pending_gate = None;
    persist_incident_state(state, &session_id, &incident)?;
    Ok(())
}

pub fn mark_incident_wait_for_user(
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    resolution_action: &str,
    root_failure_class: FailureClass,
    root_error: Option<&str>,
) -> Result<(), TransactionError> {
    let Some(mut incident) = load_incident_state(state, &session_id)? else {
        return Ok(());
    };

    incident.active = true;
    incident.stage = IncidentStage::PausedForUser.as_str().to_string();
    incident.strategy_cursor = StrategyNode::PauseForUser.as_str().to_string();
    incident.gate_state = GateState::Cleared.as_str().to_string();
    incident.resolution_action = resolution_action.to_string();
    incident.root_failure_class = root_failure_class.as_str().to_string();
    incident.root_error = root_error.map(|v| v.to_string());
    incident.pending_gate = None;
    incident.pending_remedy_fingerprint = None;
    incident.pending_remedy_tool_jcs = None;
    incident.retry_enqueued = false;
    persist_incident_state(state, &session_id, &incident)?;
    Ok(())
}

pub async fn start_or_continue_incident_recovery(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    rules: &ActionRules,
    root_retry_hash: &str,
    root_tool_name: &str,
    root_tool_jcs: &[u8],
    root_failure_class: FailureClass,
    root_error: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> Result<IncidentDirective, TransactionError> {
    let intent = classify_intent_from_resolved(
        agent_state.resolved_intent.as_ref(),
        &agent_state.goal,
        root_tool_name,
        agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.as_deref()),
    );
    let (mut strategy_name, mut strategy_node) = default_strategy_for(intent, root_failure_class);
    if let Some(ov) = policy_strategy_override(rules, intent, root_failure_class) {
        strategy_name = ov;
    }
    let max_transitions = policy_max_transitions(rules, intent, root_failure_class);

    let loaded_incident = load_incident_state(state, &session_id)?;
    let mut incident_state = match loaded_incident.as_ref() {
        Some(current)
            if current.active
                && (current.root_tool_jcs == root_tool_jcs
                    || current.root_retry_hash == root_retry_hash) =>
        {
            current.clone()
        }
        _ => IncidentState::new(
            root_retry_hash,
            root_tool_jcs,
            root_tool_name,
            intent,
            root_failure_class,
            root_error,
            strategy_name,
            strategy_node,
            max_transitions,
            agent_state.step_count,
        ),
    };

    let incident_id_stable = loaded_incident
        .as_ref()
        .map(|prior| prior.incident_id == incident_state.incident_id)
        .unwrap_or(true);
    let stage_before = incident_state.stage.clone();

    incident_state.root_error = root_error.map(|v| v.to_string());
    incident_state.intent_class = intent.as_str().to_string();
    incident_state.root_failure_class = root_failure_class.as_str().to_string();
    incident_state.max_transitions = max_transitions;
    incident_state.strategy_name = strategy_name.as_str().to_string();

    if incident_state.transitions_used >= incident_state.max_transitions {
        incident_state.active = false;
        incident_state.stage = IncidentStage::Exhausted.as_str().to_string();
        incident_state.gate_state = GateState::Cleared.as_str().to_string();
        incident_state.resolution_action = ResolutionAction::MarkExhausted.as_str().to_string();
        persist_incident_state(state, &session_id, &incident_state)?;
        emit_incident_chat_progress(
            service,
            session_id,
            block_height,
            format!(
                "System: Incident '{}' exhausted transition budget ({}/{}).",
                incident_state.incident_id,
                incident_state.transitions_used,
                incident_state.max_transitions
            ),
        )
        .await?;
        verification_checks.push("incident_active=false".to_string());
        verification_checks.push("incident_exhausted=true".to_string());
        verification_checks.push("incident_budget_remaining=0".to_string());
        return Ok(IncidentDirective::MarkExhausted);
    }

    let active_window_title = if let Some(os_driver) = service.os_driver.as_ref() {
        match os_driver.get_active_window_info().await {
            Ok(Some(win)) => format!("{} ({})", win.title, win.app_name),
            Ok(None) => "Unknown".to_string(),
            Err(_) => "Unknown".to_string(),
        }
    } else {
        "Unknown".to_string()
    };
    let tools = discover_tools(
        state,
        service.scs.as_deref(),
        service.mcp.as_deref(),
        &agent_state.goal,
        service.fast_inference.clone(),
        agent_state.current_tier,
        &active_window_title,
        agent_state.resolved_intent.as_ref(),
    )
    .await;

    let available_tool_names: BTreeSet<String> =
        tools.iter().map(|tool| tool.name.clone()).collect();
    let forbidden_tools = effective_forbidden_tools(rules);
    let planner_tools: Vec<LlmToolDefinition> = tools
        .into_iter()
        .filter(|tool| !forbidden_tools.contains(&tool.name))
        .collect();

    let mut chosen_tool =
        deterministic_recovery_tool(&available_tool_names, &incident_state, agent_state, rules)?;

    if chosen_tool.is_none() {
        if matches!(intent, IntentClass::BrowserTask) {
            incident_state.active = true;
            incident_state.stage = IncidentStage::PausedForUser.as_str().to_string();
            incident_state.strategy_cursor = StrategyNode::PauseForUser.as_str().to_string();
            incident_state.gate_state = GateState::Cleared.as_str().to_string();
            incident_state.resolution_action = ResolutionAction::Pause.as_str().to_string();
            incident_state.pending_remedy_fingerprint = None;
            incident_state.pending_remedy_tool_jcs = None;
            incident_state.retry_enqueued = false;
            incident_state.root_error = Some(format!(
                "Deterministic BrowserTask recovery unavailable for failure class {}.",
                root_failure_class.as_str()
            ));
            agent_state.status = AgentStatus::Paused(
                "Browser recovery requires deterministic remedy, but none was available."
                    .to_string(),
            );
            persist_incident_state(state, &session_id, &incident_state)?;
            emit_incident_chat_progress(
                service,
                session_id,
                block_height,
                format!(
                    "System: BrowserTask incident '{}' has no deterministic remedy. Pausing for user guidance.",
                    incident_state.incident_id
                ),
            )
            .await?;
            verification_checks.push("incident_active=true".to_string());
            verification_checks.push(format!("incident_id_stable={}", incident_id_stable));
            verification_checks.push(format!("incident_id={}", incident_state.incident_id));
            verification_checks.push(format!("incident_stage_before={}", stage_before));
            verification_checks.push(format!("incident_stage_after={}", incident_state.stage));
            verification_checks.push(format!(
                "incident_transitions_used={}",
                incident_state.transitions_used
            ));
            verification_checks.push(format!(
                "incident_budget_remaining={}",
                incident_state
                    .max_transitions
                    .saturating_sub(incident_state.transitions_used)
            ));
            verification_checks.push(format!("incident_intent={}", incident_state.intent_class));
            verification_checks.push("browser_recovery_deterministic_only=true".to_string());
            verification_checks.push("queued_retry_after_remedy_success=false".to_string());
            return Ok(IncidentDirective::Noop);
        }

        if planner_tools.is_empty() {
            return Err(TransactionError::Invalid(
                "No eligible incident recovery tools available".to_string(),
            ));
        }

        let prompt = build_planner_prompt(&incident_state, &forbidden_tools);
        let messages = json!([
            { "role": "system", "content": prompt },
            { "role": "user", "content": "Choose the next recovery action now." }
        ]);
        let input = serde_json::to_vec(&messages)
            .map_err(|e| TransactionError::Serialization(e.to_string()))?;
        let options = InferenceOptions {
            temperature: 0.0,
            json_mode: true,
            max_tokens: 384,
            tools: planner_tools,
        };
        let output = service
            .reasoning_inference
            .execute_inference(
                [0u8; 32],
                &service
                    .prepare_cloud_inference_input(
                        Some(session_id),
                        "desktop_agent",
                        "model_hash:0000000000000000000000000000000000000000000000000000000000000000",
                        &input,
                    )
                    .await?,
                options,
            )
            .await
            .map_err(|e| {
                TransactionError::Invalid(format!("Incident planner inference failed: {}", e))
            })?;
        let raw_output = String::from_utf8_lossy(&output).to_string();
        chosen_tool = Some(middleware::normalize_tool_call(&raw_output).map_err(|e| {
            TransactionError::Invalid(format!("Incident planner output invalid: {}", e))
        })?);
    }

    let recovery_tool = chosen_tool.ok_or_else(|| {
        TransactionError::Invalid("Incident planner could not choose a recovery tool".to_string())
    })?;

    validate_recovery_tool(
        &recovery_tool,
        &available_tool_names,
        &forbidden_tools,
        &incident_state.visited_node_fingerprints,
    )?;

    let recovery_tool_jcs = serde_jcs::to_vec(&recovery_tool)
        .or_else(|_| serde_json::to_vec(&recovery_tool))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let recovery_fingerprint = action_fingerprint_from_tool_jcs(&recovery_tool_jcs);
    let fp = tool_fingerprint(&recovery_tool);
    incident_state.visited_node_fingerprints.push(fp);
    incident_state.transitions_used = incident_state.transitions_used.saturating_add(1);
    incident_state.stage = IncidentStage::ExecuteRemedy.as_str().to_string();
    strategy_node = match StrategyNode::from_str(&incident_state.strategy_cursor) {
        StrategyNode::DiagnoseFailure => StrategyNode::DiscoverRemedy,
        StrategyNode::DiscoverRemedy => StrategyNode::RetryRootAction,
        StrategyNode::InstallDependency => StrategyNode::RetryRootAction,
        StrategyNode::RefreshContext => StrategyNode::RetryRootAction,
        other => other,
    };
    incident_state.strategy_cursor = strategy_node.as_str().to_string();
    incident_state.gate_state = GateState::Cleared.as_str().to_string();
    incident_state.resolution_action = ResolutionAction::ExecuteRemedy.as_str().to_string();
    incident_state.pending_remedy_fingerprint = Some(recovery_fingerprint);
    incident_state.pending_remedy_tool_jcs = Some(recovery_tool_jcs);
    incident_state.retry_enqueued = false;
    persist_incident_state(state, &session_id, &incident_state)?;

    queue_recovery_action(agent_state, session_id, &recovery_tool)?;
    agent_state.status = AgentStatus::Running;

    emit_incident_chat_progress(
        service,
        session_id,
        block_height,
        format!(
            "System: Incident '{}' transition {}/{} using strategy {} node {}.",
            incident_state.incident_id,
            incident_state.transitions_used,
            incident_state.max_transitions,
            incident_state.strategy_name,
            incident_state.strategy_cursor
        ),
    )
    .await?;
    emit_incident_chat_progress(
        service,
        session_id,
        block_height,
        format!(
            "System: Selected recovery action `{}`. Root retry will be queued only after remedy success.",
            canonical_tool_name(&recovery_tool)
        ),
    )
    .await?;

    verification_checks.push("incident_active=true".to_string());
    verification_checks.push(format!("incident_id_stable={}", incident_id_stable));
    verification_checks.push(format!("incident_id={}", incident_state.incident_id));
    verification_checks.push(format!("incident_stage_before={}", stage_before));
    verification_checks.push(format!("incident_stage_after={}", incident_state.stage));
    verification_checks.push(format!(
        "incident_transitions_used={}",
        incident_state.transitions_used
    ));
    verification_checks.push(format!(
        "incident_budget_remaining={}",
        incident_state
            .max_transitions
            .saturating_sub(incident_state.transitions_used)
    ));
    verification_checks.push(format!("incident_intent={}", incident_state.intent_class));
    verification_checks.push(format!(
        "incident_strategy={}",
        incident_state.strategy_name
    ));
    verification_checks.push(format!(
        "incident_strategy_node={}",
        incident_state.strategy_cursor
    ));
    verification_checks.push("queued_retry_after_remedy_success=false".to_string());

    Ok(IncidentDirective::QueueActions)
}
