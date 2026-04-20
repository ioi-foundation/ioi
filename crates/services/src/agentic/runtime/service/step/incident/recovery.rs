use super::core::{
    canonical_tool_args, canonical_tool_name, tool_fingerprint, IncidentState,
    FORBIDDEN_LIFECYCLE_TOOLS,
};
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::middleware;
use crate::agentic::runtime::service::step::anti_loop::FailureClass;
use crate::agentic::runtime::service::step::ontology::{IntentClass, StrategyName};
use crate::agentic::runtime::types::AgentState;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::error::TransactionError;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";

pub(super) fn policy_max_transitions(
    rules: &ActionRules,
    intent_class: IntentClass,
    failure_class: FailureClass,
) -> u32 {
    let mut max = rules.ontology_policy.max_incident_transitions.max(1);
    for ov in &rules.ontology_policy.intent_failure_overrides {
        if !ov.intent_class.eq_ignore_ascii_case(intent_class.as_str())
            || !ov
                .failure_class
                .eq_ignore_ascii_case(failure_class.as_str())
        {
            continue;
        }
        if let Some(override_max) = ov.max_transitions {
            max = override_max.max(1);
        }
    }
    max
}

pub(super) fn policy_strategy_override(
    rules: &ActionRules,
    intent_class: IntentClass,
    failure_class: FailureClass,
) -> Option<StrategyName> {
    for ov in &rules.ontology_policy.intent_failure_overrides {
        if !ov.intent_class.eq_ignore_ascii_case(intent_class.as_str())
            || !ov
                .failure_class
                .eq_ignore_ascii_case(failure_class.as_str())
        {
            continue;
        }
        if let Some(name) = ov.strategy_name.as_deref() {
            return Some(StrategyName::from_str(name));
        }
    }
    None
}

pub(super) fn effective_forbidden_tools(rules: &ActionRules) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for name in FORBIDDEN_LIFECYCLE_TOOLS {
        set.insert((*name).to_string());
    }
    for name in &rules
        .ontology_policy
        .tool_preferences
        .forbidden_remediation_tools
    {
        if !name.trim().is_empty() {
            set.insert(name.trim().to_string());
        }
    }
    set
}

pub(super) fn is_recoverable_failure(class: FailureClass) -> bool {
    !matches!(
        class,
        FailureClass::PermissionOrApprovalRequired | FailureClass::UserInterventionNeeded
    )
}

fn parse_launch_app_name(root_tool_jcs: &[u8]) -> Option<String> {
    let tool: AgentTool = serde_json::from_slice(root_tool_jcs).ok()?;
    if let AgentTool::OsLaunchApp { app_name } = tool {
        let trimmed = app_name.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn is_browser_root_tool(root_tool_name: &str) -> bool {
    root_tool_name
        .trim()
        .to_ascii_lowercase()
        .starts_with("browser__")
}

fn is_browser_snapshot_root_tool(root_tool_name: &str) -> bool {
    root_tool_name
        .trim()
        .eq_ignore_ascii_case("browser__inspect")
}

fn is_browser_reacquisition_failure(class: FailureClass) -> bool {
    matches!(
        class,
        FailureClass::TargetNotFound
            | FailureClass::VisionTargetNotFound
            | FailureClass::NoEffectAfterAction
            | FailureClass::ContextDrift
            | FailureClass::TimeoutOrHang
            | FailureClass::NonDeterministicUI
    )
}

pub(super) fn browser_root_failure_prefers_direct_retry(incident_state: &IncidentState) -> bool {
    if !is_browser_root_tool(&incident_state.root_tool_name) {
        return false;
    }

    let Some(root_error) = incident_state.root_error.as_deref() else {
        return false;
    };

    match FailureClass::from_str(&incident_state.root_failure_class) {
        Some(FailureClass::TimeoutOrHang) => {
            root_error.contains("\"browser_session_unstable\":true")
                || root_error.contains("\"retry_recommended\":true")
        }
        Some(FailureClass::NoEffectAfterAction) => {
            incident_state
                .root_tool_name
                .trim()
                .eq_ignore_ascii_case("browser__click")
                && root_error_has_click_dispatch_timeout(root_error)
        }
        _ => false,
    }
}

fn root_error_has_click_dispatch_timeout(root_error: &str) -> bool {
    root_error_verify_payload(root_error)
        .and_then(|verify| {
            verify
                .get("dispatch_failures")
                .and_then(Value::as_array)
                .cloned()
        })
        .is_some_and(|failures| {
            failures.iter().any(|failure| {
                failure
                    .get("error")
                    .and_then(Value::as_str)
                    .is_some_and(|error| error.contains("dispatch timed out"))
            })
        })
}

fn root_error_verify_payload(root_error: &str) -> Option<Value> {
    let (_, verify_text) = root_error
        .split_once(" verify=")
        .or_else(|| root_error.split_once("verify="))?;
    serde_json::from_str::<Value>(verify_text).ok()
}

fn is_gui_click_root_tool(root_tool_name: &str) -> bool {
    matches!(
        root_tool_name.trim().to_ascii_lowercase().as_str(),
        "screen__click_at" | "screen__click" | "screen"
    )
}

fn is_phase0_browser_gui_click_violation(incident_state: &IncidentState) -> bool {
    is_gui_click_root_tool(&incident_state.root_tool_name)
        && incident_state
            .root_error
            .as_deref()
            .map(|err| err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"))
            .unwrap_or(false)
}

fn is_duplicate_recovery_fingerprint(
    tool: &AgentTool,
    visited_node_fingerprints: &[String],
) -> bool {
    let fp = tool_fingerprint(tool);
    visited_node_fingerprints.iter().any(|known| known == &fp)
}

pub(super) fn deterministic_recovery_tool(
    available_tool_names: &BTreeSet<String>,
    incident_state: &IncidentState,
    agent_state: &AgentState,
    _rules: &ActionRules,
) -> Result<Option<AgentTool>, TransactionError> {
    let root_failure_class = FailureClass::from_str(&incident_state.root_failure_class);
    if is_browser_root_tool(&incident_state.root_tool_name)
        && root_failure_class
            .map(is_browser_reacquisition_failure)
            .unwrap_or(false)
        && available_tool_names.contains("browser__inspect")
        && !(is_browser_snapshot_root_tool(&incident_state.root_tool_name)
            && matches!(root_failure_class, Some(FailureClass::NoEffectAfterAction)))
    {
        let payload = json!({
            "name": "browser__inspect",
            "arguments": {}
        });
        let tool = middleware::normalize_tool_call(&payload.to_string()).map_err(|e| {
            TransactionError::Invalid(format!("browser__inspect fallback invalid: {}", e))
        })?;
        if !is_duplicate_recovery_fingerprint(&tool, &incident_state.visited_node_fingerprints) {
            return Ok(Some(tool));
        }
    }

    if is_phase0_browser_gui_click_violation(incident_state)
        && available_tool_names.contains("browser__inspect")
    {
        let payload = json!({
            "name": "browser__inspect",
            "arguments": {}
        });
        let tool = middleware::normalize_tool_call(&payload.to_string()).map_err(|e| {
            TransactionError::Invalid(format!(
                "browser__inspect fallback invalid for phase0 click guard: {}",
                e
            ))
        })?;
        if !is_duplicate_recovery_fingerprint(&tool, &incident_state.visited_node_fingerprints) {
            return Ok(Some(tool));
        }
    }

    if available_tool_names.contains("screen__find") {
        let query = parse_launch_app_name(&incident_state.root_tool_jcs)
            .or_else(|| {
                agent_state
                    .target
                    .as_ref()
                    .and_then(|target| target.app_hint.clone())
            })
            .unwrap_or_else(|| agent_state.goal.clone());
        let payload = json!({
            "name": "screen__find",
            "arguments": { "query": query }
        });
        let tool = middleware::normalize_tool_call(&payload.to_string()).map_err(|e| {
            TransactionError::Invalid(format!("screen__find fallback invalid: {}", e))
        })?;
        if !is_duplicate_recovery_fingerprint(&tool, &incident_state.visited_node_fingerprints) {
            return Ok(Some(tool));
        }
    }

    if available_tool_names.contains("window__focus") {
        if let Some(hint) = agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.clone())
        {
            let payload = json!({
                "name": "window__focus",
                "arguments": { "title": hint }
            });
            let tool = middleware::normalize_tool_call(&payload.to_string()).map_err(|e| {
                TransactionError::Invalid(format!("window__focus fallback invalid: {}", e))
            })?;
            if !is_duplicate_recovery_fingerprint(&tool, &incident_state.visited_node_fingerprints)
            {
                return Ok(Some(tool));
            }
        }
    }

    Ok(None)
}

pub(super) fn incident_specific_forbidden_tools(
    incident_state: &IncidentState,
) -> BTreeSet<String> {
    let mut forbidden = BTreeSet::new();
    let root_failure_class = FailureClass::from_str(&incident_state.root_failure_class);
    if is_browser_snapshot_root_tool(&incident_state.root_tool_name)
        && matches!(root_failure_class, Some(FailureClass::NoEffectAfterAction))
    {
        for tool_name in [
            "browser__navigate",
            "browser__back",
            "browser__switch_tab",
            "browser__close_tab",
        ] {
            forbidden.insert(tool_name.to_string());
        }
    }
    forbidden
}

pub(super) fn validate_recovery_tool(
    tool: &AgentTool,
    available_tool_names: &BTreeSet<String>,
    forbidden: &BTreeSet<String>,
    visited_node_fingerprints: &[String],
) -> Result<(), TransactionError> {
    let name = canonical_tool_name(tool);
    if forbidden.contains(&name) {
        return Err(TransactionError::Invalid(format!(
            "Forbidden incident tool selected: {}",
            name
        )));
    }
    if !available_tool_names.contains(&name) {
        return Err(TransactionError::Invalid(format!(
            "Incident tool '{}' not in available tool set",
            name
        )));
    }
    if is_duplicate_recovery_fingerprint(tool, visited_node_fingerprints) {
        return Err(TransactionError::Invalid(
            "Duplicate incident remedy fingerprint".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn build_planner_prompt(
    incident_state: &IncidentState,
    forbidden_tools: &BTreeSet<String>,
    pending_browser_state: Option<&str>,
) -> String {
    let visited = if incident_state.visited_node_fingerprints.is_empty() {
        "none".to_string()
    } else {
        incident_state.visited_node_fingerprints.join(", ")
    };
    let pending_browser_state = pending_browser_state
        .map(str::trim)
        .filter(|state| !state.is_empty())
        .map(|state| format!("         - Current pending browser state:\n{}\n", state))
        .unwrap_or_default();
    format!(
        "You are an ontology incident resolver. Choose EXACTLY ONE JSON tool call.\n\
         Rules:\n\
         1. Output exactly one JSON tool call.\n\
         2. Forbidden tools: {}.\n\
         3. Do not repeat previous remedy fingerprints.\n\
         4. Keep action tightly scoped to recover the root action.\n\
         Context:\n\
         - Incident: {}\n\
         - Intent class: {}\n\
         - Failure class: {}\n\
         - Root tool: {}\n\
         - Stage: {}\n\
         - Strategy: {} / {}\n\
         - Transitions: {}/{}\n\
         - Visited remedy fingerprints: {}\n\
         - Last error: {}\n{}",
        forbidden_tools
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        incident_state.incident_id,
        incident_state.intent_class,
        incident_state.root_failure_class,
        incident_state.root_tool_name,
        incident_state.stage,
        incident_state.strategy_name,
        incident_state.strategy_cursor,
        incident_state.transitions_used,
        incident_state.max_transitions,
        visited,
        incident_state.root_error.as_deref().unwrap_or("unknown"),
        pending_browser_state,
    )
}

fn tool_to_action_request(
    tool: &AgentTool,
    session_id: [u8; 32],
    nonce: u64,
) -> Result<ActionRequest, TransactionError> {
    let target = tool.target();
    let tool_name = canonical_tool_name(tool);
    let mut args = canonical_tool_args(tool);
    if should_embed_queue_tool_name_metadata(&target, &tool_name) {
        if let Some(obj) = args.as_object_mut() {
            obj.insert(QUEUE_TOOL_NAME_KEY.to_string(), json!(tool_name));
        }
    }
    let params =
        serde_jcs::to_vec(&args).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    Ok(ActionRequest {
        target,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce,
    })
}

fn should_embed_queue_tool_name_metadata(target: &ActionTarget, tool_name: &str) -> bool {
    matches!(target, ActionTarget::FsRead | ActionTarget::FsWrite)
        || (matches!(target, ActionTarget::GuiClick | ActionTarget::UiClick)
            && tool_name == "screen__click")
        || matches!(target, ActionTarget::BrowserInteract)
        || (matches!(target, ActionTarget::SysExec)
            && matches!(tool_name, "shell__start" | "shell__reset"))
}

pub(super) fn queue_recovery_action(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    recovery_tool: &AgentTool,
) -> Result<(), TransactionError> {
    let base_nonce = agent_state.step_count as u64 + 1;
    let recovery_request = tool_to_action_request(recovery_tool, session_id, base_nonce)?;
    agent_state.execution_queue.insert(0, recovery_request);
    Ok(())
}

pub(super) fn queue_root_retry(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    root_tool_jcs: &[u8],
) -> Result<bool, TransactionError> {
    let root_tool: AgentTool = serde_json::from_slice(root_tool_jcs).map_err(|e| {
        TransactionError::Serialization(format!("Failed to deserialize root incident tool: {}", e))
    })?;

    let nonce = agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1;
    let retry_request = tool_to_action_request(&root_tool, session_id, nonce)?;
    let duplicate = agent_state.execution_queue.iter().any(|queued| {
        queued.target == retry_request.target && queued.params == retry_request.params
    });
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.insert(0, retry_request);
    Ok(true)
}

#[cfg(test)]
#[path = "recovery/tests.rs"]
mod tests;
