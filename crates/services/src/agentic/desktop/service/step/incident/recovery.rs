use super::core::{
    canonical_tool_args, canonical_tool_name, tool_fingerprint, IncidentState,
    FORBIDDEN_LIFECYCLE_TOOLS,
};
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::step::anti_loop::FailureClass;
use crate::agentic::desktop::service::step::ontology::{IntentClass, StrategyName};
use crate::agentic::desktop::types::AgentState;
use crate::agentic::rules::ActionRules;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::error::TransactionError;
use serde_json::json;
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

pub(super) fn deterministic_recovery_tool(
    available_tool_names: &BTreeSet<String>,
    incident_state: &IncidentState,
    agent_state: &AgentState,
    _rules: &ActionRules,
) -> Result<Option<AgentTool>, TransactionError> {
    if available_tool_names.contains("ui__find") {
        let query = parse_launch_app_name(&incident_state.root_tool_jcs)
            .or_else(|| {
                agent_state
                    .target
                    .as_ref()
                    .and_then(|target| target.app_hint.clone())
            })
            .unwrap_or_else(|| agent_state.goal.clone());
        let payload = json!({
            "name": "ui__find",
            "arguments": { "query": query }
        });
        let tool = middleware::normalize_tool_call(&payload.to_string())
            .map_err(|e| TransactionError::Invalid(format!("ui__find fallback invalid: {}", e)))?;
        return Ok(Some(tool));
    }

    if available_tool_names.contains("os__focus_window") {
        if let Some(hint) = agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.clone())
        {
            let payload = json!({
                "name": "os__focus_window",
                "arguments": { "title": hint }
            });
            let tool = middleware::normalize_tool_call(&payload.to_string()).map_err(|e| {
                TransactionError::Invalid(format!("os__focus_window fallback invalid: {}", e))
            })?;
            return Ok(Some(tool));
        }
    }

    Ok(None)
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
    let fp = tool_fingerprint(tool);
    if visited_node_fingerprints.iter().any(|known| known == &fp) {
        return Err(TransactionError::Invalid(
            "Duplicate incident remedy fingerprint".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn build_planner_prompt(
    incident_state: &IncidentState,
    forbidden_tools: &BTreeSet<String>,
) -> String {
    format!(
        "You are an ontology incident resolver. Choose EXACTLY ONE JSON tool call.\n\
         Rules:\n\
         1. Output exactly one JSON tool call.\n\
         2. Forbidden tools: {}.\n\
         3. Do not repeat previous remedy fingerprints.\n\
         4. For install semantics, prefer sys__install_package over raw sys__exec.\n\
         5. Keep action tightly scoped to recover the root action.\n\
         Context:\n\
         - Incident: {}\n\
         - Intent class: {}\n\
         - Failure class: {}\n\
         - Root tool: {}\n\
         - Stage: {}\n\
         - Strategy: {} / {}\n\
         - Transitions: {}/{}\n\
         - Last error: {}\n",
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
        incident_state.root_error.as_deref().unwrap_or("unknown"),
    )
}

fn tool_to_action_request(
    tool: &AgentTool,
    session_id: [u8; 32],
    nonce: u64,
) -> Result<ActionRequest, TransactionError> {
    let mut target = tool.target();
    let tool_name = canonical_tool_name(tool);
    if matches!(
        tool_name.as_str(),
        "sys__exec_session" | "sys__exec_session_reset"
    ) {
        target = match tool_name.as_str() {
            "sys__exec_session" => ActionTarget::Custom("sys::exec_session".to_string()),
            _ => ActionTarget::Custom("sys::exec_session_reset".to_string()),
        };
    }
    let mut args = canonical_tool_args(tool);
    if should_embed_queue_tool_name_metadata(&target, &tool_name) {
        if let Some(obj) = args.as_object_mut() {
            obj.insert(QUEUE_TOOL_NAME_KEY.to_string(), json!(tool_name));
        }
    }
    let params = serde_jcs::to_vec(&args)
        .or_else(|_| serde_json::to_vec(&args))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
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
            && tool_name == "gui__click_element")
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
mod tests {
    use super::{tool_to_action_request, QUEUE_TOOL_NAME_KEY};
    use ioi_types::app::{agentic::AgentTool, ActionTarget};

    fn queued_params(tool: AgentTool) -> serde_json::Value {
        let request = tool_to_action_request(&tool, [7u8; 32], 99)
            .expect("request should serialize for deterministic queueing");
        serde_json::from_slice(&request.params).expect("request params should decode as JSON")
    }

    #[test]
    fn fs_targets_embed_tool_name_metadata() {
        let value = queued_params(AgentTool::FsPatch {
            path: "/tmp/demo.txt".to_string(),
            search: "before".to_string(),
            replace: "after".to_string(),
        });
        let tool_name = value
            .get(QUEUE_TOOL_NAME_KEY)
            .and_then(|v| v.as_str())
            .expect("fs queue metadata should be present");
        assert_eq!(tool_name, "filesystem__patch");
    }

    #[test]
    fn gui_click_element_embeds_tool_name_metadata() {
        let value = queued_params(AgentTool::GuiClickElement {
            id: "btn_submit".to_string(),
        });
        let tool_name = value
            .get(QUEUE_TOOL_NAME_KEY)
            .and_then(|v| v.as_str())
            .expect("gui click element metadata should be present");
        assert_eq!(tool_name, "gui__click_element");
    }

    #[test]
    fn sys_exec_session_recovery_request_uses_custom_alias_target() {
        let request = tool_to_action_request(
            &AgentTool::SysExecSession {
                command: "bash".to_string(),
                args: vec!["-lc".to_string(), "echo session".to_string()],
                stdin: None,
            },
            [7u8; 32],
            101,
        )
        .expect("request should serialize for deterministic queueing");

        match request.target {
            ActionTarget::Custom(name) => assert_eq!(name, "sys::exec_session"),
            _ => panic!("sys_exec_session should be queued as custom alias target"),
        }
    }

    #[test]
    fn non_fs_targets_do_not_embed_tool_name_metadata() {
        let value = queued_params(AgentTool::BrowserClickElement {
            id: "submit_button".to_string(),
        });
        assert!(
            value.get(QUEUE_TOOL_NAME_KEY).is_none(),
            "non-fs targets should not carry explicit queue metadata"
        );
    }
}
