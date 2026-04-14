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
mod tests {
    use super::{
        build_planner_prompt, deterministic_recovery_tool, incident_specific_forbidden_tools,
        tool_fingerprint, tool_to_action_request, IncidentState, QUEUE_TOOL_NAME_KEY,
    };
    use crate::agentic::rules::ActionRules;
    use crate::agentic::runtime::types::{
        AgentMode, AgentState, AgentStatus, ExecutionTier, InteractionTarget,
    };
    use ioi_types::app::{agentic::AgentTool, ActionTarget};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    fn test_agent_state(goal: &str) -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: goal.to_string(),
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
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    fn test_incident_state(root_tool_name: &str, root_failure_class: &str) -> IncidentState {
        IncidentState {
            active: true,
            incident_id: "incident-1".to_string(),
            root_retry_hash: "retry-hash-1".to_string(),
            root_tool_jcs: vec![],
            root_tool_name: root_tool_name.to_string(),
            intent_class: "BrowserTask".to_string(),
            root_failure_class: root_failure_class.to_string(),
            root_error: Some("target missing".to_string()),
            stage: "Diagnose".to_string(),
            strategy_name: "BrowserRecovery".to_string(),
            strategy_cursor: "DiscoverRemedy".to_string(),
            visited_node_fingerprints: vec![],
            pending_gate: None,
            gate_state: "None".to_string(),
            resolution_action: "none".to_string(),
            transitions_used: 0,
            max_transitions: 4,
            started_step: 0,
            pending_remedy_fingerprint: None,
            pending_remedy_tool_jcs: None,
            retry_enqueued: false,
        }
    }

    #[test]
    fn planner_prompt_includes_pending_browser_state_when_present() {
        let incident = test_incident_state("browser__inspect", "NoEffectAfterAction");
        let prompt = build_planner_prompt(
            &incident,
            &BTreeSet::new(),
            Some("RECENT PENDING BROWSER STATE:\nUse `browser__click` on `lnk_443422`."),
        );
        assert!(prompt.contains("Current pending browser state"));
        assert!(prompt.contains("lnk_443422"));
    }

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
        assert_eq!(tool_name, "file__edit");
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
        assert_eq!(tool_name, "screen__click");
    }

    #[test]
    fn sys_exec_session_recovery_request_preserves_sys_exec_target_and_embeds_tool_name() {
        let request = tool_to_action_request(
            &AgentTool::SysExecSession {
                command: "bash".to_string(),
                args: vec!["-lc".to_string(), "echo session".to_string()],
                stdin: None,
                wait_ms_before_async: None,
            },
            [7u8; 32],
            101,
        )
        .expect("request should serialize for deterministic queueing");

        assert_eq!(request.target, ActionTarget::SysExec);
        let value: serde_json::Value =
            serde_json::from_slice(&request.params).expect("params should decode as JSON");
        assert_eq!(
            value.get(QUEUE_TOOL_NAME_KEY).and_then(|v| v.as_str()),
            Some("shell__start")
        );
    }

    #[test]
    fn browser_targets_embed_tool_name_metadata() {
        let value = queued_params(AgentTool::BrowserClick {
            selector: String::new(),
            id: Some("submit_button".to_string()),
            ids: Vec::new(),
            delay_ms_between_ids: None,
            continue_with: None,
        });
        assert!(
            value.get(QUEUE_TOOL_NAME_KEY).is_some(),
            "browser targets should carry explicit queue metadata"
        );
        assert_eq!(
            value.get(QUEUE_TOOL_NAME_KEY).and_then(|v| v.as_str()),
            Some("browser__click")
        );
    }

    #[test]
    fn deterministic_recovery_prefers_browser_snapshot_for_browser_target_not_found() {
        let available =
            BTreeSet::from(["browser__inspect".to_string(), "screen__find".to_string()]);
        let incident = test_incident_state("browser__click", "TargetNotFound");
        let agent_state = test_agent_state("click sign in");

        let tool = deterministic_recovery_tool(
            &available,
            &incident,
            &agent_state,
            &ActionRules::default(),
        )
        .expect("deterministic selection should succeed")
        .expect("deterministic selection should choose a tool");

        match tool {
            AgentTool::BrowserSnapshot {} => {}
            other => panic!("expected BrowserSnapshot, got {:?}", other),
        }
    }

    #[test]
    fn deterministic_recovery_prefers_browser_snapshot_for_browser_timeout() {
        let available =
            BTreeSet::from(["browser__inspect".to_string(), "screen__find".to_string()]);
        let incident = test_incident_state("browser__click", "TimeoutOrHang");
        let agent_state = test_agent_state("click sign in");

        let tool = deterministic_recovery_tool(
            &available,
            &incident,
            &agent_state,
            &ActionRules::default(),
        )
        .expect("deterministic selection should succeed")
        .expect("deterministic selection should choose a tool");

        match tool {
            AgentTool::BrowserSnapshot {} => {}
            other => panic!("expected BrowserSnapshot, got {:?}", other),
        }
    }

    #[test]
    fn browser_root_failure_prefers_direct_retry_for_browser_session_unstable_timeout() {
        let mut incident = test_incident_state("browser__click", "TimeoutOrHang");
        incident.root_error = Some(
            "ERROR_CLASS=TimeoutOrHang Click element 'btn_buy' could not continue. verify={\"browser_session_unstable\":true,\"retry_recommended\":true}".to_string(),
        );

        assert!(super::browser_root_failure_prefers_direct_retry(&incident));
    }

    #[test]
    fn browser_root_failure_does_not_prefer_direct_retry_without_retry_signal() {
        let incident = test_incident_state("browser__click", "TimeoutOrHang");

        assert!(!super::browser_root_failure_prefers_direct_retry(&incident));
    }

    #[test]
    fn browser_root_failure_prefers_direct_retry_for_click_dispatch_timeout_no_effect() {
        let mut incident = test_incident_state("browser__click", "NoEffectAfterAction");
        incident.root_error = Some(
            "ERROR_CLASS=NoEffectAfterAction Failed to click element 'btn_buy'. verify={\"dispatch_failures\":[{\"error\":\"dispatch timed out after 2500 ms. Retry the action.\",\"method\":\"selector_grounded\",\"selector\":\"#buy\"}],\"id\":\"btn_buy\"}".to_string(),
        );

        assert!(super::browser_root_failure_prefers_direct_retry(&incident));
    }

    #[test]
    fn browser_root_failure_does_not_prefer_direct_retry_for_non_click_no_effect() {
        let mut incident = test_incident_state("browser__inspect", "NoEffectAfterAction");
        incident.root_error =
            Some("ERROR_CLASS=NoEffectAfterAction duplicate replay guard".to_string());

        assert!(!super::browser_root_failure_prefers_direct_retry(&incident));
    }

    #[test]
    fn deterministic_recovery_falls_back_to_ui_find_without_browser_snapshot() {
        let available = BTreeSet::from(["screen__find".to_string()]);
        let incident = test_incident_state("browser__click", "TargetNotFound");
        let agent_state = test_agent_state("find login button");

        let tool = deterministic_recovery_tool(
            &available,
            &incident,
            &agent_state,
            &ActionRules::default(),
        )
        .expect("deterministic selection should succeed")
        .expect("deterministic selection should choose a tool");

        match tool {
            AgentTool::UiFind { query } => assert_eq!(query, "find login button"),
            other => panic!("expected UiFind, got {:?}", other),
        }
    }

    #[test]
    fn deterministic_recovery_prefers_browser_snapshot_for_phase0_gui_click_violation() {
        let available =
            BTreeSet::from(["browser__inspect".to_string(), "screen__find".to_string()]);
        let mut incident = test_incident_state("screen__click", "TierViolation");
        incident.root_error = Some(
            "ERROR_CLASS=TierViolation ERROR_CODE=BrowserGuiClickDisallowedPhase0".to_string(),
        );
        let agent_state = test_agent_state("click sign in");

        let tool = deterministic_recovery_tool(
            &available,
            &incident,
            &agent_state,
            &ActionRules::default(),
        )
        .expect("deterministic selection should succeed")
        .expect("deterministic selection should choose a tool");

        match tool {
            AgentTool::BrowserSnapshot {} => {}
            other => panic!("expected BrowserSnapshot, got {:?}", other),
        }
    }

    #[test]
    fn deterministic_recovery_phase0_violation_falls_back_without_browser_snapshot() {
        let available = BTreeSet::from(["screen__find".to_string()]);
        let mut incident = test_incident_state("screen", "TierViolation");
        incident.root_error = Some(
            "ERROR_CLASS=TierViolation ERROR_CODE=BrowserGuiClickDisallowedPhase0".to_string(),
        );
        let agent_state = test_agent_state("find login button");

        let tool = deterministic_recovery_tool(
            &available,
            &incident,
            &agent_state,
            &ActionRules::default(),
        )
        .expect("deterministic selection should succeed")
        .expect("deterministic selection should choose a tool");

        match tool {
            AgentTool::UiFind { query } => assert_eq!(query, "find login button"),
            other => panic!("expected UiFind, got {:?}", other),
        }
    }

    #[test]
    fn deterministic_recovery_skips_visited_ui_find_without_alternative() {
        let available = BTreeSet::from(["screen__find".to_string()]);
        let mut incident = test_incident_state("browser__click", "TargetNotFound");
        let agent_state = test_agent_state("find login button");
        incident
            .visited_node_fingerprints
            .push(tool_fingerprint(&AgentTool::UiFind {
                query: "find login button".to_string(),
            }));

        let tool = deterministic_recovery_tool(
            &available,
            &incident,
            &agent_state,
            &ActionRules::default(),
        )
        .expect("deterministic selection should succeed");

        assert!(
            tool.is_none(),
            "visited screen__find fingerprint should not be selected again"
        );
    }

    #[test]
    fn deterministic_recovery_falls_back_to_focus_window_when_ui_find_is_visited() {
        let available = BTreeSet::from(["screen__find".to_string(), "window__focus".to_string()]);
        let mut incident = test_incident_state("browser__click", "TargetNotFound");
        let mut agent_state = test_agent_state("find login button");
        agent_state.target = Some(InteractionTarget {
            app_hint: Some("Firefox".to_string()),
            title_pattern: None,
        });
        incident
            .visited_node_fingerprints
            .push(tool_fingerprint(&AgentTool::UiFind {
                query: "Firefox".to_string(),
            }));

        let tool = deterministic_recovery_tool(
            &available,
            &incident,
            &agent_state,
            &ActionRules::default(),
        )
        .expect("deterministic selection should succeed")
        .expect("deterministic selection should choose focus window fallback");

        match tool {
            AgentTool::OsFocusWindow { title } => assert_eq!(title, "Firefox"),
            other => panic!("expected OsFocusWindow, got {:?}", other),
        }
    }

    #[test]
    fn deterministic_recovery_does_not_replay_browser_snapshot_after_duplicate_no_effect() {
        let available =
            BTreeSet::from(["browser__inspect".to_string(), "screen__find".to_string()]);
        let incident = test_incident_state("browser__inspect", "NoEffectAfterAction");
        let agent_state = test_agent_state("click sign in");

        let tool = deterministic_recovery_tool(
            &available,
            &incident,
            &agent_state,
            &ActionRules::default(),
        )
        .expect("deterministic selection should succeed");

        match tool {
            Some(AgentTool::UiFind { query }) => assert_eq!(query, "click sign in"),
            Some(other) => panic!("expected UiFind or None, got {:?}", other),
            None => {}
        }
    }

    #[test]
    fn duplicate_browser_snapshot_incident_forbids_navigation_remedies() {
        let incident = test_incident_state("browser__inspect", "NoEffectAfterAction");
        let forbidden = incident_specific_forbidden_tools(&incident);

        assert!(forbidden.contains("browser__navigate"));
        assert!(forbidden.contains("browser__back"));
        assert!(forbidden.contains("browser__switch_tab"));
        assert!(forbidden.contains("browser__close_tab"));
    }
}
