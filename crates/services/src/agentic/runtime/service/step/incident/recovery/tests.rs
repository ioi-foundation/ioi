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
        execution_ledger: Default::default(),
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
    let available = BTreeSet::from(["browser__inspect".to_string(), "screen__find".to_string()]);
    let incident = test_incident_state("browser__click", "TargetNotFound");
    let agent_state = test_agent_state("click sign in");

    let tool =
        deterministic_recovery_tool(&available, &incident, &agent_state, &ActionRules::default())
            .expect("deterministic selection should succeed")
            .expect("deterministic selection should choose a tool");

    match tool {
        AgentTool::BrowserSnapshot {} => {}
        other => panic!("expected BrowserSnapshot, got {:?}", other),
    }
}

#[test]
fn deterministic_recovery_prefers_browser_snapshot_for_browser_timeout() {
    let available = BTreeSet::from(["browser__inspect".to_string(), "screen__find".to_string()]);
    let incident = test_incident_state("browser__click", "TimeoutOrHang");
    let agent_state = test_agent_state("click sign in");

    let tool =
        deterministic_recovery_tool(&available, &incident, &agent_state, &ActionRules::default())
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

    let tool =
        deterministic_recovery_tool(&available, &incident, &agent_state, &ActionRules::default())
            .expect("deterministic selection should succeed")
            .expect("deterministic selection should choose a tool");

    match tool {
        AgentTool::UiFind { query } => assert_eq!(query, "find login button"),
        other => panic!("expected UiFind, got {:?}", other),
    }
}

#[test]
fn deterministic_recovery_prefers_browser_snapshot_for_phase0_gui_click_violation() {
    let available = BTreeSet::from(["browser__inspect".to_string(), "screen__find".to_string()]);
    let mut incident = test_incident_state("screen__click", "TierViolation");
    incident.root_error =
        Some("ERROR_CLASS=TierViolation ERROR_CODE=BrowserGuiClickDisallowedPhase0".to_string());
    let agent_state = test_agent_state("click sign in");

    let tool =
        deterministic_recovery_tool(&available, &incident, &agent_state, &ActionRules::default())
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
    incident.root_error =
        Some("ERROR_CLASS=TierViolation ERROR_CODE=BrowserGuiClickDisallowedPhase0".to_string());
    let agent_state = test_agent_state("find login button");

    let tool =
        deterministic_recovery_tool(&available, &incident, &agent_state, &ActionRules::default())
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

    let tool =
        deterministic_recovery_tool(&available, &incident, &agent_state, &ActionRules::default())
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

    let tool =
        deterministic_recovery_tool(&available, &incident, &agent_state, &ActionRules::default())
            .expect("deterministic selection should succeed")
            .expect("deterministic selection should choose focus window fallback");

    match tool {
        AgentTool::OsFocusWindow { title } => assert_eq!(title, "Firefox"),
        other => panic!("expected OsFocusWindow, got {:?}", other),
    }
}

#[test]
fn deterministic_recovery_does_not_replay_browser_snapshot_after_duplicate_no_effect() {
    let available = BTreeSet::from(["browser__inspect".to_string(), "screen__find".to_string()]);
    let incident = test_incident_state("browser__inspect", "NoEffectAfterAction");
    let agent_state = test_agent_state("click sign in");

    let tool =
        deterministic_recovery_tool(&available, &incident, &agent_state, &ActionRules::default())
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
