use super::{
    active_web_pipeline_chat_reply_duplicate_noop, browser_route_owns_dedicated_surface,
    duplicate_after_prior_success, duplicate_prior_success_noop,
    install_already_satisfied_operator_reply, install_already_satisfied_terminal_reason,
    install_resolution_terminal_block_reason, latest_browser_tab_id, latest_child_session_id_hex,
    latest_retained_shell_command_id, maybe_enqueue_workspace_package_manifest_recovery,
    maybe_terminalize_workspace_package_manifest_read, observe_terminal_chat_reply_shape,
    read_only_workspace_context_duplicate_noop, retained_shell_input_duplicate_noop,
    retained_shell_lifecycle_followup, retained_shell_obsolete_input_after_stop,
    select_manifest_script_recovery_candidate, should_release_browser_after_terminal_reply,
    terminal_chat_reply_layout_profile, tool_to_action_request,
    toolcat_single_tool_agent_await_followup, toolcat_single_tool_browser_setup_followup,
    toolcat_single_tool_chat_reply_recovery_followup,
    toolcat_single_tool_duplicate_after_success_reply, toolcat_single_tool_failure_reply,
    toolcat_single_tool_reply_tool_name, toolcat_single_tool_retained_shell_followup,
    toolcat_single_tool_success_followup, workspace_goal_prefers_package_manifest_recovery,
    FailureClass, ManifestScriptRecoveryCandidate,
};
use crate::agentic::runtime::service::output::terminal_reply_shape::TerminalChatReplyLayoutProfile;
use crate::agentic::runtime::service::queue::queue_action_request_to_tool;
use crate::agentic::runtime::service::tool_execution::record_execution_evidence;
use crate::agentic::runtime::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use ioi_types::app::agentic::{
    AgentTool, CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    RuntimeRouteFrame,
};
use ioi_types::app::ActionRequest;
use std::collections::{BTreeMap, VecDeque};

fn workspace_ops_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "workspace.ops".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        band: IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("filesystem.read")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn command_workspace_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "workspace.edit_and_test".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![
            CapabilityId::from("filesystem.read"),
            CapabilityId::from("filesystem.write"),
            CapabilityId::from("command.exec"),
        ],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn browser_interact_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "browser.interact".to_string(),
        scope: IntentScopeProfile::WebResearch,
        band: IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("browser.navigate")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [7u8; 32],
        goal: "test".to_string(),
        runtime_route_frame: None,
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 0,
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
        execution_queue: Vec::<ActionRequest>::new(),
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

#[test]
fn toolcat_single_tool_failure_reply_preserves_exact_row_identity() {
    assert_eq!(
        toolcat_single_tool_failure_reply("agent__await"),
        "TOOLCAT_SINGLE_TOOL agent__await live IDE probe failed; concrete trace failure recorded."
    );
}

#[test]
fn toolcat_single_tool_invalid_call_reply_uses_requested_row_identity() {
    assert_eq!(
        toolcat_single_tool_reply_tool_name(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__subagent",
            "system::invalid_tool_call",
        ),
        "browser__subagent"
    );
    assert_eq!(
        toolcat_single_tool_failure_reply(&toolcat_single_tool_reply_tool_name(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__subagent",
            "system::invalid_tool_call",
        )),
        "TOOLCAT_SINGLE_TOOL browser__subagent live IDE probe failed; concrete trace failure recorded."
    );
}

#[test]
fn toolcat_single_tool_duplicate_after_success_reply_preserves_completion_identity() {
    assert_eq!(
        toolcat_single_tool_duplicate_after_success_reply("file__read"),
        "TOOLCAT_SINGLE_TOOL file__read live IDE probe completed; duplicate replay guard recorded in trace."
    );
}

#[test]
fn toolcat_single_tool_browser_copy_advances_after_selection_setup() {
    let followup = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__copy",
        "browser__select",
        Some(r#"{"selection":{"selected_text":"TOOLCAT_BROWSER_CANARY"}}"#),
    )
    .expect("browser copy follow-up");
    assert!(matches!(followup, AgentTool::BrowserCopySelection {}));
}

#[test]
fn toolcat_single_tool_browser_paste_advances_through_clipboard_setup() {
    let after_navigate = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__paste",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser paste clipboard setup");
    match after_navigate {
        AgentTool::OsCopy { content } => assert_eq!(content, "TOOLCAT_CLIPBOARD_CANARY"),
        other => panic!("expected clipboard copy setup, got {:?}", other),
    }

    let after_clipboard_copy = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__paste",
        "clipboard__copy",
        Some(r#"{"content_length":25}"#),
    )
    .expect("browser paste target");
    match after_clipboard_copy {
        AgentTool::BrowserPasteClipboard { selector } => {
            assert_eq!(selector.as_deref(), Some("#toolcat-input"));
        }
        other => panic!("expected browser paste follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_single_tool_browser_subagent_advances_after_navigation_setup() {
    let followup = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__subagent browser_fixture_url=http://127.0.0.1:12345/",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser subagent follow-up");

    match followup {
        AgentTool::Dynamic(value) => {
            assert_eq!(
                value.get("name").and_then(|name| name.as_str()),
                Some("browser__subagent")
            );
            let task = value
                .get("arguments")
                .and_then(|arguments| arguments.get("task"))
                .and_then(|task| task.as_str())
                .unwrap_or_default();
            assert!(task.contains("browser__navigate"));
            assert!(task.contains("http://127.0.0.1:12345/"));
            assert!(task.contains("TOOLCAT_BROWSER_CANARY"));
        }
        other => panic!("expected browser subagent follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_single_tool_browser_pointer_rows_advance_after_move_setup() {
    let move_setup = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__pointer_down",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser pointer move setup");
    match move_setup {
        AgentTool::BrowserMoveMouse {
            observation_ref,
            coordinate_space_id,
            semantic_id,
            x,
            y,
        } => {
            assert_eq!(observation_ref, "toolcat-observation");
            assert_eq!(coordinate_space_id, "viewport_css_px");
            assert_eq!(semantic_id, "toolcat-canvas");
            assert_eq!(x, 48.0);
            assert_eq!(y, 48.0);
        }
        other => panic!("expected browser move pointer setup, got {:?}", other),
    }

    let pointer_down = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__pointer_down",
        "browser__move_pointer",
        Some(r#"{"pointer":{"x":48,"y":48}}"#),
    )
    .expect("browser pointer_down target");
    match pointer_down {
        AgentTool::BrowserMouseDown { button } => assert_eq!(button.as_deref(), Some("left")),
        other => panic!("expected browser pointer_down follow-up, got {:?}", other),
    }

    let pointer_up_setup = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__pointer_up",
        "browser__move_pointer",
        Some(r#"{"pointer":{"x":48,"y":48}}"#),
    )
    .expect("browser pointer_up setup");
    match pointer_up_setup {
        AgentTool::BrowserMouseDown { button } => assert_eq!(button.as_deref(), Some("left")),
        other => panic!(
            "expected browser pointer_down setup before pointer_up, got {:?}",
            other
        ),
    }

    let pointer_up = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__pointer_up",
        "browser__pointer_down",
        Some(r#"{"button":"left"}"#),
    )
    .expect("browser pointer_up target");
    match pointer_up {
        AgentTool::BrowserMouseUp { button } => assert_eq!(button.as_deref(), Some("left")),
        other => panic!("expected browser pointer_up follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_single_tool_browser_coordinate_rows_advance_after_navigation_setup() {
    let click_inspect = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__click_at",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser click_at inspect setup");
    assert!(matches!(click_inspect, AgentTool::BrowserSnapshot {}));

    let click_at = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__click_at",
        "browser__inspect",
        Some(r#"{"elements":[{"id":"toolcat-canvas"}]}"#),
    )
    .expect("browser click_at target");
    match click_at {
        AgentTool::BrowserSyntheticClick { id, .. } => {
            assert_eq!(id.as_deref(), Some("toolcat-canvas"));
        }
        other => panic!("expected browser click_at follow-up, got {:?}", other),
    }

    let scroll = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__scroll",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser scroll target");
    match scroll {
        AgentTool::BrowserScroll { delta_y, delta_x } => {
            assert_eq!(delta_y, 180);
            assert_eq!(delta_x, 0);
        }
        other => panic!("expected browser scroll follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_single_tool_browser_dom_rows_advance_after_navigation_setup() {
    let goal = "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__list_options workspace_fixture_upload=/tmp/toolcat-upload.txt";
    let list_options = toolcat_single_tool_browser_setup_followup(
        goal,
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser list_options target");
    match list_options {
        AgentTool::BrowserDropdownOptions { selector, .. } => {
            assert_eq!(selector.as_deref(), Some("#toolcat-select"));
        }
        other => panic!("expected browser list_options follow-up, got {:?}", other),
    }

    let select_option = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__select_option",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser select_option target");
    match select_option {
        AgentTool::BrowserSelectDropdown {
            selector, value, ..
        } => {
            assert_eq!(selector.as_deref(), Some("#toolcat-select"));
            assert_eq!(value.as_deref(), Some("beta"));
        }
        other => panic!("expected browser select_option follow-up, got {:?}", other),
    }

    let copy_selection_setup = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__copy",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser copy selection setup");
    match copy_selection_setup {
        AgentTool::BrowserSelectText {
            selector,
            start_offset,
            end_offset,
        } => {
            assert_eq!(selector.as_deref(), Some("#fixture-copy"));
            assert_eq!(start_offset, Some(0));
            assert_eq!(end_offset, Some(23));
        }
        other => panic!("expected browser select setup, got {:?}", other),
    }

    let upload = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__upload workspace_fixture_upload=/tmp/toolcat-upload.txt",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser upload target");
    match upload {
        AgentTool::BrowserUploadFile {
            paths, selector, ..
        } => {
            assert_eq!(paths, vec!["/tmp/toolcat-upload.txt".to_string()]);
            assert_eq!(selector.as_deref(), Some("#toolcat-file"));
        }
        other => panic!("expected browser upload follow-up, got {:?}", other),
    }

    let canvas = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__inspect_canvas",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser inspect_canvas target");
    match canvas {
        AgentTool::BrowserCanvasSummary { selector } => {
            assert_eq!(selector, "#toolcat-canvas");
        }
        other => panic!("expected browser canvas follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_single_tool_browser_input_rows_advance_after_navigation_setup() {
    let click = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__click",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser click target");
    match click {
        AgentTool::BrowserClick { selector, .. } => assert_eq!(selector, "#toolcat-input"),
        other => panic!("expected browser click follow-up, got {:?}", other),
    }

    let type_text = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__type",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser type target");
    match type_text {
        AgentTool::BrowserType { selector, text } => {
            assert_eq!(selector.as_deref(), Some("#toolcat-input"));
            assert_eq!(text, "typed through browser__type");
        }
        other => panic!("expected browser type follow-up, got {:?}", other),
    }

    let press_key = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__press_key",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser press_key target");
    match press_key {
        AgentTool::BrowserKey {
            key,
            selector,
            modifiers,
            ..
        } => {
            assert_eq!(key, "a");
            assert_eq!(selector.as_deref(), Some("#toolcat-input"));
            assert_eq!(modifiers, Some(vec!["Control".to_string()]));
        }
        other => panic!("expected browser press_key follow-up, got {:?}", other),
    }

    let wait = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__wait",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser wait target");
    match wait {
        AgentTool::BrowserWait {
            condition,
            query,
            scope,
            timeout_ms,
            ..
        } => {
            assert_eq!(condition.as_deref(), Some("text_present"));
            assert_eq!(query.as_deref(), Some("TOOLCAT_BROWSER_CANARY"));
            assert_eq!(scope.as_deref(), Some("document"));
            assert_eq!(timeout_ms, Some(3000));
        }
        other => panic!("expected browser wait follow-up, got {:?}", other),
    }

    let hover = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__hover",
        "browser__navigate",
        Some(r#"{"browser_observation_receipt":{"title":"Tool Catalogue Fixture"}}"#),
    )
    .expect("browser hover target");
    match hover {
        AgentTool::BrowserHover {
            selector,
            duration_ms,
            ..
        } => {
            assert_eq!(selector.as_deref(), Some("#toolcat-button"));
            assert_eq!(duration_ms, Some(100));
        }
        other => panic!("expected browser hover follow-up, got {:?}", other),
    }
}

#[test]
fn latest_browser_tab_id_prefers_inactive_tab_for_switching() {
    let output =
        r#"{"tabs":[{"active":true,"tab_id":"ACTIVE"},{"active":false,"tab_id":"INACTIVE"}]}"#;
    assert_eq!(latest_browser_tab_id(output), Some("INACTIVE".to_string()));
}

#[test]
fn toolcat_single_tool_browser_tab_controls_use_list_tabs_output() {
    let output =
        r#"{"tabs":[{"active":true,"tab_id":"ACTIVE"},{"active":false,"tab_id":"INACTIVE"}]}"#;
    let switch = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__switch_tab",
        "browser__list_tabs",
        Some(output),
    )
    .expect("browser switch follow-up");
    match switch {
        AgentTool::BrowserTabSwitch { tab_id } => assert_eq!(tab_id, "INACTIVE"),
        other => panic!("expected tab switch follow-up, got {:?}", other),
    }

    let close = toolcat_single_tool_browser_setup_followup(
        "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__close_tab",
        "browser__list_tabs",
        Some(output),
    )
    .expect("browser close follow-up");
    match close {
        AgentTool::BrowserTabClose { tab_id, close } => {
            assert_eq!(tab_id, "INACTIVE");
            assert!(close);
        }
        other => panic!("expected tab close follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_command_id_parser_reads_plain_and_escaped_payloads() {
    let command_id =
        "shell__start:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    assert_eq!(
        latest_retained_shell_command_id(&format!(r#"{{"command_id":"{}"}}"#, command_id)),
        Some(command_id.to_string()),
    );
    assert_eq!(
        latest_retained_shell_command_id(&format!(
            r#"Tool Output (shell__start): {{\"command_id\":\"{}\"}}"#,
            command_id
        )),
        Some(command_id.to_string()),
    );
}

#[test]
fn child_session_id_parser_reads_plain_and_escaped_payloads() {
    let child_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    assert_eq!(
        latest_child_session_id_hex(&format!(r#"{{"child_session_id_hex":"{}"}}"#, child_id)),
        Some(child_id.to_string()),
    );
    assert_eq!(
        latest_child_session_id_hex(&format!(
            r#"Tool Output (agent__delegate): {{\"child_session_id_hex\":\"{}\"}}"#,
            child_id
        )),
        Some(child_id.to_string()),
    );
}

#[test]
fn toolcat_retained_shell_setup_queues_requested_terminate_row() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let followup = toolcat_single_tool_retained_shell_followup(
        "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__terminate",
        "shell__start",
        Some(&format!(r#"{{"command_id":"{}"}}"#, command_id)),
    )
    .expect("shell__terminate follow-up should be queued from shell__start output");

    match followup {
        AgentTool::SysExecTerminate { command_id: actual } => assert_eq!(actual, command_id),
        other => panic!("expected shell__terminate follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_retained_shell_setup_queues_requested_reset_row_without_command_id() {
    let followup = toolcat_single_tool_retained_shell_followup(
        "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__reset",
        "shell__start",
        None,
    )
    .expect("shell__reset follow-up should be queued without a command id");

    match followup {
        AgentTool::SysExecSessionReset {} => {}
        other => panic!("expected shell__reset follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_retained_shell_setup_queues_input_with_disposable_stdin() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let followup = toolcat_single_tool_retained_shell_followup(
        "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__input",
        "shell__start",
        Some(&format!(r#"{{"commandId":"{}"}}"#, command_id)),
    )
    .expect("shell__input follow-up should be queued from shell__start output");

    match followup {
        AgentTool::SysExecInput {
            command_id: actual,
            stdin,
        } => {
            assert_eq!(actual, command_id);
            assert_eq!(stdin, "toolcat input\n");
        }
        other => panic!("expected shell__input follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_lifecycle_queues_status_after_start() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let followup = retained_shell_lifecycle_followup(
        goal,
        "shell__start",
        None,
        Some(&format!(r#"{{"command_id":"{}"}}"#, command_id)),
    )
    .expect("retained shell start should queue status check");

    match followup {
        AgentTool::SysExecStatus { command_id: actual } => assert_eq!(actual, command_id),
        other => panic!("expected shell__status follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_lifecycle_queues_stdin_after_status() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let executed = AgentTool::SysExecStatus {
        command_id: command_id.to_string(),
    };
    let followup = retained_shell_lifecycle_followup(goal, "shell__status", Some(&executed), None)
        .expect("retained shell status should queue stdin");

    match followup {
        AgentTool::SysExecInput {
            command_id: actual,
            stdin,
        } => {
            assert_eq!(actual, command_id);
            assert_eq!(stdin, "compile-once\n");
        }
        other => panic!("expected shell__input follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_lifecycle_status_completed_still_queues_terminate_first() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let executed = AgentTool::SysExecStatus {
        command_id: command_id.to_string(),
    };
    let followup = retained_shell_lifecycle_followup(
        goal,
        "shell__status",
        Some(&executed),
        Some(r#"{"status":"completed"}"#),
    )
    .expect("completed retained shell status should still queue terminate first");

    match followup {
        AgentTool::SysExecTerminate { command_id: actual } => assert_eq!(actual, command_id),
        other => panic!("expected shell__terminate follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_lifecycle_queues_terminate_after_input() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let executed = AgentTool::SysExecInput {
        command_id: command_id.to_string(),
        stdin: "compile-once\n".to_string(),
    };
    let followup = retained_shell_lifecycle_followup(goal, "shell__input", Some(&executed), None)
        .expect("retained shell input should queue terminate");

    match followup {
        AgentTool::SysExecTerminate { command_id: actual } => assert_eq!(actual, command_id),
        other => panic!("expected shell__terminate follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_lifecycle_completed_input_still_queues_terminate_first() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let executed = AgentTool::SysExecInput {
        command_id: command_id.to_string(),
        stdin: "compile-once\n".to_string(),
    };
    let followup = retained_shell_lifecycle_followup(
        goal,
        "shell__input",
        Some(&executed),
        Some(r#"{"status":"completed"}"#),
    )
    .expect("completed retained shell input should still queue terminate first");

    match followup {
        AgentTool::SysExecTerminate { command_id: actual } => assert_eq!(actual, command_id),
        other => panic!("expected shell__terminate follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_lifecycle_duplicate_stdin_still_queues_terminate_first() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let executed = AgentTool::SysExecInput {
        command_id: command_id.to_string(),
        stdin: "compile-once\n".to_string(),
    };
    let followup = retained_shell_lifecycle_followup(
        goal,
        "shell__input",
        Some(&executed),
        Some("Input was already sent; continuing with status/cleanup."),
    )
    .expect("duplicate retained shell input should still queue terminate first");

    match followup {
        AgentTool::SysExecTerminate { command_id: actual } => assert_eq!(actual, command_id),
        other => panic!("expected shell__terminate follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_lifecycle_obsolete_stdin_after_stop_still_queues_terminate_first() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let executed = AgentTool::SysExecInput {
        command_id: command_id.to_string(),
        stdin: "compile-once\n".to_string(),
    };
    let followup = retained_shell_lifecycle_followup(
        goal,
        "shell__input",
        Some(&executed),
        Some("Retained command was already stopped; continuing with retained shell cleanup."),
    )
    .expect("obsolete retained shell input should still queue terminate first");

    match followup {
        AgentTool::SysExecTerminate { command_id: actual } => assert_eq!(actual, command_id),
        other => panic!("expected shell__terminate follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_obsolete_input_after_stop_is_benign_cleanup() {
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    assert!(retained_shell_obsolete_input_after_stop(
        goal,
        Some("Command 'shell__start:abc' is no longer running.")
    ));
    assert!(!retained_shell_obsolete_input_after_stop(
        "Run a quick shell command.",
        Some("Command 'shell__start:abc' is no longer running.")
    ));
}

#[test]
fn retained_shell_lifecycle_queues_reset_after_terminate() {
    let command_id =
        "shell__start:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let executed = AgentTool::SysExecTerminate {
        command_id: command_id.to_string(),
    };
    let followup =
        retained_shell_lifecycle_followup(goal, "shell__terminate", Some(&executed), None)
            .expect("retained shell terminate should queue reset");

    match followup {
        AgentTool::SysExecSessionReset {} => {}
        other => panic!("expected shell__reset follow-up, got {:?}", other),
    }
}

#[test]
fn retained_shell_lifecycle_queues_clean_reply_after_reset() {
    let goal = "Start a disposable retained Node.js helper that waits for stdin and echoes a status line. Check the helper status, send the input `compile-once`, terminate the helper, reset retained shell state, and then answer in one clean sentence.";
    let followup = retained_shell_lifecycle_followup(goal, "shell__reset", None, None)
        .expect("retained shell reset should queue terminal reply");

    match followup {
        AgentTool::ChatReply { message } => assert_eq!(
            message,
            "Retained shell helper checked, received `compile-once`, terminated, and reset."
        ),
        other => panic!("expected chat__reply follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_agent_await_setup_queues_requested_await_row_from_delegate_output() {
    let child_id = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let followup = toolcat_single_tool_agent_await_followup(
        "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__await",
        "agent__delegate",
        Some(&format!(r#"{{"child_session_id_hex":"{}"}}"#, child_id)),
    )
    .expect("agent__await follow-up should be queued from agent__delegate output");

    match followup {
        AgentTool::AgentAwait {
            child_session_id_hex,
        } => assert_eq!(child_session_id_hex, child_id),
        other => panic!("expected agent__await follow-up, got {:?}", other),
    }
}

#[test]
fn toolcat_single_tool_success_followup_queues_terminal_reply_for_exact_row() {
    let followup = toolcat_single_tool_success_followup(
        "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__status",
        "shell__status",
    )
    .expect("matching single-tool success should queue chat reply");

    match followup {
        AgentTool::ChatReply { message } => assert_eq!(
            message,
            "TOOLCAT_SINGLE_TOOL shell__status live IDE probe reached the post-tool final reply path."
        ),
        other => panic!("expected chat__reply follow-up, got {:?}", other),
    }

    assert!(toolcat_single_tool_success_followup(
        "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__status",
        "shell__start",
    )
    .is_none());
}

#[test]
fn toolcat_single_tool_chat_reply_target_recovers_from_stale_non_chat_tool() {
    let followup = toolcat_single_tool_chat_reply_recovery_followup(
        "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=chat__reply",
        "shell__reset",
    )
    .expect("chat__reply target should queue the requested terminal reply");

    match followup {
        AgentTool::ChatReply { message } => assert_eq!(
            message,
            "TOOLCAT_SINGLE_TOOL chat__reply live IDE probe reached the post-tool final reply path."
        ),
        other => panic!("expected chat__reply recovery follow-up, got {:?}", other),
    }

    assert!(toolcat_single_tool_chat_reply_recovery_followup(
        "TOOLCAT_STAGE4_SHELL_SOFTWARE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=shell__reset",
        "shell__reset",
    )
    .is_none());
}

#[test]
fn retained_shell_followup_roundtrips_through_queue_mapping_with_tool_identity() {
    let command_id = "shell__start:abcdef";
    let request = tool_to_action_request(
        &AgentTool::SysExecStatus {
            command_id: command_id.to_string(),
        },
        [7u8; 32],
        42,
    )
    .expect("retained shell status should map to queue request");

    let tool = queue_action_request_to_tool(&request).expect("queue replay should preserve status");
    match tool {
        AgentTool::SysExecStatus { command_id: actual } => assert_eq!(actual, command_id),
        other => panic!("expected retained shell status, got {:?}", other),
    }
}

#[test]
fn browser_terminal_reply_completion_releases_dedicated_browser_surface() {
    let mut agent_state = test_agent_state();
    agent_state.status = AgentStatus::Completed(Some("The page title is Example Domain.".into()));
    agent_state.resolved_intent = Some(browser_interact_intent());

    assert!(browser_route_owns_dedicated_surface(&agent_state));
    assert!(should_release_browser_after_terminal_reply(
        &agent_state,
        "browser__navigate",
        Some("The page title is Example Domain."),
    ));
}

#[test]
fn browser_release_predicate_uses_typed_route_frame_fallback() {
    let mut agent_state = test_agent_state();
    agent_state.status = AgentStatus::Completed(Some("done".into()));
    agent_state.runtime_route_frame = Some(RuntimeRouteFrame {
        intent_id: "browser.interact".to_string(),
        route_family: "tool_first".to_string(),
        output_intent: "browser__navigate".to_string(),
        direct_answer_allowed: false,
        target: "https://example.com".to_string(),
        target_kind: Some("url".to_string()),
        host_mutation: false,
        required_capabilities: vec!["browser.navigate".to_string()],
        typed_evidence: vec![],
        typed_required_capabilities: vec![],
        host_mutation_scope: None,
        runtime_action: None,
        install_request: None,
        provenance: Some("test".to_string()),
    });

    assert!(browser_route_owns_dedicated_surface(&agent_state));
    assert!(should_release_browser_after_terminal_reply(
        &agent_state,
        "browser__navigate",
        Some("done"),
    ));
}

#[test]
fn non_browser_terminal_reply_does_not_release_browser_surface() {
    let mut agent_state = test_agent_state();
    agent_state.status = AgentStatus::Completed(Some("done".into()));
    agent_state.resolved_intent = Some(workspace_ops_intent());

    assert!(!browser_route_owns_dedicated_surface(&agent_state));
    assert!(!should_release_browser_after_terminal_reply(
        &agent_state,
        "file__read",
        Some("done"),
    ));
}

#[test]
fn terminal_chat_reply_shape_detects_source_collection_output() {
    let facts = observe_terminal_chat_reply_shape(
        "Legacy collection output\n\nItem 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\n- Example\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high",
    );

    assert!(!facts.heading_present);
    assert_eq!(facts.legacy_source_cluster_header_count, 0);
    assert_eq!(facts.comparison_label_count, 1);
    assert_eq!(
        terminal_chat_reply_layout_profile(&facts),
        TerminalChatReplyLayoutProfile::SourceCollection
    );
}

#[test]
fn terminal_chat_reply_shape_detects_document_report_output() {
    let facts = observe_terminal_chat_reply_shape(
        "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T12:19:24Z UTC)\n\nWhat happened: NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- NIST finalized the first three standards.\n\nCitations:\n- Post-quantum cryptography | NIST | https://www.nist.gov/pqc | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high",
    );

    assert!(facts.heading_present);
    assert_eq!(facts.legacy_source_cluster_header_count, 0);
    assert_eq!(facts.comparison_label_count, 0);
    assert!(facts.run_date_present);
    assert!(facts.run_timestamp_present);
    assert!(facts.overall_confidence_present);
    assert_eq!(
        terminal_chat_reply_layout_profile(&facts),
        TerminalChatReplyLayoutProfile::DocumentReport
    );
}

#[test]
fn terminal_chat_reply_shape_detects_single_snapshot_output() {
    let facts = observe_terminal_chat_reply_shape(
        "Right now (as of 2026-03-11T13:42:57Z UTC):\n\nCurrent conditions from cited source text: Bitcoin price right now: $86,743.63 USD.\n\nCitations:\n- Bitcoin price | index, chart and news | WorldCoinIndex | https://www.worldcoinindex.com/coin/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:42:57Z\nOverall confidence: high",
    );

    assert!(!facts.heading_present);
    assert!(facts.single_snapshot_heading_present);
    assert_eq!(facts.legacy_source_cluster_header_count, 0);
    assert_eq!(facts.comparison_label_count, 0);
    assert!(facts.run_date_present);
    assert!(facts.run_timestamp_present);
    assert!(facts.overall_confidence_present);
    assert_eq!(
        terminal_chat_reply_layout_profile(&facts),
        TerminalChatReplyLayoutProfile::SingleSnapshot
    );
}

#[test]
fn duplicate_prior_success_noop_detects_retry_boundary() {
    assert!(duplicate_prior_success_noop(&[
        "duplicate_action_fingerprint_non_command_noop=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
    ]));
    assert!(!duplicate_prior_success_noop(&[
        "duplicate_action_fingerprint_non_command_noop=true".to_string(),
    ]));
}

#[test]
fn active_web_pipeline_chat_reply_duplicate_noop_stays_in_model_loop() {
    assert!(active_web_pipeline_chat_reply_duplicate_noop(&[
        "duplicate_action_fingerprint_non_command_noop=true".to_string(),
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
        "terminal_chat_reply_deferred_for_active_web_pipeline=true".to_string(),
    ]));
    assert!(active_web_pipeline_chat_reply_duplicate_noop(&[
        "web_model_chat_reply_duplicate_suppressed=true".to_string(),
    ]));
    assert!(!active_web_pipeline_chat_reply_duplicate_noop(&[
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
    ]));
}

#[test]
fn retained_shell_input_duplicate_noop_stays_in_model_loop() {
    assert!(retained_shell_input_duplicate_noop(
        &[
            "duplicate_action_fingerprint_non_command_noop=true".to_string(),
            "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
            "retained_shell_input_duplicate_noop=true".to_string(),
        ],
        "shell__input",
    ));
    assert!(!retained_shell_input_duplicate_noop(
        &["retained_shell_input_duplicate_noop=true".to_string()],
        "shell__status",
    ));
    assert!(!retained_shell_input_duplicate_noop(
        &["duplicate_action_fingerprint_prior_success_noop=true".to_string()],
        "shell__input",
    ));
}

#[test]
fn workspace_read_context_duplicate_noop_is_not_terminal_failure() {
    let mut agent_state = test_agent_state();
    agent_state.resolved_intent = Some(workspace_ops_intent());
    record_execution_evidence(&mut agent_state.tool_execution_log, "workspace_read");
    record_execution_evidence(&mut agent_state.tool_execution_log, "file_context");

    assert!(read_only_workspace_context_duplicate_noop(
        &agent_state,
        "file__read",
    ));
    assert!(read_only_workspace_context_duplicate_noop(
        &agent_state,
        "file__search",
    ));
    assert!(!read_only_workspace_context_duplicate_noop(
        &agent_state,
        "shell__run",
    ));
}

#[test]
fn command_workspace_read_context_duplicate_noop_is_not_terminal_failure() {
    let mut agent_state = test_agent_state();
    agent_state.resolved_intent = Some(command_workspace_intent());

    assert!(read_only_workspace_context_duplicate_noop(
        &agent_state,
        "file__read",
    ));

    record_execution_evidence(&mut agent_state.tool_execution_log, "workspace_read");
    record_execution_evidence(&mut agent_state.tool_execution_log, "file_context");

    assert!(read_only_workspace_context_duplicate_noop(
        &agent_state,
        "file__read",
    ));
    assert!(read_only_workspace_context_duplicate_noop(
        &agent_state,
        "file__info",
    ));
    assert!(!read_only_workspace_context_duplicate_noop(
        &agent_state,
        "shell__run",
    ));
}

#[test]
fn command_workspace_read_context_duplicate_noop_survives_missing_resolved_intent() {
    let mut agent_state = test_agent_state();
    agent_state.goal = "Fix src/format.mjs, then run `node --test tests/*.test.mjs`.".to_string();
    agent_state.resolved_intent = None;

    assert!(read_only_workspace_context_duplicate_noop(
        &agent_state,
        "file__read",
    ));
    assert!(read_only_workspace_context_duplicate_noop(
        &agent_state,
        "file__info",
    ));
    assert!(!read_only_workspace_context_duplicate_noop(
        &agent_state,
        "shell__run",
    ));
}

#[test]
fn duplicate_after_prior_success_detects_strict_and_noop_guards() {
    assert!(duplicate_after_prior_success(&[
        "duplicate_action_fingerprint_non_command_skipped=true".to_string(),
        "duplicate_action_fingerprint_prior_success=true".to_string(),
    ]));
    assert!(duplicate_after_prior_success(&[
        "duplicate_action_fingerprint_prior_success_noop=true".to_string(),
    ]));
    assert!(!duplicate_after_prior_success(&[
        "duplicate_action_fingerprint_non_command_skipped=true".to_string(),
    ]));
}

#[test]
fn install_resolution_blocker_is_terminalized_from_receipt() {
    let checks = vec!["software_install_blocked_before_approval=true".to_string()];
    let reason = install_resolution_terminal_block_reason(
        &checks,
        Some(
            "ERROR_CLASS=InstallerResolutionRequired No verified install mapping exists for 'snorflepaint'.",
        ),
        None,
        None,
    )
    .expect("resolver blocker should terminalize");

    assert!(reason.contains("InstallerResolutionRequired"));
    assert!(reason.contains("snorflepaint"));
}

#[test]
fn non_install_failure_is_not_terminalized_as_install_blocker() {
    let checks = vec!["policy_decision=allowed".to_string()];

    assert!(install_resolution_terminal_block_reason(
        &checks,
        Some("ERROR_CLASS=UnexpectedState unrelated failure"),
        None,
        None,
    )
    .is_none());
}

#[test]
fn already_satisfied_install_is_terminalized_as_completion() {
    let checks = vec!["install_already_satisfied_before_approval=true".to_string()];
    let reason = install_already_satisfied_terminal_reason(
        &checks,
        Some("Already installed: 'LM Studio' is present before host mutation."),
        None,
    )
    .expect("verified installed target should terminalize");

    assert!(reason.contains("Already installed"));
    assert!(reason.contains("LM Studio"));
}

#[test]
fn already_satisfied_install_reply_hides_raw_receipt_tokens() {
    let reply = install_already_satisfied_operator_reply(
        r#"{"kind":"install_final_receipt","install_final_receipt":{"status":"already_installed_verified","display_name":"LM Studio","verification":{"passed":true,"command":"lms --version","observed_version":null,"evidence":[]}}}"#,
    );

    assert!(reply.contains("LM Studio is already installed"));
    assert!(reply.contains("`lms --version`"));
    assert!(!reply.contains("install_final_receipt"));
}

#[test]
fn workspace_goal_prefers_package_manifest_recovery_for_desktop_script_queries() {
    assert!(workspace_goal_prefers_package_manifest_recovery(
        "What npm script launches the desktop app in this repo?"
    ));
    assert!(!workspace_goal_prefers_package_manifest_recovery(
        "What does the README say about the desktop app?"
    ));
}

#[test]
fn select_manifest_script_recovery_candidate_prefers_unique_desktop_script() {
    let manifest = r#"{
      "scripts": {
        "dev": "vite",
        "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11",
        "test": "vitest"
      }
    }"#;

    assert_eq!(
        select_manifest_script_recovery_candidate(
            "What npm script launches the desktop app in this repo?",
            manifest,
        ),
        Some(ManifestScriptRecoveryCandidate {
            name: "dev:desktop".to_string(),
            command: "bash apps/autopilot/scripts/dev-desktop.sh x11".to_string(),
        })
    );
}

#[test]
fn select_manifest_script_recovery_candidate_prefers_launch_oriented_desktop_match() {
    let manifest = r#"{
      "scripts": {
        "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11",
        "start:desktop": "electron ."
      }
    }"#;

    assert_eq!(
        select_manifest_script_recovery_candidate(
            "What npm script launches the desktop app in this repo?",
            manifest,
        ),
        Some(ManifestScriptRecoveryCandidate {
            name: "dev:desktop".to_string(),
            command: "bash apps/autopilot/scripts/dev-desktop.sh x11".to_string(),
        })
    );
}

#[test]
fn select_manifest_script_recovery_candidate_prefers_primary_desktop_script_over_variants() {
    let manifest = r#"{
      "scripts": {
        "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11",
        "dev:desktop:wayland": "bash apps/autopilot/scripts/dev-desktop.sh wayland",
        "dryrun:desktop": "bash apps/autopilot/scripts/dry-run-desktop.sh x11"
      }
    }"#;

    assert_eq!(
        select_manifest_script_recovery_candidate(
            "What npm script launches the desktop app in this repo?",
            manifest,
        ),
        Some(ManifestScriptRecoveryCandidate {
            name: "dev:desktop".to_string(),
            command: "bash apps/autopilot/scripts/dev-desktop.sh x11".to_string(),
        })
    );
}

#[test]
fn manifest_read_terminalization_emits_desktop_script_reply() {
    let mut agent_state = test_agent_state();
    agent_state.goal = "What npm script launches the desktop app in this repo?".to_string();
    agent_state.resolved_intent = Some(workspace_ops_intent());

    let manifest = r#"{
      "scripts": {
        "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11",
        "dev:desktop:wayland": "bash apps/autopilot/scripts/dev-desktop.sh wayland"
      }
    }"#;

    assert_eq!(
        maybe_terminalize_workspace_package_manifest_read(
            &agent_state,
            "file__read",
            Some(manifest),
        ),
        Some(
            "In `package.json`, the npm script that launches the desktop app is `dev:desktop`. It runs `bash apps/autopilot/scripts/dev-desktop.sh x11`.".to_string()
        )
    );
}

#[test]
fn workspace_package_manifest_recovery_enqueues_read_then_reply_on_first_no_effect() {
    let dir = std::env::temp_dir().join(format!(
        "ioi-package-manifest-recovery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be available")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    std::fs::write(
        dir.join("package.json"),
        r#"{
          "scripts": {
            "dev:desktop": "bash apps/autopilot/scripts/dev-desktop.sh x11"
          }
        }"#,
    )
    .expect("package.json should be written");

    let mut agent_state = test_agent_state();
    agent_state.goal = "What npm script launches the desktop app in this repo?".to_string();
    agent_state.resolved_intent = Some(workspace_ops_intent());
    agent_state.working_directory = dir.to_string_lossy().to_string();

    let queued = maybe_enqueue_workspace_package_manifest_recovery(
        &mut agent_state,
        [7u8; 32],
        FailureClass::NoEffectAfterAction,
        "file__list",
    )
    .expect("recovery enqueue should succeed");

    assert!(queued);
    assert_eq!(agent_state.execution_queue.len(), 2);

    let read_tool = queue_action_request_to_tool(&agent_state.execution_queue[0])
        .expect("queued read should decode");
    let reply_tool = queue_action_request_to_tool(&agent_state.execution_queue[1])
        .expect("queued reply should decode");

    match read_tool {
        AgentTool::FsRead { path } => assert_eq!(path, "./package.json"),
        other => panic!("expected FsRead recovery tool, got {:?}", other),
    }
    match reply_tool {
        AgentTool::ChatReply { message } => {
            assert!(message.contains("`dev:desktop`"));
            assert!(message.contains("dev-desktop.sh x11"));
        }
        other => panic!("expected ChatReply recovery tool, got {:?}", other),
    }

    let _ = std::fs::remove_file(dir.join("package.json"));
    let _ = std::fs::remove_dir(dir);
}
