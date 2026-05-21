use super::{
    agent_message_exists_after_latest_user, automation_artifact_path_from_output,
    completion_message_for_history, failure_message_for_history, install_failure_summary,
    is_chat_reply_tool, is_planner_execute_tool,
    should_append_completed_tool_message_from_action_result,
    should_preserve_existing_operator_gate, should_refocus_chat_after_action_result,
    should_release_browser_after_action_result, truncate_message_chars,
};
use crate::models::{AgentPhase, AgentTask, ChatMessage, GateInfo};
use std::collections::HashSet;

#[test]
fn chat_reply_tool_detection_is_case_insensitive() {
    assert!(is_chat_reply_tool("chat__reply"));
    assert!(is_chat_reply_tool("CHAT::REPLY"));
    assert!(!is_chat_reply_tool("planner::execute"));
}

#[test]
fn planner_completion_prefers_scheduled_workflow_summary() {
    let output = "Route: route.linux.systemd_run.notify_send. Strategy: Selected Linux scheduler route. COMMAND_HISTORY:{\"command\":\"systemd-run --user --on-active=900s\"}\nStderr:\nRunning timer as unit: ioi-timer-1.timer\nWill run service as unit: ioi-timer-1.service\nScheduled workflow: set a timer for 15 minutes. Target UTC: 2026-02-24T03:47:26Z.";
    let message = completion_message_for_history("planner::execute", output).expect("message");
    assert!(message.starts_with("Scheduled workflow:"));
    assert!(message.contains("Target UTC: 2026-02-24T03:47:26Z."));
    assert!(!message.contains("COMMAND_HISTORY:"));
}

#[test]
fn planner_completion_falls_back_to_route_without_command_history_blob() {
    let output =
        "Route: route.local.timer. Strategy: fallback route. COMMAND_HISTORY:{\"command\":\"foo\"}";
    let message = completion_message_for_history("planner::execute", output).expect("message");
    assert_eq!(
        message,
        "Route: route.local.timer. Strategy: fallback route."
    );
    assert!(is_planner_execute_tool("planner::execute"));
}

#[test]
fn completion_message_is_truncated_for_very_long_output() {
    let long = "a".repeat(5000);
    let message =
        completion_message_for_history("shell__run", &long).expect("message should exist");
    assert!(message.len() < long.len());
    assert!(message.ends_with('…'));
    assert_eq!(message, truncate_message_chars(&long, 1200));
}

#[test]
fn empty_completion_output_yields_none() {
    assert!(completion_message_for_history("planner::execute", "   ").is_none());
}

#[test]
fn chat_primary_tool_completion_waits_for_chat_reply_event() {
    assert!(!should_append_completed_tool_message_from_action_result(
        true,
        true,
        "browser__navigate"
    ));
    assert!(!should_append_completed_tool_message_from_action_result(
        true,
        true,
        "chat__reply"
    ));
    assert!(!should_append_completed_tool_message_from_action_result(
        false,
        true,
        "browser__navigate"
    ));
    assert!(should_append_completed_tool_message_from_action_result(
        false,
        false,
        "browser__navigate"
    ));
}

#[test]
fn terminal_browser_actions_refocus_chat_surface() {
    assert!(should_refocus_chat_after_action_result(
        "browser__navigate",
        "Completed"
    ));
    assert!(should_refocus_chat_after_action_result(
        "browser::inspect",
        "Failed"
    ));
    assert!(!should_refocus_chat_after_action_result(
        "browser__navigate",
        "Running"
    ));
    assert!(!should_refocus_chat_after_action_result(
        "shell__run",
        "Completed"
    ));
}

#[test]
fn browser_completion_refocus_does_not_open_legacy_chat_session_surface() {
    let source = include_str!("../action_result.rs");
    assert!(
        !source.contains("windows::show_chat_session"),
        "browser completion refocus must target the already-open chat surface, not open another chat window",
    );
    assert!(source.contains("get_webview_window(\"chat\")"));
}

#[test]
fn completed_browser_actions_release_dedicated_browser_session() {
    assert!(should_release_browser_after_action_result(
        "browser__navigate",
        "Completed",
        false
    ));
    assert!(should_release_browser_after_action_result(
        "browser::inspect",
        "Completed",
        false
    ));
    assert!(should_release_browser_after_action_result(
        "chat__reply",
        "Completed",
        true
    ));
    assert!(!should_release_browser_after_action_result(
        "browser__navigate",
        "Failed",
        false
    ));
    assert!(!should_release_browser_after_action_result(
        "shell__run",
        "Completed",
        false
    ));
}

#[test]
fn action_result_dedupe_scans_current_turn_past_receipts_only() {
    let first_turn_answer = ChatMessage {
        role: "agent".to_string(),
        text: "The page title is Example Domain.".to_string(),
        timestamp: crate::kernel::state::now(),
    };
    let latest_prompt = ChatMessage {
        role: "user".to_string(),
        text: "Use the browser to open https://example.com and tell me the page title.".to_string(),
        timestamp: crate::kernel::state::now(),
    };
    let latest_answer = ChatMessage {
        role: "agent".to_string(),
        text: "The page title is Example Domain.".to_string(),
        timestamp: crate::kernel::state::now(),
    };
    let receipt = ChatMessage {
        role: "system".to_string(),
        text: "terminal_chat_reply_postcondition".to_string(),
        timestamp: crate::kernel::state::now(),
    };

    assert!(!agent_message_exists_after_latest_user(
        &[first_turn_answer, latest_prompt.clone()],
        "The page title is Example Domain."
    ));
    assert!(agent_message_exists_after_latest_user(
        &[latest_prompt, latest_answer, receipt],
        "The page title is Example Domain."
    ));
}

#[test]
fn install_failure_summary_hides_raw_error_class_receipt() {
    let output = r#"ERROR_CLASS=InstallerResolutionRequired {"summary":"No verified install candidate passed resolver policy for 'snorflepaint'.","install_event":{"stage":"unresolved"}}
install_resolution_stage=unresolved install_display_name=snorflepaint"#;

    let summary =
        install_failure_summary("software_install__resolve", output).expect("install summary");

    assert_eq!(
        summary,
        "Install blocked: No verified install candidate passed resolver policy for 'snorflepaint'."
    );
    assert!(!summary.contains("ERROR_CLASS"));
}

#[test]
fn failure_history_message_hides_raw_install_receipt() {
    let output = r#"ERROR_CLASS=InstallerResolutionRequired {"summary":"No verified install candidate passed resolver policy for 'snorflepaint'.","install_event":{"stage":"unresolved"}}
install_resolution_stage=unresolved install_display_name=snorflepaint"#;

    let message = failure_message_for_history("software_install__resolve", output);

    assert_eq!(
        message,
        "Install blocked: No verified install candidate passed resolver policy for 'snorflepaint'."
    );
    assert!(!message.contains("ERROR_CLASS"));
    assert!(!message.contains("install_resolution_stage"));
}

#[test]
fn automation_artifact_path_is_parsed_from_tool_output() {
    let output = "Scheduled workflow: Monitor Hacker News\nWorkflow ID: monitor_hn\nArtifact path: /tmp/ioi-data/automation/artifacts/monitor_hn.json";
    let path = automation_artifact_path_from_output(output).expect("artifact path");
    assert_eq!(
        path,
        std::path::PathBuf::from("/tmp/ioi-data/automation/artifacts/monitor_hn.json")
    );
}

fn gated_task() -> AgentTask {
    let mut task = AgentTask {
        id: "install-session".to_string(),
        intent: "install lmstudio".to_string(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Gate,
        progress: 0,
        total_steps: 1,
        current_step: "Awaiting install approval: LM Studio".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some("install-session".to_string()),
        credential_request: None,
        clarification_request: None,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history: Vec::new(),
        events: Vec::new(),
        artifacts: Vec::new(),
        chat_session: None,
        chat_outcome: None,
        renderer_session: None,
        build_session: None,
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        work_graph_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };
    task.phase = AgentPhase::Gate;
    task.gate_info = Some(GateInfo {
        title: "Approve software install".to_string(),
        description: "Resolver-backed install approval is pending.".to_string(),
        risk: "high".to_string(),
        approve_label: Some("Approve install".to_string()),
        deny_label: Some("Deny".to_string()),
        deadline_ms: None,
        surface_label: Some("Host system".to_string()),
        scope_label: Some("Software install".to_string()),
        operation_label: Some("Install".to_string()),
        target_label: Some("LM Studio".to_string()),
        operator_note: None,
        pii: None,
    });
    task.pending_request_hash = Some("approval-hash".to_string());
    task
}

#[test]
fn action_result_preserves_existing_operator_gate_until_decision() {
    let task = gated_task();

    assert!(should_preserve_existing_operator_gate(&task, "Completed"));
    assert!(should_preserve_existing_operator_gate(&task, "Paused"));
    assert!(!should_preserve_existing_operator_gate(&task, "Failed"));
}
