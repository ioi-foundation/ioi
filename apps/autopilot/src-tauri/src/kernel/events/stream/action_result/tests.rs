use super::{
    automation_artifact_path_from_output, completion_message_for_history, is_chat_reply_tool,
    is_planner_execute_tool, truncate_message_chars,
};

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
fn automation_artifact_path_is_parsed_from_tool_output() {
    let output = "Scheduled workflow: Monitor Hacker News\nWorkflow ID: monitor_hn\nArtifact path: /tmp/ioi-data/automation/artifacts/monitor_hn.json";
    let path = automation_artifact_path_from_output(output).expect("artifact path");
    assert_eq!(
        path,
        std::path::PathBuf::from("/tmp/ioi-data/automation/artifacts/monitor_hn.json")
    );
}
