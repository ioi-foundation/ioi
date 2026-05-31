#[test]
fn command_history_context_shows_latest_five_entries_reverse_chronological() {
    let mut history = VecDeque::new();
    for step in 0..6 {
        history.push_back(CommandExecution {
            command: format!("command-{step}"),
            exit_code: 0,
            stdout: format!("stdout-{step}"),
            stderr: String::new(),
            timestamp_ms: step,
            step_index: step as u32,
        });
    }

    let context = build_recent_command_history_context(&history);
    assert!(context.contains("1. [Step 5] command-5"));
    assert!(context.contains("5. [Step 1] command-1"));
    assert!(!context.contains("command-0"));
}

#[test]
fn command_history_context_is_empty_without_history() {
    let context = build_recent_command_history_context(&VecDeque::new());
    assert!(context.is_empty());
}

#[test]
fn command_history_context_uses_latest_five_and_excludes_older_entries() {
    let mut history = VecDeque::new();
    for step in 0..8 {
        history.push_back(CommandExecution {
            command: format!("command-{step}"),
            exit_code: 0,
            stdout: "no secrets here".to_string(),
            stderr: String::new(),
            timestamp_ms: step,
            step_index: step as u32,
        });
    }

    let context = build_recent_command_history_context(&history);
    assert!(context.contains("1. [Step 7] command-7"));
    assert!(context.contains("5. [Step 3] command-3"));
    assert!(!context.contains("command-2"));
}

#[test]
fn command_history_context_renders_sanitized_entries() {
    let mut history = VecDeque::new();
    history.push_back(CommandExecution {
        command: "command-1".to_string(),
        exit_code: 1,
        stdout: "<REDACTED>".to_string(),
        stderr: "<REDACTED>".to_string(),
        timestamp_ms: 1,
        step_index: 1,
    });
    history.push_back(CommandExecution {
        command: "command-2".to_string(),
        exit_code: 0,
        stdout: "healthy".to_string(),
        stderr: String::new(),
        timestamp_ms: 2,
        step_index: 2,
    });

    let context = build_recent_command_history_context(&history);
    assert!(context.contains("command-1"));
    assert!(context.contains("command-2"));
    assert!(context.contains("<REDACTED>"));
}

#[test]
fn inference_error_reason_marks_quota_failures_as_user_intervention() {
    let reason = inference_error_system_fail_reason(
        "Provider Error 429 Too Many Requests: { \"error\": { \"code\": \"insufficient_quota\" } }",
    );
    assert!(reason.contains("ERROR_CLASS=UserInterventionNeeded"));
    assert!(reason.contains("insufficient_quota"));
}

#[test]
fn inference_error_reason_marks_auth_failures_as_user_intervention() {
    let reason =
        inference_error_system_fail_reason("Provider Error 401 Unauthorized: invalid_api_key");
    assert!(reason.contains("ERROR_CLASS=UserInterventionNeeded"));
    assert!(reason.contains("authentication failed"));
}

#[test]
fn inference_error_reason_includes_compact_detail_for_unknown_failures() {
    let reason = inference_error_system_fail_reason(
        "upstream runtime panic: envelope decode failed in cognition bridge",
    );
    assert!(reason.contains("ERROR_CLASS=UserInterventionNeeded"));
    assert!(reason.contains("detail=upstream runtime panic"));
}

#[test]
fn browser_observation_context_prefers_current_snapshot_over_stale_history() {
    let history = vec![chat_message(
        "tool",
        r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_one" name="ONE" dom_id="subbtn" selector="[id=&quot;subbtn&quot;]" rect="105,79,40,40" /><button id="btn_two" name="TWO" dom_id="subbtn2" selector="[id=&quot;subbtn2&quot;]" rect="56,117,40,40" /></root>"#,
        1,
    )];
    let current_snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_start\" name=\"START\" dom_id=\"sync-task-cover\" selector=\"[id=&quot;sync-task-cover&quot;]\" rect=\"0,0,160,210\" />",
        "<button id=\"btn_one\" name=\"ONE\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"105,79,40,40\" />",
        "<button id=\"btn_two\" name=\"TWO\" dom_id=\"subbtn2\" selector=\"[id=&quot;subbtn2&quot;]\" rect=\"56,117,40,40\" />",
        "</root>",
    );

    let context =
        super::resolve_browser_observation_context(&history, Some(current_snapshot), true);

    assert!(context.contains("grp_start"), "{context}");
    assert!(!context.contains("btn_one"), "{context}");
    assert!(!context.contains("btn_two"), "{context}");
}

#[test]
fn format_tool_desc_appends_worker_template_catalog_when_delegate_is_available() {
    let formatted = super::format_tool_desc(
        &[LlmToolDefinition {
            name: "agent__delegate".to_string(),
            description: "Spawn a bounded child worker.".to_string(),
            parameters: "{}".to_string(),
        }],
        false,
        "Port the LocalAI parity fix in the Rust crate, research the current behavior, patch the workspace, and verify the postcondition.",
        Some(&automation_resolved_intent()),
    );

    assert!(formatted.contains("[WORKER TEMPLATES]"));
    assert!(formatted.contains("[PARENT PLAYBOOKS]"));
    assert!(formatted.contains("`researcher`"));
    assert!(formatted.contains("`verifier`"));
    assert!(formatted.contains("`coder`"));
    assert!(formatted.contains("Playbook `live_research_brief`"));
}
