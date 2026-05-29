use super::{
    blocked_terminalization_error, blocked_terminalization_summary_from_history,
    blocked_terminalization_summary_from_history_and_snapshot,
    blocked_terminalization_summary_from_history_and_snapshot_for_goal,
    browser_observation_receipt_from_navigation_output,
    completion_gate_needs_pending_browser_check, is_toolcat_single_tool_probe,
    toolcat_single_tool_pause_reply, toolcat_single_tool_success_reply, toolcat_single_tool_target,
    toolcat_single_tool_target_completed, workspace_chat_reply_looks_terminal,
};
use ioi_types::app::agentic::ChatMessage;

fn chat_message(role: &str, content: &str, timestamp: u64) -> ChatMessage {
    ChatMessage {
        role: role.to_string(),
        content: content.to_string(),
        timestamp,
        trace_hash: None,
    }
}

#[test]
fn workspace_chat_reply_terminality_rejects_planning_status() {
    assert!(!workspace_chat_reply_looks_terminal(
        "I need to read the master guide file before I can answer."
    ));
    assert!(!workspace_chat_reply_looks_terminal(
        "I'm analyzing the workspace and need to search for provider registration."
    ));
    assert!(workspace_chat_reply_looks_terminal(
        "Local and native providers are registered through the daemon model mounting catalog and exposed through the workbench route selector."
    ));
}

#[test]
fn blocked_terminalization_summary_surfaces_pending_browser_state() {
    let history = vec![
        chat_message(
            "user",
            "Find Deena in the contact book and click on their address.",
            1,
        ),
        chat_message(
            "tool",
            r#"{"query":"Deena","result":{"count":1,"first_snippet":"Find Deena in the contact book and click on their address.","found":true,"scope":"document","scrolled":true}}"#,
            2,
        ),
        chat_message(
            "tool",
            concat!(
                "Tool Output (browser__inspect): ",
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
                "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
                "<heading id=\"heading_lauraine\" name=\"Lauraine\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
                "<link id=\"lnk_5193_buchanan_ave_unit_31\" name=\"5193 Buchanan Ave, Unit 31\" tag_name=\"a\" rect=\"6,135,138,22\" />",
                "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"69,183,9,17\" />",
                "</root>",
            ),
            3,
        ),
    ];

    let blocked = blocked_terminalization_summary_from_history(&history)
        .expect("pending browser state should block terminalization");

    assert!(
        blocked.contains("Completion blocked because unresolved browser work remains"),
        "{blocked}"
    );
    assert!(
        blocked.contains("RECENT PENDING BROWSER STATE:"),
        "{blocked}"
    );
    assert!(blocked.contains("`Deena`"), "{blocked}");
    assert!(blocked.contains("`lnk_443422`"), "{blocked}");
}

#[test]
fn blocked_terminalization_summary_is_empty_without_pending_browser_state() {
    let history = vec![
        chat_message("user", "Open the page and inspect it.", 1),
        chat_message(
            "tool",
            concat!(
                "Tool Output (browser__inspect): ",
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
                "<generic id=\"grp_done\" name=\"Done\" tag_name=\"div\" rect=\"0,0,80,20\" />",
                "</root>",
            ),
            2,
        ),
    ];

    assert!(
        blocked_terminalization_summary_from_history(&history).is_none(),
        "unexpected terminalization blocker for settled browser state"
    );
}

#[test]
fn blocked_terminalization_summary_uses_current_snapshot_when_history_snapshot_is_missing() {
    let history = vec![
        chat_message(
            "user",
            "Find Deena in the contact book and click on their address.",
            1,
        ),
        chat_message(
            "tool",
            r#"{"query":"Deena","result":{"count":1,"first_snippet":"Find Deena in the contact book and click on their address.","found":true,"scope":"document","scrolled":true}}"#,
            2,
        ),
    ];
    let current_snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
        "<heading id=\"heading_lauraine\" name=\"Lauraine\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
        "<link id=\"lnk_5193_buchanan_ave_unit_31\" name=\"5193 Buchanan Ave, Unit 31\" tag_name=\"a\" rect=\"6,135,138,22\" />",
        "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"69,183,9,17\" />",
        "</root>",
    );

    let blocked =
        blocked_terminalization_summary_from_history_and_snapshot(&history, Some(current_snapshot))
            .expect("live current browser snapshot should block terminalization");

    assert!(
        blocked.contains("RECENT PENDING BROWSER STATE:"),
        "{blocked}"
    );
    assert!(blocked.contains("`Deena`"), "{blocked}");
    assert!(blocked.contains("`lnk_443422`"), "{blocked}");
}

#[test]
fn toolcat_single_tool_target_parses_exact_catalogue_row() {
    assert_eq!(
        toolcat_single_tool_target(
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__move_pointer Run exactly this row"
        ),
        Some("browser__move_pointer")
    );
    assert_eq!(toolcat_single_tool_target("ordinary browser task"), None);
}

#[test]
fn toolcat_single_tool_completed_target_skips_pending_browser_terminalization_blocker() {
    let history = vec![
        chat_message(
            "user",
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__move_pointer Run exactly this live IDE Rust/provider tool row.",
            1,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__move_pointer): {"pointer":{"action":"move","x":48,"y":48}}"#,
            2,
        ),
    ];
    let current_snapshot =
        "RECENT PENDING BROWSER STATE:\nThe pointer is already positioned. Use `browser__pointer_down` now.\n";

    assert!(toolcat_single_tool_target_completed(
        "TOOLCAT_SINGLE_TOOL toolcat_tool=browser__move_pointer",
        &history
    ));
    assert!(
        blocked_terminalization_summary_from_history_and_snapshot_for_goal(
            &history,
            Some(current_snapshot),
            "TOOLCAT_SINGLE_TOOL toolcat_tool=browser__move_pointer",
        )
        .is_none(),
        "completed catalogue row should be able to emit its final chat reply"
    );
}

#[test]
fn toolcat_single_tool_failed_target_does_not_skip_pending_browser_terminalization_blocker() {
    let history = vec![
        chat_message(
            "user",
            "TOOLCAT_STAGE5_BROWSER_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=browser__move_pointer Find Deena in the contact book and click on their address.",
            1,
        ),
        chat_message(
            "tool",
            r#"{"query":"Deena","result":{"count":1,"first_snippet":"Find Deena in the contact book and click on their address.","found":true,"scope":"document","scrolled":true}}"#,
            2,
        ),
        chat_message(
            "tool",
            "Tool Output (browser__move_pointer): ERROR_CLASS=NoEffectAfterAction pointer did not move",
            3,
        ),
    ];
    let current_snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
        "<heading id=\"heading_lauraine\" name=\"Lauraine\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
        "<link id=\"lnk_5193_buchanan_ave_unit_31\" name=\"5193 Buchanan Ave, Unit 31\" tag_name=\"a\" rect=\"6,135,138,22\" />",
        "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"69,183,9,17\" />",
        "</root>",
    );

    assert!(!toolcat_single_tool_target_completed(
        "TOOLCAT_SINGLE_TOOL toolcat_tool=browser__move_pointer",
        &history
    ));
    assert!(
        blocked_terminalization_summary_from_history_and_snapshot_for_goal(
            &history,
            Some(current_snapshot),
            "TOOLCAT_SINGLE_TOOL toolcat_tool=browser__move_pointer",
        )
        .is_some(),
        "failed catalogue row should still preserve the browser completion gate"
    );
}

#[test]
fn blocked_terminalization_is_disabled_when_browser_semantics_snapshot_is_present() {
    let history = vec![chat_message(
        "tool",
        concat!(
            "Tool Output (browser__inspect): <root />\n\n",
            "BROWSER_USE_STATE_TXT:\n[12]<button name=Submit />\n\n",
            "BROWSERGYM_AXTREE_TXT:\n[a1] button \"Submit\""
        ),
        1,
    )];

    assert!(blocked_terminalization_summary_from_history(&history).is_none());
    assert!(blocked_terminalization_summary_from_history_and_snapshot(
        &history,
        Some("BROWSER_USE_STATE_TXT:\n[12]<button name=Submit />"),
    )
    .is_none());
}

#[test]
fn blocked_terminalization_error_uses_no_effect_error_class() {
    let summary = concat!(
        "Completion blocked because unresolved browser work remains. ",
        "Do not finalize yet while RECENT PENDING BROWSER STATE is present. ",
        "Use the named browser action first.\nRECENT PENDING BROWSER STATE:\n",
        "`Deena` is not on the current record `Lauraine`.\n",
    );

    let error = blocked_terminalization_error(summary);

    assert!(
        error.starts_with("ERROR_CLASS=NoEffectAfterAction "),
        "{error}"
    );
    assert!(error.contains("RECENT PENDING BROWSER STATE:"), "{error}");
    assert!(error.contains("`Deena`"), "{error}");
}

#[test]
fn conversation_reply_completion_gate_skips_pending_browser_checks() {
    assert!(!completion_gate_needs_pending_browser_check(
        "conversation.reply"
    ));
    assert!(completion_gate_needs_pending_browser_check(
        "browser.navigate"
    ));
}

#[test]
fn toolcat_single_tool_pause_reply_preserves_exact_row_identity() {
    assert!(is_toolcat_single_tool_probe(
        "TOOLCAT_STAGE1_LIFECYCLE_SINGLE TOOLCAT_SINGLE_TOOL toolcat_tool=agent__pause"
    ));
    assert_eq!(
        toolcat_single_tool_pause_reply("agent__pause"),
        "TOOLCAT_SINGLE_TOOL agent__pause live IDE probe reached the pause control path."
    );
}

#[test]
fn toolcat_single_tool_success_reply_preserves_exact_row_identity() {
    assert_eq!(
        toolcat_single_tool_success_reply("app__launch", "Opened fixture."),
        "TOOLCAT_SINGLE_TOOL app__launch live IDE probe completed. Opened fixture."
    );
}

#[test]
fn browser_navigation_receipt_extracts_page_title_for_typed_completion() {
    let receipt = browser_observation_receipt_from_navigation_output(
        r#"{"browser_observation_receipt":{"observation_ref":"browser.observation:528","url":"https://example.com","title":"Example Domain","content_len":528},"summary":"Navigated to https://example.com."}"#,
    )
    .expect("navigation receipt should expose page title");

    assert_eq!(receipt.title.as_deref(), Some("Example Domain"));
    assert!(browser_observation_receipt_from_navigation_output(
        "Navigated to https://example.com. Page title: Example Domain. Content len: 528",
    )
    .is_none());
}
