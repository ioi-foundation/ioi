use super::{
    blocked_terminalization_error, blocked_terminalization_summary_from_history,
    blocked_terminalization_summary_from_history_and_snapshot,
    completion_gate_needs_pending_browser_check,
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
