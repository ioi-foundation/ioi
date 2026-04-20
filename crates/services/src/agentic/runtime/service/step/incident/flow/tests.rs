use super::{consume_enqueued_root_retry, planner_pending_browser_state_from_history};
use crate::agentic::runtime::service::step::incident::core::IncidentState;
use ioi_types::app::agentic::ChatMessage;

fn chat_message(role: &str, content: &str, timestamp: u64) -> ChatMessage {
    ChatMessage {
        role: role.to_string(),
        content: content.to_string(),
        timestamp,
        trace_hash: None,
    }
}

fn test_incident_state(root_tool_name: &str, root_failure_class: &str) -> IncidentState {
    IncidentState {
        incident_id: "incident-1".to_string(),
        active: true,
        root_retry_hash: "retry-hash".to_string(),
        root_tool_name: root_tool_name.to_string(),
        root_tool_jcs: br#"{"name":"browser__inspect","arguments":{}}"#.to_vec(),
        root_failure_class: root_failure_class.to_string(),
        root_error: Some("ERROR_CLASS=NoEffectAfterAction duplicate replay guard".to_string()),
        intent_class: "UIInteraction".to_string(),
        stage: "RetryRoot".to_string(),
        strategy_name: "UIRecovery".to_string(),
        strategy_cursor: "RetryRootAction".to_string(),
        visited_node_fingerprints: vec![],
        pending_gate: None,
        gate_state: "Cleared".to_string(),
        resolution_action: "execute_remedy".to_string(),
        transitions_used: 1,
        max_transitions: 32,
        started_step: 0,
        pending_remedy_fingerprint: None,
        pending_remedy_tool_jcs: None,
        retry_enqueued: false,
    }
}

#[test]
fn planner_pending_browser_state_uses_latest_snapshot_context_for_duplicate_snapshot_incident() {
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

    let pending = planner_pending_browser_state_from_history(
        &test_incident_state("browser__inspect", "NoEffectAfterAction"),
        &history,
    )
    .expect("pending browser state should be present");

    assert!(
        pending.contains("RECENT PENDING BROWSER STATE:"),
        "{pending}"
    );
    assert!(pending.contains("`Deena`"), "{pending}");
    assert!(
        pending.contains("Do not click this record's links"),
        "{pending}"
    );
    assert!(pending.contains("`lnk_443422`"), "{pending}");
}

#[test]
fn planner_pending_browser_state_falls_back_to_recent_explicit_pending_context() {
    let history = vec![
        chat_message(
            "system",
            "RECENT PENDING BROWSER STATE:\n`Deena` is not on the current record `Lauraine`. The only valid next `browser__click` id here is `lnk_443422`.\n",
            1,
        ),
        chat_message(
            "tool",
            "Tool Output (browser__inspect): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
            2,
        ),
        chat_message(
            "system",
            "System: Selected recovery action `browser__wait`.",
            3,
        ),
    ];

    let pending = planner_pending_browser_state_from_history(
        &test_incident_state("browser__inspect", "NoEffectAfterAction"),
        &history,
    )
    .expect("explicit pending browser state should backstop planner context");

    assert!(
        pending.contains("RECENT PENDING BROWSER STATE:"),
        "{pending}"
    );
    assert!(pending.contains("`Deena`"), "{pending}");
    assert!(pending.contains("`lnk_443422`"), "{pending}");
}

#[test]
fn planner_pending_browser_state_is_disabled_when_browser_semantics_snapshot_is_present() {
    let history = vec![chat_message(
        "tool",
        concat!(
            "Tool Output (browser__inspect): <root />\n\n",
            "BROWSER_USE_STATE_TXT:\n[12]<button name=Submit />\n\n",
            "BROWSERGYM_AXTREE_TXT:\n[a1] button \"Submit\""
        ),
        1,
    )];

    assert!(planner_pending_browser_state_from_history(
        &test_incident_state("browser__inspect", "NoEffectAfterAction"),
        &history,
    )
    .is_none());
}

#[test]
fn consume_enqueued_root_retry_clears_flag_when_root_retry_executes() {
    let mut incident = test_incident_state("browser__click", "NoEffectAfterAction");
    incident.retry_enqueued = true;

    let consumed = consume_enqueued_root_retry(&mut incident, "retry-hash");

    assert!(consumed);
    assert!(
        !incident.retry_enqueued,
        "executed root retry should clear the enqueued marker"
    );
}

#[test]
fn consume_enqueued_root_retry_ignores_non_root_retry_execution() {
    let mut incident = test_incident_state("browser__click", "NoEffectAfterAction");
    incident.retry_enqueued = true;

    let consumed = consume_enqueued_root_retry(&mut incident, "other-retry");

    assert!(!consumed);
    assert!(
        incident.retry_enqueued,
        "non-root executions should not clear the enqueued marker"
    );
}
