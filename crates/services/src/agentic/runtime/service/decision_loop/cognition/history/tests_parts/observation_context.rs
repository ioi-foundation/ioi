use super::{
    build_browser_observation_context_from_snapshot,
    build_browser_observation_context_from_snapshot_with_history,
    build_browser_snapshot_pending_state_context,
    build_browser_snapshot_pending_state_context_with_history,
    build_browser_snapshot_success_signal_context, build_recent_browser_observation_context,
    build_recent_pending_browser_state_context,
    build_recent_pending_browser_state_context_with_current_snapshot,
    build_recent_pending_browser_state_context_with_snapshot, build_recent_session_events_context,
    build_recent_success_signal_context, build_recent_success_signal_context_with_snapshot,
    extract_browser_xml_attr, extract_priority_browser_targets,
    latest_recent_pending_browser_state_context, recent_goal_message_recipient_target,
    recent_goal_primary_target, recent_history_return_item_id, snapshot_visible_exact_text_target,
    top_edge_jump_call_for_selector, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS,
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
fn browser_observation_context_uses_latest_browser_snapshot_even_after_system_chatter() {
    let history = vec![
            chat_message("user", "Click Mark complete", 1),
            chat_message(
                "tool",
                "Tool Output (browser__inspect): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><button id=\"btn_mark_complete\" name=\"Mark complete\" rect=\"8,114,103,21\" /></root>",
                2,
            ),
            chat_message(
                "system",
                "System: Incident resolved after retry root.",
                3,
            ),
            chat_message(
                "system",
                "System: Selected recovery action `browser__scroll`.",
                4,
            ),
        ];

    let context = build_recent_browser_observation_context(&history);
    assert!(context.contains("RECENT BROWSER OBSERVATION:"));
    assert!(context.contains("btn_mark_complete"));
    assert!(context.contains("Mark complete"));
}

#[test]
fn browser_observation_context_prefers_semantic_snapshot_over_later_snapshot_error() {
    let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__inspect): <root><button id=\"btn_mark_complete\" name=\"Mark complete\" rect=\"8,114,103,21\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                "Tool Output (browser__inspect): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
                2,
            ),
        ];

    let context = build_recent_browser_observation_context(&history);
    assert!(context.contains("btn_mark_complete"));
    assert!(!context.contains("ERROR_CLASS=NoEffectAfterAction"));
}

#[test]
fn browser_observation_context_ignores_non_browser_tool_messages() {
    let history = vec![
        chat_message("tool", "Tool Output (screen__click): clicked btn_ok", 1),
        chat_message("system", "System: noop", 2),
    ];

    let context = build_recent_browser_observation_context(&history);
    assert!(context.is_empty());
}

#[test]
fn browser_observation_context_truncates_large_snapshot_payloads() {
    let long_snapshot = format!(
            "Tool Output (browser__inspect): {}",
            format!(
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}</root>",
                "<button id=\"btn_mark_complete\" name=\"Mark complete\" rect=\"8,114,103,21\">alpha beta gamma</button> ".repeat(200)
            )
        );
    let history = vec![chat_message("tool", &long_snapshot, 1)];

    let context = build_recent_browser_observation_context(&history);
    assert!(context.contains("RECENT BROWSER OBSERVATION:"));
    assert!(context.chars().count() <= BROWSER_OBSERVATION_CONTEXT_MAX_CHARS + 120);
    assert!(context.ends_with(".\n") || context.ends_with("...\n"));
}

#[test]
fn browser_observation_context_promotes_goal_target_into_compact_priority_targets() {
    let noise = (0..80)
        .map(|idx| {
            format!(
                "<button id=\"btn_noise_{idx}\" name=\"Noise {idx}\" tag_name=\"span\" dom_clickable=\"true\" rect=\"0,0,1,1\" />"
            )
        })
        .collect::<String>();
    let snapshot = format!(
        concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "{}",
            "<generic id=\"grp_query\" name=\"Find the email by Lonna and click the trash icon to delete it.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<generic id=\"grp_lonna\" name=\"Lonna\" tag_name=\"span\" rect=\"82,3,30,11\" />",
            "<generic id=\"grp_primary_josselyn_diam_dot_erat\" name=\"Primary Josselyn Diam. Erat mauris mor.. Lonna Cras...\" dom_id=\"main\" selector=\"[id=&quot;main&quot;]\" tag_name=\"div\" scroll_top=\"0\" scroll_height=\"294\" client_height=\"150\" can_scroll_up=\"false\" can_scroll_down=\"true\" rect=\"2,52,155,150\" />",
            "<button id=\"btn_open_search\" name=\"open search\" dom_id=\"open-search\" selector=\"[id=&quot;open-search&quot;]\" tag_name=\"span\" dom_clickable=\"true\" rect=\"122,55,12,12\" />",
            "<generic id=\"grp_josselyn\" name=\"Josselyn\" tag_name=\"div\" class_name=\"email-sender\" dom_clickable=\"true\" rect=\"7,75,88,12\" />",
            "<button id=\"btn_trash\" name=\"trash\" tag_name=\"span\" class_name=\"trash\" dom_clickable=\"true\" rect=\"117,80,12,12\" />",
            "<generic id=\"grp_lonna_row\" name=\"Lonna\" tag_name=\"div\" class_name=\"email-sender\" dom_clickable=\"true\" rect=\"7,114,88,12\" />",
            "<button id=\"btn_trash_row\" name=\"trash\" tag_name=\"span\" class_name=\"trash\" dom_clickable=\"true\" rect=\"117,119,12,12\" />",
            "</root>"
        ),
        noise
    );
    let history = vec![
        chat_message(
            "user",
            "Find the email by Lonna and click the trash icon to delete it.",
            1,
        ),
        chat_message(
            "tool",
            &format!("Tool Output (browser__inspect): {snapshot}"),
            2,
        ),
    ];

    let context = build_recent_browser_observation_context(&history);
    assert!(context.contains("IMPORTANT TARGETS:"), "{context}");
    assert!(context.contains("grp_lonna_row"), "{context}");
}

#[test]
fn browser_observation_context_does_not_promote_goal_text_while_autocomplete_is_unresolved() {
    let noise = (0..120)
        .map(|idx| {
            format!(
                "<button id=\"btn_noise_{idx}\" name=\"Noise {idx}\" dom_clickable=\"true\" rect=\"0,0,1,1\" />"
            )
        })
        .collect::<String>();
    let snapshot = format!(
        concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "{}",
            "<generic id=\"grp_augusta_ga\" name=\"Augusta, GA\" class_name=\"bold\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_from\" name=\"From:\" value=\"Kiana, AK (IAN)\" focused=\"true\" dom_id=\"flight-from\" selector=\"[id=&quot;flight-from&quot;]\" autocomplete=\"list\" tag_name=\"input\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_kiana_ak_ian\" name=\"Kiana, AK (IAN)\" dom_id=\"ui-id-4\" selector=\"[id=&quot;ui-id-4&quot;]\" class_name=\"ui-menu-item-wrapper\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
            "<status id=\"status_kiana\" name=\"1 result is available, use up and down arrow keys to navigate. Kiana, AK (IAN)\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
            "<textbox id=\"inp_to\" name=\"To:\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_search\" name=\"Search\" dom_id=\"search\" selector=\"[id=&quot;search&quot;]\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
            "</root>"
        ),
        noise
    );
    let history = vec![
        chat_message(
            "user",
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Book the shortest one-way flight from: Kiana, AK to: Augusta, GA on 10/07/2016.",
            1,
        ),
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#flight-from","text":"Kiana, AK","value":"Kiana, AK","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            2,
        ),
        chat_message(
            "tool",
            r##"{"key":{"key":"Enter","modifiers":[],"is_chord":false,"value":"Kiana, AK (IAN)","focused":true,"autocomplete":{"mode":"list","assistive_hint":"Kiana, AK (IAN)"}}}"##,
            3,
        ),
    ];

    let context = build_browser_observation_context_from_snapshot_with_history(&snapshot, &history);
    assert!(context.contains("IMPORTANT TARGETS:"), "{context}");
    assert!(
        context.contains("`inp_from`") || context.contains("inp_from"),
        "{context}"
    );
    assert!(!context.contains("grp_augusta_ga"), "{context}");
}

#[test]
fn browser_observation_context_from_snapshot_reuses_same_formatting() {
    let snapshot =
        r#"<root id="root_dom_fallback_tree"><button id="btn_submit" name="Submit" /></root>"#;
    let context = build_browser_observation_context_from_snapshot(snapshot);
    assert!(context.contains("RECENT BROWSER OBSERVATION:"));
    assert!(context.contains("btn_submit"));
    assert!(context.contains("Submit"));
}

#[test]
fn browser_observation_context_keeps_submit_visible_with_geometry_targets() {
    let history = vec![
        chat_message(
            "tool",
            concat!(
                "Tool Output (browser__inspect): ",
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
                "<generic id=\"grp_blue_circle\" name=\"small blue circle at 63,97 radius 4\" dom_id=\"blue-circle\" selector=\"[id=&quot;blue-circle&quot;]\" ",
                "tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"endpoint\" center_x=\"63\" center_y=\"96\" rect=\"60,93,7,7\" />",
                "<generic id=\"grp_large_line_from_31108_to_9181\" name=\"large line from 31,108 to 91,81\" ",
                "tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"91\" line_y2=\"81\" ",
                "line_angle_deg=\"-24\" center_x=\"61\" center_y=\"94\" rect=\"31,81,60,27\" />",
                "<generic id=\"grp_small_blue_circle_at_31108_rad\" name=\"small blue circle at 31,108 radius 4\" ",
                "tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"vertex\" center_x=\"31\" center_y=\"108\" rect=\"28,105,7,7\" />",
                "<generic id=\"grp_large_line_from_31108_to_71125\" name=\"large line from 31,108 to 71,125\" ",
                "tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"71\" line_y2=\"125\" ",
                "line_angle_deg=\"23\" center_x=\"51\" center_y=\"116\" rect=\"31,108,40,17\" />",
                "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"30,178,95,31\" />",
                "</root>",
            ),
            1,
        ),
        chat_message(
            "tool",
            r##"Synthetic click at (63.5, 96.5) verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false},"synthetic_click":{"id":"grp_blue_circle","x":63.5,"y":96.5},"pre_target":{"semantic_id":"grp_blue_circle","selector":"#blue-circle","tag_name":"circle","center_point":[63.5,96.5]},"post_target":{"semantic_id":"grp_blue_circle","selector":"#blue-circle","tag_name":"circle","center_point":[65.5,98.5]}}"##,
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_blue_circle\" name=\"small blue circle at 66,99 radius 4\" dom_id=\"blue-circle\" selector=\"[id=&quot;blue-circle&quot;]\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"endpoint\" connected_lines=\"1\" connected_points=\"31,108\" connected_line_angles_deg=\"-15\" center_x=\"65\" center_y=\"98\" rect=\"62,95,7,7\" />",
        "<generic id=\"grp_large_line_from_31108_to_9181\" name=\"large line from 31,108 to 91,81\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"91\" line_y2=\"81\" line_angle_deg=\"-24\" center_x=\"61\" center_y=\"94\" rect=\"31,81,60,27\" />",
        "<generic id=\"grp_small_blue_circle_at_31108_rad\" name=\"small blue circle at 31,108 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"vertex\" connected_lines=\"3\" connected_points=\"91,81|65,98|71,125\" connected_line_angles_deg=\"-24|-15|23\" center_x=\"31\" center_y=\"108\" rect=\"28,105,7,7\" />",
        "<generic id=\"grp_large_line_from_31108_to_71125\" name=\"large line from 31,108 to 71,125\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"71\" line_y2=\"125\" line_angle_deg=\"23\" center_x=\"51\" center_y=\"116\" rect=\"31,108,40,17\" />",
        "<generic id=\"grp_large_line_from_6598_to_31108\" name=\"large line from 65,98 to 31,108\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"65\" line_y1=\"98\" line_x2=\"31\" line_y2=\"108\" line_angle_deg=\"-15\" center_x=\"48\" center_y=\"103\" rect=\"31,98,34,10\" />",
        "<generic id=\"grp_small_black_circle_at_71125_ra\" name=\"small black circle at 71,125 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"endpoint\" connected_lines=\"1\" connected_points=\"31,108\" connected_line_angles_deg=\"23\" center_x=\"71\" center_y=\"125\" rect=\"68,122,7,7\" />",
        "<generic id=\"grp_small_black_circle_at_9181_rad\" name=\"small black circle at 91,81 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"endpoint\" connected_lines=\"1\" connected_points=\"31,108\" connected_line_angles_deg=\"-24\" center_x=\"91\" center_y=\"81\" rect=\"88,78,7,7\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "</root>"
    );

    let context = build_browser_observation_context_from_snapshot_with_history(snapshot, &history);

    assert!(context.contains("IMPORTANT TARGETS:"), "{context}");
    assert!(
        context.contains("grp_small_black_circle_at_9181_rad"),
        "{context}"
    );
    assert!(context.contains("btn_submit"), "{context}");
    assert!(context.contains("connected_points=31,108"), "{context}");
    assert!(context.contains("line_angle=-24deg"), "{context}");
}

#[test]
fn browser_observation_context_surfaces_stateful_control_attributes() {
    let noise =
        "<generic id=\"grp_noise\" name=\"alpha beta gamma delta epsilon zeta eta theta\" />"
            .repeat(120);
    let snapshot = format!(
        concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "{}",
            "<checkbox id=\"checkbox_alpha\" name=\"Alpha\" checked=\"true\" focused=\"true\" dom_id=\"ch0\" selector=\"[id=&quot;ch0&quot;]\" />",
            "<textbox id=\"inp_datepicker\" name=\"datepicker\" readonly=\"true\" dom_id=\"datepicker\" selector=\"[id=&quot;datepicker&quot;]\" />",
            "<button id=\"btn_submit\" name=\"Submit\" selected=\"true\" />",
            "</root>",
        ),
        noise
    );

    let context = build_browser_observation_context_from_snapshot(&snapshot);
    assert!(context.contains("checkbox_alpha"));
    assert!(context.contains("checked=true"));
    assert!(context.contains("focused=true"));
    assert!(context.contains("selected=true"));
    assert!(context.contains("readonly=true"));
}

#[test]
fn browser_observation_context_surfaces_assistive_hints_before_truncation() {
    let snapshot = format!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}<status id=\"status_poland\" name=\"Poland\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" /></root>",
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

    let context = build_browser_observation_context_from_snapshot(&snapshot);
    assert!(context.contains("ASSISTIVE BROWSER HINTS: Poland"));
    assert!(context.contains("RECENT BROWSER OBSERVATION:"));
}

#[test]
fn recent_session_events_context_suppresses_stale_snapshot_no_effect_after_later_tree_change() {
    let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__inspect): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
                1,
            ),
            chat_message(
                "system",
                "System: Remedy succeeded for incident 'abc'; queued root retry.",
                2,
            ),
            chat_message(
                "system",
                "System: Incident 'abc' resolved after 1 transition(s).",
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_next' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                4,
            ),
        ];

    let context = build_recent_session_events_context(&history, true);
    assert!(!context.contains("duplicate replay guard"), "{context}");
    assert!(!context.contains("queued root retry"), "{context}");
    assert!(
        !context.contains("resolved after 1 transition"),
        "{context}"
    );
    assert!(context.contains("Clicked element 'lnk_next'"), "{context}");
}

#[test]
fn recent_session_events_context_keeps_snapshot_no_effect_without_later_refresh() {
    let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__inspect): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
                1,
            ),
            chat_message(
                "system",
                "System: Remedy succeeded for incident 'abc'; queued root retry.",
                2,
            ),
        ];

    let context = build_recent_session_events_context(&history, true);
    assert!(context.contains("duplicate replay guard"), "{context}");
    assert!(context.contains("queued root retry"), "{context}");
}

#[test]
fn recent_session_events_context_suppresses_browser_context_echoes_when_latest_snapshot_is_grounded(
) {
    let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_lauraine" name="Lauraine" rect="2,64,156,17" /></root>"#;
    let history = vec![
        chat_message(
            "tool",
            &format!("Tool Output (browser__inspect): {snapshot}"),
            1,
        ),
        chat_message(
            "system",
            "RECENT PENDING BROWSER STATE:\nUse `browser__inspect` once now.\n",
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_443422' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            3,
        ),
    ];

    let context = build_recent_session_events_context(&history, true);
    assert!(
        !context.contains("Tool Output (browser__inspect)"),
        "{context}"
    );
    assert!(
        !context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(
        context.contains("Clicked element 'lnk_443422'"),
        "{context}"
    );
}

#[test]
fn recent_session_events_context_compacts_verbose_browser_verify_payloads() {
    let history = vec![chat_message(
        "tool",
        r#"Clicked element 'grp_3' via geometry fallback. verify={"center_point":[94.0,85.0],"dispatch_succeeded":true,"method":"geometry_center","postcondition":{"met":true,"tree_changed":true,"url_changed":false,"semantic_change_delta":0}}"#,
        1,
    )];

    let context = build_recent_session_events_context(&history, true);
    assert!(
        context.contains("Clicked element 'grp_3' via geometry fallback."),
        "{context}"
    );
    assert!(!context.contains("\"postcondition\""), "{context}");
    assert!(!context.contains("semantic_change_delta"), "{context}");
}

#[test]
fn recent_session_events_context_keeps_compact_synthetic_click_verify_payload() {
    let history = vec![chat_message(
        "tool",
        r##"Synthetic click at (51.0, 95.0) verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false},"pre_target":{"semantic_id":"grp_large_line_from_31108_to_9181","selector":"#svg-grid > line:nth-of-type(2)","tag_name":"line","center_point":[61.0,94.5]},"post_target":{"semantic_id":"grp_blue_circle","dom_id":"blue-circle","selector":"#blue-circle","tag_name":"circle","center_point":[53.5,97.5]}}"##,
        1,
    )];

    let context = build_recent_session_events_context(&history, true);
    assert!(
        context.contains("Synthetic click at (51.0, 95.0)"),
        "{context}"
    );
    assert!(context.contains("\"pre_target\""), "{context}");
    assert!(context.contains("\"post_target\""), "{context}");
    assert!(
        context.contains("\"semantic_id\":\"grp_blue_circle\""),
        "{context}"
    );
}

#[test]
fn recent_session_events_context_compacts_verbose_web_read_payloads_for_non_browser_work() {
    let history = vec![chat_message(
        "tool",
        &format!(
            r#"{{
                "schema_version": 1,
                "tool": "web__read",
                "url": "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
                "sources": [{{
                    "url": "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
                    "title": "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                }}],
                "documents": [{{
                    "url": "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
                    "title": "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC",
                    "content_text": "{}"
                }}]
            }}"#,
            "Date Published: July 2022. Planning Note: NIST updated the report and retained details about the post-quantum cryptography standardization process. ".repeat(12)
        ),
        1,
    )];

    let context = build_recent_session_events_context(&history, false);
    assert!(
        context.contains("tool: web__read ; https://csrc.nist.gov/pubs/ir/8413/upd1/final"),
        "{context}"
    );
    assert!(
        context.contains("IR 8413, Status Report on the Third Round"),
        "{context}"
    );
    assert!(context.contains("Date Published: July 2022."), "{context}");
    assert!(!context.contains("\"content_text\""), "{context}");
    assert!(context.chars().count() < 700, "{context}");
}

#[test]
fn recent_session_events_context_compacts_verbose_web_search_payloads_for_non_browser_work() {
    let history = vec![chat_message(
        "tool",
        r#"{
            "schema_version": 1,
            "tool": "web__search",
            "query": "nist post quantum cryptography standards site:nist.gov site:www.nist.gov",
            "sources": [
                {
                    "url": "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
                    "title": "Status Report on the Third Round of the NIST Post-Quantum Cryptography ...",
                    "snippet": "The National Institute of Standards and Technology is in the process of selecting public-key cryptographic algorithms."
                },
                {
                    "url": "https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms",
                    "title": "NIST Announces First Four Quantum-Resistant Cryptographic Algorithms | NIST",
                    "snippet": "The four selected encryption algorithms will become part of NIST's post-quantum cryptographic standard."
                }
            ],
            "provider_candidates": [{"provider_id": "edge:bing-search-rss", "source_count": 1, "success": true}]
        }"#,
        1,
    )];

    let context = build_recent_session_events_context(&history, false);
    assert!(context.contains("tool: web__search ; nist post quantum cryptography standards site:nist.gov site:www.nist.gov"), "{context}");
    assert!(
        context.contains("sources=Status Report on the Third Round"),
        "{context}"
    );
    assert!(
        context.contains("NIST Announces First Four Quantum-Resistant Cryptographic Algorithms"),
        "{context}"
    );
    assert!(!context.contains("provider_candidates"), "{context}");
    assert!(context.chars().count() < 700, "{context}");
}

#[test]
fn latest_recent_pending_browser_state_context_keeps_recent_explicit_context_without_refresh() {
    let history = vec![
            chat_message(
                "system",
                "RECENT PENDING BROWSER STATE:\nUse `browser__click` on `lnk_443422` now.\n",
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

    let pending = latest_recent_pending_browser_state_context(&history)
        .expect("explicit pending browser state should remain available");
    assert!(
        pending.contains("RECENT PENDING BROWSER STATE:"),
        "{pending}"
    );
    assert!(pending.contains("`lnk_443422`"), "{pending}");
}

#[test]
fn latest_recent_pending_browser_state_context_drops_stale_explicit_context_after_refresh() {
    let history = vec![
        chat_message(
            "system",
            "RECENT PENDING BROWSER STATE:\nUse `browser__click` on `lnk_443422` now.\n",
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_443422' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];

    assert!(
        latest_recent_pending_browser_state_context(&history).is_none(),
        "explicit pending browser state should not survive a later browser refresh"
    );
}

#[test]
fn browser_observation_context_surfaces_visible_scroll_target_focus_hint() {
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"257\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
            "</root>",
        );

    let context = build_browser_observation_context_from_snapshot(snapshot);
    assert!(context.contains("ASSISTIVE BROWSER HINTS:"));
    assert!(context.contains(
        "Visible scroll target `inp_lorem tag=textbox dom_id=text-area` is already on the page."
    ));
    assert!(context.contains("If the goal requires interacting with that control"));
    assert!(context.contains("page-level edge keys"));
}

#[test]
fn browser_observation_context_preserves_late_high_priority_targets_under_truncation() {
    let snapshot = format!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}<link id=\"lnk_t_215\" name=\"T-215\" omitted=\"true\" dom_id=\"ticket-link-t-215\" selector=\"[id=&quot;ticket-link-t-215&quot;]\" rect=\"0,0,1,1\" /></root>",
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

    let context = build_browser_observation_context_from_snapshot(&snapshot);
    assert!(context.contains("IMPORTANT TARGETS:"));
    assert!(context.contains("lnk_t_215 tag=link"));
    assert!(context.contains("ticket-link-t-215"));
}

#[test]
fn browser_observation_context_prefers_actionable_omitted_targets_over_generic_noise() {
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_noise_0\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_noise_1\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_fiber\" name=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_awaiting_dispatch\" name=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_row_noise_0\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<listitem id=\"item_noise_0\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_202\" name=\"T-202\" omitted=\"true\" dom_id=\"ticket-link-t-202\" selector=\"[id=&quot;ticket-link-t-202&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_row_noise_1\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<listitem id=\"item_noise_1\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_204\" name=\"T-204\" omitted=\"true\" dom_id=\"ticket-link-t-204\" selector=\"[id=&quot;ticket-link-t-204&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_row_noise_2\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<listitem id=\"item_noise_2\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_215\" name=\"T-215\" omitted=\"true\" dom_id=\"ticket-link-t-215\" selector=\"[id=&quot;ticket-link-t-215&quot;]\" rect=\"0,0,1,1\" />",
            "</root>"
        );
    let long_snapshot = snapshot.replace(
        "</root>",
        &format!(
            "{}{}",
            "<generic id=\"grp_pad\" name=\"padding\" rect=\"0,0,1,1\" /> ".repeat(200),
            "</root>"
        ),
    );

    let context = build_browser_observation_context_from_snapshot(&long_snapshot);
    assert!(context.contains("ticket-link-t-202"), "{context}");
    assert!(context.contains("ticket-link-t-204"), "{context}");
    assert!(context.contains("ticket-link-t-215"), "{context}");
    assert!(
        !context.contains("grp_row_noise_0 tag=generic"),
        "{context}"
    );
}

#[test]
fn browser_observation_context_preserves_svg_geometry_targets_under_truncation() {
    let snapshot = format!(
            concat!(
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
                "{}",
                "<generic id=\"grp_svg_grid_object\" name=\"svg grid object\" dom_id=\"svg-grid\" selector=\"[id=&quot;svg-grid&quot;]\" tag_name=\"svg\" rect=\"2,52,150,130\" />",
                "<generic id=\"grp_small_blue_circle\" name=\"small blue circle at 31,108\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"blue\" geometry_role=\"vertex\" connected_lines=\"2\" connected_points=\"91,81|71,125\" connected_line_angles_deg=\"-24|23\" angle_mid_deg=\"0\" angle_span_deg=\"47\" center_x=\"31\" center_y=\"108\" rect=\"28,105,7,7\" />",
                "<generic id=\"grp_small_black_circle\" name=\"small black circle at 71,125\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"black\" center_x=\"71\" center_y=\"125\" rect=\"68,122,7,7\" />",
                "<generic id=\"grp_small_black_circle_2\" name=\"small black circle at 91,81\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"black\" center_x=\"91\" center_y=\"81\" rect=\"88,78,7,7\" />",
                "<generic id=\"grp_angle_arm\" name=\"line from 31,108 to 71,125\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"71\" line_y2=\"125\" line_length=\"43\" line_angle_deg=\"23\" rect=\"31,108,40,17\" />",
                "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
                "<generic id=\"grp_click_canvas\" name=\"click canvas\" dom_id=\"click-canvas\" selector=\"[id=&quot;click-canvas&quot;]\" tag_name=\"canvas\" rect=\"165,0,160,210\" />",
                "<generic id=\"grp_last_reward_last_10_average_ti\" name=\"Last reward: - Last 10 average: - Time left: 9 / 10sec\" dom_id=\"reward-display\" selector=\"[id=&quot;reward-display&quot;]\" tag_name=\"div\" rect=\"165,0,160,210\" />",
                "<generic id=\"grp_minus\" name=\"-\" dom_id=\"reward-last\" selector=\"[id=&quot;reward-last&quot;]\" tag_name=\"span\" rect=\"251,10,5,16\" />",
                "<generic id=\"grp_minus_2\" name=\"-\" dom_id=\"reward-avg\" selector=\"[id=&quot;reward-avg&quot;]\" tag_name=\"span\" rect=\"278,36,5,16\" />",
                "<generic id=\"grp_9_divide_10sec\" name=\"9 / 10sec\" dom_id=\"timer-countdown\" selector=\"[id=&quot;timer-countdown&quot;]\" tag_name=\"span\" rect=\"231,62,58,16\" />",
                "<generic id=\"grp_0\" name=\"0\" dom_id=\"episode-id\" selector=\"[id=&quot;episode-id&quot;]\" tag_name=\"span\" rect=\"270,88,8,16\" />",
                "</root>"
            ),
            "<generic id=\"grp_noise\" name=\"padding\" rect=\"0,0,1,1\" /> ".repeat(200),
        );

    let context = build_browser_observation_context_from_snapshot(&snapshot);
    assert!(
        context.contains("grp_small_blue_circle tag=generic"),
        "{context}"
    );
    assert!(context.contains("small blue circle at 31,108"), "{context}");
    assert!(context.contains("shape_kind=circle"), "{context}");
    assert!(context.contains("geometry_role=vertex"), "{context}");
    assert!(context.contains("connected_lines=2"), "{context}");
    assert!(
        context.contains("connected_points=91,81|71,125"),
        "{context}"
    );
    assert!(
        context.contains("connected_line_angles=-24|23deg"),
        "{context}"
    );
    assert!(context.contains("angle_mid=0deg"), "{context}");
    assert!(context.contains("angle_span=47deg"), "{context}");
    assert!(context.contains("center=31,108"), "{context}");
    assert!(context.contains("grp_angle_arm tag=generic"), "{context}");
    assert!(context.contains("line=31,108->71,125"), "{context}");
    assert!(context.contains("line_length=43"), "{context}");
    assert!(context.contains("line_angle=23deg"), "{context}");
    assert!(
        !context.contains("grp_angle_arm tag=generic name=line from 31,108 to 71,125 center="),
        "{context}"
    );
    assert!(context.contains("btn_submit tag=button"), "{context}");
}

#[test]
fn extract_priority_browser_targets_prefers_visible_start_gate_over_covered_targets() {
    let snapshot = format!(
        concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "{}",
            "<generic id=\"grp_start\" name=\"START\" dom_id=\"sync-task-cover\" selector=\"[id=&quot;sync-task-cover&quot;]\" rect=\"0,0,160,210\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
            "<generic id=\"grp_click_canvas\" name=\"click canvas\" dom_id=\"click-canvas\" selector=\"[id=&quot;click-canvas&quot;]\" tag_name=\"canvas\" rect=\"0,0,160,210\" />",
            "<generic id=\"grp_reward_display\" name=\"Last reward: -\" dom_id=\"reward-display\" selector=\"[id=&quot;reward-display&quot;]\" rect=\"165,0,160,210\" />",
            "</root>"
        ),
        "<generic id=\"grp_padding\" name=\"padding\" rect=\"0,0,1,1\" /> ".repeat(220),
    );

    let targets = extract_priority_browser_targets(&snapshot, 8).join(" | ");

    assert!(targets.contains("grp_start"), "{targets}");
    assert!(!targets.contains("grp_click_canvas"), "{targets}");
    assert!(!targets.contains("btn_submit"), "{targets}");
}

#[test]
fn extract_priority_browser_targets_collapses_to_start_gate_even_when_canvas_is_uncovered() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_start\" name=\"START\" dom_id=\"sync-task-cover\" selector=\"[id=&quot;sync-task-cover&quot;]\" rect=\"0,0,160,210\" />",
        "<generic id=\"grp_click_canvas\" name=\"click canvas\" dom_id=\"click-canvas\" selector=\"[id=&quot;click-canvas&quot;]\" tag_name=\"canvas\" rect=\"165,0,160,210\" />",
        "<generic id=\"grp_reward_display\" name=\"Last reward: -\" dom_id=\"reward-display\" selector=\"[id=&quot;reward-display&quot;]\" rect=\"165,0,160,210\" />",
        "<button id=\"btn_buy\" name=\"Buy\" dom_id=\"buy\" selector=\"[id=&quot;buy&quot;]\" rect=\"40,150,60,20\" />",
        "</root>"
    );

    let targets = extract_priority_browser_targets(snapshot, 8).join(" | ");

    assert!(targets.contains("grp_start"), "{targets}");
    assert!(!targets.contains("grp_click_canvas"), "{targets}");
    assert!(!targets.contains("reward-display"), "{targets}");
    assert!(!targets.contains("btn_buy"), "{targets}");
}

#[test]
fn extract_priority_browser_targets_prefers_grounded_geometry_over_status_telemetry() {
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_svg_grid_object\" name=\"svg grid object\" dom_id=\"svg-grid\" selector=\"[id=&quot;svg-grid&quot;]\" tag_name=\"svg\" rect=\"2,52,150,130\" />",
            "<generic id=\"grp_small_blue_circle\" name=\"small blue circle at 31,108\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"blue\" geometry_role=\"vertex\" connected_lines=\"2\" connected_points=\"91,81|71,125\" connected_line_angles_deg=\"-24|23\" angle_mid_deg=\"0\" angle_span_deg=\"47\" center_x=\"31\" center_y=\"108\" rect=\"28,105,7,7\" />",
            "<generic id=\"grp_small_black_circle\" name=\"small black circle at 71,125\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"black\" center_x=\"71\" center_y=\"125\" rect=\"68,122,7,7\" />",
            "<generic id=\"grp_small_black_circle_2\" name=\"small black circle at 91,81\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"black\" center_x=\"91\" center_y=\"81\" rect=\"88,78,7,7\" />",
            "<generic id=\"grp_angle_arm\" name=\"line from 31,108 to 71,125\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"71\" line_y2=\"125\" line_length=\"43\" line_angle_deg=\"23\" rect=\"31,108,40,17\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
            "<generic id=\"grp_click_canvas\" name=\"click canvas\" dom_id=\"click-canvas\" selector=\"[id=&quot;click-canvas&quot;]\" tag_name=\"canvas\" rect=\"165,0,160,210\" />",
            "<generic id=\"grp_last_reward_last_10_average_ti\" name=\"Last reward: - Last 10 average: - Time left: 9 / 10sec\" dom_id=\"reward-display\" selector=\"[id=&quot;reward-display&quot;]\" tag_name=\"div\" rect=\"165,0,160,210\" />",
            "<generic id=\"grp_minus\" name=\"-\" dom_id=\"reward-last\" selector=\"[id=&quot;reward-last&quot;]\" tag_name=\"span\" rect=\"251,10,5,16\" />",
            "<generic id=\"grp_minus_2\" name=\"-\" dom_id=\"reward-avg\" selector=\"[id=&quot;reward-avg&quot;]\" tag_name=\"span\" rect=\"278,36,5,16\" />",
            "<generic id=\"grp_9_divide_10sec\" name=\"9 / 10sec\" dom_id=\"timer-countdown\" selector=\"[id=&quot;timer-countdown&quot;]\" tag_name=\"span\" rect=\"231,62,58,16\" />",
            "<generic id=\"grp_0\" name=\"0\" dom_id=\"episode-id\" selector=\"[id=&quot;episode-id&quot;]\" tag_name=\"span\" rect=\"270,88,8,16\" />",
            "</root>"
        );

    let targets = extract_priority_browser_targets(snapshot, 8);
    let joined = targets.join(" | ");
    let svg_index = targets
        .iter()
        .position(|target| target.contains("grp_svg_grid_object"));
    let geometry_index = targets
        .iter()
        .position(|target| target.contains("grp_small_blue_circle"));
    let submit_index = targets
        .iter()
        .position(|target| target.contains("btn_submit"));

    assert!(joined.contains("grp_small_blue_circle"), "{joined}");
    assert!(joined.contains("shape_kind=circle"), "{joined}");
    assert!(joined.contains("geometry_role=vertex"), "{joined}");
    assert!(joined.contains("connected_points=91,81|71,125"), "{joined}");
    assert!(joined.contains("angle_mid=0deg"), "{joined}");
    assert!(joined.contains("grp_angle_arm"), "{joined}");
    assert!(joined.contains("line=31,108->71,125"), "{joined}");
    assert!(joined.contains("line_angle=23deg"), "{joined}");
    assert!(joined.contains("btn_submit tag=button"), "{joined}");
    assert!(svg_index.is_none(), "{joined}");
    assert!(
        geometry_index
            .zip(submit_index)
            .is_some_and(|(geometry, submit)| geometry < submit),
        "{joined}"
    );
    assert!(!joined.contains("grp_click_canvas"), "{joined}");
    assert!(!joined.contains("reward-display"), "{joined}");
    assert!(!joined.contains("timer-countdown"), "{joined}");
    assert!(!joined.contains("episode-id"), "{joined}");
}

#[test]
fn extract_priority_browser_targets_surfaces_calendar_navigation_state_over_dense_numeric_noise() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_datepicker\" name=\"datepicker\" dom_id=\"datepicker\" selector=\"[id=&quot;datepicker&quot;]\" class_name=\"hasDatepicker\" dom_clickable=\"true\" rect=\"29,52,128,21\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"27,84,95,31\" />",
        "<link id=\"lnk_prev\" name=\"Prev\" omitted=\"true\" tag_name=\"a\" rect=\"38,86,14,14\" />",
        "<generic id=\"grp_december_2016\" name=\"December 2016\" tag_name=\"div\" rect=\"54,86,48,14\" />",
        "<link id=\"lnk_1\" name=\"1\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"40,108,8,12\" />",
        "<link id=\"lnk_2\" name=\"2\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"52,108,8,12\" />",
        "<link id=\"lnk_3\" name=\"3\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"64,108,8,12\" />",
        "<link id=\"lnk_4\" name=\"4\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"76,108,8,12\" />",
        "<link id=\"lnk_5\" name=\"5\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"88,108,8,12\" />",
        "<link id=\"lnk_6\" name=\"6\" omitted=\"true\" context=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 <REDACTED:card_pan> 26 27 28 29 30 31\" tag_name=\"a\" rect=\"100,108,8,12\" />",
        "</root>"
    );

    let targets = extract_priority_browser_targets(snapshot, 8);
    let joined = targets.join(" | ");

    assert!(joined.contains("lnk_prev tag=link name=Prev"), "{joined}");
    assert!(
        joined.contains("grp_december_2016 tag=generic name=December 2016"),
        "{joined}"
    );
    assert!(!joined.contains("<REDACTED:card_pan>"), "{joined}");
    assert!(!joined.contains("context=1 2 3 4 5 6"), "{joined}");
}

#[test]
fn browser_observation_context_keeps_calendar_header_navigation_and_day_targets_within_budget() {
    let mut calendar_days = String::new();
    for day in 1..=31 {
        calendar_days.push_str(&format!(
            "<link id=\"lnk_{day}\" name=\"{day}\" omitted=\"true\" tag_name=\"a\" class_name=\"ui-state-default\" dom_clickable=\"true\" rect=\"0,0,1,1\" />"
        ));
    }

    let snapshot = format!(
        concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_datepicker\" name=\"datepicker\" dom_id=\"datepicker\" selector=\"[id=&quot;datepicker&quot;]\" class_name=\"hasDatepicker\" dom_clickable=\"true\" rect=\"29,52,128,21\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"27,84,95,31\" />",
            "<link id=\"lnk_prev\" name=\"Prev\" tag_name=\"a\" class_name=\"ui-datepicker-prev ui-corner-all\" dom_clickable=\"true\" rect=\"38,86,14,14\" />",
            "<link id=\"lnk_next\" name=\"Next\" tag_name=\"a\" class_name=\"ui-datepicker-next ui-corner-all\" dom_clickable=\"true\" rect=\"126,86,14,14\" />",
            "<generic id=\"grp_december_2016\" name=\"December 2016\" tag_name=\"div\" rect=\"54,86,48,14\" />",
            "{}",
            "<generic id=\"grp_last_reward_last_10_average_ti\" name=\"Last reward: - Last 10 average: - Time left: 19 / 20sec\" dom_id=\"reward-display\" selector=\"[id=&quot;reward-display&quot;]\" tag_name=\"div\" rect=\"165,0,160,210\" />",
            "<generic id=\"grp_minus\" name=\"-\" dom_id=\"reward-last\" selector=\"[id=&quot;reward-last&quot;]\" tag_name=\"span\" rect=\"251,10,5,16\" />",
            "<generic id=\"grp_minus_2\" name=\"-\" dom_id=\"reward-avg\" selector=\"[id=&quot;reward-avg&quot;]\" tag_name=\"span\" rect=\"278,36,5,16\" />",
            "<generic id=\"grp_19_divide_20sec\" name=\"19 / 20sec\" dom_id=\"timer-countdown\" selector=\"[id=&quot;timer-countdown&quot;]\" tag_name=\"span\" rect=\"231,62,58,16\" />",
            "</root>"
        ),
        calendar_days
    );

    let context = build_browser_observation_context_from_snapshot(&snapshot);
    assert!(context.contains("lnk_prev tag=link name=Prev"), "{context}");
    assert!(context.contains("lnk_next tag=link name=Next"), "{context}");
    assert!(
        context.contains("grp_december_2016 tag=generic name=December 2016"),
        "{context}"
    );
    assert!(context.contains("lnk_6 tag=link name=6"), "{context}");
}

#[test]
fn browser_observation_context_preserves_omitted_target_row_context() {
    let snapshot = format!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}<link id=\"lnk_t_204\" name=\"T-204\" omitted=\"true\" dom_id=\"ticket-link-t-204\" selector=\"[id=&quot;ticket-link-t-204&quot;]\" context=\"Unassigned / Awaiting Dispatch\" rect=\"0,0,1,1\" /></root>",
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

    let context = build_browser_observation_context_from_snapshot(&snapshot);
    assert!(context.contains("ticket-link-t-204"), "{context}");
    assert!(
        context.contains("context=Unassigned / Awaiting Dispatch"),
        "{context}"
    );
}

#[test]
fn browser_observation_context_prioritizes_clickable_controls_over_instruction_copy() {
    let snapshot = format!(
            concat!(
                "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
                "<generic id=\"grp_find_the_email_by_lonna\" name=\"Find the email by Lonna and click the trash icon.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
                "<generic id=\"grp_lonna\" name=\"Lonna\" tag_name=\"span\" class_name=\"bold\" rect=\"82,3,30,11\" />",
                "{}",
                "<generic id=\"grp_email_row\" name=\"Lonna Cras. A dictumst. Ali..\" tag_name=\"div\" class_name=\"email-thread\" dom_clickable=\"true\" rect=\"2,112,140,39\" />",
                "<generic id=\"grp_trash\" name=\"trash\" tag_name=\"span\" class_name=\"trash\" dom_clickable=\"true\" rect=\"117,119,12,12\" />",
                "</root>"
            ),
            "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
        );

    let context = build_browser_observation_context_from_snapshot(&snapshot);

    assert!(context.contains("IMPORTANT TARGETS:"), "{context}");
    assert!(context.contains("grp_email_row tag=generic"), "{context}");
    assert!(context.contains("grp_trash tag=generic"), "{context}");
    assert!(context.contains("dom_clickable=true"), "{context}");
    assert!(
        !context.contains("grp_find_the_email_by_lonna tag=generic"),
        "{context}"
    );
    assert!(
        !context.contains("grp_lonna tag=generic name=Lonna"),
        "{context}"
    );
}

#[test]
fn browser_observation_context_promotes_large_active_working_target_over_instruction_token() {
    let snapshot = format!(
        concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_query\" name=\"Move the cube around so that 6 is the active side facing the user.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,220,40\" />",
            "<generic id=\"grp_6\" name=\"6\" tag_name=\"span\" class_name=\"bold\" rect=\"140,3,6,11\" />",
            "{}",
            "<generic id=\"grp_cube_face_6\" name=\"6\" tag_name=\"div\" class_name=\"cube-image active\" rect=\"46,67,68,60\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
            "</root>"
        ),
        "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(180)
    );

    let context = build_browser_observation_context_from_snapshot(&snapshot);

    assert!(context.contains("IMPORTANT TARGETS:"), "{context}");
    assert!(context.contains("grp_cube_face_6"), "{context}");
    assert!(
        context.contains("class_name=cube-image active"),
        "{context}"
    );
    assert!(!context.contains("grp_6 tag=generic name=6"), "{context}");
}

#[test]
fn snapshot_visible_exact_text_target_prefers_large_active_working_target_over_instruction_token() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Move the cube around so that 6 is the active side facing the user.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,220,40\" />",
        "<generic id=\"grp_6\" name=\"6\" tag_name=\"span\" class_name=\"bold\" rect=\"140,3,6,11\" />",
        "<generic id=\"grp_cube_face_6\" name=\"6\" tag_name=\"div\" class_name=\"cube-image active\" rect=\"46,67,68,60\" />",
        "</root>",
    );

    let target = snapshot_visible_exact_text_target(snapshot, "6");
    assert_eq!(
        target.as_ref().map(|value| value.semantic_id.as_str()),
        Some("grp_cube_face_6")
    );
}

#[test]
fn success_signal_context_highlights_recent_browser_effect() {
    let history = vec![chat_message(
            "tool",
            "Clicked element 'btn_mark_complete' via geometry fallback. verify={\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
            1,
        )];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("Do not repeat the same interaction"));
    assert!(context.contains("agent__complete"));
}

#[test]
fn success_signal_context_prefers_new_surface_targets_after_start_gate_clears() {
    let history = vec![chat_message(
        "tool",
        "Clicked element 'grp_start' via geometry fallback. verify={\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_large_line_from_31108_to_9181\" name=\"large line from 31,108 to 91,81\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"91\" line_y2=\"81\" line_angle_deg=\"-24\" rect=\"31,81,60,27\" />",
        "<generic id=\"grp_large_line_from_31108_to_71125\" name=\"large line from 31,108 to 71,125\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"71\" line_y2=\"125\" line_angle_deg=\"23\" rect=\"31,108,40,17\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("exposed a different task surface"),
        "{context}"
    );
    assert!(
        context.contains("grp_large_line_from_31108_to_9181"),
        "{context}"
    );
    assert!(
        !context.contains("Use a visible control such as `btn_submit`"),
        "{context}"
    );
}

