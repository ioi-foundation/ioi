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

#[test]
fn success_signal_context_highlights_selected_form_control_follow_up() {
    let history = vec![chat_message(
            "tool",
            "Clicked element 'radio_tecslmn' via geometry fallback. verify={\"post_target\":{\"semantic_id\":\"radio_tecslmn\",\"checked\":true},\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
            1,
        )];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("selected a form control"));
    assert!(context.contains("Do not click the surrounding option group"));
    assert!(context.contains("Submit"));
}

#[test]
fn recent_goal_primary_target_requires_explicit_quoted_target() {
    let history = vec![chat_message(
        "user",
        r#"Find the email by Regan and reply to them with the text "Vitae mi, eu."."#,
        1,
    )];

    let target = recent_goal_primary_target(&history);
    assert_eq!(target.as_deref(), Some("Vitae mi, eu."));
}

#[test]
fn recent_goal_primary_target_ignores_unquoted_benchmark_instruction() {
    let history = vec![chat_message("user", "Select TeCSlMn and click Submit.", 1)];

    let target = recent_goal_primary_target(&history);
    assert_eq!(target, None);
}

#[test]
fn recent_goal_message_recipient_target_extracts_message_recipient() {
    let history = vec![chat_message(
        "user",
        "I want to send Sadie the e-mail that I got from Judi.",
        1,
    )];

    let target = recent_goal_message_recipient_target(&history);
    assert_eq!(target.as_deref(), Some("Sadie"));
}

#[test]
fn pending_browser_state_context_does_not_emit_select_submit_shortcut_from_prompt_text() {
    let history = vec![chat_message("user", "Select TeCSlMn and click Submit.", 1)];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<radio id=\"radio_tecslmn\" name=\"TeCSlMn\" dom_id=\"ch0\" selector=\"[id=&quot;ch0&quot;]\" tag_name=\"input\" rect=\"7,55,20,13\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"2,153,95,31\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn browser_snapshot_pending_state_context_does_not_emit_select_submit_shortcut_from_page_text() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Select TeCSlMn and click Submit.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
        "<radio id=\"radio_tecslmn\" name=\"TeCSlMn\" dom_id=\"ch0\" selector=\"[id=&quot;ch0&quot;]\" tag_name=\"input\" rect=\"7,55,20,13\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"2,153,95,31\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context(snapshot);
    assert!(context.is_empty(), "{context}");
}

#[test]
fn success_signal_context_keeps_submit_follow_up_when_target_still_visible() {
    let history = vec![
            chat_message(
                "user",
                "Select TeCSlMn and click Submit.",
                1,
            ),
            chat_message(
                "tool",
                "Clicked element 'radio_tecslmn' via geometry fallback. verify={\"post_target\":{\"semantic_id\":\"radio_tecslmn\",\"checked\":true},\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
                2,
            ),
            chat_message(
                "tool",
                "Clicked element 'btn_submit' via selector fallback '[id=\"subbtn\"]'. Browser click/focus succeeded. verify={\"postcondition_met\":true}",
                3,
            ),
        ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_select_tecslmn_and_click_submi\" name=\"Select TeCSlMn and click Submit.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<radio id=\"radio_tecslmn\" name=\"TeCSlMn\" checked=\"true\" focused=\"true\" dom_id=\"ch0\" selector=\"[id=&quot;ch0&quot;]\" tag_name=\"input\" rect=\"7,55,20,13\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"2,153,95,31\" />",
            "</root>",
        );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
    assert!(
        !context.contains("Do not treat the newly visible controls"),
        "{context}"
    );
    assert!(!context.contains("`agent__complete`"), "{context}");
}

#[test]
fn success_signal_context_uses_duplicate_success_noop_guidance() {
    let history = vec![chat_message(
            "tool",
            "Skipped immediate replay of 'browser__click' because the identical action already succeeded on the previous step. Do not repeat it. Verify the updated state once or finish with the gathered evidence.",
            1,
        )];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("already succeeded on the previous step"));
}

#[test]
fn success_signal_context_highlights_successful_dropdown_selection() {
    let history = vec![chat_message(
        "tool",
        r#"{"id":"inp_country","selected":{"label":"Australia","value":"Australia"}}"#,
        1,
    )];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("dropdown selection already succeeded"));
    assert!(context.contains("next required action"));
}

#[test]
fn success_signal_context_highlights_prefixed_dropdown_selection_output() {
    let history = vec![chat_message(
        "tool",
        r#"Tool Output (browser__select_option): {"id":"inp_country","selected":{"label":"Australia","value":"Australia"}}"#,
        1,
    )];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("dropdown selection already succeeded"));
    assert!(context.contains("`inp_country`"));
    assert!(context.contains("`Australia`"));
}

#[test]
fn success_signal_context_points_to_remaining_controls_after_dropdown_selection() {
    let history = vec![
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><combobox id="inp_awaiting_dispatch" name="Awaiting Dispatch" dom_id="status" selector="[id=&quot;status&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
            1,
        ),
        chat_message(
            "tool",
            r#"{"id":"inp_assign_team","selected":{"label":"Network Ops","value":"Network Ops"}}"#,
            2,
        ),
    ];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("`inp_assign_team`"));
    assert!(context.contains("`Network Ops`"));
    assert!(context.contains("`inp_awaiting_dispatch`"));
    assert!(context.contains("`inp_dispatch_note`"));
    assert!(context.contains("`btn_review_update`"));
}

#[test]
fn success_signal_context_uses_compacted_snapshot_targets_for_dropdown_follow_up() {
    let history = vec![
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"> <generic id="grp_ticket_t_215" name="Ticket T-215" rect="0,0,1,1" /> IMPORTANT TARGETS: lnk_queue tag=link name=Queue dom_id=queue-link selector=[id="queue-link"] | inp_assign_team tag=combobox name=Assign team dom_id=assignee selector=[id="assignee"] | inp_awaiting_dispatch tag=combobox name=Awaiting Dispatch dom_id=status selector=[id="status"] | inp_dispatch_note tag=textbox name=Dispatch note dom_id=note selector=[id="note"] | btn_review_update tag=button name=Review update dom_id=review-update selector=[id="review-update"]</root>"#,
            1,
        ),
        chat_message(
            "tool",
            r#"{"id":"inp_assign_team","selected":{"label":"Network Ops","value":"Network Ops"}}"#,
            2,
        ),
    ];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("dropdown selection already succeeded"));
    assert!(context.contains("`inp_assign_team`"));
    assert!(context.contains("`inp_awaiting_dispatch`"));
    assert!(context.contains("`inp_dispatch_note`"));
    assert!(context.contains("`btn_review_update`"));
}

#[test]
fn priority_target_extraction_reads_compact_summary_targets() {
    let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"> <generic id="grp_ticket_t_215" name="Ticket T-215" rect="0,0,1,1" /> IMPORTANT TARGETS: lnk_queue tag=link name=Queue dom_id=queue-link selector=[id="queue-link"] | inp_assign_team tag=combobox name=Assign team dom_id=assignee selector=[id="assignee"] | inp_awaiting_dispatch tag=combobox name=Awaiting Dispatch dom_id=status selector=[id="status"] | inp_dispatch_note tag=textbox name=Dispatch note dom_id=note selector=[id="note"] | btn_review_update tag=button name=Review update dom_id=review-update selector=[id="review-update"] | heading_ticket_t_215 tag=heading name=Ticket T-215 dom_id=ticket-title selector=[id="ticket-title"]</root>"#;

    let targets = extract_priority_browser_targets(snapshot, 8);
    assert!(targets
        .iter()
        .any(|target| target.contains("lnk_queue tag=link")));
    assert!(targets
        .iter()
        .any(|target| target.contains("inp_assign_team tag=combobox")));
    assert!(targets
        .iter()
        .any(|target| target.contains("inp_awaiting_dispatch tag=combobox")));
    assert!(targets
        .iter()
        .any(|target| target.contains("inp_dispatch_note tag=textbox")));
    assert!(targets
        .iter()
        .any(|target| target.contains("btn_review_update tag=button")));
}

#[test]
fn priority_target_extraction_drops_passive_metric_targets_from_compact_summary() {
    let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"> IMPORTANT TARGETS: grp_circ tag=generic name=large circle centered at 89,138 radius 22 dom_id=circ selector=[id="circ"] class_name=[object SVGAnimatedString] shape_kind=circle center=89,138 radius=22 | grp_area tag=generic name=area dom_id=area selector=[id="area"] | grp_click_canvas tag=generic name=click canvas dom_id=click-canvas selector=[id="click-canvas"] | grp_last_reward_last_10_average_ti tag=generic name=Last reward: - Last 10 average: - Time left: 10 / 10sec dom_id=reward-display selector=[id="reward-display"] | grp_10_divide_10sec tag=generic name=10 / 10sec dom_id=timer-countdown selector=[id="timer-countdown"] | grp_0 tag=generic name=0 dom_id=episode-id selector=[id="episode-id"] | grp_time_left_10_divide_10sec tag=generic name=Time left: 10 / 10sec class_name=info | label_episodes_done tag=label name=Episodes done:</root>"#;

    let targets = extract_priority_browser_targets(snapshot, 8);
    let joined = targets.join(" | ");

    assert!(joined.contains("grp_circ tag=generic"), "{joined}");
    assert!(joined.contains("grp_area tag=generic"), "{joined}");
    assert!(!joined.contains("reward-display"), "{joined}");
    assert!(!joined.contains("timer-countdown"), "{joined}");
    assert!(!joined.contains("episode-id"), "{joined}");
    assert!(!joined.contains("Episodes done"), "{joined}");
}

#[test]
fn observation_context_hides_surface_wrappers_when_geometry_is_still_unresolved() {
    let history = vec![chat_message(
        "tool",
        r##"{"synthetic_click":{"x":51,"y":116},"postcondition":{"met":true,"tree_changed":true,"url_changed":false},"pre_target":{"semantic_id":"grp_large_line_from_31108_to_71125","selector":"#svg-grid > line:nth-of-type(1)","tag_name":"line","center_point":[51.0,116.5]},"post_target":{"semantic_id":"grp_large_line_from_31108_to_71125","selector":"#svg-grid > line:nth-of-type(1)","tag_name":"line","center_point":[51.0,116.5]}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Create a line that bisects the angle evenly in two, then press submit.\" />",
        "<generic id=\"grp_svg_grid_object\" name=\"svg grid object\" dom_id=\"svg-grid\" selector=\"[id=&quot;svg-grid&quot;]\" tag_name=\"svg\" rect=\"2,52,150,130\" />",
        "<generic id=\"grp_click_canvas\" name=\"click canvas\" dom_id=\"click-canvas\" selector=\"[id=&quot;click-canvas&quot;]\" rect=\"0,50,160,160\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "<generic id=\"grp_blue_circle\" name=\"small blue circle at 53,118 radius 4\" dom_id=\"blue-circle\" selector=\"[id=&quot;blue-circle&quot;]\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"endpoint\" connected_lines=\"1\" connected_points=\"31,108\" center_x=\"53\" center_y=\"118\" radius=\"4\" rect=\"49,114,7,7\" />",
        "<generic id=\"grp_small_blue_circle_at_31108_rad\" name=\"small blue circle at 31,108 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"vertex\" connected_lines=\"3\" connected_points=\"91,81|71,125|53,118\" connected_line_angles_deg=\"-24|23|24\" center_x=\"31\" center_y=\"108\" radius=\"4\" rect=\"27,104,7,7\" />",
        "<generic id=\"grp_large_line_from_31108_to_9181\" name=\"large line from 31,108 to 91,81\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"91\" line_y2=\"81\" line_length=\"66\" line_angle_deg=\"-24\" rect=\"30,80,60,27\" />",
        "<generic id=\"grp_large_line_from_31108_to_71125\" name=\"large line from 31,108 to 71,125\" tag_name=\"line\" shape_kind=\"line\" line_x1=\"31\" line_y1=\"108\" line_x2=\"71\" line_y2=\"125\" line_length=\"43\" line_angle_deg=\"23\" rect=\"30,107,40,17\" />",
        "</root>",
    );

    let context = build_browser_observation_context_from_snapshot_with_history(snapshot, &history);
    assert!(context.contains("RECENT BROWSER OBSERVATION:"), "{context}");
    assert!(
        context.contains("grp_large_line_from_31108_to_71125"),
        "{context}"
    );
    assert!(!context.contains("grp_svg_grid_object"), "{context}");
    assert!(!context.contains("grp_click_canvas"), "{context}");
}

#[test]
fn success_signal_context_prefers_more_recent_click_success_over_older_dropdown_success() {
    let history = vec![
        chat_message(
            "tool",
            r#"{"id":"inp_awaiting_dispatch","selected":{"label":"Awaiting Dispatch","value":"Awaiting Dispatch"}}"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_t_215' via selector fallback '[id=\"ticket-link-t-215\"]'. Browser click/focus succeeded. verify={"postcondition_met":true}"#,
            2,
        ),
    ];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("observable state change"));
    assert!(context.contains("Do not repeat the same interaction"));
    assert!(!context.contains("`inp_awaiting_dispatch`"));
}

#[test]
fn success_signal_context_prefers_prefixed_dropdown_selection_over_older_click_success() {
    let history = vec![
        chat_message(
            "tool",
            r#"Clicked element 'lnk_t_215' via selector fallback '[id=\"ticket-link-t-215\"]'. Browser click/focus succeeded. verify={"postcondition_met":true}"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><combobox id="inp_awaiting_dispatch" name="Awaiting Dispatch" dom_id="status" selector="[id=&quot;status&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__select_option): {"id":"inp_assign_team","selected":{"label":"Network Ops","value":"Network Ops"}}"#,
            3,
        ),
    ];

    let context = build_recent_success_signal_context(&history);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("dropdown selection already succeeded"));
    assert!(context.contains("`inp_assign_team`"));
    assert!(context.contains("`inp_awaiting_dispatch`"));
    assert!(context.contains("`inp_dispatch_note`"));
    assert!(context.contains("`btn_review_update`"));
    assert!(!context.contains("observable state change"));
}

#[test]
fn success_signal_context_suppresses_stale_dropdown_when_latest_snapshot_moved_on() {
    let history = vec![
        chat_message(
            "tool",
            r#"{"id":"inp_awaiting_dispatch","selected":{"label":"Awaiting Dispatch","value":"Awaiting Dispatch"}}"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_ticket_t_215" name="Ticket T-215" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /></root>"#,
            2,
        ),
    ];

    let context = build_recent_success_signal_context(&history);
    assert!(context.is_empty(), "{context}");
}

#[test]
fn browser_observation_context_suppresses_stale_snapshot_after_unobserved_navigation() {
    let history = vec![
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
            2,
        ),
    ];

    let context = build_recent_browser_observation_context(&history);
    assert!(context.is_empty(), "{context}");
}

#[test]
fn browser_observation_context_uses_newer_snapshot_after_navigation() {
    let history = vec![
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_confirm_update" name="Confirm update" dom_id="confirm-update" selector="[id=&quot;confirm-update&quot;]" rect="0,0,1,1" /></root>"#,
            3,
        ),
    ];

    let context = build_recent_browser_observation_context(&history);
    assert!(context.contains("RECENT BROWSER OBSERVATION:"), "{context}");
    assert!(context.contains("btn_confirm_update"), "{context}");
}

#[test]
fn pending_browser_state_context_requires_snapshot_after_unobserved_navigation() {
    let history = vec![
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
            2,
        ),
    ];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("browser__inspect"), "{context}");
    assert!(context.contains("btn_review_update"), "{context}");
    assert!(context.contains("/review"), "{context}");
}

#[test]
fn pending_browser_state_context_skips_navigation_snapshot_when_current_snapshot_exists() {
    let history = vec![
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
            2,
        ),
    ];

    let context = build_recent_pending_browser_state_context_with_current_snapshot(&history, true);
    assert!(context.is_empty(), "{context}");
}

#[test]
fn snapshot_pending_context_highlights_filter_mismatch_after_recent_dropdown_change() {
    let history = vec![chat_message(
        "tool",
        r#"{"id":"inp_ticket_status","selected":{"label":"Escalated","value":"Escalated"}}"#,
        1,
    )];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_queue_search\" name=\"Queue search\" value=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`inp_ticket_status`"), "{context}");
    assert!(context.contains("`Escalated`"), "{context}");
    assert!(context.contains("`inp_queue_status_filter`"), "{context}");
    assert!(context.contains("`Queue status filter`"), "{context}");
    assert!(context.contains("`Awaiting Dispatch`"), "{context}");
    assert!(context.contains("browser__select_option"), "{context}");
}

#[test]
fn pending_browser_state_context_with_snapshot_highlights_filter_mismatch() {
    let history = vec![chat_message(
        "tool",
        r#"{"id":"inp_ticket_status","selected":{"label":"Escalated","value":"Escalated"}}"#,
        1,
    )];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("may hide the updated item"), "{context}");
    assert!(context.contains("browser__select_option"), "{context}");
}

#[test]
fn success_signal_context_with_snapshot_suppresses_generic_click_when_filter_hides_update() {
    let history = vec![
        chat_message(
            "tool",
            r#"{"id":"inp_ticket_status","selected":{"label":"Escalated","value":"Escalated"}}"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_202\" name=\"T-202\" dom_id=\"ticket-link-t-202\" selector=\"[id=&quot;ticket-link-t-202&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn pending_browser_state_context_guides_stale_queue_reverification_before_history() {
    let history = vec![
            chat_message(
                "user",
                "Sign in, keep the queue sort on \"Ticket ID\", then after saving switch the queue sort to \"Recently Updated\" and refresh before trusting row order.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                2,
            ),
        ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Ticket ID\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_queue_stale_warning\" name=\"This queue view is stale. Reapply the queue controls and refresh the list before using row order as evidence.\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Stale queue/list view"), "{context}");
    assert!(context.contains("`inp_queue_sort`"), "{context}");
    assert!(context.contains("`Ticket ID`"), "{context}");
    assert!(context.contains("`Recently Updated`"), "{context}");
    assert!(context.contains("`btn_apply_filters`"), "{context}");
    assert!(
        context.contains("Do not open ticket/history links"),
        "{context}"
    );
    assert!(
        context.contains("call `browser__inspect` again"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_guides_queue_reverification_after_confirmation_return_with_compact_snapshot(
) {
    let history = vec![
            chat_message(
                "user",
                "Return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                2,
            ),
        ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_queue_dispatch_stale\" name=\"Login / Queue Dispatch stale queue reorder Return ...\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_dispatch_stale_queue_reorder\" name=\"Dispatch stale queue reorder\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_queue_search\" name=\"Queue search\" value=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Ticket ID\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_215\" name=\"T-215\" dom_id=\"ticket-link-t-215\" selector=\"[id=&quot;ticket-link-t-215&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`inp_queue_sort`"), "{context}");
    assert!(context.contains("`Ticket ID`"), "{context}");
    assert!(context.contains("`Recently Updated`"), "{context}");
    assert!(context.contains("ticket/history links"), "{context}");
}

#[test]
fn success_signal_context_suppresses_generic_click_when_stale_queue_reverification_pending() {
    let history = vec![chat_message(
        "tool",
        r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
        1,
    )];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Ticket ID\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_queue_stale_warning\" name=\"This queue view is stale. Reapply the queue controls and refresh the list before using row order as evidence.\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn pending_browser_state_context_guides_distractor_history_after_reverified_queue_order() {
    let history = vec![
            chat_message(
                "user",
                "Open T-318, assign it to Billing Review, return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state. Stop only after typed verification shows T-318 moved above T-310 with assignee Billing Review while distractor T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-310 and verify no saved dispatch update was persisted there.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_assign_team","selected":{"label":"Billing Review","value":"Billing Review"}}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_confirm_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/review","post_url":"http://127.0.0.1:40363/workflow/case/confirmation"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                4,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_queue_sort","selected":{"label":"Recently Updated","value":"Recently Updated"}}"#,
                5,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_apply_filters' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                6,
            ),
        ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_queue_search\" name=\"Queue search\" value=\"invoice\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_status_filter\" name=\"Queue status filter\" value=\"Pending Review\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Recently Updated\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_318\" name=\"T-318\" context=\"Invoice adjustment awaiting callback / Pending Review / Billing Review\" dom_id=\"ticket-link-t-318\" selector=\"[id=&quot;ticket-link-t-318&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_318\" name=\"History\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" dom_id=\"ticket-history-link-t-318\" selector=\"[id=&quot;ticket-history-link-t-318&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_310\" name=\"T-310\" context=\"Recurring invoice delta / Pending Review / Unassigned\" dom_id=\"ticket-link-t-310\" selector=\"[id=&quot;ticket-link-t-310&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_807ebf\" name=\"History\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" dom_id=\"ticket-history-link-t-310\" selector=\"[id=&quot;ticket-history-link-t-310&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`T-318`"), "{context}");
    assert!(context.contains("`T-310`"), "{context}");
    assert!(context.contains("Do not reopen `T-318`"), "{context}");
    assert!(context.contains("`lnk_history_807ebf`"), "{context}");
    assert!(context.contains("another `browser__inspect`"), "{context}");
}

#[test]
fn success_signal_context_suppresses_generic_click_when_distractor_history_follow_up_pending() {
    let history = vec![
            chat_message(
                "user",
                "Open T-318, assign it to Billing Review, return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state. Stop only after typed verification shows T-318 moved above T-310 with assignee Billing Review while distractor T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-310 and verify no saved dispatch update was persisted there.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_assign_team","selected":{"label":"Billing Review","value":"Billing Review"}}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_apply_filters' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                4,
            ),
        ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Recently Updated\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_318\" name=\"T-318\" context=\"Invoice adjustment awaiting callback / Pending Review / Billing Review\" dom_id=\"ticket-link-t-318\" selector=\"[id=&quot;ticket-link-t-318&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_318\" name=\"History\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" dom_id=\"ticket-history-link-t-318\" selector=\"[id=&quot;ticket-history-link-t-318&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_t_310\" name=\"T-310\" context=\"Recurring invoice delta / Pending Review / Unassigned\" dom_id=\"ticket-link-t-310\" selector=\"[id=&quot;ticket-link-t-310&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_807ebf\" name=\"History\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" dom_id=\"ticket-history-link-t-310\" selector=\"[id=&quot;ticket-history-link-t-310&quot;]\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn pending_browser_state_context_falls_back_to_recent_queue_snapshot_for_distractor_history_follow_up(
) {
    let history = vec![
            chat_message(
                "user",
                "Open T-318, assign it to Billing Review, return to the queue, switch the queue sort to \"Recently Updated\", and refresh the queue before trusting any row state. Stop only after typed verification shows T-318 moved above T-310 with assignee Billing Review while distractor T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-310 and verify no saved dispatch update was persisted there.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_assign_team","selected":{"label":"Billing Review","value":"Billing Review"}}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"{"id":"inp_queue_sort","selected":{"label":"Recently Updated","value":"Recently Updated"}}"#,
                4,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_apply_filters' via selector fallback '[id="apply-filters"]'. Browser click/focus succeeded. verify={"postcondition_met":true}"#,
                5,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><textbox id="inp_queue_search" name="Queue search" value="invoice" dom_id="queue-search" selector="[id=&quot;queue-search&quot;]" rect="0,0,1,1" /><combobox id="inp_queue_sort" name="Queue sort" value="Recently Updated" dom_id="queue-sort" selector="[id=&quot;queue-sort&quot;]" rect="0,0,1,1" /><button id="btn_apply_filters" name="Apply filters" dom_id="apply-filters" selector="[id=&quot;apply-filters&quot;]" rect="0,0,1,1" /><link id="lnk_t_318" name="T-318" context="Invoice adjustment awaiting callback / Pending Review / Billing Review" dom_id="ticket-link-t-318" selector="[id=&quot;ticket-link-t-318&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_history_318" name="History" context="T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History" dom_id="ticket-history-link-t-318" selector="[id=&quot;ticket-history-link-t-318&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_t_310" name="T-310" context="Recurring invoice delta / Pending Review / Unassigned" dom_id="ticket-link-t-310" selector="[id=&quot;ticket-link-t-310&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_history_807ebf" name="History" context="T-310 Recurring invoice delta Pending Review Unassigned Billing Review History" dom_id="ticket-history-link-t-310" selector="[id=&quot;ticket-history-link-t-310&quot;]" omitted="true" rect="0,0,1,1" /></root>"#,
                6,
            ),
        ];
    let current_snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_queue_search\" name=\"Queue search\" value=\"invoice\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_queue_sort\" name=\"Queue sort\" value=\"Recently Updated\" dom_id=\"queue-sort\" selector=\"[id=&quot;queue-sort&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(current_snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Do not reopen `T-318`"), "{context}");
    assert!(context.contains("`lnk_history_807ebf`"), "{context}");
}

#[test]
fn pending_browser_state_context_guides_alternate_tab_exploration_when_target_missing() {
    let history = vec![
        chat_message(
            "user",
            r#"Expand the sections below, to find and click on the link "elit"."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'tab_section_1' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tablist id=\"tablist_section_1_orci_elementum_conse\" name=\"Section #1 Orci elementum consectetur egestas est ...\" dom_id=\"area\" selector=\"[id=&quot;area&quot;]\" tag_name=\"div\" rect=\"0,50,160,123\" />",
            "<tab id=\"tab_section_1\" name=\"Section #1\" focused=\"true\" dom_id=\"ui-id-1\" selector=\"[id=&quot;ui-id-1&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-2\" rect=\"4,54,152,17\" />",
            "<tabpanel id=\"tabpanel_section_1\" name=\"Orci elementum consectetur egestas est morbi a. Pharetra lacus.\" dom_id=\"ui-id-2\" selector=\"[id=&quot;ui-id-2&quot;]\" tag_name=\"div\" rect=\"4,73,152,58\" />",
            "<tab id=\"tab_section_2\" name=\"Section #2\" dom_id=\"ui-id-3\" selector=\"[id=&quot;ui-id-3&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-4\" rect=\"4,133,152,17\" />",
            "<tab id=\"tab_section_3\" name=\"Section #3\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,152,152,17\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`elit`"), "{context}");
    assert!(
        context.contains("Do not click `tab_section_1` again"),
        "{context}"
    );
    assert!(context.contains("`tab_section_2`"), "{context}");
    assert!(context.contains("`tab_section_3`"), "{context}");
    assert!(context.contains("another `browser__inspect`"), "{context}");
}

#[test]
fn pending_browser_state_context_ignores_alternate_tab_exploration_when_target_visible() {
    let history = vec![
        chat_message(
            "user",
            r#"Expand the sections below, to find and click on the link "elit"."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'tab_section_3' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_1\" name=\"Section #1\" dom_id=\"ui-id-1\" selector=\"[id=&quot;ui-id-1&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-2\" rect=\"4,54,152,17\" />",
            "<tab id=\"tab_section_2\" name=\"Section #2\" dom_id=\"ui-id-3\" selector=\"[id=&quot;ui-id-3&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-4\" rect=\"4,73,152,17\" />",
            "<tab id=\"tab_section_3\" name=\"Section #3\" focused=\"true\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,92,152,17\" />",
            "<tabpanel id=\"tabpanel_section_3\" name=\"Consectetur. elit non, ultrices risus.\" dom_id=\"ui-id-6\" selector=\"[id=&quot;ui-id-6&quot;]\" tag_name=\"div\" rect=\"4,111,152,58\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn pending_browser_state_context_guides_exact_visible_target_click() {
    let history = vec![
        chat_message(
            "user",
            r#"Expand the sections below, to find and click on the link "elit"."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'tab_section_3' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_1\" name=\"Section #1\" dom_id=\"ui-id-1\" selector=\"[id=&quot;ui-id-1&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-2\" rect=\"4,54,152,17\" />",
            "<tab id=\"tab_section_2\" name=\"Section #2\" dom_id=\"ui-id-3\" selector=\"[id=&quot;ui-id-3&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-4\" rect=\"4,73,152,17\" />",
            "<tab id=\"tab_section_3\" name=\"Section #3\" focused=\"true\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,92,152,17\" />",
            "<tabpanel id=\"tabpanel_section_3\" name=\"Consectetur. Gravida. Consectetur elit non,. In enim.\" dom_id=\"ui-id-6\" selector=\"[id=&quot;ui-id-6&quot;]\" tag_name=\"div\" rect=\"4,111,152,58\" />",
            "<generic id=\"grp_consectetur_dot\" name=\"Consectetur.\" tag_name=\"span\" rect=\"6,112,56,11\" />",
            "<generic id=\"grp_elit\" name=\"elit\" tag_name=\"span\" rect=\"63,123,13,11\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`grp_elit`"), "{context}");
    assert!(context.contains("browser__click"), "{context}");
    assert!(
        context.contains("Do not click a surrounding container"),
        "{context}"
    );
    assert!(context.contains("`browser__find_text`"), "{context}");
    assert!(context.contains("another `browser__inspect`"), "{context}");
}

#[test]
fn pending_browser_state_context_prefers_actionable_target_over_instruction_token() {
    let history = vec![chat_message(
        "user",
        r#"For the user @olin, click on the "Reply" button."#,
        1,
    )];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_query\" name=\"For the user @olin, click on the Reply button.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<generic id=\"grp_reply\" name=\"Reply\" tag_name=\"span\" rect=\"6,14,27,11\" />",
            "<generic id=\"grp_olin\" name=\"@olin\" tag_name=\"span\" rect=\"59,3,28,11\" />",
            "<generic id=\"grp_target_reply\" name=\"Reply\" selector=\"#area > div:nth-of-type(3) > div:nth-of-type(3) > span:nth-of-type(1)\" class_name=\"reply\" dom_clickable=\"true\" tag_name=\"span\" rect=\"20,221,14,14\" />",
            "</root>",
        );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`grp_target_reply`"), "{context}");
    assert!(!context.contains("`grp_reply` now"), "{context}");
}

#[test]
fn pending_browser_state_context_ignores_trailing_submit_clause_until_work_is_done() {
    let history = vec![chat_message(
        "user",
        "Create a line that bisects the angle evenly in two, then press submit.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Create a line that bisects the angle evenly in two, then press submit.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "<generic id=\"grp_small_blue_circle\" name=\"small blue circle at 31,108 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"vertex\" connected_lines=\"2\" center_x=\"31\" center_y=\"108\" rect=\"28,105,7,7\" />",
        "<generic id=\"grp_small_black_circle\" name=\"small black circle at 71,125 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"endpoint\" connected_lines=\"1\" center_x=\"71\" center_y=\"125\" rect=\"68,122,7,7\" />",
        "<generic id=\"grp_small_black_circle_2\" name=\"small black circle at 91,81 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" geometry_role=\"endpoint\" connected_lines=\"1\" center_x=\"91\" center_y=\"81\" rect=\"88,78,7,7\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(!context.contains("`btn_submit` now"), "{context}");
    assert!(
        !context.contains("`grp_create_a_line_that_bisects_the` now"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_still_targets_submit_for_submit_only_goal() {
    let history = vec![chat_message("user", "Press submit.", 1)];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`btn_submit`"), "{context}");
}

#[test]
fn pending_browser_state_context_recovers_visible_goal_text_without_explicit_target_quote() {
    let history = vec![chat_message(
        "user",
        "Find the email by Lonna and click the trash icon to delete it.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Find the email by Lonna and click the trash icon to delete it.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
        "<generic id=\"grp_lonna\" name=\"Lonna\" tag_name=\"span\" rect=\"82,3,30,11\" />",
        "<generic id=\"grp_primary\" name=\"Primary Josselyn Diam. Erat mauris mor.. Lonna Cras...\" dom_id=\"main\" selector=\"[id=&quot;main&quot;]\" tag_name=\"div\" scroll_top=\"0\" scroll_height=\"294\" client_height=\"150\" can_scroll_up=\"false\" can_scroll_down=\"true\" rect=\"2,52,155,150\" />",
        "<generic id=\"grp_josselyn\" name=\"Josselyn\" tag_name=\"div\" class_name=\"email-sender\" dom_clickable=\"true\" rect=\"7,75,88,12\" />",
        "<button id=\"btn_trash\" name=\"trash\" tag_name=\"span\" class_name=\"trash\" dom_clickable=\"true\" rect=\"117,80,12,12\" />",
        "<generic id=\"grp_lonna_row\" name=\"Lonna\" tag_name=\"div\" class_name=\"email-sender\" dom_clickable=\"true\" rect=\"7,114,88,12\" />",
        "<button id=\"btn_trash_row\" name=\"trash\" tag_name=\"span\" class_name=\"trash\" dom_clickable=\"true\" rect=\"117,119,12,12\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(
        context.contains("The target text `Lonna` is already visible"),
        "{context}"
    );
    assert!(context.contains("`grp_lonna_row`"), "{context}");
    assert!(!context.contains("`btn_trash_row` now"), "{context}");
}

#[test]
fn pending_browser_state_context_guides_search_control_for_missing_message_source_target() {
    let history = vec![chat_message(
        "user",
        "I want to send Sadie the e-mail that I got from Judi.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"I want to send Sadie the e-mail that I got from Judi.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_open_search\" name=\"open search\" dom_id=\"open-search\" selector=\"[id=&quot;open-search&quot;]\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "<generic id=\"grp_elladine\" name=\"Elladine\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_email\" name=\"email\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`Judi`"), "{context}");
    assert!(context.contains("`btn_open_search`"), "{context}");
    assert!(context.contains("search control"), "{context}");
    assert!(
        context.contains("do not click unrelated list actions"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_ignores_non_actionable_instruction_copy_goal_text() {
    let history = vec![chat_message(
        "user",
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Click on the numbers in ascending order.",
        1,
    )];
    let snapshot = concat!(
        "<rootwebarea id=\"rootwebarea_ascending_numbers_task\" name=\"Ascending Numbers Task\" focused=\"true\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_f4eec3\" rect=\"0,0,800,210\">",
        "<generic id=\"grp_9a0753\" rect=\"0,0,160,210\">",
        "<generic id=\"grp_9f4210\" rect=\"0,0,160,50\">",
        "<statictext id=\"statictext_click_on_the_numbers_in_ascend\" name=\"Click on the numbers in ascending order.\" rect=\"3,3,153,11\" />",
        "</generic>",
        "</generic>",
        "<generic id=\"grp_9a0753_9a0753\" rect=\"0,0,160,210\">",
        "<statictext id=\"statictext_start\" name=\"START\" rect=\"48,94,64,22\" />",
        "</generic>",
        "</generic>",
        "</rootwebarea>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(!context.contains("The target text"), "{context}");
    assert!(
        !context.contains("`statictext_click_on_the_numbers_in_ascend`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_prioritizes_visible_start_gate_over_instruction_copy() {
    let history = vec![chat_message(
        "user",
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Click on the numbers in ascending order.",
        1,
    )];
    let snapshot = concat!(
        "<rootwebarea id=\"rootwebarea_ascending_numbers_task\" name=\"Ascending Numbers Task\" focused=\"true\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_f4eec3\" rect=\"0,0,800,210\">",
        "<generic id=\"grp_9a0753\" rect=\"0,0,160,210\">",
        "<generic id=\"grp_9f4210\" rect=\"0,0,160,50\">",
        "<statictext id=\"statictext_click_on_the_numbers_in_ascend\" name=\"Click on the numbers in ascending order.\" rect=\"3,3,153,11\" />",
        "</generic>",
        "</generic>",
        "<generic id=\"grp_9a0753_9a0753\" rect=\"0,0,160,210\">",
        "<statictext id=\"statictext_start\" name=\"START\" rect=\"48,94,64,22\" />",
        "</generic>",
        "</generic>",
        "</rootwebarea>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(context.contains("visible start gate"), "{context}");
    assert!(context.contains("`statictext_start`"), "{context}");
    assert!(context.contains("browser__click"), "{context}");
    assert!(
        !context.contains("`statictext_click_on_the_numbers_in_ascend`"),
        "{context}"
    );
    assert!(
        !context.contains("The target text `Click on the numbers in ascending order.` is visible"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_guides_recipient_field_before_forward_send() {
    let history = vec![chat_message(
        "user",
        "I want to send Sadie the e-mail that I got from Judi.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_wrap\" name=\"I want to send Sadie the e-mail that I got from Judi.\" dom_id=\"wrap\" selector=\"[id=&quot;wrap&quot;]\" rect=\"0,0,1,1\" />",
        "<label id=\"label_to\" name=\"to:\" rect=\"0,0,1,1\" />",
        "<textbox id=\"inp_forward_sender\" name=\"forward sender\" class_name=\"forward-sender\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_send_forward\" name=\"send forward\" dom_id=\"send-forward\" selector=\"[id=&quot;send-forward&quot;]\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`Sadie`"), "{context}");
    assert!(context.contains("`inp_forward_sender`"), "{context}");
    assert!(
        context.contains("Do not click `btn_send_forward` yet."),
        "{context}"
    );
    assert!(!context.contains("`label_to`"), "{context}");
}

#[test]
fn pending_browser_state_context_guides_mouse_down_after_drag_hover() {
    let history = vec![
        chat_message(
            "user",
            "Drag the smaller box so that it is completely inside the larger box.",
            1,
        ),
        chat_message(
            "tool",
            r#"{"pointer":{"action":"hover","x":42.0,"y":104.0,"target":{"id":"grp_s","target_kind":"semantic_id"},"hovered":null}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_s\" name=\"s\" dom_id=\"draggableSmall\" class_name=\"ui-draggable ui-draggable-handle\" rect=\"10,90,18,18\" />",
        "<generic id=\"grp_l\" name=\"L\" dom_id=\"draggableLarge\" class_name=\"ui-draggable ui-draggable-handle\" rect=\"70,70,50,50\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`browser__pointer_down`"), "{context}");
    assert!(context.contains("`grp_s`"), "{context}");
    assert!(
        context.contains("Do not repeat `browser__hover`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_guides_mouse_up_after_drag_destination_hover() {
    let history = vec![
        chat_message(
            "user",
            "Drag the smaller box so that it is completely inside the larger box.",
            1,
        ),
        chat_message(
            "tool",
            r#"{"pointer":{"action":"hover","x":42.0,"y":104.0,"target":{"id":"grp_s","target_kind":"semantic_id"},"hovered":null}}"#,
            2,
        ),
        chat_message(
            "tool",
            r#"{"pointer":{"action":"mouse_down","button":"left","x":42.0,"y":104.0,"buttons":["left"]}}"#,
            3,
        ),
        chat_message(
            "tool",
            r#"{"pointer":{"action":"hover","x":96.0,"y":96.0,"target":{"id":"grp_l","target_kind":"semantic_id"},"hovered":null}}"#,
            4,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_s\" name=\"s\" dom_id=\"draggableSmall\" class_name=\"ui-draggable ui-draggable-handle\" rect=\"10,90,18,18\" />",
        "<generic id=\"grp_l\" name=\"L\" dom_id=\"draggableLarge\" class_name=\"ui-draggable ui-draggable-handle\" rect=\"70,70,50,50\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`browser__pointer_up`"), "{context}");
    assert!(context.contains("`grp_l`"), "{context}");
    assert!(
        context.contains("Do not repeat `browser__hover`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_guides_submit_after_single_pointer_gesture_release() {
    let history = vec![
        chat_message(
            "user",
            "Drag the smaller box so that it is completely inside the larger box.",
            1,
        ),
        chat_message(
            "tool",
            r#"{"pointer":{"action":"hover","x":42.0,"y":104.0,"target":{"id":"grp_s","target_kind":"semantic_id"},"hovered":null}}"#,
            2,
        ),
        chat_message(
            "tool",
            r#"{"pointer":{"action":"mouse_down","button":"left","x":42.0,"y":104.0,"buttons":["left"]}}"#,
            3,
        ),
        chat_message(
            "tool",
            r#"{"pointer":{"action":"hover","x":96.0,"y":96.0,"target":{"id":"grp_l","target_kind":"semantic_id"},"hovered":null}}"#,
            4,
        ),
        chat_message(
            "tool",
            r#"{"pointer":{"action":"mouse_up","button":"left","x":96.0,"y":96.0,"buttons":[]}}"#,
            5,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_s\" name=\"s\" dom_id=\"draggableSmall\" class_name=\"ui-draggable ui-draggable-handle\" rect=\"10,90,18,18\" />",
        "<generic id=\"grp_l\" name=\"L\" dom_id=\"draggableLarge\" class_name=\"ui-draggable ui-draggable-handle\" rect=\"70,70,50,50\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`btn_submit`"), "{context}");
    assert!(
        context.contains("Do not call `agent__complete`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_guides_submit_when_target_is_already_active() {
    let history = vec![chat_message(
        "user",
        "Move the cube around so that \"6\" is the active side facing the user.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Move the cube around so that &quot;6&quot; is the active side facing the user.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" rect=\"0,0,160,40\" />",
        "<generic id=\"grp_6_b13e98_1\" name=\"6\" class_name=\"cube-image active\" rect=\"48,57,64,64\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" rect=\"40,170,80,32\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("already active"), "{context}");
    assert!(context.contains("`btn_submit`"), "{context}");
    assert!(
        context.contains("Do not click `grp_6_b13e98_1` again"),
        "{context}"
    );
    assert!(
        context.contains("do not call `agent__complete` before submission"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_suppresses_exact_visible_target_after_target_click() {
    let history = vec![
        chat_message(
            "user",
            r#"Expand the sections below, to find and click on the link "elit"."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'grp_elit' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_3\" name=\"Section #3\" focused=\"true\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,92,152,17\" />",
            "<tabpanel id=\"tabpanel_section_3\" name=\"Consectetur. Gravida. Consectetur elit non,. In enim.\" dom_id=\"ui-id-6\" selector=\"[id=&quot;ui-id-6&quot;]\" tag_name=\"div\" rect=\"4,111,152,58\" />",
            "<generic id=\"grp_elit\" name=\"elit\" tag_name=\"span\" rect=\"63,123,13,11\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn pending_browser_state_context_guides_ranked_result_pagination() {
    let history = vec![
        chat_message(
            "user",
            r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_search' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_sergio\" name=\"Sergio\" tag_name=\"span\" rect=\"115,3,31,11\" />",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_karrie\" name=\"Karrie\" dom_id=\"result-0\" selector=\"#page-content > div:nth-of-type(1) > a\" rect=\"4,77,29,11\" />",
            "<link id=\"lnk_riley\" name=\"Riley\" dom_id=\"result-1\" selector=\"#page-content > div:nth-of-type(2) > a\" rect=\"4,110,24,11\" />",
            "<link id=\"lnk_kanesha\" name=\"Kanesha\" dom_id=\"result-2\" selector=\"#page-content > div:nth-of-type(3) > a\" rect=\"4,143,42,11\" />",
            "<link id=\"lnk_page_1\" name=\"1\" selector=\"#pagination > li:nth-of-type(3) > a\" rect=\"44,191,8,17\" />",
            "<link id=\"lnk_page_2\" name=\"2\" selector=\"#pagination > li:nth-of-type(4) > a\" rect=\"56,191,8,17\" />",
            "<link id=\"lnk_page_3\" name=\"3\" selector=\"#pagination > li:nth-of-type(5) > a\" rect=\"68,191,8,17\" />",
            "<link id=\"lnk_next\" name=\">\" selector=\"#pagination > li:nth-of-type(6) > a\" rect=\"81,191,9,17\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`grp_6th`"), "{context}");
    assert!(context.contains("not a search result"), "{context}");
    assert!(context.contains("Only 3 actual result links"), "{context}");
    assert!(context.contains("ranks 1-3"), "{context}");
    assert!(context.contains("`lnk_page_2`"), "{context}");
    assert!(context.contains("Do not click `grp_6th`"), "{context}");
    assert!(context.contains("`browser__scroll`"), "{context}");
}

#[test]
fn pending_browser_state_context_guides_ranked_result_link_after_page_change() {
    let history = vec![
        chat_message(
            "user",
            r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_page_2' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_result_4\" name=\"Teodora\" dom_id=\"result-3\" selector=\"#page-content > div:nth-of-type(1) > a\" rect=\"4,77,29,11\" />",
            "<link id=\"lnk_result_5\" name=\"Merrie\" dom_id=\"result-4\" selector=\"#page-content > div:nth-of-type(2) > a\" rect=\"4,110,24,11\" />",
            "<link id=\"lnk_result_6\" name=\"Sergio result\" dom_id=\"result-5\" selector=\"#page-content > div:nth-of-type(3) > a\" rect=\"4,143,42,11\" />",
            "<link id=\"lnk_page_1\" name=\"1\" selector=\"#pagination > li:nth-of-type(3) > a\" rect=\"44,191,8,17\" />",
            "<link id=\"lnk_page_2\" name=\"2\" selector=\"#pagination > li:nth-of-type(4) > a\" rect=\"56,191,8,17\" />",
            "<link id=\"lnk_page_3\" name=\"3\" selector=\"#pagination > li:nth-of-type(5) > a\" rect=\"68,191,8,17\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`grp_6th`"), "{context}");
    assert!(context.contains("`lnk_result_6`"), "{context}");
    assert!(context.contains("not the result to click"), "{context}");
    assert!(context.contains("`browser__scroll`"), "{context}");
}

#[test]
fn pending_browser_state_context_guides_ranked_result_link_after_failed_page_click() {
    let history = vec![
        chat_message(
            "user",
            r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__click): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_page_2'. verify={"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_thaddeus\" name=\"Thaddeus\" dom_id=\"result-3\" selector=\"#page-content > div:nth-of-type(1) > a\" rect=\"4,77,47,11\" />",
            "<link id=\"lnk_emile\" name=\"Emile\" dom_id=\"result-4\" selector=\"#page-content > div:nth-of-type(2) > a\" rect=\"4,110,27,11\" />",
            "<link id=\"lnk_sergio\" name=\"Sergio\" dom_id=\"result-5\" selector=\"#page-content > div:nth-of-type(3) > a\" rect=\"4,143,31,11\" />",
            "<link id=\"lnk_prev\" name=\"<\" selector=\"#pagination > li:nth-of-type(2) > a\" rect=\"44,191,9,17\" />",
            "<link id=\"lnk_page_1\" name=\"1\" selector=\"#pagination > li:nth-of-type(3) > a\" rect=\"57,191,8,17\" />",
            "<link id=\"lnk_page_2\" name=\"2\" selector=\"#pagination > li:nth-of-type(4) > a\" rect=\"69,191,8,17\" />",
            "<link id=\"lnk_page_3\" name=\"3\" selector=\"#pagination > li:nth-of-type(5) > a\" rect=\"81,191,8,17\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Result 6 on this page"), "{context}");
    assert!(context.contains("`lnk_sergio`"), "{context}");
    assert!(!context.contains("`lnk_page_2`"), "{context}");
    assert!(context.contains("`browser__scroll`"), "{context}");
}

#[test]
fn pending_browser_state_context_guides_ranked_result_link_after_failed_page_click_without_result_markers(
) {
    let history = vec![
        chat_message(
            "user",
            r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__click): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_2'. verify={"attempts":[{"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}],"id":"lnk_2"}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_thaddeus\" name=\"Thaddeus\" tag_name=\"a\" rect=\"4,77,47,11\" />",
            "<link id=\"lnk_emile\" name=\"Emile\" tag_name=\"a\" rect=\"4,110,27,11\" />",
            "<link id=\"lnk_sergio\" name=\"Sergio\" tag_name=\"a\" rect=\"4,143,31,11\" />",
            "<generic id=\"grp_123\" name=\"&lt;123&gt;\" dom_id=\"pagination\" selector=\"#pagination\" tag_name=\"ul\" rect=\"2,191,103,17\" />",
            "<link id=\"lnk_prev\" name=\"&lt;\" tag_name=\"a\" rect=\"44,191,9,17\" />",
            "<link id=\"lnk_1\" name=\"1\" tag_name=\"a\" rect=\"57,191,8,17\" />",
            "<link id=\"lnk_2\" name=\"2\" tag_name=\"a\" rect=\"69,191,8,17\" />",
            "<link id=\"lnk_3\" name=\"3\" tag_name=\"a\" rect=\"81,191,8,17\" />",
            "<link id=\"lnk_next\" name=\"&gt;\" omitted=\"true\" tag_name=\"a\" rect=\"94,191,9,17\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Result 6 on this page"), "{context}");
    assert!(context.contains("`lnk_sergio`"), "{context}");
    assert!(
        !context.contains("`lnk_2` (`2`) now to advance"),
        "{context}"
    );
    assert!(context.contains("`browser__scroll`"), "{context}");
}

#[test]
fn pending_browser_state_context_retries_visible_non_submit_click_after_dispatch_timeout() {
    let history = vec![
        chat_message(
            "user",
            r#"Buy YJV stock when the price is less than $59.60."#,
            1,
        ),
        chat_message(
            "tool",
            r##"Tool Output (browser__click): ERROR_CLASS=NoEffectAfterAction Failed to click element 'btn_buy'. verify={"dispatch_failures":[{"error":"dispatch timed out after 2500 ms. Retry the action.","method":"selector_grounded","selector":"#buy"}],"id":"btn_buy"}"##,
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<button id=\"btn_buy\" name=\"Buy\" dom_id=\"buy\" selector=\"[id=&quot;buy&quot;]\" tag_name=\"button\" rect=\"20,140,101,31\" />",
        "<generic id=\"grp_yjv\" name=\"YJV\" dom_id=\"stock-symbol\" selector=\"[id=&quot;stock-symbol&quot;]\" tag_name=\"span\" rect=\"20,90,24,12\" />",
        "<generic id=\"grp_59_dot_00\" name=\"$59.00\" dom_id=\"stock-price\" selector=\"[id=&quot;stock-price&quot;]\" tag_name=\"span\" rect=\"20,110,40,12\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`btn_buy`"), "{context}");
    assert!(
        context.contains("retry `browser__click` on `btn_buy` now"),
        "{context}"
    );
    assert!(
        context.contains("Do not spend the next step on `browser__inspect`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_guides_pagination_after_instruction_only_find_text_hit() {
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
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<heading id=\"heading_karol\" name=\"Karol\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<generic id=\"grp_address\" name=\"Address:\" tag_name=\"span\" rect=\"6,124,46,11\" />",
            "<link id=\"lnk_5735_valdez_crescent\" name=\"5735 Valdez Crescent\" tag_name=\"a\" rect=\"52,124,98,11\" />",
            "<generic id=\"grp_1\" name=\"1&gt;\" dom_id=\"pagination\" selector=\"[id=&quot;pagination&quot;]\" tag_name=\"ul\" rect=\"2,183,65,17\" />",
            "<link id=\"lnk_1\" name=\"1\" tag_name=\"a\" rect=\"44,183,8,17\" />",
            "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"56,183,9,17\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`Deena`"), "{context}");
    assert!(context.contains("`Karol`"), "{context}");
    assert!(
        context.contains("Do not click this record's links"),
        "{context}"
    );
    assert!(context.contains("`lnk_443422`"), "{context}");
    assert!(context.contains("`browser__find_text`"), "{context}");
    assert!(context.contains("Do not invent ids"), "{context}");
}

#[test]
fn pending_browser_state_context_suppresses_instruction_only_find_text_hint_once_target_is_visible()
{
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
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<heading id=\"heading_deena\" name=\"Deena\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<link id=\"lnk_19_townsend_road\" name=\"19 Townsend Road\" tag_name=\"a\" rect=\"52,124,98,11\" />",
            "<generic id=\"grp_2\" name=\"2&gt;\" dom_id=\"pagination\" selector=\"[id=&quot;pagination&quot;]\" tag_name=\"ul\" rect=\"2,183,65,17\" />",
            "<link id=\"lnk_2\" name=\"2\" tag_name=\"a\" rect=\"44,183,8,17\" />",
            "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"56,183,9,17\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn pending_browser_state_context_requests_snapshot_after_successful_tree_change_link_click_without_reobservation(
) {
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_find_deena_in_the_contact_book\" name=\"Find Deena in the contact book and click on their address.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<heading id=\"heading_karol\" name=\"Karol\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<link id=\"lnk_5735_valdez_crescent\" name=\"5735 Valdez Crescent\" tag_name=\"a\" rect=\"52,124,98,11\" />",
            "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"56,183,9,17\" />",
            "</root>",
        );
    let history = vec![
        chat_message(
            "user",
            "Find Deena in the contact book and click on their address.",
            1,
        ),
        chat_message(
            "tool",
            &format!("Tool Output (browser__inspect): {snapshot}"),
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_443422' via geometry fallback. verify={"post_target":{"semantic_id":"lnk_443422","tag_name":"a","center_point":[73.5,191.5]},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            3,
        ),
    ];

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`lnk_443422`"), "{context}");
    assert!(context.contains("`browser__inspect`"), "{context}");
    assert!(context.contains("stale controls"), "{context}");
    assert!(
        !context.contains("Do not click this record's links"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_allows_reusable_navigation_control_repeat_after_tree_change() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_datepicker\" name=\"datepicker\" dom_id=\"datepicker\" class_name=\"hasDatepicker\" dom_clickable=\"true\" rect=\"29,52,128,21\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"27,84,95,31\" />",
        "<link id=\"lnk_prev\" name=\"Prev\" tag_name=\"a\" class_name=\"ui-datepicker-prev ui-corner-all\" dom_clickable=\"true\" rect=\"38,86,14,14\" />",
        "<link id=\"lnk_next\" name=\"Next\" tag_name=\"a\" class_name=\"ui-datepicker-next ui-corner-all\" dom_clickable=\"true\" rect=\"126,86,14,14\" />",
        "<generic id=\"grp_november_2016\" name=\"November 2016\" tag_name=\"div\" rect=\"54,86,48,14\" />",
        "</root>",
    );
    let history = vec![
        chat_message("user", "Select 06/20/2016 as the date and hit submit.", 1),
        chat_message(
            "tool",
            &format!("Tool Output (browser__inspect): {snapshot}"),
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_prev' via geometry fallback. verify={"post_target":{"semantic_id":"lnk_prev","tag_name":"a","center_point":[40.5,84.5]},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            3,
        ),
    ];

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("reusable"), "{context}");
    assert!(context.contains("may click `lnk_prev` again"), "{context}");
    assert!(
        !context.contains("Do not click `lnk_prev` again"),
        "{context}"
    );
    assert!(
        !context.contains("Use `browser__inspect` once now"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_suppresses_tree_change_reverification_after_later_snapshot() {
    let old_snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<heading id=\"heading_karol\" name=\"Karol\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
        "<link id=\"lnk_443422\" name=\"&gt;\" tag_name=\"a\" rect=\"56,183,9,17\" />",
        "</root>",
    );
    let new_snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<heading id=\"heading_deena\" name=\"Deena\" tag_name=\"h2\" rect=\"2,64,156,17\" />",
            "<link id=\"lnk_5159_middleton_crescent_apt_5\" name=\"5159 Middleton Crescent, Apt 5\" tag_name=\"a\" rect=\"6,124,115,22\" />",
            "</root>",
        );
    let history = vec![
        chat_message(
            "user",
            "Find Deena in the contact book and click on their address.",
            1,
        ),
        chat_message(
            "tool",
            &format!("Tool Output (browser__inspect): {old_snapshot}"),
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_443422' via geometry fallback. verify={"post_target":{"semantic_id":"lnk_443422","tag_name":"a","center_point":[73.5,191.5]},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            3,
        ),
        chat_message(
            "tool",
            &format!("Tool Output (browser__inspect): {new_snapshot}"),
            4,
        ),
    ];

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(new_snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn pending_browser_state_context_resets_ranked_result_page_after_resubmit_returns_to_first_page() {
    let history = vec![
        chat_message(
            "user",
            r#"Use the textbox to enter "Sergio" and press "Search", then find and click the 6th search result."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_search' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__click): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_2'. verify={"attempts":[{"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}],"id":"lnk_2"}"#,
            3,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_search' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            4,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_6th\" name=\"6th\" tag_name=\"span\" rect=\"42,25,15,11\" />",
            "<link id=\"lnk_karrie\" name=\"Karrie\" tag_name=\"a\" rect=\"4,77,29,11\" />",
            "<link id=\"lnk_riley\" name=\"Riley\" tag_name=\"a\" rect=\"4,110,24,11\" />",
            "<link id=\"lnk_kanesha\" name=\"Kanesha\" tag_name=\"a\" rect=\"4,143,42,11\" />",
            "<generic id=\"grp_123\" name=\"123&gt;\" dom_id=\"pagination\" selector=\"#pagination\" tag_name=\"ul\" rect=\"2,191,90,17\" />",
            "<link id=\"lnk_1\" name=\"1\" tag_name=\"a\" rect=\"44,191,8,17\" />",
            "<link id=\"lnk_2\" name=\"2\" tag_name=\"a\" rect=\"56,191,8,17\" />",
            "<link id=\"lnk_3\" name=\"3\" tag_name=\"a\" rect=\"69,191,8,17\" />",
            "<link id=\"lnk_next\" name=\"&gt;\" omitted=\"true\" tag_name=\"a\" rect=\"81,191,9,17\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Only 3 actual result links"), "{context}");
    assert!(context.contains("ranks 1-3"), "{context}");
    assert!(context.contains("`lnk_2`"), "{context}");
    assert!(!context.contains("`lnk_kanesha`"), "{context}");
}

#[test]
fn success_signal_context_suppresses_generic_click_when_alternate_tab_exploration_pending() {
    let history = vec![
        chat_message(
            "user",
            r#"Expand the sections below, to find and click on the link "elit"."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'tab_section_1' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_1\" name=\"Section #1\" focused=\"true\" dom_id=\"ui-id-1\" selector=\"[id=&quot;ui-id-1&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-2\" rect=\"4,54,152,17\" />",
            "<tabpanel id=\"tabpanel_section_1\" name=\"Orci elementum consectetur egestas est morbi a. Pharetra lacus.\" dom_id=\"ui-id-2\" selector=\"[id=&quot;ui-id-2&quot;]\" tag_name=\"div\" rect=\"4,73,152,58\" />",
            "<tab id=\"tab_section_2\" name=\"Section #2\" dom_id=\"ui-id-3\" selector=\"[id=&quot;ui-id-3&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-4\" rect=\"4,133,152,17\" />",
            "<tab id=\"tab_section_3\" name=\"Section #3\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,152,152,17\" />",
            "</root>",
        );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn success_signal_context_suppresses_generic_click_when_exact_target_click_is_pending() {
    let history = vec![
        chat_message(
            "user",
            r#"Expand the sections below, to find and click on the link "elit"."#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'tab_section_3' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<tab id=\"tab_section_3\" name=\"Section #3\" focused=\"true\" dom_id=\"ui-id-5\" selector=\"[id=&quot;ui-id-5&quot;]\" tag_name=\"h3\" controls_dom_id=\"ui-id-6\" rect=\"4,92,152,17\" />",
            "<tabpanel id=\"tabpanel_section_3\" name=\"Consectetur. Gravida. Consectetur elit non,. In enim.\" dom_id=\"ui-id-6\" selector=\"[id=&quot;ui-id-6&quot;]\" tag_name=\"div\" rect=\"4,111,152,58\" />",
            "<generic id=\"grp_elit\" name=\"elit\" tag_name=\"span\" rect=\"63,123,13,11\" />",
            "</root>",
        );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn success_signal_context_suppresses_generic_click_after_unobserved_navigation() {
    let history = vec![
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
            2,
        ),
    ];

    let context = build_recent_success_signal_context(&history);
    assert!(context.is_empty(), "{context}");
}

#[test]
fn success_signal_context_points_to_visible_controls_after_navigation_click() {
    let history = vec![chat_message(
        "tool",
        r#"Clicked element 'btn_sign_in' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/login","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
        1,
    )];
    let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"> <generic id="grp_login_divide_queue" name="Login / Queue" rect="0,0,1,1" /> IMPORTANT TARGETS: lnk_history tag=link name=History dom_id=ticket-history-link-t-202 selector=[id="ticket-history-link-t-202"] | lnk_t_204 tag=link name=T-204 dom_id=ticket-link-t-204 selector=[id="ticket-link-t-204"] | lnk_history_4c23bd tag=link name=History dom_id=ticket-history-link-t-204 selector=[id="ticket-history-link-t-204"] | lnk_t_215 tag=link name=T-215 dom_id=ticket-link-t-215 selector=[id="ticket-link-t-215"]</root>"#;

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
    assert!(context.contains("`lnk_t_204`"), "{context}");
    assert!(context.contains("`lnk_t_215`"), "{context}");
    assert!(
        context.contains("Do not spend the next step on another `browser__inspect`"),
        "{context}"
    );
    assert!(
        !context.contains("finish with `agent__complete` when the goal is satisfied"),
        "{context}"
    );
}

#[test]
fn success_signal_context_prefers_actionable_calendar_controls_over_generic_headers() {
    let history = vec![chat_message(
        "tool",
        r#"Clicked element 'inp_datepicker_hasdatepicker' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "IMPORTANT TARGETS: ",
        "inp_datepicker_hasdatepicker tag=textbox name=datepicker hasdatepicker dom_id=datepicker selector=[id=\"datepicker\"] class_name=hasDatepicker dom_clickable=true | ",
        "btn_submit tag=button name=Submit dom_id=subbtn selector=[id=\"subbtn\"] class_name=secondary-action dom_clickable=true | ",
        "lnk_prev tag=link name=Prev class_name=ui-datepicker-prev ui-corner-all dom_clickable=true | ",
        "grp_prev_next_december_2016 tag=generic name=Prev Next December 2016 class_name=ui-datepicker-header ui-widget-header ui-helper-clearfix ui-corn... | ",
        "grp_december_2016 tag=generic name=December 2016 class_name=ui-datepicker-title | ",
        "lnk_1 tag=link name=1 class_name=ui-state-default dom_clickable=true omitted | ",
        "lnk_2 tag=link name=2 class_name=ui-state-default dom_clickable=true omitted",
        "</root>",
    );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
    assert!(context.contains("`lnk_prev`"), "{context}");
    assert!(context.contains("`lnk_1`"), "{context}");
    assert!(
        context.contains("Do not spend the next step on another `browser__inspect`"),
        "{context}"
    );
    assert!(
        !context.contains("`grp_prev_next_december_2016`"),
        "{context}"
    );
    assert!(!context.contains("`grp_december_2016`"), "{context}");
}

#[test]
fn pending_browser_state_context_guides_alternate_history_after_returning_to_list() {
    let history = vec![
        chat_message(
            "user",
            "Verify T-215 changed and T-204 stayed unchanged before finishing.",
            1,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" rect="0,0,1,1" /></root>"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
            3,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_t_202\" name=\"History\" dom_id=\"ticket-history-link-t-202\" context=\"T-202 Fiber handoff requires vendor logs / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_215\" name=\"History\" dom_id=\"ticket-history-link-t-215\" context=\"T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Do not reopen `T-215`"), "{context}");
    assert!(
        context.contains("`lnk_history_t_204` for `T-204`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_ignores_queue_snapshots_when_guiding_alternate_history() {
    let history = vec![
        chat_message(
            "user",
            "Verify T-215 changed and T-204 stayed unchanged before finishing.",
            1,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_history_t_202" name="History" dom_id="ticket-history-link-t-202" /><link id="lnk_history_t_204" name="History" dom_id="ticket-history-link-t-204" context="T-204 Metro fiber outage / Awaiting Dispatch / Unassigned" /><link id="lnk_history_t_215" name="History" dom_id="ticket-history-link-t-215" context="T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops" /></root>"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_history_t_215' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history"}"#,
            3,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" tag_name="h1" rect="0,0,1,1" /><generic id="grp_verify_saved_dispatch" name="Verify that the saved dispatch event matches the requested change before you return to the queue." dom_id="history-status" rect="0,0,1,1" /></root>"#,
            4,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
            5,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_t_202\" name=\"History\" dom_id=\"ticket-history-link-t-202\" context=\"T-202 Fiber handoff requires vendor logs / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_215\" name=\"History\" dom_id=\"ticket-history-link-t-215\" context=\"T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Do not reopen `T-215`"), "{context}");
    assert!(
        context.contains("`lnk_history_t_204` for `T-204`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_guides_alternate_history_after_confirmation_audit_return() {
    let history = vec![
        chat_message(
            "user",
            "Verify T-318 changed and T-310 stayed unchanged before finishing.",
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_confirm_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/review","post_url":"http://127.0.0.1:40363/workflow/case/confirmation"}"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_open_audit_history' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history"}"#,
            3,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
            4,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
            5,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_t_303\" name=\"History\" dom_id=\"ticket-history-link-t-303\" context=\"Invoice reminder needs correction / Pending Review / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_7c01a1\" name=\"History\" dom_id=\"ticket-history-link-t-310\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_1ebf96\" name=\"History\" dom_id=\"ticket-history-link-t-318\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Do not reopen `T-318`"), "{context}");
    assert!(
        context.contains("`lnk_history_7c01a1` for `T-310`"),
        "{context}"
    );
}

#[test]
fn recent_history_return_item_id_prefers_ticket_segment_over_case_slug() {
    let history = vec![chat_message(
        "tool",
        r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/queue"}"#,
        1,
    )];

    assert_eq!(
        recent_history_return_item_id(&history),
        Some("T-318".to_string())
    );
}

#[test]
fn pending_browser_state_context_excludes_completed_item_after_slugged_history_return() {
    let history = vec![
        chat_message(
            "user",
            "Verify T-318 changed and T-310 stayed unchanged before finishing.",
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_open_audit_history' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/confirmation","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history"}"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
            3,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/queue"}"#,
            4,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_7c01a1\" name=\"History\" dom_id=\"ticket-history-link-t-310\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_1ebf96\" name=\"History\" dom_id=\"ticket-history-link-t-318\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("Do not reopen `T-318`"), "{context}");
    assert!(
        context.contains("`lnk_history_7c01a1` for `T-310`"),
        "{context}"
    );
    assert!(!context.contains("`lnk_history_1ebf96`"), "{context}");
}

#[test]
fn pending_browser_state_context_skips_generic_confirmation_history_link_after_return() {
    let history = vec![
        chat_message(
            "user",
            "Verify T-318 changed and T-310 stayed unchanged before finishing.",
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_open_audit_history' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/confirmation","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history"}"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
            3,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/tickets/T-318/history","post_url":"http://127.0.0.1:40139/workflow/workflow-workflow-mutation-isolation-billing-review-1773478730656/queue"}"#,
            4,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_open_audit_history\" name=\"Open audit history\" dom_id=\"history-link\" selector=\"[id=&quot;history-link&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_save_status\" name=\"Saved, cross-ticket queue/history verification pending\" dom_id=\"save-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_assignment_banner\" name=\"Ticket T-318 was routed to Billing Review.\" dom_id=\"assignment-banner\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_status_summary\" name=\"Saved status: Pending Review\" dom_id=\"status-summary\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_note_summary\" name=\"Saved note: Validate recurring invoice delta\" dom_id=\"note-summary\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn success_signal_context_suppresses_generic_click_when_alternate_history_verification_pending() {
    let history = vec![
        chat_message(
            "user",
            "Verify T-215 changed and T-204 stayed unchanged before finishing.",
            1,
        ),
        chat_message(
            "tool",
            r#"Tool Output (browser__inspect): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" rect="0,0,1,1" /></root>"#,
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
            3,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_t_204\" name=\"History\" dom_id=\"ticket-history-link-t-204\" context=\"T-204 Metro fiber outage / Awaiting Dispatch / Unassigned\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_t_215\" name=\"History\" dom_id=\"ticket-history-link-t-215\" context=\"T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn pending_browser_state_context_highlights_autocomplete_follow_up() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","controls_dom_id":"ui-id-1","active_descendant_dom_id":"ui-id-2","assistive_hint":"1 result is available, use up and down arrow keys to navigate. Poland"}}}"##,
        1,
    )];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("autocomplete state"));
    assert!(context.contains("Do not submit or finish"));
    assert!(context.contains("browser__press_key"));
}

#[test]
fn pending_browser_state_context_highlights_key_follow_up() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Enter","modifiers":[],"is_chord":false,"value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate. Poland"}}}"##,
        1,
    )];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("key did not resolve the widget"));
    assert!(context.contains("ArrowDown"));
    assert!(context.contains("browser__inspect"));
}

#[test]
fn pending_browser_state_context_highlights_navigation_key_commit() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"ArrowDown","modifiers":[],"is_chord":false,"value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"Poland"}}}"##,
        1,
    )];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("active autocomplete candidate"));
    assert!(context.contains("press `Enter` to commit"));
    assert!(context.contains("browser__inspect"));
}

#[test]
fn success_signal_context_ignores_autocomplete_follow_up() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","controls_dom_id":"ui-id-1","active_descendant_dom_id":"ui-id-2","assistive_hint":"1 result is available, use up and down arrow keys to navigate. Poland"}}}"##,
        1,
    )];

    let context = build_recent_success_signal_context(&history);
    assert!(context.is_empty());
}

#[test]
fn success_signal_context_highlights_committed_autocomplete_and_submit_follow_up() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#flight-to","text":"Augusta, GA","value":"Augusta, GA","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            1,
        ),
        chat_message(
            "tool",
            "Clicked element 'grp_augusta_ga_ags' via geometry fallback. verify={\"postcondition\":{\"met\":true,\"tree_changed\":true}}",
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_from\" name=\"From:\" value=\"Kiana, AK (IAN)\" dom_id=\"flight-from\" selector=\"[id=&quot;flight-from&quot;]\" tag_name=\"input\" rect=\"4,81,126,21\" />",
        "<textbox id=\"inp_to\" name=\"To:\" value=\"Augusta, GA (AGS)\" focused=\"true\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" tag_name=\"input\" rect=\"4,106,126,21\" />",
        "<textbox id=\"inp_10_divide_07_divide_2016\" name=\"10/07/2016\" value=\"10/07/2016\" dom_id=\"datepicker\" selector=\"[id=&quot;datepicker&quot;]\" tag_name=\"input\" rect=\"12,161,106,16\" />",
        "<button id=\"btn_search\" name=\"Search\" dom_id=\"search\" selector=\"[id=&quot;search&quot;]\" tag_name=\"button\" dom_clickable=\"true\" rect=\"4,184,126,19\" />",
        "</root>",
    );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
    assert!(
        context.contains("autocomplete selection already succeeded"),
        "{context}"
    );
    assert!(
        context.contains("`inp_to` is now `Augusta, GA (AGS)`"),
        "{context}"
    );
    assert!(context.contains("`btn_search`"), "{context}");

    let submit_index = context.find("`btn_search`").unwrap();
    let from_index = context.find("`inp_from`").unwrap();
    assert!(submit_index < from_index, "{context}");
}

#[test]
fn pending_browser_state_context_uses_snapshot_to_commit_single_autocomplete_result() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
        1,
    )];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_tags\" name=\"Tags:\" value=\"Poland\" focused=\"true\" dom_id=\"tags\" selector=\"[id=&quot;tags&quot;]\" tag_name=\"input\" rect=\"10,71,128,21\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"10,97,95,31\" />",
            "<status id=\"status_poland\" name=\"1 result is available, use up and down arrow keys to navigate. Poland\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("Autocomplete is still open on `inp_tags`"));
    assert!(context.contains("`Poland`"));
    assert!(context.contains("`ArrowDown`"));
    assert!(context.contains("`Enter`"));
    assert!(context.contains("The suggestion is not committed yet"));
}

#[test]
fn pending_browser_state_context_treats_submit_on_open_autocomplete_as_incomplete() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_submit' via geometry fallback. verify={"focused_control":{"semantic_id":"inp_tags","dom_id":"tags","focused":true},"postcondition":{"met":true,"tree_changed":true}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_tags\" name=\"Tags:\" value=\"Poland\" focused=\"true\" dom_id=\"tags\" selector=\"[id=&quot;tags&quot;]\" tag_name=\"input\" rect=\"10,71,128,21\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"10,97,95,31\" />",
            "<status id=\"status_poland\" name=\"1 result is available, use up and down arrow keys to navigate. Poland\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("A recent `btn_submit` click left autocomplete unresolved"));
    assert!(context.contains("does not finish the task"));
    assert!(context.contains("`ArrowDown`"));
    assert!(context.contains("`Enter`"));

    let success = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(success.is_empty(), "{success}");
}

#[test]
fn pending_browser_state_context_treats_unresolved_enter_as_navigation_then_commit() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#tags","text":"Poland","value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            1,
        ),
        chat_message(
            "tool",
            r##"{"key":{"key":"Enter","modifiers":[],"is_chord":false,"value":"Poland","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_tags\" name=\"Tags:\" value=\"Poland\" focused=\"true\" dom_id=\"tags\" selector=\"[id=&quot;tags&quot;]\" tag_name=\"input\" rect=\"10,71,128,21\" />",
            "<status id=\"status_poland\" name=\"1 result is available, use up and down arrow keys to navigate. Poland\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
            "</root>",
        );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("A recent `Enter` key left autocomplete unresolved"));
    assert!(context.contains("`ArrowDown`"));
    assert!(context.contains("`Enter`"));
}

#[test]
fn pending_browser_state_context_prefers_click_for_visible_single_autocomplete_suggestion() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#flight-to","text":"ISN","value":"ISN","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_to\" name=\"To:\" value=\"ISN\" focused=\"true\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" autocomplete=\"list\" tag_name=\"input\" rect=\"4,106,126,21\" />",
        "<generic id=\"grp_williston_nd_isn\" name=\"Williston, ND (ISN)\" dom_id=\"ui-id-4\" selector=\"[id=&quot;ui-id-4&quot;]\" class_name=\"ui-menu-item-wrapper\" dom_clickable=\"true\" rect=\"5,128,126,17\" />",
        "<status id=\"status_isn\" name=\"1 result is available, use up and down arrow keys to navigate. Williston, ND (ISN)\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("`grp_williston_nd_isn`"));
    assert!(context.contains("browser__click"));
    assert!(context.contains("commit it in one step"));
    assert!(!context.contains("`ArrowDown` now"));
}

#[test]
fn extract_browser_xml_attr_does_not_match_suffix_attr_names() {
    let fragment = r##"generic id="grp_augusta_ga_ags_leaf" selector="#ui-id-2 > li" class_name="ui-menu-item" dom_clickable="true" /"##;

    assert_eq!(
        extract_browser_xml_attr(fragment, "name"),
        None,
        "{fragment}"
    );
    assert_eq!(
        extract_browser_xml_attr(fragment, "class_name").as_deref(),
        Some("ui-menu-item")
    );
}

#[test]
fn pending_browser_state_context_prefers_click_for_omitted_autocomplete_suggestion() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#flight-to","text":"ISN","value":"ISN","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_to\" name=\"To:\" value=\"ISN\" focused=\"true\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" autocomplete=\"list\" tag_name=\"input\" rect=\"4,106,126,21\" />",
        "<generic id=\"grp_williston_nd_isn\" name=\"Williston, ND (ISN)\" dom_id=\"ui-id-4\" selector=\"[id=&quot;ui-id-4&quot;]\" class_name=\"ui-menu-item-wrapper ui-menu-item\" dom_clickable=\"true\" omitted=\"true\" rect=\"5,128,126,17\" />",
        "<status id=\"status_isn\" name=\"1 result is available, use up and down arrow keys to navigate. Williston, ND (ISN)\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("`grp_williston_nd_isn`"));
    assert!(context.contains("browser__click"));
    assert!(context.contains("commit it in one step"));
    assert!(!context.contains("`ArrowDown` now"));
}

#[test]
fn pending_browser_state_context_prefers_popup_leaf_over_named_autocomplete_container() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#flight-to","text":"Augusta, GA","value":"Augusta, GA","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_to\" name=\"To:\" value=\"Augusta, GA\" focused=\"true\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" controls_dom_id=\"ui-id-2\" autocomplete=\"list\" tag_name=\"input\" rect=\"4,106,126,21\" />",
        "<generic id=\"grp_augusta_ga_ags\" name=\"Augusta, GA (AGS)\" dom_id=\"ui-id-2\" selector=\"[id=&quot;ui-id-2&quot;]\" class_name=\"ui-menu ui-widget ui-widget-content ui-autocomplete ui-front\" dom_clickable=\"true\" rect=\"4,127,128,19\" />",
        "<generic id=\"grp_augusta_ga_ags_leaf\" selector=\"#ui-id-2 > li\" class_name=\"ui-menu-item\" dom_clickable=\"true\" rect=\"5,128,126,17\" />",
        "<status id=\"status_augusta\" name=\"1 result is available, use up and down arrow keys to navigate. Augusta, GA (AGS)\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("`grp_augusta_ga_ags_leaf`"), "{context}");
    assert!(!context.contains("`grp_augusta_ga_ags` now"), "{context}");
    assert!(context.contains("browser__click"), "{context}");
    assert!(context.contains("commit it in one step"), "{context}");
}

#[test]
fn pending_browser_state_context_clears_committed_autocomplete_with_hidden_live_region() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#flight-from","text":"Dothan, AL","value":"Dothan, AL","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            1,
        ),
        chat_message(
            "tool",
            "Clicked element 'grp_dothan_al_dhn' via geometry fallback.",
            2,
        ),
        chat_message(
            "tool",
            r##"{"key":{"key":"Enter","modifiers":[],"is_chord":false,"value":"Dothan, AL (DHN)","focused":true,"autocomplete":{"mode":"list","assistive_hint":"Dothan, AL (DHN)"}}}"##,
            3,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_from\" name=\"From:\" value=\"Dothan, AL (DHN)\" focused=\"true\" dom_id=\"flight-from\" selector=\"[id=&quot;flight-from&quot;]\" autocomplete=\"list\" controls_dom_id=\"ui-id-1\" tag_name=\"input\" rect=\"4,81,126,21\" />",
        "<textbox id=\"inp_to\" name=\"To:\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" rect=\"4,106,126,21\" />",
        "<button id=\"btn_search\" name=\"Search\" dom_id=\"search\" selector=\"[id=&quot;search&quot;]\" dom_clickable=\"true\" rect=\"4,194,126,21\" />",
        "<generic id=\"grp_dothan_hidden\" name=\"Dothan, AL (DHN)\" dom_id=\"ui-id-6\" selector=\"#ui-id-1 > li\" class_name=\"ui-menu-item-wrapper\" visible=\"false\" dom_clickable=\"true\" rect=\"5,128,126,17\" />",
        "<status id=\"status_dothan\" name=\"1 result is available, use up and down arrow keys to navigate. Dothan, AL (DHN)\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.is_empty(), "{context}");
}

#[test]
fn browser_snapshot_pending_state_context_prioritizes_invalid_field_over_lingering_autocomplete() {
    let history = vec![
        chat_message(
            "user",
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Book the shortest one-way flight from: Dothan, AL to: ISN on 10/15/2016.",
            1,
        ),
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#flight-to","text":"ISN","value":"ISN","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'grp_williston_nd_isn_9d1c2c' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true}}"#,
            3,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_search' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true}}"#,
            4,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_from\" name=\"From:\" value=\"Dothan, AL (DHN)\" dom_id=\"flight-from\" selector=\"[id=&quot;flight-from&quot;]\" tag_name=\"input\" rect=\"4,82,126,21\" />",
        "<textbox id=\"inp_to\" name=\"To:\" value=\"Williston, ND (ISN)\" focused=\"true\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" class_name=\"flight-input ui-autocomplete-input\" tag_name=\"input\" rect=\"4,107,126,21\" />",
        "<textbox id=\"inp_datepicker_flight_input\" name=\"datepicker flight input\" class_name=\"flight-input hasDatepicker error\" dom_id=\"datepicker\" selector=\"[id=&quot;datepicker&quot;]\" tag_name=\"input\" rect=\"12,162,106,16\" />",
        "<button id=\"btn_search\" name=\"Search\" dom_id=\"search\" selector=\"[id=&quot;search&quot;]\" dom_clickable=\"true\" rect=\"4,185,126,19\" />",
        "<generic id=\"grp_williston_nd_isn_9d1c2c\" name=\"Williston, ND (ISN)\" selector=\"#ui-id-2 > li\" class_name=\"ui-menu-item\" dom_clickable=\"true\" omitted=\"true\" rect=\"5,128,126,17\" />",
        "<status id=\"status_isn\" name=\"1 result is available, use up and down arrow keys to navigate. Williston, ND (ISN)\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("`inp_datepicker_flight_input`"),
        "{context}"
    );
    assert!(
        context.contains("Do not click `btn_search` again yet"),
        "{context}"
    );
    assert!(
        !context.contains("`grp_williston_nd_isn_9d1c2c`"),
        "{context}"
    );
}

#[test]
fn browser_snapshot_pending_state_context_advances_past_committed_autocomplete_popup() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#flight-to","text":"ISN","value":"ISN","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'grp_williston_nd_isn_9d1c2c' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_from\" name=\"From:\" value=\"Dothan, AL (DHN)\" dom_id=\"flight-from\" selector=\"[id=&quot;flight-from&quot;]\" tag_name=\"input\" rect=\"4,82,126,21\" />",
        "<textbox id=\"inp_to\" name=\"To:\" value=\"Williston, ND (ISN)\" focused=\"true\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" class_name=\"flight-input ui-autocomplete-input\" tag_name=\"input\" rect=\"4,107,126,21\" />",
        "<textbox id=\"inp_datepicker_flight_input\" name=\"datepicker flight input\" dom_id=\"datepicker\" selector=\"[id=&quot;datepicker&quot;]\" class_name=\"flight-input hasDatepicker\" tag_name=\"input\" rect=\"12,162,106,16\" />",
        "<button id=\"btn_search\" name=\"Search\" dom_id=\"search\" selector=\"[id=&quot;search&quot;]\" dom_clickable=\"true\" rect=\"4,185,126,19\" />",
        "<generic id=\"grp_williston_nd_isn_9d1c2c\" name=\"Williston, ND (ISN)\" selector=\"#ui-id-2 > li\" class_name=\"ui-menu-item\" dom_clickable=\"true\" omitted=\"true\" rect=\"5,128,126,17\" />",
        "<status id=\"status_isn\" name=\"1 result is available, use up and down arrow keys to navigate. Williston, ND (ISN)\" visible=\"false\" assistive_hint=\"true\" assistive_reason=\"assistive_live_region\" />",
        "</root>",
    );

    let pending_context =
        build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(pending_context.is_empty(), "{pending_context}");

    let success_context =
        build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(
        success_context.contains("autocomplete selection already succeeded"),
        "{success_context}"
    );
    assert!(
        success_context.contains(
            "Continue with the next required visible control such as `inp_datepicker_flight_input`"
        ),
        "{success_context}"
    );
    assert!(
        !success_context.contains("commit it in one step"),
        "{success_context}"
    );
}

#[test]
fn pending_state_context_reframes_submit_after_committed_autocomplete_popup() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#flight-to","text":"ISN","value":"ISN","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate."}}}"##,
            1,
        ),
        chat_message(
            "tool",
            r##"{"key":{"key":"ArrowDown","selector":"#flight-to","dom_id":"flight-to","focused":true,"autocomplete":{"mode":"list","assistive_hint":"1 result is available, use up and down arrow keys to navigate.","active_descendant_dom_id":"ui-id-4"}}}"##,
            2,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'grp_williston_nd_isn_9d1c2c' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true}}"#,
            3,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'btn_search' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true}}"#,
            4,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_from\" name=\"From:\" value=\"Dothan, AL (DHN)\" dom_id=\"flight-from\" selector=\"[id=&quot;flight-from&quot;]\" tag_name=\"input\" rect=\"4,82,126,21\" />",
        "<textbox id=\"inp_to\" name=\"To:\" value=\"Williston, ND (ISN)\" focused=\"true\" dom_id=\"flight-to\" selector=\"[id=&quot;flight-to&quot;]\" class_name=\"flight-input ui-autocomplete-input\" tag_name=\"input\" rect=\"4,107,126,21\" />",
        "<textbox id=\"inp_datepicker_flight_input\" name=\"datepicker flight input\" dom_id=\"datepicker\" selector=\"[id=&quot;datepicker&quot;]\" class_name=\"flight-input hasDatepicker\" tag_name=\"input\" rect=\"12,162,106,16\" />",
        "<button id=\"btn_search\" name=\"Search\" dom_id=\"search\" selector=\"[id=&quot;search&quot;]\" tag_name=\"button\" dom_clickable=\"true\" rect=\"4,185,126,19\" />",
        "<generic id=\"grp_williston_nd_isn\" name=\"Williston, ND (ISN)\" dom_id=\"ui-id-2\" selector=\"[id=&quot;ui-id-2&quot;]\" class_name=\"ui-menu ui-widget ui-widget-content ui-autocomplete ui-front\" dom_clickable=\"true\" omitted=\"true\" rect=\"5,128,126,18\" />",
        "<generic id=\"grp_williston_nd_isn_9d1c2c\" name=\"Williston, ND (ISN)\" class_name=\"ui-menu-item\" dom_clickable=\"true\" omitted=\"true\" rect=\"5,128,126,18\" />",
        "</root>",
    );

    let pending_context =
        build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        pending_context.contains("autocomplete selection already looks committed"),
        "{pending_context}"
    );
    assert!(
        pending_context.contains("`inp_datepicker_flight_input`"),
        "{pending_context}"
    );
    assert!(
        !pending_context.contains("commit it in one step"),
        "{pending_context}"
    );
}

#[test]
fn pending_browser_state_context_prioritizes_shortest_visible_result_action_over_goal_text() {
    let history = vec![
        chat_message(
            "user",
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Book the shortest one-way flight from: Kiana, AK to: Augusta, GA on 10/07/2016.",
            1,
        ),
        chat_message(
            "tool",
            "Clicked element 'btn_search' via geometry fallback. verify={\"postcondition\":{\"met\":true}}",
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_augusta_ga\" name=\"Augusta, GA\" class_name=\"bold\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_1029\" name=\"Book flight for $1029\" context=\"Duration: 9h 48m\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_183\" name=\"Book flight for $183\" context=\"Duration: 4h 47m\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_137\" name=\"Book flight for $137\" context=\"Duration: 14h 42m\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_944\" name=\"Book flight for $944\" context=\"Duration: 3h 56m\" dom_clickable=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("`btn_book_flight_for_944`"), "{context}");
    assert!(context.contains("shortest"), "{context}");
    assert!(
        !context.contains("Use `browser__click` on `grp_augusta_ga`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_prioritizes_shortest_omitted_result_action_over_goal_text() {
    let history = vec![
        chat_message(
            "user",
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Book the shortest one-way flight from: Kiana, AK to: Augusta, GA on 10/07/2016.",
            1,
        ),
        chat_message(
            "tool",
            "Clicked element 'btn_search' via geometry fallback. verify={\"postcondition\":{\"met\":true}}",
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_augusta_ga\" name=\"Augusta, GA\" class_name=\"bold\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_1029\" name=\"Book flight for $1029\" context=\"Duration: 9h 48m\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_183\" name=\"Book flight for $183\" context=\"Duration: 4h 47m\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_137\" name=\"Book flight for $137\" context=\"Duration: 14h 42m\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_944\" name=\"Book flight for $944\" context=\"Duration: 3h 56m\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("`btn_book_flight_for_944`"), "{context}");
    assert!(context.contains("shortest"), "{context}");
    assert!(
        !context.contains("Use `browser__click` on `grp_augusta_ga`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_recovers_shortest_result_action_from_row_text() {
    let history = vec![
        chat_message(
            "user",
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Book the shortest one-way flight from: Kiana, AK to: Augusta, GA on 10/07/2016.",
            1,
        ),
        chat_message(
            "tool",
            "Clicked element 'btn_search' via geometry fallback. verify={\"postcondition\":{\"met\":true}}",
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_augusta_ga\" name=\"Augusta, GA\" class_name=\"bold\" rect=\"0,0,1,1\" />",
        "<generic id=\"grp_result_1029\" name=\"Depart: 8:48 PM Fri Oct 07 2016 Kiana, AK (IAN) Arrives: 6:36 AM Sat Oct 08 2016 Augusta, GA Duration: 9h 48m\" selector=\"#results > div:nth-of-type(2) > div:nth-of-type(1)\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_1029\" name=\"Book flight for $1029\" selector=\"#results > div:nth-of-type(2) > div:nth-of-type(4) > button\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "<generic id=\"grp_result_137\" name=\"Depart: 7:09 AM Fri Oct 07 2016 Kiana, AK (IAN) Arrives: 9:52 PM Fri Oct 07 2016 Augusta, GA Duration: 14h 42m\" selector=\"#results > div:nth-of-type(4) > div:nth-of-type(1)\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_137\" name=\"Book flight for $137\" selector=\"#results > div:nth-of-type(4) > div:nth-of-type(4) > button\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "<generic id=\"grp_result_944\" name=\"Depart: 1:13 AM Fri Oct 07 2016 Kiana, AK (IAN) Arrives: 5:09 AM Fri Oct 07 2016 Augusta, GA Duration: 3h 56m\" selector=\"#results > div:nth-of-type(5) > div:nth-of-type(1)\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_944\" name=\"Book flight for $944\" selector=\"#results > div:nth-of-type(5) > div:nth-of-type(4) > button\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("`btn_book_flight_for_944`"), "{context}");
    assert!(context.contains("shortest"), "{context}");
    assert!(
        !context.contains("Use `browser__click` on `grp_augusta_ga`"),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_recovers_shortest_result_action_from_neighbor_text() {
    let history = vec![
        chat_message(
            "user",
            "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Book the shortest one-way flight from: Kiana, AK to: Augusta, GA on 10/07/2016.",
            1,
        ),
        chat_message(
            "tool",
            "Clicked element 'btn_search' via geometry fallback. verify={\"postcondition\":{\"met\":true}}",
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_augusta_ga\" name=\"Augusta, GA\" class_name=\"bold\" rect=\"0,0,1,1\" />",
        "<generic id=\"grp_result_137\" name=\"Depart: 7:09 AM Fri Oct 07 2016 Kiana, AK (IAN) Arrives: 9:52 PM Fri Oct 07 2016 Augusta, GA Duration: 14h 42m\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_137\" name=\"Book flight for $137\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "<generic id=\"grp_result_944\" name=\"Depart: 1:13 AM Fri Oct 07 2016 Kiana, AK (IAN) Arrives: 5:09 AM Fri Oct 07 2016 Augusta, GA Duration: 3h 56m\" rect=\"0,0,1,1\" />",
        "<button id=\"btn_book_flight_for_944\" name=\"Book flight for $944\" dom_clickable=\"true\" omitted=\"true\" rect=\"0,0,1,1\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("`btn_book_flight_for_944`"), "{context}");
    assert!(context.contains("shortest"), "{context}");
    assert!(
        !context.contains("Use `browser__click` on `grp_augusta_ga`"),
        "{context}"
    );
}

#[test]
fn success_signal_context_highlights_already_satisfied_typed_field() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#queue-search","text":"fiber","value":"fiber","focused":true,"already_satisfied":true}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_queue_search\" name=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" tag_name=\"input\" value=\"fiber\" focused=\"true\" rect=\"4,82,126,21\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("already contained the requested text"));
    assert!(context.contains("Do not type the same text"));
    assert!(context.contains("`btn_submit`"), "{context}");
}

#[test]
fn success_signal_context_highlights_synthetic_click_state_change_follow_up() {
    let history = vec![chat_message(
        "tool",
        r#"{"synthetic_click":{"x":60,"y":107},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_svg_grid_object\" name=\"svg grid object\" dom_id=\"svg-grid\" selector=\"[id=&quot;svg-grid&quot;]\" tag_name=\"svg\" rect=\"2,52,150,130\" />",
        "<generic id=\"grp_small_blue_circle\" name=\"small blue circle at 62,109\" dom_id=\"blue-circle\" selector=\"[id=&quot;blue-circle&quot;]\" tag_name=\"circle\" shape_kind=\"circle\" center_x=\"62\" center_y=\"109\" rect=\"59,106,7,7\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
    assert!(
        context.contains("A recent browser synthetic click already caused observable state change"),
        "{context}"
    );
    assert!(
        context.contains("Do not repeat the same coordinate blindly"),
        "{context}"
    );
    assert!(
        context.contains("Visible controls now include `btn_submit`"),
        "{context}"
    );
}

#[test]
fn success_signal_context_prioritizes_submit_after_duplicate_typed_action() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#tt","text":"myron","value":"myron","focused":true,"already_satisfied":null}}"##,
            1,
        ),
        chat_message(
            "tool",
            "Skipped immediate replay of 'browser__type' because the identical action already succeeded on the previous step. Do not repeat it.",
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_tt\" name=\"myron\" dom_id=\"tt\" selector=\"[id=&quot;tt&quot;]\" tag_name=\"input\" value=\"myron\" focused=\"true\" rect=\"4,82,126,21\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
    assert!(
        context.contains("identical action already succeeded"),
        "{context}"
    );
    assert!(
        context.contains("Use visible control `btn_submit` next."),
        "{context}"
    );
    assert!(
        context.contains("Do not spend the next step on another `browser__inspect`"),
        "{context}"
    );
}

#[test]
fn success_signal_context_uses_semantic_textbox_name_when_password_value_is_hidden() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#verify","text":"P322","value":"P322","focused":true,"already_satisfied":true,"dom_id":"verify"}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_p322\" name=\"P322\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" tag_name=\"input\" rect=\"4,82,126,21\" />",
        "<textbox id=\"inp_p322_1ef3fa\" name=\"P322\" dom_id=\"verify\" selector=\"[id=&quot;verify&quot;]\" tag_name=\"input\" focused=\"true\" rect=\"4,107,126,21\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
    assert!(
        context.contains("already contained the requested text"),
        "{context}"
    );
    assert!(
        context.contains("Use visible control `btn_submit` next."),
        "{context}"
    );
}

#[test]
fn pending_browser_state_context_highlights_no_effect_scroll() {
    let history = vec![chat_message(
        "tool",
        r##"{"scroll":{"delta_x":0,"delta_y":-1000,"anchor":"viewport_center","anchor_x":400.0,"anchor_y":300.0,"page_before":{"x":0.0,"y":0.0},"page_after":{"x":0.0,"y":0.0},"page_moved":false,"target_before":{"selector":"#text-area","dom_id":"text-area","tag_name":"textarea","focused":false,"scroll_top":120.0,"scroll_height":510.0,"client_height":104.0,"can_scroll_up":true,"can_scroll_down":true},"target_after":{"selector":"#text-area","dom_id":"text-area","tag_name":"textarea","focused":false,"scroll_top":120.0,"scroll_height":510.0,"client_height":104.0,"can_scroll_up":true,"can_scroll_down":true},"target_moved":false}}"##,
        1,
    )];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("no grounded effect"));
    assert!(context.contains("browser__inspect"));
    assert!(context.contains("browser__press_key"));
}

#[test]
fn pending_browser_state_context_highlights_incomplete_auth_form() {
    let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__inspect): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"Username\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"Password\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
                2,
            ),
        ];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("password credential field"));
    assert!(context.contains("Do not click `Sign in`"));
}

#[test]
fn pending_browser_state_context_highlights_ready_auth_submit() {
    let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__inspect): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"dispatch-215\" value=\"dispatch-215\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#password","text":"dispatch-215","dom_id":"password","value":"dispatch-215","focused":true}}"##,
                3,
            ),
        ];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("both credential fields were filled"));
    assert!(context.contains("Use the login action now"));
    assert!(context.contains("browser__click"));
}

#[test]
fn snapshot_pending_context_highlights_incomplete_auth_without_history_snapshot() {
    let history = vec![chat_message(
        "tool",
        r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
        1,
    )];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_dispatch_dot_agent\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_password\" name=\"Password\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("password credential field"));
    assert!(context.contains("Do not click `Sign in`"));
}

#[test]
fn snapshot_pending_context_highlights_ready_auth_submit_without_history_snapshot() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
            1,
        ),
        chat_message(
            "tool",
            r##"{"typed":{"selector":"#password","text":"dispatch-215","dom_id":"password","value":"dispatch-215","focused":true}}"##,
            2,
        ),
    ];
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<textbox id=\"inp_dispatch_dot_agent\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_dispatch_215\" name=\"dispatch-215\" value=\"dispatch-215\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("both credential fields were filled"));
    assert!(context.contains("Use the login action now"));
    assert!(context.contains("browser__click"));
}

#[test]
fn success_signal_context_suppresses_stale_click_guidance_while_auth_pending() {
    let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__inspect): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"dispatch-215\" value=\"dispatch-215\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#username","text":"dispatch.agent","dom_id":"username","value":"dispatch.agent","focused":true}}"##,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#password","text":"dispatch-215","dom_id":"password","value":"dispatch-215","focused":true}}"##,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_sign_in' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                4,
            ),
        ];

    let context = build_recent_success_signal_context(&history);
    assert!(context.is_empty());
}

#[test]
fn pending_browser_state_context_highlights_page_level_key_target() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":null,"dom_id":null,"tag_name":"body","value":"Scroll the textarea to the top of the text hit submit.","focused":true,"scroll_top":null,"scroll_height":null,"client_height":null,"can_scroll_up":null,"can_scroll_down":null,"autocomplete":null}}"##,
        1,
    )];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("page itself"));
    assert!(context.contains("focus that control first"));
    assert!(context.contains("browser__click"));
    assert!(context.contains("otherwise continue with the next required visible control"));
}

#[test]
fn pending_browser_state_context_highlights_focused_scroll_control_after_click() {
    let history = vec![chat_message(
        "tool",
        r#"Clicked element 'grp_scroll_the_textarea_to_the_top' via geometry fallback. verify={"post_target":{"dom_id":"wrap","focused":false},"focused_control":{"dom_id":"text-area","selector":"[id=\"text-area\"]","tag_name":"textarea","focused":true,"scroll_top":257,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true},"postcondition":{"met":true,"tree_changed":true}}"#,
        1,
    )];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("already focused a scrollable control"));
    assert!(context.contains("Do not keep clicking"));
    assert!(context.contains("text selection"));
    assert!(context.contains("browser__select"));
}

#[test]
fn pending_browser_state_context_highlights_no_effect_home_on_focused_scroll_control() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":257,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("Do not use `Home` again"));
    assert!(context.contains("scroll_top=257"));
    assert!(context.contains("spend the next step on `PageUp`"));
    assert!(context.contains("can_scroll_up=true"));
    assert!(context.contains("can_scroll_up=false"));
    assert!(context.contains("scroll_top=0"));
    assert!(context.contains(&top_edge_jump_call_for_selector(
        Some("[id=\"text-area\"]",)
    )));
}

#[test]
fn pending_browser_state_context_keeps_page_up_option_when_home_is_near_top() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":24,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("Use `PageUp` or"));
    assert!(!context.contains("Do not spend the next step on `PageUp`"));
    assert!(context.contains(&top_edge_jump_call_for_selector(
        Some("[id=\"text-area\"]",)
    )));
}

#[test]
fn pending_browser_state_context_escalates_repeated_page_up_to_control_home() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"key":{"key":"PageUp","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":112,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
            1,
        ),
        chat_message(
            "tool",
            r##"{"key":{"key":"PageUp","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":24,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
            2,
        ),
    ];

    let context = build_recent_pending_browser_state_context(&history);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("Repeated `PageUp`"));
    assert!(context.contains(&top_edge_jump_call_for_selector(
        Some("[id=\"text-area\"]",)
    )));
    assert!(context.contains("Stop repeating `PageUp`"));
    assert!(context.contains("scroll_top=0"));
}

#[test]
fn snapshot_pending_signal_chains_top_edge_jump_to_unique_follow_up_when_near_top() {
    let history = vec![
        chat_message(
            "tool",
            r##"{"key":{"key":"PageUp","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":112,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
            1,
        ),
        chat_message(
            "tool",
            r##"{"key":{"key":"PageUp","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":24,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"24\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("scroll_top=24"), "{context}");
    assert!(context.contains("btn_submit"), "{context}");
    assert!(context.contains("browser__press_key {"), "{context}");
    assert!(context.contains("\"key\":\"Home\""), "{context}");
    assert!(
        context.contains("\"selector\":\"[id=\\\"text-area\\\"]\""),
        "{context}"
    );
    assert!(context.contains("\"continue_with\":{"), "{context}");
    assert!(context.contains("\"id\":\"btn_submit\""), "{context}");
}

#[test]
fn snapshot_pending_signal_chains_page_up_then_top_edge_jump_when_one_page_window_remains() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":["Control"],"is_chord":true,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":166,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"166\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("scroll_top=166"), "{context}");
    assert!(context.contains("browser__press_key {"), "{context}");
    assert!(context.contains("\"key\":\"PageUp\""), "{context}");
    assert!(
        context.contains("\"name\":\"browser__press_key\""),
        "{context}"
    );
    assert!(context.contains("\"key\":\"Home\""), "{context}");
    assert!(context.contains("\"modifiers\":[\"Control\"]"), "{context}");
    assert!(context.contains("\"id\":\"btn_submit\""), "{context}");
}

#[test]
fn observation_context_highlights_page_up_then_top_edge_jump_chain_near_finish_window() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":["Control"],"is_chord":true,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":166,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"166\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_browser_observation_context_from_snapshot_with_history(snapshot, &history);
    assert!(context.contains("ASSISTIVE BROWSER HINTS:"), "{context}");
    assert!(context.contains("scroll_top=166"), "{context}");
    assert!(context.contains("browser__press_key {"), "{context}");
    assert!(context.contains("\"key\":\"PageUp\""), "{context}");
    assert!(
        context.contains("\"name\":\"browser__press_key\""),
        "{context}"
    );
    assert!(context.contains("\"id\":\"btn_submit\""), "{context}");
}

#[test]
fn snapshot_pending_signal_chains_page_up_then_top_edge_jump_when_scroll_target_is_focused() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":["Control"],"is_chord":true,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":166,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" focused=\"true\" scroll_top=\"166\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("\"key\":\"PageUp\""), "{context}");
    assert!(
        context.contains("\"name\":\"browser__press_key\""),
        "{context}"
    );
    assert!(context.contains("\"key\":\"Home\""), "{context}");
    assert!(context.contains("\"id\":\"btn_submit\""), "{context}");
}

#[test]
fn snapshot_pending_signal_uses_page_up_after_top_edge_jump_leaves_multiple_pages() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":["Control"],"is_chord":true,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":257,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" focused=\"true\" scroll_top=\"257\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("scroll_top=257"), "{context}");
    assert!(context.contains("\"key\":\"PageUp\""), "{context}");
    assert!(
        context.contains("\"selector\":\"[id=\\\"text-area\\\"]\""),
        "{context}"
    );
    assert!(
        !context.contains("\"modifiers\":[\"Control\"]"),
        "{context}"
    );
}

#[test]
fn observation_context_uses_page_up_after_top_edge_jump_leaves_multiple_pages() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":["Control"],"is_chord":true,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":257,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" focused=\"true\" scroll_top=\"257\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_browser_observation_context_from_snapshot_with_history(snapshot, &history);
    assert!(context.contains("ASSISTIVE BROWSER HINTS:"), "{context}");
    assert!(context.contains("scroll_top=257"), "{context}");
    assert!(context.contains("\"key\":\"PageUp\""), "{context}");
    assert!(
        context.contains("\"selector\":\"[id=\\\"text-area\\\"]\""),
        "{context}"
    );
    assert!(
        !context.contains("\"modifiers\":[\"Control\"]"),
        "{context}"
    );
}

#[test]
fn snapshot_pending_signal_chains_top_edge_submit_when_canvas_wrapper_is_present() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"PageUp","modifiers":[],"is_chord":false,"selector":"[id=\"text-area\"]","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":75,"scroll_height":565,"client_height":104,"can_scroll_up":true,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Scroll the textarea to the top of the text hit submit.\" />",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" focused=\"true\" scroll_top=\"75\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
        "<generic id=\"grp_click_canvas\" name=\"click canvas\" dom_id=\"click-canvas\" selector=\"[id=&quot;click-canvas&quot;]\" dom_clickable=\"true\" rect=\"0,0,160,210\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("\"name\":\"browser__click\""), "{context}");
    assert!(context.contains("\"id\":\"btn_submit\""), "{context}");
    assert!(!context.contains("grp_click_canvas"), "{context}");
}

#[test]
fn success_signal_context_highlights_scroll_edge_key_completion() {
    let history = vec![chat_message(
        "tool",
        r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":"#text-area","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":0,"scroll_height":510,"client_height":104,"can_scroll_up":false,"can_scroll_down":true,"autocomplete":null}}"##,
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"0\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"false\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" rect=\"30,178,95,31\" />",
        "</root>",
    );

    let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("top edge"));
    assert!(context.contains("Do not repeat the same key"));
    assert!(context.contains("`btn_submit`"), "{context}");
}

#[test]
fn snapshot_success_signal_highlights_already_satisfied_negative_selection_state() {
    let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><generic id="grp_query" name="Select nothing and click Submit." /><checkbox id="checkbox_r8" name="r8" /><checkbox id="checkbox_bptkv" name="BpTkv" /><button id="btn_submit" name="Submit" /></root>"#;

    let context = build_browser_snapshot_success_signal_context(snapshot);
    assert!(context.contains("RECENT SUCCESS SIGNAL:"));
    assert!(context.contains("requires no selections"));
    assert!(context.contains("Do not click any checkbox"));
    assert!(context.contains("Submit"));
}

#[test]
fn snapshot_pending_signal_highlights_negative_selection_violation() {
    let snapshot = r#"<root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><generic id="grp_query" name="Select nothing and click Submit." /><checkbox id="checkbox_r8" name="r8" checked="true" /><checkbox id="checkbox_bptkv" name="BpTkv" /><button id="btn_submit" name="Submit" /></root>"#;

    let context = build_browser_snapshot_pending_state_context(snapshot);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("requires no selections"));
    assert!(context.contains("Do not submit yet"));
    assert!(context.contains("unchecked or unselected"));
}

#[test]
fn snapshot_pending_signal_highlights_remaining_requested_selectables() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Select NYt2, Pj6KGY, NIQkfGd and click Submit.\" />",
        "<checkbox id=\"checkbox_nyt2\" name=\"NYt2\" checked=\"true\" />",
        "<checkbox id=\"checkbox_pj6kgy\" name=\"Pj6KGY\" />",
        "<checkbox id=\"checkbox_niqkfgd\" name=\"NIQkfGd\" />",
        "<button id=\"btn_submit\" name=\"Submit\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context(snapshot);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("Requested selectable targets still missing"));
    assert!(context.contains("`checkbox_pj6kgy` (`Pj6KGY`)"));
    assert!(context.contains("`checkbox_niqkfgd` (`NIQkfGd`)"));
    assert!(context
        .contains("Use `browser__click` with `ids` [`checkbox_pj6kgy`, `checkbox_niqkfgd`] now"));
}

#[test]
fn snapshot_pending_signal_highlights_submit_after_requested_selectables_are_done() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Select NYt2 and click Submit.\" />",
        "<checkbox id=\"checkbox_nyt2\" name=\"NYt2\" checked=\"true\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_clickable=\"true\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context(snapshot);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("All requested selectable targets already appear checked or selected"));
    assert!(context.contains("`btn_submit`"));
}

#[test]
fn snapshot_pending_signal_allows_omitted_requested_selectables() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Select NYt2, KX7 and click Submit.\" />",
        "<checkbox id=\"checkbox_nyt2\" name=\"NYt2\" checked=\"true\" dom_id=\"ch1\" selector=\"[id=&quot;ch1&quot;]\" dom_clickable=\"true\" />",
        "<checkbox id=\"checkbox_kx7\" name=\"KX7\" dom_id=\"ch11\" selector=\"[id=&quot;ch11&quot;]\" dom_clickable=\"true\" omitted=\"true\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" omitted=\"true\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context(snapshot);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("Requested selectable target still missing"));
    assert!(context.contains("`checkbox_kx7` (`KX7`)"));
    assert!(context.contains("Do not re-click already selected controls or `Submit` yet"));
}

#[test]
fn snapshot_pending_signal_allows_omitted_submit_after_requested_selectables_are_done() {
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Select NYt2 and click Submit.\" />",
        "<checkbox id=\"checkbox_nyt2\" name=\"NYt2\" checked=\"true\" dom_id=\"ch1\" selector=\"[id=&quot;ch1&quot;]\" dom_clickable=\"true\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" omitted=\"true\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context(snapshot);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains("All requested selectable targets already appear checked or selected"));
    assert!(context.contains("`btn_submit`"));
}

#[test]
fn success_signal_context_surfaces_remaining_selectable_controls_after_click_progress() {
    let history = vec![
        chat_message(
            "tool",
            r#"Clicked element 'checkbox_nyt2' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true}}"#,
            1,
        ),
        chat_message(
            "tool",
            r#"Clicked element 'checkbox_pj6kgy' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true}}"#,
            2,
        ),
    ];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Select NYt2, Pj6KGY, GtqzX and click Submit.\" />",
        "<checkbox id=\"checkbox_nyt2\" name=\"NYt2\" dom_id=\"ch1\" selector=\"[id=&quot;ch1&quot;]\" dom_clickable=\"true\" checked=\"true\" />",
        "<checkbox id=\"checkbox_pj6kgy\" name=\"Pj6KGY\" dom_id=\"ch8\" selector=\"[id=&quot;ch8&quot;]\" dom_clickable=\"true\" checked=\"true\" />",
        "<checkbox id=\"checkbox_gtqzx\" name=\"GtqzX\" dom_id=\"ch9\" selector=\"[id=&quot;ch9&quot;]\" dom_clickable=\"true\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" omitted=\"true\" />",
        "</root>",
    );

    let pending =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    let success = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
    assert!(pending.is_empty(), "{pending}");
    assert!(success.contains("RECENT SUCCESS SIGNAL:"), "{success}");
    assert!(success.contains("checkbox_gtqzx"), "{success}");
    assert!(success.contains("btn_submit"), "{success}");
}

#[test]
fn pending_browser_state_context_prefers_select_submit_progress_over_single_goal_token_match() {
    let history = vec![chat_message(
        "user",
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Select NYt2, Pj6KGY, GtqzX and click Submit.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Select NYt2, Pj6KGY, GtqzX and click Submit.\" />",
        "<checkbox id=\"checkbox_nyt2\" name=\"NYt2\" dom_id=\"ch1\" selector=\"[id=&quot;ch1&quot;]\" dom_clickable=\"true\" />",
        "<checkbox id=\"checkbox_vglh\" name=\"vgLH\" dom_id=\"ch2\" selector=\"[id=&quot;ch2&quot;]\" dom_clickable=\"true\" />",
        "<checkbox id=\"checkbox_pj6kgy\" name=\"Pj6KGY\" dom_id=\"ch8\" selector=\"[id=&quot;ch8&quot;]\" dom_clickable=\"true\" />",
        "<checkbox id=\"checkbox_gtqzx\" name=\"GtqzX\" dom_id=\"ch9\" selector=\"[id=&quot;ch9&quot;]\" dom_clickable=\"true\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(
        context.contains(
            "Use `browser__click` with `ids` [`checkbox_nyt2`, `checkbox_pj6kgy`, `checkbox_gtqzx`] now"
        ),
        "{context}"
    );
    assert!(!context.contains("The target text"), "{context}");
}

#[test]
fn pending_browser_state_context_recovers_select_submit_progress_from_history_when_snapshot_lacks_query(
) {
    let history = vec![chat_message(
        "user",
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Select NYt2, Pj6KGY, GtqzX and click Submit.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<checkbox id=\"checkbox_nyt2\" name=\"NYt2\" dom_id=\"ch1\" selector=\"[id=&quot;ch1&quot;]\" dom_clickable=\"true\" />",
        "<checkbox id=\"checkbox_vglh\" name=\"vgLH\" dom_id=\"ch2\" selector=\"[id=&quot;ch2&quot;]\" dom_clickable=\"true\" />",
        "<checkbox id=\"checkbox_pj6kgy\" name=\"Pj6KGY\" dom_id=\"ch8\" selector=\"[id=&quot;ch8&quot;]\" dom_clickable=\"true\" />",
        "<checkbox id=\"checkbox_gtqzx\" name=\"GtqzX\" dom_id=\"ch9\" selector=\"[id=&quot;ch9&quot;]\" dom_clickable=\"true\" />",
        "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" dom_clickable=\"true\" omitted=\"true\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(
        context.contains(
            "Use `browser__click` with `ids` [`checkbox_nyt2`, `checkbox_pj6kgy`, `checkbox_gtqzx`] now"
        ),
        "{context}"
    );
    assert!(!context.contains("The target text"), "{context}");
}

#[test]
fn snapshot_pending_signal_highlights_visible_scroll_target_before_body_key() {
    let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_query\" name=\"Scroll the textarea to the top of the text hit submit.\" />",
            "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"257\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
            "<button id=\"btn_submit\" name=\"Submit\" />",
            "</root>",
        );

    let context = build_browser_snapshot_pending_state_context(snapshot);
    assert!(context.contains("RECENT PENDING BROWSER STATE:"));
    assert!(context.contains(
        "Visible scroll target `inp_lorem tag=textbox dom_id=text-area` is already on the page."
    ));
    assert!(context.contains("browser__press_key"));
    assert!(context.contains("grounded `selector`"));
    assert!(context.contains("otherwise continue with the next required visible control"));
}

#[test]
fn snapshot_pending_signal_prefers_jump_key_for_explicit_top_scroll_goal() {
    let history = vec![chat_message(
        "user",
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Scroll the textarea to the top of the text hit submit.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Scroll the textarea to the top of the text hit submit.\" />",
        "<textbox id=\"inp_lorem\" name=\"Lorem\" dom_id=\"text-area\" selector=\"[id=&quot;text-area&quot;]\" tag_name=\"textarea\" scroll_top=\"257\" scroll_height=\"565\" client_height=\"104\" can_scroll_up=\"true\" can_scroll_down=\"true\" rect=\"2,57,156,106\" />",
        "<button id=\"btn_submit\" name=\"Submit\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(
        context.contains("RECENT PENDING BROWSER STATE:"),
        "{context}"
    );
    assert!(context.contains("toward the top edge"), "{context}");
    assert!(
        context.contains(&top_edge_jump_call_for_selector(
            Some("[id=\"text-area\"]",)
        )),
        "{context}"
    );
    assert!(!context.contains("for `Home` or `End`"), "{context}");
}

#[test]
fn snapshot_pending_signal_skips_scroll_hint_for_non_scroll_goal_history() {
    let history = vec![chat_message(
        "user",
        "Keep your mouse inside the circle as it moves around.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Keep your mouse inside the circle as it moves around.\" />",
        "<generic id=\"grp_wrap\" name=\"task wrapper\" dom_id=\"wrap\" selector=\"[id=&quot;wrap&quot;]\" scroll_top=\"0\" scroll_height=\"600\" client_height=\"210\" can_scroll_up=\"false\" can_scroll_down=\"true\" rect=\"0,0,160,210\" />",
        "<generic id=\"grp_circ\" name=\"large circle\" dom_id=\"circ\" selector=\"[id=&quot;circ&quot;]\" tag_name=\"circle\" shape_kind=\"circle\" center_x=\"95\" center_y=\"135\" rect=\"73,113,44,44\" />",
        "</root>",
    );

    let context = build_browser_snapshot_pending_state_context_with_history(snapshot, &history);
    assert!(!context.contains("Visible scroll target"), "{context}");
}

#[test]
fn recent_pending_context_skips_scroll_hint_for_non_scroll_goal_history() {
    let history = vec![chat_message(
        "user",
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Task brief: Keep your mouse inside the circle as it moves around.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_query\" name=\"Keep your mouse inside the circle as it moves around.\" />",
        "<generic id=\"grp_wrap\" name=\"task wrapper\" dom_id=\"wrap\" selector=\"[id=&quot;wrap&quot;]\" scroll_top=\"0\" scroll_height=\"600\" client_height=\"210\" can_scroll_up=\"false\" can_scroll_down=\"true\" rect=\"0,0,160,210\" />",
        "<generic id=\"grp_circ\" name=\"large circle\" dom_id=\"circ\" selector=\"[id=&quot;circ&quot;]\" tag_name=\"circle\" shape_kind=\"circle\" center_x=\"95\" center_y=\"135\" rect=\"73,113,44,44\" />",
        "</root>",
    );

    let context =
        build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
    assert!(!context.contains("Visible scroll target"), "{context}");
}

#[test]
fn observation_context_skips_scroll_hint_for_non_scroll_goal_history() {
    let history = vec![chat_message(
        "user",
        "Keep your mouse inside the circle as it moves around.",
        1,
    )];
    let snapshot = concat!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
        "<generic id=\"grp_wrap\" name=\"task wrapper\" dom_id=\"wrap\" selector=\"[id=&quot;wrap&quot;]\" scroll_top=\"0\" scroll_height=\"600\" client_height=\"210\" can_scroll_up=\"false\" can_scroll_down=\"true\" rect=\"0,0,160,210\" />",
        "<generic id=\"grp_circ\" name=\"large circle\" dom_id=\"circ\" selector=\"[id=&quot;circ&quot;]\" tag_name=\"circle\" shape_kind=\"circle\" center_x=\"95\" center_y=\"135\" rect=\"73,113,44,44\" />",
        "</root>",
    );

    let context = build_browser_observation_context_from_snapshot_with_history(snapshot, &history);
    assert!(!context.contains("Visible scroll target"), "{context}");
    assert!(context.contains("grp_circ"), "{context}");
}
