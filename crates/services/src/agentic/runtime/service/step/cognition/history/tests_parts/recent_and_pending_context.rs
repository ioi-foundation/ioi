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

