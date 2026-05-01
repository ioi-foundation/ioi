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

