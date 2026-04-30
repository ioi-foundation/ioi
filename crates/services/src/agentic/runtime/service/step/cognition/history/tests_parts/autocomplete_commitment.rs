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

