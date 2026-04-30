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
