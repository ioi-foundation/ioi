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

