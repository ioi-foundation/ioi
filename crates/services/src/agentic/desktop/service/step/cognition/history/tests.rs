    use super::{
        build_browser_observation_context_from_snapshot,
        build_browser_snapshot_pending_state_context,
        build_browser_snapshot_pending_state_context_with_history,
        build_browser_snapshot_success_signal_context, build_recent_browser_observation_context,
        build_recent_pending_browser_state_context,
        build_recent_pending_browser_state_context_with_current_snapshot,
        build_recent_pending_browser_state_context_with_snapshot,
        build_recent_session_events_context, build_recent_success_signal_context,
        build_recent_success_signal_context_with_snapshot, extract_priority_browser_targets,
        latest_recent_pending_browser_state_context, recent_goal_primary_target,
        recent_history_return_item_id, top_edge_jump_call, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS,
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
                "Tool Output (browser__snapshot): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><button id=\"btn_mark_complete\" name=\"Mark complete\" rect=\"8,114,103,21\" /></root>",
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
                "Tool Output (browser__snapshot): <root><button id=\"btn_mark_complete\" name=\"Mark complete\" rect=\"8,114,103,21\" /></root>",
                1,
            ),
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
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
            chat_message(
                "tool",
                "Tool Output (gui__click_element): clicked btn_ok",
                1,
            ),
            chat_message("system", "System: noop", 2),
        ];

        let context = build_recent_browser_observation_context(&history);
        assert!(context.is_empty());
    }

    #[test]
    fn browser_observation_context_truncates_large_snapshot_payloads() {
        let long_snapshot = format!(
            "Tool Output (browser__snapshot): {}",
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
    fn browser_observation_context_from_snapshot_reuses_same_formatting() {
        let snapshot =
            r#"<root id="root_dom_fallback_tree"><button id="btn_submit" name="Submit" /></root>"#;
        let context = build_browser_observation_context_from_snapshot(snapshot);
        assert!(context.contains("RECENT BROWSER OBSERVATION:"));
        assert!(context.contains("btn_submit"));
        assert!(context.contains("Submit"));
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
                "Tool Output (browser__snapshot): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
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
                "Tool Output (browser__snapshot): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
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
                &format!("Tool Output (browser__snapshot): {snapshot}"),
                1,
            ),
            chat_message(
                "system",
                "RECENT PENDING BROWSER STATE:\nUse `browser__snapshot` once now.\n",
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
            !context.contains("Tool Output (browser__snapshot)"),
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
    fn latest_recent_pending_browser_state_context_keeps_recent_explicit_context_without_refresh() {
        let history = vec![
            chat_message(
                "system",
                "RECENT PENDING BROWSER STATE:\nUse `browser__click_element` on `lnk_443422` now.\n",
                1,
            ),
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): ERROR_CLASS=NoEffectAfterAction duplicate replay guard",
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
                "RECENT PENDING BROWSER STATE:\nUse `browser__click_element` on `lnk_443422` now.\n",
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
    fn recent_goal_primary_target_falls_back_to_select_submit_instruction() {
        let history = vec![chat_message("user", "Select TeCSlMn and click Submit.", 1)];

        let target = recent_goal_primary_target(&history);
        assert_eq!(target.as_deref(), Some("TeCSlMn"));
    }

    #[test]
    fn success_signal_context_highlights_submit_turnover_after_selected_control() {
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
            "<generic id=\"grp_select_jtddg_and_click_submit_\" name=\"Select JtddG and click Submit.\" dom_id=\"query\" selector=\"[id=&quot;query&quot;]\" tag_name=\"div\" rect=\"0,0,160,50\" />",
            "<label id=\"label_hdbp\" name=\"hDbp\" tag_name=\"label\" rect=\"2,59,52,11\" />",
            "<radio id=\"radio_hdbp\" name=\"hDbp\" dom_id=\"ch0\" selector=\"[id=&quot;ch0&quot;]\" tag_name=\"input\" rect=\"7,55,20,13\" />",
            "<button id=\"btn_submit\" name=\"Submit\" dom_id=\"subbtn\" selector=\"[id=&quot;subbtn&quot;]\" tag_name=\"button\" rect=\"2,171,95,31\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.contains("RECENT SUCCESS SIGNAL:"), "{context}");
        assert!(context.contains("`btn_submit`"), "{context}");
        assert!(context.contains("`TeCSlMn`"), "{context}");
        assert!(context.contains("`radio_tecslmn`"), "{context}");
        assert!(context.contains("turned over the page"), "{context}");
        assert!(context.contains("current browser observation"), "{context}");
        assert!(
            context.contains("Do not use the new page's controls"),
            "{context}"
        );
        assert!(context.contains("`agent__complete`"), "{context}");
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
            "Skipped immediate replay of 'browser__click_element' because the identical action already succeeded on the previous step. Do not repeat it. Verify the updated state once or finish with the gathered evidence.",
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
            r#"Tool Output (browser__select_dropdown): {"id":"inp_country","selected":{"label":"Australia","value":"Australia"}}"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><combobox id="inp_awaiting_dispatch" name="Awaiting Dispatch" dom_id="status" selector="[id=&quot;status&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"> <generic id="grp_ticket_t_215" name="Ticket T-215" rect="0,0,1,1" /> IMPORTANT TARGETS: lnk_queue tag=link name=Queue dom_id=queue-link selector=[id="queue-link"] | inp_assign_team tag=combobox name=Assign team dom_id=assignee selector=[id="assignee"] | inp_awaiting_dispatch tag=combobox name=Awaiting Dispatch dom_id=status selector=[id="status"] | inp_dispatch_note tag=textbox name=Dispatch note dom_id=note selector=[id="note"] | btn_review_update tag=button name=Review update dom_id=review-update selector=[id="review-update"]</root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><combobox id="inp_awaiting_dispatch" name="Awaiting Dispatch" dom_id="status" selector="[id=&quot;status&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__select_dropdown): {"id":"inp_assign_team","selected":{"label":"Network Ops","value":"Network Ops"}}"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_ticket_t_215" name="Ticket T-215" rect="0,0,1,1" /><combobox id="inp_assign_team" name="Assign team" dom_id="assignee" selector="[id=&quot;assignee&quot;]" rect="0,0,1,1" /><textbox id="inp_dispatch_note" name="Dispatch note" dom_id="note" selector="[id=&quot;note&quot;]" rect="0,0,1,1" /></root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_queue" name="Queue" dom_id="queue-link" selector="[id=&quot;queue-link&quot;]" rect="0,0,1,1" /><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_confirm_update" name="Confirm update" dom_id="confirm-update" selector="[id=&quot;confirm-update&quot;]" rect="0,0,1,1" /></root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
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
        assert!(context.contains("browser__snapshot"), "{context}");
        assert!(context.contains("btn_review_update"), "{context}");
        assert!(context.contains("/review"), "{context}");
    }

    #[test]
    fn pending_browser_state_context_skips_navigation_snapshot_when_current_snapshot_exists() {
        let history = vec![
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                2,
            ),
        ];

        let context =
            build_recent_pending_browser_state_context_with_current_snapshot(&history, true);
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
        assert!(context.contains("browser__select_dropdown"), "{context}");
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
        assert!(context.contains("browser__select_dropdown"), "{context}");
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
            context.contains("call `browser__snapshot` again"),
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
        assert!(context.contains("another `browser__snapshot`"), "{context}");
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><textbox id="inp_queue_search" name="Queue search" value="invoice" dom_id="queue-search" selector="[id=&quot;queue-search&quot;]" rect="0,0,1,1" /><combobox id="inp_queue_sort" name="Queue sort" value="Recently Updated" dom_id="queue-sort" selector="[id=&quot;queue-sort&quot;]" rect="0,0,1,1" /><button id="btn_apply_filters" name="Apply filters" dom_id="apply-filters" selector="[id=&quot;apply-filters&quot;]" rect="0,0,1,1" /><link id="lnk_t_318" name="T-318" context="Invoice adjustment awaiting callback / Pending Review / Billing Review" dom_id="ticket-link-t-318" selector="[id=&quot;ticket-link-t-318&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_history_318" name="History" context="T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History" dom_id="ticket-history-link-t-318" selector="[id=&quot;ticket-history-link-t-318&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_t_310" name="T-310" context="Recurring invoice delta / Pending Review / Unassigned" dom_id="ticket-link-t-310" selector="[id=&quot;ticket-link-t-310&quot;]" omitted="true" rect="0,0,1,1" /><link id="lnk_history_807ebf" name="History" context="T-310 Recurring invoice delta Pending Review Unassigned Billing Review History" dom_id="ticket-history-link-t-310" selector="[id=&quot;ticket-history-link-t-310&quot;]" omitted="true" rect="0,0,1,1" /></root>"#,
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

        let context = build_recent_pending_browser_state_context_with_snapshot(
            &history,
            Some(current_snapshot),
        );
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
        assert!(context.contains("another `browser__snapshot`"), "{context}");
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
        assert!(context.contains("browser__click_element"), "{context}");
        assert!(
            context.contains("Do not click a surrounding container"),
            "{context}"
        );
        assert!(context.contains("`browser__find_text`"), "{context}");
        assert!(context.contains("another `browser__snapshot`"), "{context}");
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
                r#"Tool Output (browser__click_element): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_page_2'. verify={"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}"#,
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
                r#"Tool Output (browser__click_element): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_2'. verify={"attempts":[{"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}],"id":"lnk_2"}"#,
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
    fn pending_browser_state_context_suppresses_instruction_only_find_text_hint_once_target_is_visible(
    ) {
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
                &format!("Tool Output (browser__snapshot): {snapshot}"),
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
        assert!(context.contains("`browser__snapshot`"), "{context}");
        assert!(context.contains("stale controls"), "{context}");
        assert!(
            !context.contains("Do not click this record's links"),
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
                &format!("Tool Output (browser__snapshot): {old_snapshot}"),
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_443422' via geometry fallback. verify={"post_target":{"semantic_id":"lnk_443422","tag_name":"a","center_point":[73.5,191.5]},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#,
                3,
            ),
            chat_message(
                "tool",
                &format!("Tool Output (browser__snapshot): {new_snapshot}"),
                4,
            ),
        ];

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(new_snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_resets_ranked_result_page_after_resubmit_returns_to_first_page(
    ) {
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
                r#"Tool Output (browser__click_element): ERROR_CLASS=NoEffectAfterAction Failed to click element 'lnk_2'. verify={"attempts":[{"postcondition":{"met":false,"tree_changed":true,"url_changed":false}}],"id":"lnk_2"}"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><button id="btn_review_update" name="Review update" dom_id="review-update" selector="[id=&quot;review-update&quot;]" rect="0,0,1,1" /></root>"#,
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
            context.contains("Do not spend the next step on another `browser__snapshot`"),
            "{context}"
        );
        assert!(
            !context.contains("finish with `agent__complete` when the goal is satisfied"),
            "{context}"
        );
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" rect="0,0,1,1" /></root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><link id="lnk_history_t_202" name="History" dom_id="ticket-history-link-t-202" /><link id="lnk_history_t_204" name="History" dom_id="ticket-history-link-t-204" context="T-204 Metro fiber outage / Awaiting Dispatch / Unassigned" /><link id="lnk_history_t_215" name="History" dom_id="ticket-history-link-t-215" context="T-215 Fiber maintenance escalation / Awaiting Dispatch / Network Ops" /></root>"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_215' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history"}"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" tag_name="h1" rect="0,0,1,1" /><generic id="grp_verify_saved_dispatch" name="Verify that the saved dispatch event matches the requested change before you return to the queue." dom_id="history-status" rect="0,0,1,1" /></root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
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
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
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
    fn success_signal_context_suppresses_generic_click_when_alternate_history_verification_pending()
    {
        let history = vec![
            chat_message(
                "user",
                "Verify T-215 changed and T-204 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_215" name="Audit history for ticket T-215" rect="0,0,1,1" /></root>"#,
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
    fn success_signal_context_suppresses_generic_click_after_confirmation_audit_return() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_open_audit_history' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"Tool Output (browser__snapshot): <root id="root_dom_fallback_tree" name="DOM fallback tree" rect="0,0,800,600"><heading id="heading_audit_history_t_318" name="Audit history for ticket T-318" tag_name="h1" rect="0,0,1,1" /><generic id="grp_typed_audit_verification_complete" name="Typed audit verification complete." dom_id="history-status" rect="0,0,1,1" /><generic id="grp_saved_dispatch_row" name="dispatch.agent Saved dispatch update Billing Review Pending Review Validate recurring invoice delta" tag_name="tr" rect="0,0,1,1" /></root>"#,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_queue' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history","post_url":"http://127.0.0.1:40363/workflow/case/queue"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_history_7c01a1\" name=\"History\" dom_id=\"ticket-history-link-t-310\" context=\"T-310 Recurring invoice delta Pending Review Unassigned Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_history_1ebf96\" name=\"History\" dom_id=\"ticket-history-link-t-318\" context=\"T-318 Invoice adjustment awaiting callback Pending Review Billing Review Billing Review History\" omitted=\"true\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_history_page_verification_return_to_queue() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-215 changed and T-204 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_215' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_audit_history_for_ticket_t_215\" name=\"Audit history for ticket T-215\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_verify_saved_dispatch\" name=\"Verify that the saved dispatch event matches the requested change before you return to the queue.\" dom_id=\"history-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_history_header\" name=\"Actor Action Assignee Status Note\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_saved_dispatch_row\" name=\"dispatch.agent Saved dispatch update Network Ops Awaiting Dispatch Escalate fiber outage to on-call\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("`lnk_queue`"), "{context}");
        assert!(context.contains("`T-204`"), "{context}");
        assert!(
            context.contains("Do not call `browser__snapshot` again"),
            "{context}"
        );
        assert!(
            context.contains("Do not reopen or mutate the item"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_history_page_verification_is_pending() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-215 changed and T-204 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_215' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-215/history"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_audit_history_for_ticket_t_215\" name=\"Audit history for ticket T-215\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_verify_saved_dispatch\" name=\"Verify that the saved dispatch event matches the requested change before you return to the queue.\" dom_id=\"history-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_saved_dispatch_row\" name=\"dispatch.agent Saved dispatch update Network Ops Awaiting Dispatch Escalate fiber outage to on-call\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_history_page_mismatch_recovery() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_318' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_confirmation\" name=\"Confirmation\" dom_id=\"confirmation-link\" selector=\"[id=&quot;confirmation-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_audit_history_for_ticket_t_318\" name=\"Audit history for ticket T-318\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_verify_saved_dispatch\" name=\"Verify that the saved dispatch event matches the requested change before you return to the queue.\" dom_id=\"history-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_history_header\" name=\"Actor Action Assignee Status Note\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_requested_callback_row\" name=\"dispatch.agent Requested billing callback Unassigned Pending Review Awaiting customer callback\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_reopen_ticket\" name=\"Reopen ticket\" dom_id=\"reopen-ticket\" selector=\"[id=&quot;reopen-ticket&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(
            context
                .contains("does not yet show a row matching the page-visible verification prompt"),
            "{context}"
        );
        assert!(context.contains("`lnk_confirmation`"), "{context}");
        assert!(context.contains("`btn_reopen_ticket`"), "{context}");
        assert!(
            context.contains("Do not spend the next step on another `browser__snapshot`"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_history_page_verification_is_unmet() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'lnk_history_t_318' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/queue","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318/history"}"#,
                2,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_confirmation\" name=\"Confirmation\" dom_id=\"confirmation-link\" selector=\"[id=&quot;confirmation-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_audit_history_for_ticket_t_318\" name=\"Audit history for ticket T-318\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_verify_saved_dispatch\" name=\"Verify that the saved dispatch event matches the requested change before you return to the queue.\" dom_id=\"history-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_requested_callback_row\" name=\"dispatch.agent Requested billing callback Unassigned Pending Review Awaiting customer callback\" tag_name=\"tr\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_reopen_ticket\" name=\"Reopen ticket\" dom_id=\"reopen-ticket\" selector=\"[id=&quot;reopen-ticket&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_confirmation_mismatch_recovery() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                3,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<link id=\"lnk_open_audit_history\" name=\"Open audit history\" dom_id=\"history-link\" selector=\"[id=&quot;history-link&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_save_status\" name=\"Saved, cross-ticket queue/history verification pending\" dom_id=\"save-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_assignment_banner\" name=\"Ticket T-318 was routed to Unassigned.\" dom_id=\"assignment-banner\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_status_summary\" name=\"Saved status: Pending Review\" dom_id=\"status-summary\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_note_summary\" name=\"Saved note: Validate recurring invoice delta\" dom_id=\"note-summary\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_reopen_ticket\" name=\"Reopen ticket\" dom_id=\"reopen-ticket\" selector=\"[id=&quot;reopen-ticket&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(
            context.contains("does not yet reflect the recent saved update"),
            "{context}"
        );
        assert!(context.contains("`Billing Review`"), "{context}");
        assert!(context.contains("`Unassigned`"), "{context}");
        assert!(context.contains("`btn_reopen_ticket`"), "{context}");
        assert!(
            context.contains("Do not spend the next step on `browser__snapshot`"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_confirmation_summary_is_stale() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                3,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_save_status\" name=\"Saved, cross-ticket queue/history verification pending\" dom_id=\"save-status\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_assignment_banner\" name=\"Ticket T-318 was routed to Unassigned.\" dom_id=\"assignment-banner\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_status_summary\" name=\"Saved status: Pending Review\" dom_id=\"status-summary\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_reopen_ticket\" name=\"Reopen ticket\" dom_id=\"reopen-ticket\" selector=\"[id=&quot;reopen-ticket&quot;]\" tag_name=\"button\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_reopened_draft_resume() {
        let history = vec![
            chat_message(
                "user",
                "Verify T-318 changed and T-310 stayed unchanged before finishing.",
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                2,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                3,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                4,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_reopen_ticket' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318"}"#,
                5,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_ticket_t_318\" name=\"Ticket T-318\" dom_id=\"ticket-title\" selector=\"[id=&quot;ticket-title&quot;]\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_assign_team\" name=\"Assign team\" dom_id=\"assignee\" selector=\"[id=&quot;assignee&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_ticket_status\" name=\"Ticket status\" value=\"Pending Review\" dom_id=\"status\" selector=\"[id=&quot;status&quot;]\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_dispatch_note\" name=\"Dispatch note\" dom_id=\"note\" selector=\"[id=&quot;note&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_review_update\" name=\"Review update\" dom_id=\"review-update\" selector=\"[id=&quot;review-update&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(
            context.contains("reopened so the saved state can be corrected"),
            "{context}"
        );
        assert!(
            context.contains("Do not return to queue/history verification yet"),
            "{context}"
        );
        assert!(context.contains("`Billing Review`"), "{context}");
        assert!(context.contains("`Pending Review`"), "{context}");
        assert!(
            context.contains("`Validate recurring invoice delta`"),
            "{context}"
        );
        assert!(context.contains("`btn_review_update`"), "{context}");
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_reopened_draft_requires_resume() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_reopen_ticket' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/confirmation","post_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_ticket_t_318\" name=\"Ticket T-318\" dom_id=\"ticket-title\" selector=\"[id=&quot;ticket-title&quot;]\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_assign_team\" name=\"Assign team\" dom_id=\"assignee\" selector=\"[id=&quot;assignee&quot;]\" rect=\"0,0,1,1\" />",
            "<combobox id=\"inp_ticket_status\" name=\"Ticket status\" value=\"Pending Review\" dom_id=\"status\" selector=\"[id=&quot;status&quot;]\" rect=\"0,0,1,1\" />",
            "<textbox id=\"inp_dispatch_note\" name=\"Dispatch note\" dom_id=\"note\" selector=\"[id=&quot;note&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_review_update\" name=\"Review update\" dom_id=\"review-update\" selector=\"[id=&quot;review-update&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context = build_recent_success_signal_context_with_snapshot(&history, Some(snapshot));
        assert!(context.is_empty(), "{context}");
    }

    #[test]
    fn pending_browser_state_context_guides_review_confirmation_before_queue_return() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<link id=\"lnk_queue\" name=\"Queue\" dom_id=\"queue-link\" selector=\"[id=&quot;queue-link&quot;]\" rect=\"0,0,1,1\" />",
            "<heading id=\"heading_review_queued_update\" name=\"Review queued update\" tag_name=\"h1\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_ticket_t_318\" name=\"Ticket T-318\" dom_id=\"review-ticket\" selector=\"[id=&quot;review-ticket&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_draft_assignee\" name=\"Draft assignee: Billing Review\" dom_id=\"review-assignee\" selector=\"[id=&quot;review-assignee&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_draft_status\" name=\"Draft status: Pending Review\" dom_id=\"review-status\" selector=\"[id=&quot;review-status&quot;]\" rect=\"0,0,1,1\" />",
            "<generic id=\"grp_draft_note\" name=\"Draft note: Validate recurring invoice delta\" dom_id=\"review-note\" selector=\"[id=&quot;review-note&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_edit_draft\" name=\"Edit draft\" dom_id=\"edit-update\" selector=\"[id=&quot;edit-update&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_confirm_update\" name=\"Confirm update\" dom_id=\"confirm-update\" selector=\"[id=&quot;confirm-update&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_cancel_draft\" name=\"Cancel draft\" dom_id=\"cancel-update\" selector=\"[id=&quot;cancel-update&quot;]\" rect=\"0,0,1,1\" />",
            "</root>",
        );

        let context =
            build_recent_pending_browser_state_context_with_snapshot(&history, Some(snapshot));
        assert!(
            context.contains("RECENT PENDING BROWSER STATE:"),
            "{context}"
        );
        assert!(context.contains("ready to be saved"), "{context}");
        assert!(context.contains("`Billing Review`"), "{context}");
        assert!(context.contains("`Pending Review`"), "{context}");
        assert!(
            context.contains("`Validate recurring invoice delta`"),
            "{context}"
        );
        assert!(context.contains("`btn_confirm_update`"), "{context}");
        assert!(context.contains("`btn_edit_draft`"), "{context}");
        assert!(
            context.contains("Do not return to queue/history verification"),
            "{context}"
        );
    }

    #[test]
    fn success_signal_context_suppresses_generic_click_when_review_confirmation_is_pending() {
        let history = vec![
            chat_message(
                "tool",
                r#"{"selected":{"label":"Billing Review"},"id":"inp_assign_team"}"#,
                1,
            ),
            chat_message(
                "tool",
                r#"{"selected":{"label":"Pending Review"},"id":"inp_ticket_status"}"#,
                2,
            ),
            chat_message(
                "tool",
                r##"{"typed":{"selector":"#note","text":"Validate recurring invoice delta","value":"Validate recurring invoice delta","dom_id":"note"}}"##,
                3,
            ),
            chat_message(
                "tool",
                r#"Clicked element 'btn_review_update' via geometry fallback. verify={"postcondition":{"met":true,"tree_changed":true,"url_changed":true},"pre_url":"http://127.0.0.1:40363/workflow/case/tickets/T-318","post_url":"http://127.0.0.1:40363/workflow/case/review"}"#,
                4,
            ),
        ];
        let snapshot = concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "<generic id=\"grp_ticket_t_318\" name=\"Ticket T-318\" dom_id=\"review-ticket\" selector=\"[id=&quot;review-ticket&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_edit_draft\" name=\"Edit draft\" dom_id=\"edit-update\" selector=\"[id=&quot;edit-update&quot;]\" rect=\"0,0,1,1\" />",
            "<button id=\"btn_confirm_update\" name=\"Confirm update\" dom_id=\"confirm-update\" selector=\"[id=&quot;confirm-update&quot;]\" rect=\"0,0,1,1\" />",
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
        assert!(context.contains("browser__key"));
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
        assert!(context.contains("browser__snapshot"));
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
        assert!(context.contains("browser__snapshot"));
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
    fn success_signal_context_highlights_already_satisfied_typed_field() {
        let history = vec![chat_message(
            "tool",
            r##"{"typed":{"selector":"#queue-search","text":"fiber","value":"fiber","focused":true,"already_satisfied":true}}"##,
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("already contained the requested text"));
        assert!(context.contains("Do not type the same text"));
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
        assert!(context.contains("browser__snapshot"));
        assert!(context.contains("browser__key"));
    }

    #[test]
    fn pending_browser_state_context_highlights_incomplete_auth_form() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"Username\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"Password\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
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
                "Tool Output (browser__snapshot): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"dispatch-215\" value=\"dispatch-215\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
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
        assert!(context.contains("browser__click_element"));
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
        assert!(context.contains("browser__click_element"));
    }

    #[test]
    fn success_signal_context_suppresses_stale_click_guidance_while_auth_pending() {
        let history = vec![
            chat_message(
                "tool",
                "Tool Output (browser__snapshot): <root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\"><textbox id=\"inp_username\" name=\"dispatch.agent\" value=\"dispatch.agent\" dom_id=\"username\" selector=\"[id=&quot;username&quot;]\" rect=\"0,0,1,1\" /><textbox id=\"inp_password\" name=\"dispatch-215\" value=\"dispatch-215\" dom_id=\"password\" selector=\"[id=&quot;password&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_sign_in\" name=\"Sign in\" dom_id=\"sign-in\" selector=\"[id=&quot;sign-in&quot;]\" rect=\"0,0,1,1\" /></root>",
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
        assert!(context.contains("browser__click_element"));
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
        assert!(context.contains("browser__select_text"));
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
        assert!(context.contains("Do not submit yet"));
        assert!(context.contains("Do not use `Home` again"));
        assert!(context.contains("scroll_top=257"));
        assert!(context.contains("spend the next step on `PageUp`"));
        assert!(context.contains("can_scroll_up=true"));
        assert!(context.contains("can_scroll_up=false"));
        assert!(context.contains("scroll_top=0"));
        assert!(context.contains(top_edge_jump_call()));
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
        assert!(context.contains(top_edge_jump_call()));
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
        assert!(context.contains("Several recent `PageUp` steps"));
        assert!(context.contains(top_edge_jump_call()));
        assert!(context.contains("stop spending steps on repeated `PageUp`"));
        assert!(context.contains("scroll_top=0"));
    }

    #[test]
    fn success_signal_context_highlights_scroll_edge_key_completion() {
        let history = vec![chat_message(
            "tool",
            r##"{"key":{"key":"Home","modifiers":[],"is_chord":false,"selector":"#text-area","dom_id":"text-area","tag_name":"textarea","value":"Lorem ipsum","focused":true,"scroll_top":0,"scroll_height":510,"client_height":104,"can_scroll_up":false,"can_scroll_down":true,"autocomplete":null}}"##,
            1,
        )];

        let context = build_recent_success_signal_context(&history);
        assert!(context.contains("RECENT SUCCESS SIGNAL:"));
        assert!(context.contains("top edge"));
        assert!(context.contains("Do not repeat the same key"));
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
        assert!(context.contains("browser__click_element"));
        assert!(context.contains("otherwise continue with the next required visible control"));
    }
