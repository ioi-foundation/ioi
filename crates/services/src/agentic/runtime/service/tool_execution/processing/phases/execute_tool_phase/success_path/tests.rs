use super::{
    compact_tool_history_entry_for_chat, should_record_success_idempotence_for_tool_result,
    should_treat_command_failure_as_tool_observation, tool_history_message_content,
    transcript_context_excerpts, workspace_change_lifecycle_receipt_details,
    workspace_edit_receipt_details, workspace_read_receipt_details,
    TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT,
};
use crate::agentic::runtime::types::CommandExecution;
use ioi_types::app::agentic::AgentTool;
use serde_json::json;

#[test]
fn transcript_context_excerpts_evenly_sample_long_text() {
    let transcript = [
        "Maxwell introduces the electric field and the magnetic field as coupled quantities.",
        "Gauss's law relates electric flux to enclosed charge.",
        "Gauss's law for magnetism states that magnetic monopoles do not appear in the model.",
        "Faraday's law explains how changing magnetic fields induce electric fields.",
        "Ampere-Maxwell law adds displacement current to complete the system.",
        "The lecturer closes by connecting the equations to electromagnetic waves.",
    ]
    .join(" ");

    let excerpts = transcript_context_excerpts(&transcript);

    assert!(excerpts.len() >= 3);
    assert!(excerpts
        .first()
        .is_some_and(|value| value.contains("Maxwell")));
    assert!(excerpts
        .last()
        .is_some_and(|value| value.contains("electromagnetic waves")));
}

#[test]
fn media_multimodal_history_is_compacted_for_chat_context() {
    let raw = json!({
        "schema_version": 1,
        "retrieved_at_ms": 1773264032396u64,
        "tool": "media__extract_evidence",
        "requested_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
        "canonical_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
        "title": "Electromagnetism - Maxwell's Laws",
        "duration_seconds": 2909u64,
        "requested_language": "en",
        "provider_candidates": [
            {
                "provider_id": "yt_dlp.managed_subtitles",
                "modality": "transcript",
                "source_count": 1,
                "selected": true,
                "success": true,
                "request_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
                "affordances": ["detail_document"]
            },
            {
                "provider_id": "ffmpeg.managed_frames_vision",
                "modality": "visual",
                "source_count": 1,
                "selected": true,
                "success": true,
                "request_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
                "affordances": ["detail_document"]
            }
        ],
        "selected_modalities": ["transcript", "visual"],
        "selected_provider_ids": ["yt_dlp.managed_subtitles", "ffmpeg.managed_frames_vision"],
        "transcript": {
            "schema_version": 1,
            "retrieved_at_ms": 1773263984722u64,
            "tool": "media__extract_transcript",
            "backend": "edge:media:yt_dlp_subtitles",
            "provider_id": "yt_dlp.managed_subtitles",
            "provider_version": "2026.03.03",
            "requested_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
            "canonical_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
            "title": "Electromagnetism - Maxwell's Laws",
            "duration_seconds": 2909u64,
            "requested_language": "en",
            "transcript_language": "en",
            "transcript_source_kind": "manual",
            "segment_count": 310,
            "transcript_char_count": 21822,
            "transcript_hash": "sha256:transcript",
            "transcript_text": "Maxwell introduces the electric field. Gauss's law relates flux to charge. Faraday's law explains induction. Ampere-Maxwell law closes the system. The lecture ends by deriving electromagnetic waves."
        },
        "visual": {
            "schema_version": 1,
            "retrieved_at_ms": 1773264032396u64,
            "tool": "media__extract_visual_evidence",
            "backend": "edge:media:ffmpeg_frames_vision",
            "provider_id": "ffmpeg.managed_frames_vision",
            "provider_version": "2026.03.06",
            "requested_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
            "canonical_url": "https://www.youtube.com/watch?v=9Tm2c6NJH4Y",
            "title": "Electromagnetism - Maxwell's Laws",
            "duration_seconds": 2909u64,
            "frame_count": 2,
            "visual_char_count": 420,
            "visual_hash": "sha256:visual",
            "visual_summary": "Slides cover Maxwell's equations.",
            "frames": [
                {
                    "timestamp_ms": 0u64,
                    "timestamp_label": "00:00",
                    "frame_hash": "frame-1",
                    "mime_type": "image/jpeg",
                    "width": 1280,
                    "height": 720,
                    "scene_summary": "Title slide introducing electromagnetism and Maxwell's laws.",
                    "visible_text": "Electromagnetism - Maxwell's Laws",
                    "transcript_excerpt": "The lecture opens by stating the four Maxwell equations."
                },
                {
                    "timestamp_ms": 120000u64,
                    "timestamp_label": "02:00",
                    "frame_hash": "frame-2",
                    "mime_type": "image/jpeg",
                    "width": 1280,
                    "height": 720,
                    "scene_summary": "Equation slide showing Faraday's law and Ampere-Maxwell law.",
                    "visible_text": "Faraday's law | Ampere-Maxwell law",
                    "transcript_excerpt": "These equations explain induction and displacement current."
                }
            ]
        }
    })
    .to_string();

    let compact = compact_tool_history_entry_for_chat("media__extract_evidence", &raw);

    assert!(compact.contains("selected_modalities=transcript,visual"));
    assert!(compact.contains("transcript_evidence[1]="));
    assert!(compact.contains("visual_evidence[1]="));
    assert!(!compact.contains("\"transcript_text\""));
    assert!(compact.chars().count() < TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT * 2);
}

#[test]
fn non_browser_tool_history_is_prefixed_for_next_model_turn() {
    let content = tool_history_message_content("file__read", "hello from the repo");

    assert_eq!(content, "Tool Output (file__read): hello from the repo");
}

#[test]
fn shell_history_omits_large_raw_streams_from_chat_context() {
    let history_entry = format!(
        "COMMAND_HISTORY:{}\n{}",
        serde_json::to_string(&CommandExecution {
            command: "node -e <inline script>".to_string(),
            exit_code: 0,
            stdout: (0..40_000)
                .map(|idx| format!("cap-line-{idx}\n"))
                .collect::<String>(),
            stderr: String::new(),
            timestamp_ms: 1_780_000_000_000,
            step_index: 0,
        })
        .expect("command history serializes"),
        "cap-line-0\ncap-line-1\n"
    );

    let compact = compact_tool_history_entry_for_chat("shell__run", &history_entry);

    assert!(compact.contains("command_exit_code=0"), "{compact}");
    assert!(compact.contains("stdout_lines=40000"), "{compact}");
    assert!(
        compact.contains("stdout_content=omitted_large_stream"),
        "{compact}"
    );
    assert!(
        compact.contains("raw_streams=work_lane_and_tracing_only"),
        "{compact}"
    );
    assert!(!compact.contains("cap-line-0"), "{compact}");
    assert!(!compact.contains("cap-line-39999"), "{compact}");
    assert!(!compact.contains("node -e"), "{compact}");
}

#[test]
fn command_exit_failure_is_a_tool_observation_for_model_repair() {
    let tool = AgentTool::SysExec {
        command: "node".to_string(),
        args: vec!["--test".to_string(), "tests/*.test.mjs".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history_entry = Some(format!(
        "COMMAND_HISTORY:{}",
        serde_json::to_string(&CommandExecution {
            command: "node --test tests/*.test.mjs".to_string(),
            exit_code: 1,
            stdout: "not ok 1 format.test.mjs".to_string(),
            stderr: "Expected values to be strictly equal".to_string(),
            timestamp_ms: 1_780_000_000_000,
            step_index: 0,
        })
        .expect("command history serializes"),
    ));

    assert!(should_treat_command_failure_as_tool_observation(
        true,
        &tool,
        false,
        &history_entry,
        false,
    ));
    assert!(!should_treat_command_failure_as_tool_observation(
        false,
        &tool,
        false,
        &history_entry,
        false,
    ));
    assert!(!should_treat_command_failure_as_tool_observation(
        true,
        &tool,
        true,
        &history_entry,
        false,
    ));
    assert!(!should_treat_command_failure_as_tool_observation(
        true,
        &tool,
        false,
        &history_entry,
        true,
    ));
}

#[test]
fn deferred_chat_reply_is_not_recorded_as_success_idempotence() {
    assert!(!should_record_success_idempotence_for_tool_result(&[
        "terminal_chat_reply_deferred_for_active_web_pipeline=true".to_string()
    ]));
    assert!(should_record_success_idempotence_for_tool_result(&[
        "terminal_chat_reply_ready=true".to_string()
    ]));
}

#[test]
fn file_read_history_preserves_tail_context_for_large_documents() {
    let long_file = format!(
        "# Campaign Guide\n\n{}\n\n## Stage 12: Integrated Soak\nCleanup proof and soak manifest remain.",
        "middle section ".repeat(800)
    );

    let compact = compact_tool_history_entry_for_chat("file__read", &long_file);

    assert!(compact.contains("# Campaign Guide"), "{compact}");
    assert!(compact.contains("Markdown heading outline"), "{compact}");
    assert!(compact.contains("middle omitted"), "{compact}");
    assert!(
        compact.contains("## Stage 12: Integrated Soak"),
        "{compact}"
    );
    assert!(
        compact.contains("Cleanup proof and soak manifest remain"),
        "{compact}"
    );
    assert!(compact.chars().count() <= TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT);
}

#[test]
fn file_read_history_preserves_late_markdown_outline_for_long_plans() {
    let long_plan = format!(
        "# Product Guide\n\n{}\n\n## Stage 9: Refactor And Modularization Checkpoint\n{}\n\n## Stage 10: User-Like Repository Fixture Suite\nbody\n\n## Stage 11: Evidence, Tracing, And Cleanup\ncleanup proof belongs here\n\n## Stage 12: Integrated Soak\nsoak manifest belongs here\n\n## Final Deliverables\nfinish",
        "intro body ".repeat(1_200),
        "stage nine body ".repeat(300)
    );

    let compact = compact_tool_history_entry_for_chat("file__read", &long_plan);

    assert!(compact.contains("Markdown heading outline"), "{compact}");
    assert!(
        compact.contains("## Stage 11: Evidence, Tracing, And Cleanup"),
        "{compact}"
    );
    assert!(
        compact.contains("## Stage 12: Integrated Soak"),
        "{compact}"
    );
    assert!(compact.contains("cleanup proof belongs here"), "{compact}");
    assert!(compact.contains("soak manifest belongs here"), "{compact}");
    assert!(compact.chars().count() <= TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT);
}

#[test]
fn tool_history_prefix_is_not_duplicated() {
    let content = tool_history_message_content(
        "browser__inspect",
        "Tool Output (browser__inspect): <root />",
    );

    assert_eq!(content, "Tool Output (browser__inspect): <root />");
}

#[test]
fn compact_browser_snapshot_history_entry_preserves_late_actionable_targets() {
    let snapshot = format!(
        "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">{}<textbox id=\"inp_fiber\" name=\"fiber\" dom_id=\"queue-search\" selector=\"[id=&quot;queue-search&quot;]\" rect=\"0,0,1,1\" /><combobox id=\"inp_awaiting_dispatch\" name=\"Awaiting Dispatch\" dom_id=\"queue-status-filter\" selector=\"[id=&quot;queue-status-filter&quot;]\" rect=\"0,0,1,1\" /><button id=\"btn_apply_filters\" name=\"Apply filters\" dom_id=\"apply-filters\" selector=\"[id=&quot;apply-filters&quot;]\" rect=\"0,0,1,1\" /><generic id=\"grp_row_noise_0\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" /><listitem id=\"item_noise_0\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" /><link id=\"lnk_t_202\" name=\"T-202\" omitted=\"true\" dom_id=\"ticket-link-t-202\" selector=\"[id=&quot;ticket-link-t-202&quot;]\" rect=\"0,0,1,1\" /><generic id=\"grp_row_noise_1\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" /><listitem id=\"item_noise_1\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" /><link id=\"lnk_t_204\" name=\"T-204\" omitted=\"true\" dom_id=\"ticket-link-t-204\" selector=\"[id=&quot;ticket-link-t-204&quot;]\" context=\"Unassigned / Awaiting Dispatch\" rect=\"0,0,1,1\" /><generic id=\"grp_row_noise_2\" name=\"Row noise\" omitted=\"true\" rect=\"0,0,1,1\" /><listitem id=\"item_noise_2\" name=\"Noise row\" omitted=\"true\" rect=\"0,0,1,1\" /><link id=\"lnk_t_215\" name=\"T-215\" omitted=\"true\" dom_id=\"ticket-link-t-215\" selector=\"[id=&quot;ticket-link-t-215&quot;]\" rect=\"0,0,1,1\" /></root>",
        "<generic id=\"grp_noise\" name=\"alpha beta gamma delta\" rect=\"0,0,1,1\" /> ".repeat(200)
    );

    let compact = compact_tool_history_entry_for_chat("browser__inspect", &snapshot);

    assert!(compact.starts_with("<root"), "{compact}");
    assert!(compact.contains("ticket-link-t-202"), "{compact}");
    assert!(compact.contains("ticket-link-t-204"), "{compact}");
    assert!(compact.contains("ticket-link-t-215"), "{compact}");
    assert!(
        compact.contains("context=Unassigned / Awaiting Dispatch"),
        "{compact}"
    );
    assert!(compact.chars().count() <= TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT + 1);
}

#[test]
fn compact_browser_snapshot_history_entry_prioritizes_clickable_controls_over_instruction_copy() {
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

    let compact = compact_tool_history_entry_for_chat("browser__inspect", &snapshot);

    assert!(compact.starts_with("<root"), "{compact}");
    assert!(compact.contains("grp_email_row tag=generic"), "{compact}");
    assert!(compact.contains("grp_trash tag=generic"), "{compact}");
    assert!(compact.contains("dom_clickable=true"), "{compact}");
    assert!(
        !compact.contains("grp_find_the_email_by_lonna tag=generic"),
        "{compact}"
    );
    assert!(
        !compact.contains("grp_lonna tag=generic name=Lonna"),
        "{compact}"
    );
}

#[test]
fn compact_browser_snapshot_history_entry_preserves_svg_geometry_targets() {
    let snapshot = format!(
        concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "{}",
            "<generic id=\"grp_svg_grid_object\" name=\"svg grid object\" dom_id=\"svg-grid\" selector=\"[id=&quot;svg-grid&quot;]\" tag_name=\"svg\" rect=\"2,52,150,130\" />",
            "<generic id=\"grp_small_blue_circle\" name=\"small blue circle at 29,56 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"blue\" geometry_role=\"vertex\" connected_lines=\"2\" radius=\"4\" center_x=\"31\" center_y=\"108\" rect=\"28,105,7,7\" />",
            "<generic id=\"grp_small_black_circle\" name=\"small black circle at 69,73 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"black\" radius=\"4\" center_x=\"71\" center_y=\"125\" rect=\"68,122,7,7\" />",
            "<generic id=\"grp_small_black_circle_2\" name=\"small black circle at 89,29 radius 4\" tag_name=\"circle\" shape_kind=\"circle\" shape_size=\"small\" shape_color=\"black\" radius=\"4\" center_x=\"91\" center_y=\"81\" rect=\"88,78,7,7\" />",
            "<generic id=\"grp_large_line_from_2956_to_6973\" name=\"large line from 29,56 to 69,73\" tag_name=\"line\" shape_kind=\"line\" shape_size=\"large\" line_x1=\"29\" line_y1=\"56\" line_x2=\"69\" line_y2=\"73\" line_length=\"43\" line_angle_deg=\"23\" center_x=\"51\" center_y=\"116\" rect=\"31,108,40,17\" />",
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

    let compact = compact_tool_history_entry_for_chat("browser__inspect", &snapshot);

    assert!(
        compact.contains("grp_small_blue_circle tag=generic"),
        "{compact}"
    );
    assert!(compact.contains("shape_kind=circle"), "{compact}");
    assert!(compact.contains("geometry_role=vertex"), "{compact}");
    assert!(compact.contains("connected_lines=2"), "{compact}");
    assert!(compact.contains("center=31,108"), "{compact}");
    assert!(compact.contains("radius=4"), "{compact}");
    assert!(
        compact.contains("grp_large_line_from_2956_to_6973 tag=generic"),
        "{compact}"
    );
    assert!(compact.contains("line=29,56->69,73"), "{compact}");
    assert!(compact.contains("line_length=43"), "{compact}");
    assert!(compact.contains("line_angle=23deg"), "{compact}");
    assert!(
        !compact.contains("grp_large_line_from_2956_to_6973 tag=generic name=large line from 29,56 to 69,73 center="),
        "{compact}"
    );
    assert!(compact.contains("btn_submit tag=button"), "{compact}");
}

#[test]
fn compact_browser_snapshot_history_entry_surfaces_calendar_navigation_state() {
    let snapshot = format!(
        concat!(
            "<root id=\"root_dom_fallback_tree\" name=\"DOM fallback tree\" rect=\"0,0,800,600\">",
            "{}",
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
        ),
        "<generic id=\"grp_noise\" name=\"padding\" rect=\"0,0,1,1\" /> ".repeat(200),
    );

    let compact = compact_tool_history_entry_for_chat("browser__inspect", &snapshot);

    assert!(compact.contains("lnk_prev tag=link name=Prev"), "{compact}");
    assert!(
        compact.contains("grp_december_2016 tag=generic name=December 2016"),
        "{compact}"
    );
    assert!(!compact.contains("<REDACTED:card_pan>"), "{compact}");
    assert!(!compact.contains("context=1 2 3 4 5 6"), "{compact}");
}

#[test]
fn compact_browser_click_history_entry_summarizes_verbose_verify_payload() {
    let raw = concat!(
        "Clicked element 'grp_4' via geometry fallback. verify=",
        "{\"center_point\":[52.0,69.0],\"dispatch_elapsed_ms\":18234,",
        "\"dispatch_succeeded\":true,",
        "\"prompt_observation_source\":\"recent_prompt_observation_snapshot\",",
        "\"prompt_observation_elapsed_ms\":17802,",
        "\"focused_control\":null,\"method\":\"geometry_center\",",
        "\"post_target\":{\"semantic_id\":\"grp_5\",\"dom_id\":null,",
        "\"selector\":\"#area_svg > rect:nth-of-type(1)\",\"tag_name\":\"rect\",",
        "\"backend_dom_node_id\":null},",
        "\"post_snapshot_elapsed_ms\":14,",
        "\"post_url\":\"file:///tmp/ioi-miniwob-bridge/demo/miniwob/ascending-numbers.1.html\",",
        "\"postcondition\":{\"editable_focus_transition\":false,",
        "\"material_semantic_change\":true,\"met\":true,",
        "\"semantic_change_delta\":6,\"target_disappeared\":false,",
        "\"tree_changed\":true,\"url_changed\":false},",
        "\"pre_target\":{\"semantic_id\":\"grp_4\",\"selector\":\"#area_svg > rect:nth-of-type(1)\",",
        "\"tag_name\":\"rect\",\"center_point\":[52.0,69.0]},",
        "\"pre_url\":\"file:///tmp/ioi-miniwob-bridge/demo/miniwob/ascending-numbers.1.html\",",
        "\"settle_ms\":360,\"target_resolution_source\":\"prompt_observation_tree\",",
        "\"verify_elapsed_ms\":379}"
    );

    let compact = compact_tool_history_entry_for_chat("browser__click", raw);

    assert!(
        compact.contains("Clicked element 'grp_4' via geometry fallback."),
        "{compact}"
    );
    assert!(
        compact.contains("\"method\":\"geometry_center\""),
        "{compact}"
    );
    assert!(
        compact.contains("\"dispatch_elapsed_ms\":18234"),
        "{compact}"
    );
    assert!(
        compact.contains("\"prompt_observation_source\":\"recent_prompt_observation_snapshot\""),
        "{compact}"
    );
    assert!(
        compact.contains("\"target_resolution_source\":\"prompt_observation_tree\""),
        "{compact}"
    );
    assert!(compact.contains("\"semantic_change_delta\":6"), "{compact}");
    assert!(compact.contains("\"post_target\""), "{compact}");
    assert!(!compact.contains("\"pre_target\""), "{compact}");
    assert!(!compact.contains("\"dispatch_succeeded\""), "{compact}");
    assert!(compact.chars().count() <= super::TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT + 1);
}

#[test]
fn compact_browser_synthetic_click_history_entry_summarizes_postcondition() {
    let raw = r##"{"synthetic_click":{"x":60,"y":107},"pre_target":{"semantic_id":"grp_vertex","selector":"#blue-circle","tag_name":"circle","center_point":[31.0,108.0],"focused":false},"post_target":{"semantic_id":"grp_blue_circle","selector":"#blue-circle","tag_name":"circle","center_point":[53.0,118.0],"focused":false},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"##;

    let compact = compact_tool_history_entry_for_chat("browser__click_at", raw);

    assert!(
        compact.contains("Synthetic click at (60, 107)"),
        "{compact}"
    );
    assert!(compact.contains(r#""met":true"#), "{compact}");
    assert!(compact.contains(r#""tree_changed":true"#), "{compact}");
    assert!(compact.contains(r#""pre_target":{"#), "{compact}");
    assert!(
        compact.contains(r#""semantic_id":"grp_vertex""#),
        "{compact}"
    );
    assert!(compact.contains(r#""post_target":{"#), "{compact}");
    assert!(
        compact.contains(r#""semantic_id":"grp_blue_circle""#),
        "{compact}"
    );
}

#[test]
fn compact_browser_synthetic_click_history_entry_keeps_verify_json_parseable_under_budget() {
    let raw = r##"{"synthetic_click":{"x":51.0,"y":103.0},"pre_target":{"semantic_id":"grp_large_line_from_31108_to_9181","selector":"#svg-grid > line:nth-of-type(2)","tag_name":"line","center_point":[61.0,94.5],"focused":false,"editable":false,"checked":null,"selected":null},"post_target":{"semantic_id":"grp_blue_circle","dom_id":"blue-circle","selector":"#blue-circle","tag_name":"circle","center_point":[53.5,105.5],"focused":false,"editable":false,"checked":null,"selected":null},"postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"##;

    let compact = compact_tool_history_entry_for_chat("browser__click_at", raw);
    let verify_json = compact
        .split_once(" verify=")
        .map(|(_, verify)| verify)
        .expect("synthetic click compact summary should keep verify payload");
    let parsed = serde_json::from_str::<serde_json::Value>(verify_json)
        .expect("verify payload should remain valid JSON");

    assert!(
        compact.chars().count() <= super::TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT,
        "{compact}"
    );
    assert_eq!(
        parsed["postcondition"]["met"],
        serde_json::Value::Bool(true),
        "{compact}"
    );
    assert_eq!(
        parsed["post_target"]["semantic_id"],
        serde_json::Value::String("grp_blue_circle".to_string()),
        "{compact}"
    );
}

#[test]
fn workspace_edit_receipt_details_distinguish_write_edit_and_patch_tools() {
    let write = workspace_edit_receipt_details(
        &AgentTool::FsWrite {
            path: "path_utils.py".to_string(),
            content: "updated".to_string(),
            line_number: None,
        },
        7,
    )
    .expect("write receipt details should exist");
    assert_eq!(write.0, "file__write");
    assert_eq!(write.1, "step=7;tool=file__write;path=path_utils.py");

    let edit = workspace_edit_receipt_details(
        &AgentTool::FsWrite {
            path: "path_utils.py".to_string(),
            content: "return normalized".to_string(),
            line_number: Some(12),
        },
        8,
    )
    .expect("edit receipt details should exist");
    assert_eq!(edit.0, "file__write");
    assert_eq!(edit.1, "step=8;tool=file__write;path=path_utils.py");

    let patch = workspace_edit_receipt_details(
        &AgentTool::FsPatch {
            path: "path_utils.py".to_string(),
            search: "old".to_string(),
            replace: "new".to_string(),
        },
        9,
    )
    .expect("patch receipt details should exist");
    assert_eq!(patch.0, "file__edit");
    assert_eq!(patch.1, "step=9;tool=file__edit;path=path_utils.py");
}

#[test]
fn workspace_read_receipt_details_include_search_as_file_context() {
    let search = workspace_read_receipt_details(
        &AgentTool::FsSearch {
            path: ".".to_string(),
            regex: "local|native|provider".to_string(),
            file_pattern: Some("*.mjs".to_string()),
        },
        11,
    )
    .expect("search receipt details should exist");

    assert!(search.contains("step=11"), "{search}");
    assert!(search.contains("tool=file__search"), "{search}");
    assert!(search.contains("path=."), "{search}");
    assert!(search.contains("regex=local|native|provider"), "{search}");
    assert!(search.contains("file_pattern=*.mjs"), "{search}");
}

#[test]
fn workspace_change_lifecycle_receipt_details_accept_reject_and_rollback_records() {
    let rejected_record = json!({
        "change_id": "workspace_change:test",
        "tool_name": "file__edit",
        "path": "src/lib.rs",
        "lifecycle": "rejected",
        "edit_count": 1,
        "hunks": []
    })
    .to_string();
    let reject = workspace_change_lifecycle_receipt_details(
        &AgentTool::WorkspaceChangeReject {
            change_id: Some("workspace_change:test".to_string()),
            change: None,
            changes: vec![],
            reason: "operator declined".to_string(),
        },
        Some(&rejected_record),
    )
    .expect("reject lifecycle receipt should parse");
    assert_eq!(reject.0, "workspace_change_rejected");
    assert_eq!(reject.1, "workspace_change__reject");

    let rolled_back_record = json!({
        "change_id": "workspace_change:test",
        "tool_name": "file__edit",
        "path": "src/lib.rs",
        "lifecycle": "rolled_back",
        "edit_count": 1,
        "hunks": []
    })
    .to_string();
    let rollback = workspace_change_lifecycle_receipt_details(
        &AgentTool::WorkspaceChangeRollback {
            change_id: Some("workspace_change:test".to_string()),
            change: None,
            changes: vec![],
        },
        Some(&rolled_back_record),
    )
    .expect("rollback lifecycle receipt should parse");
    assert_eq!(rollback.0, "workspace_change_rolled_back");
    assert_eq!(rollback.1, "workspace_change__rollback");
}

#[test]
fn workspace_change_lifecycle_receipt_details_reject_invalid_transition_payloads() {
    let details = workspace_change_lifecycle_receipt_details(
        &AgentTool::WorkspaceChangeRollback {
            change_id: Some("workspace_change:test".to_string()),
            change: None,
            changes: vec![],
        },
        Some("not-json"),
    );

    assert!(details.is_none());
}

/// Real end-to-end coverage of the managed-session producer chain with NO fixtures:
/// the actual private producer `emit_managed_browser_session` (the exact function
/// `handle_execution_success` invokes on a successful `browser__*` tool) records a
/// managed browser session into real KV, rebuilds the snapshot, and emits a
/// `KernelEvent::RuntimeThreadEvent` carrier; the real event-log bridge resolves the
/// daemon thread and persists it onto `<state_dir>/events`; and the kernel
/// managed-session projection (which `GET /v1/threads/:id/managed-sessions` delegates
/// to verbatim) reads it back. Closes the producer->channel->bridge->jsonl->projection
/// verification gap that the HTTP-only lifecycle ratchet cannot exercise in-process.
mod managed_session_producer_e2e {
    use crate::agentic::runtime::event_log_bridge::persist_runtime_thread_event_json;
    use crate::agentic::runtime::kernel::runtime_managed_session_control::{
        RuntimeManagedSessionProjectionCore, RuntimeManagedSessionProjectionRequest,
        RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION,
    };
    use crate::agentic::runtime::service::RuntimeAgentService;
    use crate::agentic::runtime::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::UnavailableInferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent};
    use ioi_types::error::VmError;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }
        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }
        async fn capture_tree(&self) -> Result<String, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }
        async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }
        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Err(VmError::HostError("noop gui".into()))
        }
        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }
        async fn register_som_overlay(
            &self,
            _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn agent_state(session_id: [u8; 32]) -> AgentState {
        AgentState {
            session_id,
            goal: "managed session producer e2e".to_string(),
            runtime_route_frame: None,
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 1,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            execution_ledger: Default::default(),
            visual_som_map: None,
            visual_semantic_map: None,
            work_graph_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            active_lens: None,
            pending_search_completion: None,
            planner_state: None,
            command_history: Default::default(),
        }
    }

    #[test]
    fn real_browser_producer_bridges_a_managed_session_the_daemon_projection_serves() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().to_string_lossy().to_string();
        let session_id = [0x38u8; 32];

        // Daemon-side precondition: the agent record + runtime_session_id linkage the
        // daemon persists when the runtime-bridge thread starts (RuntimeBridgeThreadStart).
        let agents_dir = temp.path().join("agents");
        std::fs::create_dir_all(&agents_dir).expect("agents dir");
        std::fs::write(
            agents_dir.join("agent_e2e.json"),
            serde_json::to_string(&json!({
                "id": "agent_e2e",
                "object": "ioi.agent",
                "thread_id": "thread_e2e",
                "runtime_session_id": hex::encode(session_id),
            }))
            .expect("agent json"),
        )
        .expect("write agent record");

        // A real service holding a real KernelEvent channel.
        let (tx, mut rx) = tokio::sync::broadcast::channel::<KernelEvent>(16);
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let service = RuntimeAgentService::new(
            gui,
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            Arc::new(UnavailableInferenceRuntime::new("test")),
        )
        .with_event_sender(tx);

        let agent = agent_state(session_id);
        let mut state = IAVLTree::new(HashCommitmentScheme::new());

        // Drive the REAL producer — the exact private fn handle_execution_success calls
        // after a successful browser__* tool. No fixture event is seeded.
        super::super::emit_managed_browser_session(
            &service,
            &mut state,
            &agent,
            "browser__inspect",
            Some("{\"ok\":true}"),
            None,
            1000,
        );

        // The producer emitted a RuntimeThreadEvent carrier on the channel.
        let event = rx.try_recv().expect("producer emitted a KernelEvent");
        let (sent_session, event_json) = match event {
            KernelEvent::RuntimeThreadEvent {
                session_id,
                event_json,
            } => (session_id, event_json),
            other => panic!("expected RuntimeThreadEvent, got {other:?}"),
        };
        assert_eq!(sent_session, session_id);

        // The event-log bridge persists it onto the daemon log (the body of
        // run_event_log_bridge's match arm).
        let admitted = persist_runtime_thread_event_json(&state_dir, &session_id, &event_json)
            .expect("bridge persists")
            .expect("an event was admitted");
        assert_eq!(admitted["event_kind"], "managed_session.projected");
        assert_eq!(admitted["thread_id"], "thread_e2e");
        assert!(admitted
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .is_some());

        // The daemon's projection core (what GET /managed-sessions delegates to) serves it.
        let request: RuntimeManagedSessionProjectionRequest = serde_json::from_value(json!({
            "schema_version": RUNTIME_MANAGED_SESSION_PROJECTION_REQUEST_SCHEMA_VERSION,
            "operation": "managed_session_inspection",
            "operation_kind": "managed_session.inspect",
            "projection_kind": "list",
            "thread_id": "thread_e2e",
            "state_dir": state_dir,
            "source": "runtime.managed_session_state",
        }))
        .expect("projection request");
        let record = RuntimeManagedSessionProjectionCore
            .project(&request)
            .expect("projection");
        assert_eq!(
            record.record_count, 1,
            "the daemon projects the produced managed session"
        );
        let sessions = record.projection.as_array().expect("sessions array");
        assert_eq!(sessions[0]["kind"], "sandbox_browser");
    }
}
