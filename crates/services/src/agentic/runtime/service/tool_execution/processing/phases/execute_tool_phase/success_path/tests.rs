use super::{
    compact_tool_history_entry_for_chat, transcript_context_excerpts,
    workspace_edit_receipt_details, TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT,
    TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT,
};
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
