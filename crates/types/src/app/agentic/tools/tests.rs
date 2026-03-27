use super::*;
use crate::app::agentic::AgentToolCall;
use serde_json::json;

fn is_expected_egress_tool_exhaustive(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::OsCopy { .. }
        | AgentTool::BrowserNavigate { .. }
        | AgentTool::WebSearch { .. }
        | AgentTool::WebRead { .. }
        | AgentTool::MediaExtractTranscript { .. }
        | AgentTool::MediaExtractMultimodalEvidence { .. }
        | AgentTool::NetFetch { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::CommerceCheckout { .. } => true,

        AgentTool::Computer(_)
        | AgentTool::FsWrite { .. }
        | AgentTool::FsPatch { .. }
        | AgentTool::FsRead { .. }
        | AgentTool::FsList { .. }
        | AgentTool::FsSearch { .. }
        | AgentTool::FsStat { .. }
        | AgentTool::FsMove { .. }
        | AgentTool::FsCopy { .. }
        | AgentTool::FsDelete { .. }
        | AgentTool::FsCreateDirectory { .. }
        | AgentTool::FsCreateZip { .. }
        | AgentTool::SysExec { .. }
        | AgentTool::SysExecSession { .. }
        | AgentTool::SysExecSessionReset {}
        | AgentTool::SysInstallPackage { .. }
        | AgentTool::SysChangeDir { .. }
        | AgentTool::BrowserSnapshot {}
        | AgentTool::BrowserClick { .. }
        | AgentTool::BrowserClickElement { .. }
        | AgentTool::BrowserHover { .. }
        | AgentTool::BrowserMoveMouse { .. }
        | AgentTool::BrowserMouseDown { .. }
        | AgentTool::BrowserMouseUp { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserKey { .. }
        | AgentTool::BrowserSelectText { .. }
        | AgentTool::BrowserCopySelection {}
        | AgentTool::BrowserPasteClipboard { .. }
        | AgentTool::BrowserFindText { .. }
        | AgentTool::BrowserCanvasSummary { .. }
        | AgentTool::BrowserScreenshot { .. }
        | AgentTool::BrowserWait { .. }
        | AgentTool::BrowserUploadFile { .. }
        | AgentTool::BrowserDropdownOptions { .. }
        | AgentTool::BrowserSelectDropdown { .. }
        | AgentTool::BrowserGoBack { .. }
        | AgentTool::BrowserTabList {}
        | AgentTool::BrowserTabSwitch { .. }
        | AgentTool::BrowserTabClose { .. }
        | AgentTool::GuiClick { .. }
        | AgentTool::GuiType { .. }
        | AgentTool::GuiScroll { .. }
        | AgentTool::GuiSnapshot {}
        | AgentTool::GuiClickElement { .. }
        | AgentTool::UiFind { .. }
        | AgentTool::OsFocusWindow { .. }
        | AgentTool::OsPaste {}
        | AgentTool::OsLaunchApp { .. }
        | AgentTool::MathEval { .. }
        | AgentTool::ChatReply { .. }
        | AgentTool::MemorySearch { .. }
        | AgentTool::MemoryInspect { .. }
        | AgentTool::MemoryReplaceCore { .. }
        | AgentTool::MemoryAppendCore { .. }
        | AgentTool::MemoryClearCore { .. }
        | AgentTool::AgentDelegate { .. }
        | AgentTool::AgentAwait { .. }
        | AgentTool::AgentPause { .. }
        | AgentTool::AgentComplete { .. }
        | AgentTool::AutomationCreateMonitor { .. }
        | AgentTool::SystemFail { .. }
        | AgentTool::Dynamic(_) => false,
    }
}

#[test]
fn browser_navigate_target_maps_to_browser_interact_scope() {
    let tool = AgentTool::BrowserNavigate {
        url: "https://news.ycombinator.com".to_string(),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn web_search_target_maps_to_web_retrieve_scope() {
    let tool = AgentTool::WebSearch {
        query: "internet of intelligence".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: None,
        url: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::WebRetrieve);
}

#[test]
fn web_read_target_maps_to_web_retrieve_scope() {
    let tool = AgentTool::WebRead {
        url: "https://example.com".to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::WebRetrieve);
}

#[test]
fn media_extract_transcript_target_maps_to_media_extract_transcript_scope() {
    let tool = AgentTool::MediaExtractTranscript {
        url: "https://example.com/video".to_string(),
        language: Some("en".to_string()),
        max_chars: Some(4096),
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::MediaExtractTranscript
    );
}

#[test]
fn media_extract_multimodal_target_maps_to_media_extract_multimodal_scope() {
    let tool = AgentTool::MediaExtractMultimodalEvidence {
        url: "https://example.com/video".to_string(),
        language: Some("en".to_string()),
        max_chars: Some(4096),
        frame_limit: Some(6),
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::MediaExtractMultimodalEvidence
    );
}

#[test]
fn net_fetch_target_maps_to_net_fetch_scope() {
    let tool = AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::NetFetch);
}

#[test]
fn browser_snapshot_target_maps_to_browser_inspect_scope() {
    let tool = AgentTool::BrowserSnapshot {};
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInspect);
}

#[test]
fn filesystem_patch_target_maps_to_fs_write_scope() {
    let tool = AgentTool::FsPatch {
        path: "/tmp/demo.txt".to_string(),
        search: "hello".to_string(),
        replace: "world".to_string(),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::FsWrite);
}

#[test]
fn filesystem_search_target_maps_to_fs_read_scope() {
    let tool = AgentTool::FsSearch {
        path: "/tmp".to_string(),
        regex: "needle".to_string(),
        file_pattern: Some("*.rs".to_string()),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::FsRead);
}

#[test]
fn filesystem_stat_target_maps_to_fs_read_scope() {
    let tool = AgentTool::FsStat {
        path: "/tmp/example.pdf".to_string(),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::FsRead);
}

#[test]
fn filesystem_move_target_maps_to_custom_scope() {
    let tool = AgentTool::FsMove {
        source_path: "/tmp/a.txt".to_string(),
        destination_path: "/tmp/b.txt".to_string(),
        overwrite: false,
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("filesystem__move_path".into())
    );
}

#[test]
fn filesystem_copy_target_maps_to_custom_scope() {
    let tool = AgentTool::FsCopy {
        source_path: "/tmp/a.txt".to_string(),
        destination_path: "/tmp/b.txt".to_string(),
        overwrite: false,
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("filesystem__copy_path".into())
    );
}

#[test]
fn filesystem_delete_target_maps_to_fs_write_scope() {
    let tool = AgentTool::FsDelete {
        path: "/tmp/a.txt".to_string(),
        recursive: false,
        ignore_missing: false,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::FsWrite);
}

#[test]
fn google_bigquery_dynamic_target_distinguishes_read_and_write_queries() {
    let read_tool = AgentTool::Dynamic(serde_json::json!({
        "name": "connector__google__bigquery_execute_query",
        "arguments": { "query": "select * from dataset.table" }
    }));
    assert_eq!(
        read_tool.target(),
        crate::app::ActionTarget::Custom("connector__google__bigquery_execute_query__read".into())
    );

    let write_tool = AgentTool::Dynamic(serde_json::json!({
        "name": "connector__google__bigquery_execute_query",
        "arguments": { "query": "delete from dataset.table where id = 1" }
    }));
    assert_eq!(
        write_tool.target(),
        crate::app::ActionTarget::Custom("connector__google__bigquery_execute_query__write".into())
    );
}

#[test]
fn filesystem_create_directory_target_maps_to_custom_scope() {
    let tool = AgentTool::FsCreateDirectory {
        path: "/tmp/work".to_string(),
        recursive: true,
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("filesystem__create_directory".into())
    );
}

#[test]
fn filesystem_create_zip_target_maps_to_custom_scope() {
    let tool = AgentTool::FsCreateZip {
        source_path: "/tmp/projects".to_string(),
        destination_zip_path: "/tmp/projects.zip".to_string(),
        overwrite: false,
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("filesystem__create_zip".into())
    );
}

#[test]
fn browser_click_element_target_maps_to_browser_click_element_scope() {
    let tool = AgentTool::BrowserClickElement {
        id: Some("btn_submit".to_string()),
        ids: Vec::new(),
        delay_ms_between_ids: None,
        continue_with: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_click_element_serializes_timed_sequence() {
    let tool = AgentTool::BrowserClickElement {
        id: None,
        ids: vec!["btn_one".to_string(), "btn_two".to_string()],
        delay_ms_between_ids: Some(2_000),
        continue_with: None,
    };

    let payload = serde_json::to_value(&tool).expect("serialize tool");
    assert_eq!(payload["name"], "browser__click_element");
    assert_eq!(payload["arguments"]["ids"], json!(["btn_one", "btn_two"]));
    assert_eq!(payload["arguments"]["delay_ms_between_ids"], 2_000);
}

#[test]
fn browser_click_element_serializes_follow_up_browser_action() {
    let tool = AgentTool::BrowserClickElement {
        id: Some("grp_start".to_string()),
        ids: Vec::new(),
        delay_ms_between_ids: None,
        continue_with: Some(AgentToolCall {
            name: "browser__click_element".to_string(),
            arguments: json!({
                "ids": ["btn_one", "btn_two"],
                "delay_ms_between_ids": 2_000
            }),
        }),
    };

    let payload = serde_json::to_value(&tool).expect("serialize tool");
    assert_eq!(payload["name"], "browser__click_element");
    assert_eq!(payload["arguments"]["id"], "grp_start");
    assert_eq!(
        payload["arguments"]["continue_with"]["name"],
        "browser__click_element"
    );
    assert_eq!(
        payload["arguments"]["continue_with"]["arguments"]["ids"],
        json!(["btn_one", "btn_two"])
    );
    assert_eq!(
        payload["arguments"]["continue_with"]["arguments"]["delay_ms_between_ids"],
        2_000
    );
}

#[test]
fn browser_pointer_primitives_target_map_to_browser_interact_scope() {
    let hover_tool = AgentTool::BrowserHover {
        selector: Some("#highlight".to_string()),
        id: None,
        duration_ms: None,
        resample_interval_ms: None,
    };
    let move_tool = AgentTool::BrowserMoveMouse { x: 120.0, y: 80.0 };
    let down_tool = AgentTool::BrowserMouseDown {
        button: Some("left".to_string()),
    };
    let up_tool = AgentTool::BrowserMouseUp {
        button: Some("left".to_string()),
    };

    assert_eq!(
        hover_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
    assert_eq!(
        move_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
    assert_eq!(
        down_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
    assert_eq!(up_tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_hover_serializes_tracking_window() {
    let tool = AgentTool::BrowserHover {
        selector: None,
        id: Some("grp_circ".to_string()),
        duration_ms: Some(3_000),
        resample_interval_ms: Some(75),
    };

    let payload = serde_json::to_value(&tool).expect("serialize tool");
    assert_eq!(payload["name"], "browser__hover");
    assert_eq!(payload["arguments"]["id"], "grp_circ");
    assert_eq!(payload["arguments"]["duration_ms"], 3_000);
    assert_eq!(payload["arguments"]["resample_interval_ms"], 75);
}

#[test]
fn browser_scroll_target_maps_to_browser_scroll_scope() {
    let tool = AgentTool::BrowserScroll {
        delta_x: 0,
        delta_y: 480,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_type_target_maps_to_custom_browser_type_tool() {
    let tool = AgentTool::BrowserType {
        text: "hello".to_string(),
        selector: Some("input[name='q']".to_string()),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_key_target_maps_to_custom_browser_key_tool() {
    let tool = AgentTool::BrowserKey {
        key: "Enter".to_string(),
        selector: None,
        modifiers: None,
        continue_with: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_key_serializes_follow_up_browser_action() {
    let tool = AgentTool::BrowserKey {
        key: "Home".to_string(),
        selector: Some("[id=\"text-area\"]".to_string()),
        modifiers: Some(vec!["Control".to_string()]),
        continue_with: Some(AgentToolCall {
            name: "browser__click_element".to_string(),
            arguments: json!({
                "id": "btn_submit"
            }),
        }),
    };

    let payload = serde_json::to_value(&tool).expect("serialize tool");
    assert_eq!(payload["name"], "browser__key");
    assert_eq!(payload["arguments"]["key"], "Home");
    assert_eq!(payload["arguments"]["selector"], "[id=\"text-area\"]");
    assert_eq!(payload["arguments"]["modifiers"], json!(["Control"]));
    assert_eq!(
        payload["arguments"]["continue_with"]["name"],
        "browser__click_element"
    );
    assert_eq!(
        payload["arguments"]["continue_with"]["arguments"]["id"],
        "btn_submit"
    );
}

#[test]
fn browser_selection_and_clipboard_tools_map_to_browser_interact_scope() {
    let select_tool = AgentTool::BrowserSelectText {
        selector: Some("#editor".to_string()),
        start_offset: Some(0),
        end_offset: Some(5),
    };
    let copy_tool = AgentTool::BrowserCopySelection {};
    let paste_tool = AgentTool::BrowserPasteClipboard {
        selector: Some("#destination".to_string()),
    };

    assert_eq!(
        select_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
    assert_eq!(
        copy_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
    assert_eq!(
        paste_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
}

#[test]
fn browser_find_text_target_maps_to_browser_interact_scope() {
    let tool = AgentTool::BrowserFindText {
        query: "weather".to_string(),
        scope: Some("visible".to_string()),
        scroll: true,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_canvas_summary_target_maps_to_browser_inspect_scope() {
    let tool = AgentTool::BrowserCanvasSummary {
        selector: "#canvas".to_string(),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInspect);
}

#[test]
fn browser_screenshot_target_maps_to_browser_interact_scope() {
    let tool = AgentTool::BrowserScreenshot { full_page: true };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInspect);
}

#[test]
fn browser_wait_target_maps_to_browser_interact_scope() {
    let tool = AgentTool::BrowserWait {
        ms: Some(250),
        condition: None,
        selector: None,
        query: None,
        scope: None,
        timeout_ms: None,
        continue_with: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_wait_serializes_follow_up_browser_action() {
    let tool = AgentTool::BrowserWait {
        ms: Some(2000),
        condition: None,
        selector: None,
        query: None,
        scope: None,
        timeout_ms: None,
        continue_with: Some(AgentToolCall {
            name: "browser__click_element".to_string(),
            arguments: json!({ "id": "btn_two" }),
        }),
    };

    let payload = serde_json::to_value(&tool).expect("serialize tool");
    assert_eq!(payload["name"], "browser__wait");
    assert_eq!(
        payload["arguments"]["continue_with"]["name"],
        "browser__click_element"
    );
    assert_eq!(
        payload["arguments"]["continue_with"]["arguments"]["id"],
        "btn_two"
    );
}

#[test]
fn browser_synthetic_click_serializes_follow_up_browser_action() {
    let tool = AgentTool::BrowserSyntheticClick {
        id: None,
        x: Some(85.012),
        y: Some(105.824),
        continue_with: Some(AgentToolCall {
            name: "browser__click_element".to_string(),
            arguments: json!({ "id": "btn_submit" }),
        }),
    };

    let payload = serde_json::to_value(&tool).expect("serialize tool");
    assert_eq!(payload["name"], "browser__synthetic_click");
    assert_eq!(
        payload["arguments"]["continue_with"]["name"],
        "browser__click_element"
    );
    assert_eq!(
        payload["arguments"]["continue_with"]["arguments"]["id"],
        "btn_submit"
    );
}

#[test]
fn browser_synthetic_click_serializes_grounded_target_id() {
    let tool = AgentTool::BrowserSyntheticClick {
        id: Some("grp_blue_circle".to_string()),
        x: None,
        y: None,
        continue_with: None,
    };

    let payload = serde_json::to_value(&tool).expect("serialize tool");
    assert_eq!(payload["name"], "browser__synthetic_click");
    assert_eq!(payload["arguments"]["id"], "grp_blue_circle");
    assert!(payload["arguments"].get("x").is_none(), "{payload}");
    assert!(payload["arguments"].get("y").is_none(), "{payload}");
}

#[test]
fn browser_upload_target_maps_to_browser_interact_scope() {
    let tool = AgentTool::BrowserUploadFile {
        paths: vec!["/tmp/demo.txt".to_string()],
        selector: Some("input[type='file']".to_string()),
        som_id: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_dropdown_tools_target_map_to_browser_interact_scope() {
    let options_tool = AgentTool::BrowserDropdownOptions {
        id: None,
        selector: Some("select[name='country']".to_string()),
        som_id: None,
    };
    let select_tool = AgentTool::BrowserSelectDropdown {
        id: None,
        selector: Some("select[name='country']".to_string()),
        som_id: None,
        value: Some("US".to_string()),
        label: None,
    };

    assert_eq!(
        options_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
    assert_eq!(
        select_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
}

#[test]
fn browser_go_back_target_maps_to_browser_interact_scope() {
    let tool = AgentTool::BrowserGoBack { steps: Some(2) };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_tab_tools_target_map_to_browser_interact_scope() {
    let list_tool = AgentTool::BrowserTabList {};
    let switch_tool = AgentTool::BrowserTabSwitch {
        tab_id: "tab-a".to_string(),
    };
    let close_tool = AgentTool::BrowserTabClose {
        tab_id: "tab-b".to_string(),
        close: true,
    };

    assert_eq!(
        list_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
    assert_eq!(
        switch_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
    assert_eq!(
        close_tool.target(),
        crate::app::ActionTarget::BrowserInteract
    );
}

#[test]
fn math_eval_target_maps_to_math_eval_scope() {
    let tool = AgentTool::MathEval {
        expression: "247 * 38".to_string(),
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("math::eval".to_string())
    );
}

#[test]
fn os_launch_app_target_maps_to_custom_os_launch_scope() {
    let tool = AgentTool::OsLaunchApp {
        app_name: "calculator".to_string(),
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("os::launch_app".to_string())
    );
}

#[test]
fn pii_egress_specs_cover_known_egress_tools() {
    use crate::app::agentic::security::PiiTarget;
    use crate::app::ActionTarget;

    assert!(is_expected_egress_tool_exhaustive(&AgentTool::OsCopy {
        content: "secret".to_string()
    }));
    assert!(is_expected_egress_tool_exhaustive(
        &AgentTool::BrowserNavigate {
            url: "https://example.com".to_string()
        }
    ));
    assert!(is_expected_egress_tool_exhaustive(&AgentTool::WebSearch {
        query: "internet of intelligence".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: None,
        url: Some("https://duckduckgo.com/?q=internet+of+intelligence".to_string()),
    }));
    assert!(is_expected_egress_tool_exhaustive(&AgentTool::WebRead {
        url: "https://example.com".to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    }));
    assert!(is_expected_egress_tool_exhaustive(&AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    }));
    assert!(is_expected_egress_tool_exhaustive(
        &AgentTool::BrowserType {
            text: "hello".to_string(),
            selector: None,
        }
    ));
    assert!(is_expected_egress_tool_exhaustive(
        &AgentTool::CommerceCheckout {
            merchant_url: "https://merchant.example".to_string(),
            items: vec![],
            total_amount: 1.0,
            currency: "USD".to_string(),
            buyer_email: Some("buyer@example.com".to_string()),
        }
    ));
    assert!(!is_expected_egress_tool_exhaustive(&AgentTool::ChatReply {
        message: "ok".to_string(),
    }));

    let os_copy_specs = AgentTool::OsCopy {
        content: "secret".to_string(),
    }
    .pii_egress_specs();
    assert_eq!(os_copy_specs.len(), 1);
    assert_eq!(os_copy_specs[0].field, PiiEgressField::OsCopyContent);
    assert!(os_copy_specs[0].supports_transform);
    assert_eq!(
        os_copy_specs[0].target,
        PiiTarget::Action(ActionTarget::ClipboardWrite)
    );

    let nav_specs = AgentTool::BrowserNavigate {
        url: "https://example.com".to_string(),
    }
    .pii_egress_specs();
    assert_eq!(nav_specs.len(), 1);
    assert_eq!(nav_specs[0].field, PiiEgressField::BrowserNavigateUrl);
    assert!(!nav_specs[0].supports_transform);
    assert_eq!(
        nav_specs[0].target,
        PiiTarget::Action(ActionTarget::BrowserInteract)
    );

    let web_search_specs = AgentTool::WebSearch {
        query: "internet of intelligence".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: None,
        url: Some("https://duckduckgo.com/?q=internet+of+intelligence".to_string()),
    }
    .pii_egress_specs();
    assert_eq!(web_search_specs.len(), 1);
    assert_eq!(web_search_specs[0].field, PiiEgressField::WebSearchUrl);
    assert!(!web_search_specs[0].supports_transform);
    assert_eq!(
        web_search_specs[0].target,
        PiiTarget::Action(ActionTarget::WebRetrieve)
    );

    let web_read_specs = AgentTool::WebRead {
        url: "https://example.com".to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    }
    .pii_egress_specs();
    assert_eq!(web_read_specs.len(), 1);
    assert_eq!(web_read_specs[0].field, PiiEgressField::WebReadUrl);
    assert!(!web_read_specs[0].supports_transform);
    assert_eq!(
        web_read_specs[0].target,
        PiiTarget::Action(ActionTarget::WebRetrieve)
    );

    let media_specs = AgentTool::MediaExtractTranscript {
        url: "https://example.com/video".to_string(),
        language: Some("en".to_string()),
        max_chars: Some(4096),
    }
    .pii_egress_specs();
    assert_eq!(media_specs.len(), 1);
    assert_eq!(
        media_specs[0].field,
        PiiEgressField::MediaExtractTranscriptUrl
    );
    assert!(!media_specs[0].supports_transform);
    assert_eq!(
        media_specs[0].target,
        PiiTarget::Action(ActionTarget::MediaExtractTranscript)
    );

    let multimodal_specs = AgentTool::MediaExtractMultimodalEvidence {
        url: "https://example.com/video".to_string(),
        language: Some("en".to_string()),
        max_chars: Some(4096),
        frame_limit: Some(6),
    }
    .pii_egress_specs();
    assert_eq!(multimodal_specs.len(), 1);
    assert_eq!(
        multimodal_specs[0].field,
        PiiEgressField::MediaExtractMultimodalEvidenceUrl
    );
    assert!(!multimodal_specs[0].supports_transform);
    assert_eq!(
        multimodal_specs[0].target,
        PiiTarget::Action(ActionTarget::MediaExtractMultimodalEvidence)
    );

    let net_fetch_specs = AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    }
    .pii_egress_specs();
    assert_eq!(net_fetch_specs.len(), 1);
    assert_eq!(net_fetch_specs[0].field, PiiEgressField::NetFetchUrl);
    assert!(!net_fetch_specs[0].supports_transform);
    assert_eq!(
        net_fetch_specs[0].target,
        PiiTarget::Action(ActionTarget::NetFetch)
    );

    let browser_type_specs = AgentTool::BrowserType {
        text: "hello".to_string(),
        selector: None,
    }
    .pii_egress_specs();
    assert_eq!(browser_type_specs.len(), 1);
    assert_eq!(browser_type_specs[0].field, PiiEgressField::BrowserTypeText);
    assert!(browser_type_specs[0].supports_transform);
    assert_eq!(
        browser_type_specs[0].target,
        PiiTarget::Action(ActionTarget::BrowserInteract)
    );

    let checkout_specs = AgentTool::CommerceCheckout {
        merchant_url: "https://merchant.example".to_string(),
        items: vec![],
        total_amount: 1.0,
        currency: "USD".to_string(),
        buyer_email: Some("buyer@example.com".to_string()),
    }
    .pii_egress_specs();
    assert_eq!(checkout_specs.len(), 2);
    assert!(checkout_specs
        .iter()
        .any(|s| s.field == PiiEgressField::CommerceBuyerEmail && s.supports_transform));
    assert!(checkout_specs
        .iter()
        .any(|s| s.field == PiiEgressField::CommerceMerchantUrl && !s.supports_transform));
}

#[test]
fn pii_egress_field_mut_maps_to_expected_text_slots() {
    let mut tool = AgentTool::CommerceCheckout {
        merchant_url: "https://merchant.example".to_string(),
        items: vec![],
        total_amount: 1.0,
        currency: "USD".to_string(),
        buyer_email: Some("buyer@example.com".to_string()),
    };

    let merchant = tool
        .pii_egress_field_mut(PiiEgressField::CommerceMerchantUrl)
        .expect("merchant url");
    *merchant = "https://clean.example".to_string();

    let buyer = tool
        .pii_egress_field_mut(PiiEgressField::CommerceBuyerEmail)
        .expect("buyer email");
    *buyer = "clean@example.com".to_string();

    match tool {
        AgentTool::CommerceCheckout {
            merchant_url,
            buyer_email,
            ..
        } => {
            assert_eq!(merchant_url, "https://clean.example");
            assert_eq!(buyer_email.as_deref(), Some("clean@example.com"));
        }
        _ => panic!("unexpected tool variant"),
    }

    let mut net_fetch = AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    };
    let url = net_fetch
        .pii_egress_field_mut(PiiEgressField::NetFetchUrl)
        .expect("net fetch url");
    *url = "https://clean.example".to_string();
    match net_fetch {
        AgentTool::NetFetch { url, .. } => assert_eq!(url, "https://clean.example"),
        _ => panic!("unexpected tool variant"),
    }

    let mut media_tool = AgentTool::MediaExtractTranscript {
        url: "https://example.com/video".to_string(),
        language: Some("en".to_string()),
        max_chars: Some(1200),
    };
    let media_url = media_tool
        .pii_egress_field_mut(PiiEgressField::MediaExtractTranscriptUrl)
        .expect("media transcript url");
    *media_url = "https://clean.example/video".to_string();
    match media_tool {
        AgentTool::MediaExtractTranscript { url, .. } => {
            assert_eq!(url, "https://clean.example/video")
        }
        _ => panic!("unexpected tool variant"),
    }

    let mut multimodal_tool = AgentTool::MediaExtractMultimodalEvidence {
        url: "https://example.com/video".to_string(),
        language: Some("en".to_string()),
        max_chars: Some(1200),
        frame_limit: Some(6),
    };
    let multimodal_url = multimodal_tool
        .pii_egress_field_mut(PiiEgressField::MediaExtractMultimodalEvidenceUrl)
        .expect("media multimodal url");
    *multimodal_url = "https://clean.example/video".to_string();
    match multimodal_tool {
        AgentTool::MediaExtractMultimodalEvidence { url, .. } => {
            assert_eq!(url, "https://clean.example/video")
        }
        _ => panic!("unexpected tool variant"),
    }
}

#[test]
fn media_extract_tools_are_reserved_native_names() {
    assert!(AgentTool::is_reserved_tool_name(
        "media__extract_transcript"
    ));
    assert!(AgentTool::is_reserved_tool_name(
        "media__extract_multimodal_evidence"
    ));
}
