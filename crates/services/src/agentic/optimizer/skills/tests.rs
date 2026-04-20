use super::*;
use serde_json::json;

#[test]
fn macro_step_browser_navigate_maps_to_browser_interact_bucket() {
    let target =
        action_target_for_macro_step("browser__navigate", &json!({"url": "https://example.com"}));
    assert_eq!(target, ActionTarget::BrowserInteract);
}

#[test]
fn macro_step_net_fetch_maps_to_net_fetch_target() {
    let target = action_target_for_macro_step(
        "http__fetch",
        &json!({"url": "https://example.com", "max_chars": 123}),
    );
    assert_eq!(target, ActionTarget::NetFetch);
}

#[test]
fn macro_step_sys_exec_session_maps_to_sys_exec_target_and_injects_queue_tool_name() {
    let params = json!({"command": "echo", "args": ["ok"]});
    let target = action_target_for_macro_step("shell__start", &params);
    assert_eq!(target, ActionTarget::SysExec);

    let args = macro_step_params_with_queue_metadata("shell__start", &params);
    assert_eq!(
        args.get(QUEUE_TOOL_NAME_KEY).and_then(|v| v.as_str()),
        Some("shell__start")
    );
    assert_eq!(args.get("command").and_then(|v| v.as_str()), Some("echo"));
}

#[test]
fn macro_step_gui_click_element_injects_queue_tool_name() {
    let params = json!({"id": "btn_submit"});
    let target = action_target_for_macro_step("screen__click", &params);
    assert_eq!(target, ActionTarget::GuiClick);

    let args = macro_step_params_with_queue_metadata("screen__click", &params);
    assert_eq!(
        args.get(QUEUE_TOOL_NAME_KEY).and_then(|v| v.as_str()),
        Some(GUI_CLICK_ELEMENT_TOOL_NAME)
    );
    assert_eq!(args.get("id").and_then(|v| v.as_str()), Some("btn_submit"));
}

#[test]
fn macro_step_browser_interact_tool_injects_queue_tool_name() {
    let params = json!({"selector": "select[name='country']"});
    let target = action_target_for_macro_step("browser__list_options", &params);
    assert_eq!(target, ActionTarget::BrowserInteract);

    let args = macro_step_params_with_queue_metadata("browser__list_options", &params);
    assert_eq!(
        args.get(QUEUE_TOOL_NAME_KEY).and_then(|v| v.as_str()),
        Some("browser__list_options")
    );
    assert_eq!(
        args.get("selector").and_then(|v| v.as_str()),
        Some("select[name='country']")
    );
}

#[test]
fn macro_step_media_extract_transcript_maps_to_media_scope_and_injects_queue_tool_name() {
    let params = json!({"url": "https://example.com/video", "language": "en"});
    let target = action_target_for_macro_step("media__extract_transcript", &params);
    assert_eq!(target, ActionTarget::MediaExtractTranscript);

    let args = macro_step_params_with_queue_metadata("media__extract_transcript", &params);
    assert_eq!(
        args.get(QUEUE_TOOL_NAME_KEY).and_then(|v| v.as_str()),
        Some("media__extract_transcript")
    );
    assert_eq!(
        args.get("url").and_then(|v| v.as_str()),
        Some("https://example.com/video")
    );
}

#[test]
fn macro_step_media_extract_multimodal_maps_to_media_scope_and_injects_queue_tool_name() {
    let params = json!({"url": "https://example.com/video", "language": "en", "frame_limit": 6});
    let target = action_target_for_macro_step("media__extract_evidence", &params);
    assert_eq!(target, ActionTarget::MediaExtractMultimodalEvidence);

    let args = macro_step_params_with_queue_metadata("media__extract_evidence", &params);
    assert_eq!(
        args.get(QUEUE_TOOL_NAME_KEY).and_then(|v| v.as_str()),
        Some("media__extract_evidence")
    );
    assert_eq!(
        args.get("url").and_then(|v| v.as_str()),
        Some("https://example.com/video")
    );
}
