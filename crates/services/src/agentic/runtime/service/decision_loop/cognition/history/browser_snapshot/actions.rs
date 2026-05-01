pub(super) fn top_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowUp"
    } else {
        "Control+Home"
    }
}

pub(super) fn top_edge_jump_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__press_key {"key":"ArrowUp","modifiers":["Meta"]}"#
    } else {
        r#"browser__press_key {"key":"Home","modifiers":["Control"]}"#
    }
}

pub(super) fn bottom_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowDown"
    } else {
        "Control+End"
    }
}

pub(super) fn bottom_edge_jump_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__press_key {"key":"ArrowDown","modifiers":["Meta"]}"#
    } else {
        r#"browser__press_key {"key":"End","modifiers":["Control"]}"#
    }
}

fn browser_key_tool_call_with_selector(
    key: &str,
    modifiers: &[&str],
    selector: Option<&str>,
    continue_with: Option<serde_json::Value>,
) -> String {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "key".to_string(),
        serde_json::Value::String(key.to_string()),
    );

    if !modifiers.is_empty() {
        payload.insert("modifiers".to_string(), serde_json::json!(modifiers));
    }
    if let Some(selector) = selector.map(str::trim).filter(|value| !value.is_empty()) {
        payload.insert(
            "selector".to_string(),
            serde_json::Value::String(selector.to_string()),
        );
    }
    if let Some(continue_with) = continue_with {
        payload.insert("continue_with".to_string(), continue_with);
    }

    format!(
        "browser__press_key {}",
        serde_json::Value::Object(payload).to_string()
    )
}

fn click_element_follow_up_call(follow_up_id: Option<&str>) -> Option<serde_json::Value> {
    follow_up_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|follow_up_id| {
            serde_json::json!({
                "name": "browser__click",
                "arguments": {
                    "id": follow_up_id,
                }
            })
        })
}

pub(super) fn top_edge_jump_call_for_selector(selector: Option<&str>) -> String {
    if cfg!(target_os = "macos") {
        browser_key_tool_call_with_selector("ArrowUp", &["Meta"], selector, None)
    } else {
        browser_key_tool_call_with_selector("Home", &["Control"], selector, None)
    }
}

pub(super) fn bottom_edge_jump_call_for_selector(selector: Option<&str>) -> String {
    if cfg!(target_os = "macos") {
        browser_key_tool_call_with_selector("ArrowDown", &["Meta"], selector, None)
    } else {
        browser_key_tool_call_with_selector("End", &["Control"], selector, None)
    }
}

pub(super) fn top_edge_jump_call_for_selector_with_follow_up(
    selector: Option<&str>,
    follow_up_id: Option<&str>,
) -> String {
    if cfg!(target_os = "macos") {
        browser_key_tool_call_with_selector(
            "ArrowUp",
            &["Meta"],
            selector,
            click_element_follow_up_call(follow_up_id),
        )
    } else {
        browser_key_tool_call_with_selector(
            "Home",
            &["Control"],
            selector,
            click_element_follow_up_call(follow_up_id),
        )
    }
}

pub(super) fn page_up_then_top_edge_jump_call_for_selector_with_follow_up(
    selector: Option<&str>,
    follow_up_id: Option<&str>,
) -> String {
    let nested_top_edge = if cfg!(target_os = "macos") {
        serde_json::json!({
            "name": "browser__press_key",
            "arguments": {
                "key": "ArrowUp",
                "modifiers": ["Meta"],
                "selector": selector,
                "continue_with": click_element_follow_up_call(follow_up_id),
            }
        })
    } else {
        serde_json::json!({
            "name": "browser__press_key",
            "arguments": {
                "key": "Home",
                "modifiers": ["Control"],
                "selector": selector,
                "continue_with": click_element_follow_up_call(follow_up_id),
            }
        })
    };
    browser_key_tool_call_with_selector("PageUp", &[], selector, Some(nested_top_edge))
}

pub(super) fn page_up_call_for_selector(selector: Option<&str>) -> String {
    browser_key_tool_call_with_selector("PageUp", &[], selector, None)
}
