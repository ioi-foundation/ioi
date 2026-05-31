use ioi_types::app::agentic::AgentTool;
use serde_json::json;

pub(super) fn is_toolcat_single_tool_probe(goal: &str) -> bool {
    goal.contains("TOOLCAT_SINGLE_TOOL") || goal.contains("toolcat_tool=")
}

pub(super) fn toolcat_single_tool_target(goal: &str) -> Option<&str> {
    goal.split_whitespace()
        .find_map(|part| part.strip_prefix("toolcat_tool="))
        .map(str::trim)
        .filter(|tool| !tool.is_empty())
}

fn toolcat_single_tool_marker_value(goal: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    goal.split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn toolcat_browser_subagent_tool(goal: &str) -> AgentTool {
    let target_url = toolcat_single_tool_marker_value(goal, "browser_fixture_url")
        .unwrap_or_else(|| "the current browser fixture page".to_string());
    AgentTool::Dynamic(json!({
        "name": "browser__subagent",
        "arguments": {
            "task_name": "tool catalogue browser fixture",
            "task_summary": "Verify browser subagent packaging reaches the fixture page.",
            "recording_name": "toolcat-browser-subagent",
            "task": format!(
                "Use browser__navigate to open {}, then inspect the browser page and report the TOOLCAT_BROWSER_CANARY text without external actions.",
                target_url
            ),
        }
    }))
}

fn toolcat_browser_target_after_navigation(goal: &str, target: &str) -> Option<AgentTool> {
    match target {
        "browser__inspect" => Some(AgentTool::BrowserSnapshot {}),
        "browser__find_text" => Some(AgentTool::BrowserFindText {
            query: "TOOLCAT_BROWSER_CANARY".to_string(),
            scope: Some("document".to_string()),
            scroll: true,
        }),
        "browser__screenshot" => Some(AgentTool::BrowserScreenshot { full_page: false }),
        "browser__list_options" => Some(AgentTool::BrowserDropdownOptions {
            id: None,
            selector: Some("#toolcat-select".to_string()),
            som_id: None,
        }),
        "browser__select_option" => Some(AgentTool::BrowserSelectDropdown {
            id: None,
            selector: Some("#toolcat-select".to_string()),
            som_id: None,
            value: Some("beta".to_string()),
            label: None,
        }),
        "browser__click" => Some(AgentTool::BrowserClick {
            selector: "#toolcat-input".to_string(),
            id: None,
            ids: vec![],
            delay_ms_between_ids: None,
            continue_with: None,
        }),
        "browser__type" => Some(AgentTool::BrowserType {
            text: "typed through browser__type".to_string(),
            selector: Some("#toolcat-input".to_string()),
        }),
        "browser__press_key" => Some(AgentTool::BrowserKey {
            key: "a".to_string(),
            selector: Some("#toolcat-input".to_string()),
            modifiers: Some(vec!["Control".to_string()]),
            continue_with: None,
        }),
        "browser__select" | "browser__copy" => Some(AgentTool::BrowserSelectText {
            selector: Some("#fixture-copy".to_string()),
            start_offset: Some(0),
            end_offset: Some(23),
        }),
        "browser__wait" => Some(AgentTool::BrowserWait {
            ms: None,
            condition: Some("text_present".to_string()),
            selector: None,
            query: Some("TOOLCAT_BROWSER_CANARY".to_string()),
            scope: Some("document".to_string()),
            timeout_ms: Some(3000),
            continue_with: None,
        }),
        "browser__upload" => Some(AgentTool::BrowserUploadFile {
            paths: vec![
                toolcat_single_tool_marker_value(goal, "workspace_fixture_upload")
                    .filter(|path| !path.is_empty())
                    .unwrap_or_else(|| "toolcat-missing-upload-path".to_string()),
            ],
            selector: Some("#toolcat-file".to_string()),
            som_id: None,
        }),
        "browser__list_tabs" | "browser__switch_tab" | "browser__close_tab" => {
            Some(AgentTool::BrowserTabList {})
        }
        "browser__inspect_canvas" => Some(AgentTool::BrowserCanvasSummary {
            selector: "#toolcat-canvas".to_string(),
        }),
        "browser__hover" => Some(AgentTool::BrowserHover {
            selector: Some("#toolcat-button".to_string()),
            id: None,
            duration_ms: Some(100),
            resample_interval_ms: None,
        }),
        "browser__move_pointer" => Some(AgentTool::BrowserMoveMouse {
            observation_ref: "toolcat-observation".to_string(),
            coordinate_space_id: "viewport_css_px".to_string(),
            semantic_id: "toolcat-canvas".to_string(),
            x: 48.0,
            y: 48.0,
        }),
        _ => None,
    }
}

pub(super) fn toolcat_single_tool_reply_tool_name(goal: &str, current_tool_name: &str) -> String {
    if current_tool_name == "system::invalid_tool_call" {
        return toolcat_single_tool_target(goal)
            .unwrap_or(current_tool_name)
            .to_string();
    }
    current_tool_name.to_string()
}

pub(super) fn toolcat_single_tool_failure_reply(current_tool_name: &str) -> String {
    format!(
        "TOOLCAT_SINGLE_TOOL {} live IDE probe failed; concrete trace failure recorded.",
        current_tool_name
    )
}

pub(super) fn toolcat_single_tool_duplicate_after_success_reply(current_tool_name: &str) -> String {
    format!(
        "TOOLCAT_SINGLE_TOOL {} live IDE probe completed; duplicate replay guard recorded in trace.",
        current_tool_name
    )
}

pub(super) fn latest_retained_shell_command_id(text: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok();
    if let Some(command_id) = value
        .as_ref()
        .and_then(|value| value.get("command_id").or_else(|| value.get("commandId")))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
    {
        return Some(command_id.trim().to_string());
    }

    let re = regex::Regex::new(r#"(?i)\\?"command_?id\\?"\s*:\s*\\?"([^"\\\s]+)\\?""#).ok()?;
    re.captures_iter(text)
        .filter_map(|captures| {
            captures
                .get(1)
                .map(|value| value.as_str().trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .last()
}

pub(super) fn latest_child_session_id_hex(text: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok();
    if let Some(child_session_id) = value
        .as_ref()
        .and_then(|value| {
            value
                .get("child_session_id_hex")
                .or_else(|| value.get("childSessionIdHex"))
                .or_else(|| value.get("child_session_id"))
                .or_else(|| value.get("childSessionId"))
        })
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.chars().all(|ch| ch == '0'))
    {
        return Some(child_session_id.to_string());
    }

    let re = regex::Regex::new(
        r#"(?i)\\?"child(?:_?session)?_?id(?:_hex)?\\?"\s*:\s*\\?"([A-Fa-f0-9]{16,64})\\?""#,
    )
    .ok()?;
    re.captures_iter(text)
        .filter_map(|captures| {
            captures
                .get(1)
                .map(|value| value.as_str().trim().to_string())
        })
        .filter(|value| !value.is_empty() && !value.chars().all(|ch| ch == '0'))
        .last()
}

pub(super) fn toolcat_single_tool_retained_shell_followup(
    goal: &str,
    current_tool_name: &str,
    output: Option<&str>,
) -> Option<AgentTool> {
    if !is_toolcat_single_tool_probe(goal) || current_tool_name != "shell__start" {
        return None;
    }
    let target = toolcat_single_tool_target(goal)?;
    if target == "shell__reset" {
        return Some(AgentTool::SysExecSessionReset {});
    }
    let command_id = latest_retained_shell_command_id(output?)?;
    match target {
        "shell__status" => Some(AgentTool::SysExecStatus { command_id }),
        "shell__input" => Some(AgentTool::SysExecInput {
            command_id,
            stdin: "toolcat input\n".to_string(),
        }),
        "shell__terminate" => Some(AgentTool::SysExecTerminate { command_id }),
        _ => None,
    }
}

pub(super) fn toolcat_single_tool_agent_await_followup(
    goal: &str,
    current_tool_name: &str,
    output: Option<&str>,
) -> Option<AgentTool> {
    if !is_toolcat_single_tool_probe(goal) || current_tool_name != "agent__delegate" {
        return None;
    }
    let target = toolcat_single_tool_target(goal)?;
    if target != "agent__await" {
        return None;
    }
    let child_session_id_hex = latest_child_session_id_hex(output?)?;
    Some(AgentTool::AgentAwait {
        child_session_id_hex,
    })
}

pub(super) fn latest_browser_tab_id(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let json_text = if trimmed.starts_with('{') {
        Some(trimmed)
    } else {
        let start = trimmed.find('{')?;
        let end = trimmed.rfind('}')?;
        (start <= end).then_some(&trimmed[start..=end])
    };
    if let Some(value) =
        json_text.and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
    {
        if let Some(tabs) = value.get("tabs").and_then(|value| value.as_array()) {
            let selected = tabs
                .iter()
                .find(|tab| tab.get("active").and_then(|value| value.as_bool()) == Some(false))
                .or_else(|| tabs.first());
            if let Some(tab_id) = selected.and_then(|tab| {
                tab.get("tab_id")
                    .or_else(|| tab.get("tabId"))
                    .and_then(|value| value.as_str())
            }) {
                let tab_id = tab_id.trim();
                if !tab_id.is_empty() {
                    return Some(tab_id.to_string());
                }
            }
        }
    }
    let re = regex::Regex::new(r#"(?i)\\?"tab_?id\\?"\s*:\s*\\?"([^"\\\s]+)\\?""#).ok()?;
    let tab_id = re
        .captures_iter(text)
        .filter_map(|captures| {
            captures
                .get(1)
                .map(|value| value.as_str().trim().to_string())
        })
        .find(|value| !value.is_empty());
    tab_id
}

pub(super) fn toolcat_single_tool_browser_setup_followup(
    goal: &str,
    current_tool_name: &str,
    output: Option<&str>,
) -> Option<AgentTool> {
    if !is_toolcat_single_tool_probe(goal) {
        return None;
    }
    let target = toolcat_single_tool_target(goal)?;
    match (target, current_tool_name) {
        ("browser__paste", "browser__navigate") => Some(AgentTool::OsCopy {
            content: "TOOLCAT_CLIPBOARD_CANARY".to_string(),
        }),
        ("browser__copy" | "browser__paste", "browser__select") => {
            Some(AgentTool::BrowserCopySelection {})
        }
        ("browser__paste", "browser__copy") => Some(AgentTool::BrowserPasteClipboard {
            selector: Some("#toolcat-input".to_string()),
        }),
        ("browser__paste", "clipboard__copy") => Some(AgentTool::BrowserPasteClipboard {
            selector: Some("#toolcat-input".to_string()),
        }),
        ("browser__switch_tab", "browser__list_tabs") => {
            let tab_id = latest_browser_tab_id(output?)?;
            Some(AgentTool::BrowserTabSwitch { tab_id })
        }
        ("browser__close_tab", "browser__list_tabs") => {
            let tab_id = latest_browser_tab_id(output?)?;
            Some(AgentTool::BrowserTabClose {
                tab_id,
                close: true,
            })
        }
        ("browser__back", "browser__navigate") => Some(AgentTool::BrowserGoBack { steps: Some(1) }),
        ("browser__pointer_down" | "browser__pointer_up", "browser__navigate") => {
            Some(AgentTool::BrowserMoveMouse {
                observation_ref: "toolcat-observation".to_string(),
                coordinate_space_id: "viewport_css_px".to_string(),
                semantic_id: "toolcat-canvas".to_string(),
                x: 48.0,
                y: 48.0,
            })
        }
        ("browser__pointer_down" | "browser__pointer_up", "browser__move_pointer") => {
            Some(AgentTool::BrowserMouseDown {
                button: Some("left".to_string()),
            })
        }
        ("browser__pointer_up", "browser__pointer_down") => Some(AgentTool::BrowserMouseUp {
            button: Some("left".to_string()),
        }),
        ("browser__click_at", "browser__navigate") => Some(AgentTool::BrowserSnapshot {}),
        ("browser__click_at", "browser__inspect") => Some(AgentTool::BrowserSyntheticClick {
            id: Some("toolcat-canvas".to_string()),
            observation_ref: None,
            coordinate_space_id: None,
            semantic_id: None,
            x: None,
            y: None,
            continue_with: None,
        }),
        ("browser__scroll", "browser__navigate") => Some(AgentTool::BrowserScroll {
            delta_y: 180,
            delta_x: 0,
        }),
        ("browser__subagent", "browser__navigate") => Some(toolcat_browser_subagent_tool(goal)),
        (_, "browser__navigate") => toolcat_browser_target_after_navigation(goal, target),
        _ => None,
    }
}

pub(super) fn toolcat_single_tool_success_followup(
    goal: &str,
    current_tool_name: &str,
) -> Option<AgentTool> {
    if !is_toolcat_single_tool_probe(goal) || current_tool_name == "chat__reply" {
        return None;
    }
    let target = toolcat_single_tool_target(goal)?;
    if target != current_tool_name {
        return None;
    }
    Some(AgentTool::ChatReply {
        message: format!(
            "TOOLCAT_SINGLE_TOOL {} live IDE probe reached the post-tool final reply path.",
            current_tool_name
        ),
    })
}

pub(super) fn toolcat_single_tool_chat_reply_recovery_followup(
    goal: &str,
    current_tool_name: &str,
) -> Option<AgentTool> {
    if !is_toolcat_single_tool_probe(goal) || current_tool_name == "chat__reply" {
        return None;
    }
    let target = toolcat_single_tool_target(goal)?;
    if target != "chat__reply" {
        return None;
    }
    Some(AgentTool::ChatReply {
        message:
            "TOOLCAT_SINGLE_TOOL chat__reply live IDE probe reached the post-tool final reply path."
                .to_string(),
    })
}
