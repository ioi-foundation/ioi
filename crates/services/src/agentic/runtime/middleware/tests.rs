use super::*;
use ioi_types::app::agentic::{AgentTool, ScreenAction};
use serde_json::json;

fn assert_rejects(input: &str, expected: &str) {
    let err = ToolNormalizer::normalize(input).expect_err("expected strict normalizer rejection");
    let message = err.to_string();
    assert!(
        message.contains(expected),
        "expected error to contain {:?}, got {:?}",
        expected,
        message
    );
}

#[test]
fn test_normalize_clean_json() {
    let input = r#"{"name": "screen", "arguments": {"action": "screenshot"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::Screen(ScreenAction::Screenshot) => {}
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_markdown() {
    let input = "```json\n{\"name\": \"shell__run\", \"arguments\": {\"command\": \"ls\"}}\n```";
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysExec { command, .. } => assert_eq!(command, "ls"),
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_explanatory_prefix_with_fenced_json() {
    let input = "I should inspect the root package file first.\n\n```json\n{\"name\":\"file__read\",\"arguments\":{\"path\":\"./package.json\"}}\n```";
    let result = normalize_tool_call_with_observation(input).unwrap();
    match result.tool {
        AgentTool::FsRead { path } => assert_eq!(path, "./package.json"),
        other => panic!("Expected FsRead, got {:?}", other),
    }
    assert_eq!(result.observation.raw_name.as_deref(), Some("file__read"));
    assert_eq!(
        result.observation.normalized_name.as_deref(),
        Some("file__read")
    );
}

#[test]
fn test_flat_top_level_arguments_for_file_read_are_rejected() {
    let input = r#"{
        "tool":"file__read",
        "path":"./package.json"
    }"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_tool_name_line_with_fenced_arguments_is_rejected() {
    let input = "file__list\n```json\n{\"path\":\"./ioi-data\"}\n```";
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_tool_name_line_with_argument_aliases_is_rejected() {
    let input =
        "file__search\n{\"root\":\".\",\"query\":\"package\\\\.json\",\"glob\":\"package.json\"}";
    assert_rejects(input, "JSON Syntax Error");
}

#[test]
fn test_sys_exec_single_underscore_alias_is_rejected() {
    let input = r#"{"name":"sys_exec","arguments":{"command":"ls"}}"#;
    assert_rejects(input, "legacy tool alias");
}

#[test]
fn test_sys_exec_colon_alias_is_rejected() {
    let input = r#"{"name":"sys::exec","arguments":{"command":"pwd"}}"#;
    assert_rejects(input, "legacy tool alias");
}

#[test]
fn test_normalize_openai_tool_calls_wrapper_with_string_arguments() {
    let input = r#"{
          "tool_calls": [
            {
              "id": "call_1",
              "type": "function",
              "function": {
                "name": "shell__run",
                "arguments": "{\"command\":\"ls\",\"args\":[]}"
              }
            }
          ]
        }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysExec { command, args, .. } => {
            assert_eq!(command, "ls");
            assert!(args.is_empty());
        }
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_openai_function_wrapper_with_object_arguments() {
    let input = r#"{
          "type": "function",
          "function": {
            "name": "browser__navigate",
            "arguments": { "url": "https://example.com" }
          }
        }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserNavigate { url } => assert_eq!(url, "https://example.com"),
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_anthropic_input_alias_is_rejected() {
    let input = r#"{"name":"shell__run","input":{"command":"echo","args":["hi"]}}"#;
    assert_rejects(input, "built-in tool");
}

#[test]
fn test_normalize_arguments_json_string() {
    let input = r#"{"name":"shell__run","arguments":"{\"command\":\"pwd\"}"}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysExec { command, .. } => assert_eq!(command, "pwd"),
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_parameters_alias_is_rejected() {
    let input = r#"{"name": "screen__type", "parameters": {"text": "hello"}}"#;
    assert_rejects(input, "built-in tool");
}

#[test]
fn test_normalize_file_search_pattern_alias_with_observation() {
    let input = r#"{"name":"file__search","arguments":{"path":".","pattern":"package\\.json"}}"#;
    let result = normalize_tool_call_with_observation(input).unwrap();
    match result.tool {
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            assert_eq!(path, ".");
            assert_eq!(regex, "package\\.json");
            assert_eq!(file_pattern, None);
        }
        other => panic!("Expected FsSearch, got {:?}", other),
    }
    assert_eq!(result.observation.raw_name.as_deref(), Some("file__search"));
    assert_eq!(
        result.observation.normalized_name.as_deref(),
        Some("file__search")
    );
    assert!(result
        .observation
        .labels
        .contains(&"file_search_arguments_normalized".to_string()));
}

#[test]
fn test_normalize_file_search_glob_aliases() {
    let input = r#"{
        "name":"file__search",
        "arguments":{
            "root":".",
            "query":"TODO",
            "glob":"*.rs"
        }
    }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            assert_eq!(path, ".");
            assert_eq!(regex, "TODO");
            assert_eq!(file_pattern.as_deref(), Some("*.rs"));
        }
        other => panic!("Expected FsSearch, got {:?}", other),
    }
}

#[test]
fn test_tool_and_args_aliases_for_file_search_are_rejected() {
    let input = r#"{
        "tool":"file__search",
        "args":{
            "pattern":"package\\.json",
            "recursive":true
        }
    }"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_single_key_file_search_wrapper_is_rejected() {
    let input = r#"{
        "file__search":{
            "path":"./",
            "pattern":"package\\.json",
            "recursive":true
        }
    }"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_normalize_prefers_tool_field_over_noncanonical_name() {
    let input = r#"{
        "name":"find_npm_scripts",
        "tool":"file__search",
        "arguments":{"path":".","query":"package.json"}
    }"#;
    let result = normalize_tool_call_with_observation(input).unwrap();
    match result.tool {
        AgentTool::Dynamic(value) => {
            assert_eq!(
                value.get("name").and_then(|v| v.as_str()),
                Some("find_npm_scripts")
            );
            assert_eq!(
                value.pointer("/arguments/query").and_then(|v| v.as_str()),
                Some("package.json")
            );
        }
        other => panic!("Expected Dynamic, got {:?}", other),
    }
    assert_eq!(
        result.observation.raw_name.as_deref(),
        Some("find_npm_scripts")
    );
    assert_eq!(
        result.observation.normalized_name.as_deref(),
        Some("find_npm_scripts")
    );
}

#[test]
fn test_file_list_with_pattern_does_not_promote_to_search() {
    let input = r#"{
        "tool":"file__list",
        "args":{"path":".","pattern":"package.json"}
    }"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_observation_rejects_common_aliases_without_migration() {
    let input = r#"{"recipient_name":"functions.chat__reply","parameters":{"message":"hello"}}"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_normalize_with_observation_records_ui_click_lowering() {
    let input = r#"{"name":"ui__click","arguments":{"x":"24","y":"48"}}"#;
    let result = normalize_tool_call_with_observation(input).unwrap();
    match result.tool {
        AgentTool::GuiClick { x, y, .. } => {
            assert_eq!(x, 24);
            assert_eq!(y, 48);
        }
        other => panic!("Expected GuiClick, got {:?}", other),
    }
    assert_eq!(result.observation.raw_name.as_deref(), Some("ui__click"));
    assert_eq!(
        result.observation.normalized_name.as_deref(),
        Some("screen__click_at")
    );
    assert!(result
        .observation
        .labels
        .contains(&"ui_click_to_screen_click_at".to_string()));
}

#[test]
fn test_functions_prefix_is_rejected() {
    let input = r#"{"name": "functions.chat__reply", "arguments": {"message": "hello"}}"#;
    assert_rejects(input, "legacy tool alias");
}

#[test]
fn test_recipient_name_is_rejected() {
    let input =
        r#"{"recipient_name": "functions.computer", "parameters": {"action": "screenshot"}}"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_flat_sys_exec_payload_is_rejected() {
    let input = r#"{"command": "gnome-calculator", "args": [], "detach": true}"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_result_only_payload_is_rejected() {
    let input = r#"{"result":"Timer has been scheduled."}"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_schema_violation_for_builtin_tool_is_rejected() {
    // Missing required field for deterministic tool name should be a hard schema error
    // (not `Dynamic` fallback routed to MCP).
    let input = r#"{"name": "browser__navigate", "arguments": {}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err.to_string().contains("Schema Validation Error"));
    assert!(err.to_string().contains("browser__navigate"));
}

#[test]
fn test_normalize_browser_wait_with_follow_up_click_element() {
    let input = r#"{
        "name": "browser__wait",
        "arguments": {
            "ms": 2000,
            "continue_with": {
                "name": "browser__click",
                "arguments": { "id": "btn_two" }
            }
        }
    }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserWait {
            ms, continue_with, ..
        } => {
            assert_eq!(ms, Some(2000));
            let continue_with = continue_with.expect("follow-up should be present");
            assert_eq!(continue_with.name, "browser__click");
            assert_eq!(continue_with.arguments["id"], "btn_two");
        }
        other => panic!("Expected BrowserWait, got {:?}", other),
    }
}

#[test]
fn test_normalize_browser_wait_with_follow_up_shorthand_arguments() {
    let input = r#"{
        "name": "browser__wait",
        "arguments": {
            "ms": 2000,
            "continue_with": {
                "name": "browser__click",
                "id": "btn_two"
            }
        }
    }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserWait {
            ms, continue_with, ..
        } => {
            assert_eq!(ms, Some(2000));
            let continue_with = continue_with.expect("follow-up should be present");
            assert_eq!(continue_with.name, "browser__click");
            assert_eq!(continue_with.arguments, json!({ "id": "btn_two" }));
        }
        other => panic!("Expected BrowserWait, got {:?}", other),
    }
}

#[test]
fn test_normalize_browser_click_element_with_follow_up_shorthand_arguments() {
    let input = r#"{
        "name": "browser__click",
        "arguments": {
            "id": "grp_start",
            "continue_with": {
                "name": "browser__click",
                "ids": ["btn_one", "btn_two"],
                "delay_ms_between_ids": 2000
            }
        }
    }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserClick {
            id, continue_with, ..
        } => {
            assert_eq!(id.as_deref(), Some("grp_start"));
            let continue_with = continue_with.expect("follow-up should be present");
            assert_eq!(continue_with.name, "browser__click");
            assert_eq!(
                continue_with.arguments,
                json!({
                    "ids": ["btn_one", "btn_two"],
                    "delay_ms_between_ids": 2000
                })
            );
        }
        other => panic!("Expected BrowserClick, got {:?}", other),
    }
}

#[test]
fn test_normalize_browser_key_with_nested_follow_up_shorthand_arguments() {
    let input = r#"{
        "name": "browser__press_key",
        "arguments": {
            "key": "PageUp",
            "selector": "[id=\"text-area\"]",
            "continue_with": {
                "name": "browser__press_key",
                "key": "Home",
                "modifiers": ["Control"],
                "selector": "[id=\"text-area\"]",
                "continue_with": {
                    "name": "browser__click",
                    "id": "btn_submit"
                }
            }
        }
    }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserKey {
            key,
            selector,
            continue_with,
            ..
        } => {
            assert_eq!(key, "PageUp");
            assert_eq!(selector.as_deref(), Some("[id=\"text-area\"]"));
            let continue_with = continue_with.expect("follow-up should be present");
            assert_eq!(continue_with.name, "browser__press_key");
            assert_eq!(
                continue_with.arguments,
                json!({
                    "key": "Home",
                    "modifiers": ["Control"],
                    "selector": "[id=\"text-area\"]",
                    "continue_with": {
                        "name": "browser__click",
                        "id": "btn_submit"
                    }
                })
            );
        }
        other => panic!("Expected BrowserKey, got {:?}", other),
    }
}

#[test]
fn test_normalize_browser_wait_drops_empty_follow_up_shorthand() {
    let input = r#"{
        "name": "browser__wait",
        "arguments": {
            "ms": 2000,
            "continue_with": {
                "name": "browser__click"
            }
        }
    }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserWait {
            ms, continue_with, ..
        } => {
            assert_eq!(ms, Some(2000));
            assert!(continue_with.is_none());
        }
        other => panic!("Expected BrowserWait, got {:?}", other),
    }
}

#[test]
fn test_normalize_browser_click_element_drops_empty_follow_up_shorthand() {
    let input = r#"{
        "name": "browser__click",
        "arguments": {
            "id": "grp_start",
            "continue_with": {
                "name": "browser__click"
            }
        }
    }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserClick {
            id, continue_with, ..
        } => {
            assert_eq!(id.as_deref(), Some("grp_start"));
            assert!(continue_with.is_none());
        }
        other => panic!("Expected BrowserClick, got {:?}", other),
    }
}

#[test]
fn test_dynamic_tool_without_name_is_rejected() {
    let input = r#"{"arguments":{"query":"latest news"}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err
        .to_string()
        .contains("dynamic tool calls require a non-empty string 'name'"));
}

#[test]
fn test_dynamic_tool_with_blank_name_is_rejected() {
    let input = r#"{"name":"   ","arguments":{"query":"latest news"}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err.to_string().contains("Schema Validation Error"));
    assert!(err
        .to_string()
        .contains("dynamic tool calls require a non-empty string 'name'"));
}

#[test]
fn test_dynamic_tool_unknown_name_is_rejected() {
    let input = r#"{"name":"Custom(\"unknown\")","arguments":{"query":"latest news"}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err.to_string().contains("Schema Validation Error"));
    assert!(err.to_string().contains("invalid"));
}

#[test]
fn test_single_key_tool_wrapper_for_builtin_tool_is_rejected() {
    let input = r#"{"file__list":{"path":"./ioi-data"}}"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_single_key_tool_wrapper_for_dynamic_tool_is_rejected() {
    let input = r#"{"slack.send_message":{"channel":"ops","text":"hello"}}"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_bare_file_list_tool_token_is_rejected() {
    assert_rejects("file__list", "JSON Syntax Error");
}

#[test]
fn test_bare_filesystem_list_alias_token_is_rejected() {
    assert_rejects("filesystem__list_dir", "JSON Syntax Error");
}

#[test]
fn test_normalize_ui_click_component_lowers_to_gui_click_element() {
    let input = r#"{"name":"screen__click","arguments":{"id":"btn_submit"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::GuiClickElement { id } => assert_eq!(id, "btn_submit"),
        other => panic!("Expected GuiClickElement, got {:?}", other),
    }
}

#[test]
fn test_normalize_ui_click_component_accepts_component_id_alias() {
    let input = r#"{"name":"screen__click","arguments":{"component_id":"btn_submit"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::GuiClickElement { id } => assert_eq!(id, "btn_submit"),
        other => panic!("Expected GuiClickElement, got {:?}", other),
    }
}

#[test]
fn test_normalize_ui_click_component_rejects_missing_id() {
    let input = r#"{"name":"screen__click","arguments":{}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err.to_string().contains("Schema Validation Error"));
    assert!(err.to_string().contains("screen__click"));
    assert!(err.to_string().contains("id"));
}

#[test]
fn test_normalize_ui_type_lowers_to_gui_type() {
    let input = r#"{"name":"ui__type","arguments":{"text":"hello"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::GuiType { text } => assert_eq!(text, "hello"),
        other => panic!("Expected GuiType, got {:?}", other),
    }
}

#[test]
fn test_normalize_ui_scroll_lowers_to_gui_scroll() {
    let input = r#"{"name":"ui__scroll","arguments":{"delta_y":120}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::GuiScroll { delta_x, delta_y } => {
            assert_eq!(delta_x, 0);
            assert_eq!(delta_y, 120);
        }
        other => panic!("Expected GuiScroll, got {:?}", other),
    }
}

#[test]
fn test_normalize_ui_click_with_id_lowers_to_gui_click_element() {
    let input = r#"{"name":"ui__click","arguments":{"id":"btn_submit"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::GuiClickElement { id } => assert_eq!(id, "btn_submit"),
        other => panic!("Expected GuiClickElement, got {:?}", other),
    }
}

#[test]
fn test_normalize_ui_click_with_coordinate_lowers_to_gui_click() {
    let input = r#"{"name":"ui__click","arguments":{"coordinate":[100,200]}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::GuiClick { x, y, button } => {
            assert_eq!(x, 100);
            assert_eq!(y, 200);
            assert!(button.is_none());
        }
        other => panic!("Expected GuiClick, got {:?}", other),
    }
}

#[test]
fn test_normalize_ui_click_element_lowers_to_gui_click_element() {
    let input = r#"{"name":"screen__click","arguments":{"id":"btn_submit"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::GuiClickElement { id } => assert_eq!(id, "btn_submit"),
        other => panic!("Expected GuiClickElement, got {:?}", other),
    }
}

#[test]
fn test_normalize_ui_type_rejects_missing_text() {
    let input = r#"{"name":"ui__type","arguments":{}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err.to_string().contains("Schema Validation Error"));
    assert!(err.to_string().contains("ui__type"));
    assert!(err.to_string().contains("text"));
}

#[test]
fn test_normalize_net_fetch_accepts_valid_args() {
    let input =
        r#"{"name":"http__fetch","arguments":{"url":"https://example.com","max_chars":123}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::NetFetch { url, max_chars } => {
            assert_eq!(url, "https://example.com");
            assert_eq!(max_chars, Some(123));
        }
        other => panic!("Expected NetFetch tool, got {:?}", other),
    }
}

#[test]
fn test_normalize_net_fetch_rejects_empty_url() {
    let input = r#"{"name":"http__fetch","arguments":{"url":"   "}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err.to_string().contains("Schema Validation Error"));
    assert!(err.to_string().contains("http__fetch"));
    assert!(err.to_string().contains("url"));
}

#[test]
fn test_normalize_net_fetch_decodes_arguments_string() {
    let input = r#"{"name":"http__fetch","arguments":"{\"url\":\"https://example.com\"}"}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::NetFetch { url, max_chars } => {
            assert_eq!(url, "https://example.com");
            assert_eq!(max_chars, None);
        }
        other => panic!("Expected NetFetch tool, got {:?}", other),
    }
}

#[test]
fn test_flat_browser_navigation_payload_is_rejected() {
    let input = r#"{"url":"https://news.ycombinator.com"}"#;
    assert_rejects(input, "non-empty string 'name'");
}

#[test]
fn test_empty_input_fails() {
    let input = "   ";
    assert!(ToolNormalizer::normalize(input).is_err());
}

#[test]
fn test_normalize_synthetic_click() {
    let input = r#"{"name": "browser__click_at", "arguments": {"x": 100.5, "y": 200.1}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserSyntheticClick {
            id,
            x,
            y,
            continue_with,
        } => {
            assert!(id.is_none());
            assert!((x.expect("x") - 100.5).abs() < f64::EPSILON);
            assert!((y.expect("y") - 200.1).abs() < f64::EPSILON);
            assert!(continue_with.is_none());
        }
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_synthetic_click_with_grounded_id() {
    let input = r#"{"name": "browser__click_at", "arguments": {"id": "grp_blue_circle"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserSyntheticClick {
            id,
            x,
            y,
            continue_with,
        } => {
            assert_eq!(id.as_deref(), Some("grp_blue_circle"));
            assert!(x.is_none());
            assert!(y.is_none());
            assert!(continue_with.is_none());
        }
        other => panic!("Expected BrowserSyntheticClick, got {:?}", other),
    }
}

#[test]
fn test_normalize_synthetic_click_preserves_coordinates_with_grounded_id() {
    let input = r#"{"name": "browser__click_at", "arguments": {"id": "grp_click_canvas", "x": "51", "y": 116}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserSyntheticClick {
            id,
            x,
            y,
            continue_with,
        } => {
            assert_eq!(id.as_deref(), Some("grp_click_canvas"));
            assert_eq!(x, Some(51.0));
            assert_eq!(y, Some(116.0));
            assert!(continue_with.is_none());
        }
        other => panic!("Expected BrowserSyntheticClick, got {:?}", other),
    }
}

#[test]
fn test_normalize_synthetic_click_with_follow_up_shorthand_arguments() {
    let input = r#"{
        "name": "browser__click_at",
        "arguments": {
            "x": "85.012",
            "y": "105.824",
            "continue_with": {
                "name": "browser__click",
                "id": "btn_submit"
            }
        }
    }"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserSyntheticClick {
            id,
            x,
            y,
            continue_with,
        } => {
            assert!(id.is_none());
            assert!((x.expect("x") - 85.012).abs() < f64::EPSILON);
            assert!((y.expect("y") - 105.824).abs() < f64::EPSILON);
            let continue_with = continue_with.expect("follow-up should be present");
            assert_eq!(continue_with.name, "browser__click");
            assert_eq!(continue_with.arguments, json!({ "id": "btn_submit" }));
        }
        other => panic!("Expected BrowserSyntheticClick, got {:?}", other),
    }
}

#[test]
fn test_normalize_synthetic_click_rejects_pointer_state_follow_up() {
    let input = r#"{
        "name": "browser__click_at",
        "arguments": {
            "x": 85,
            "y": 107,
            "continue_with": {
                "name": "browser__pointer_down",
                "arguments": {}
            }
        }
    }"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err.to_string().contains("Schema Validation Error"));
    assert!(err
        .to_string()
        .contains("browser__click_at continue_with does not allow pointer button state changes"));
}

#[test]
fn test_normalize_synthetic_click_rejects_missing_target_and_coordinates() {
    let input = r#"{"name":"browser__click_at","arguments":{"x":85}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected schema error");
    assert!(err.to_string().contains("Schema Validation Error"));
    assert!(err
        .to_string()
        .contains("browser__click_at requires both numeric 'x' and 'y'"));
}

#[test]
fn test_normalize_browser_scroll() {
    let input = r#"{"name":"browser__scroll","arguments":{"delta_x":32.8,"delta_y":480.9}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserScroll { delta_x, delta_y } => {
            assert_eq!(delta_x, 32);
            assert_eq!(delta_y, 480);
        }
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_install_package_preserves_typed_tool() {
    let input = r#"{"name":"package__install","arguments":{"manager":"pip","package":"pydantic"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysInstallPackage { package, manager } => {
            assert_eq!(package, "pydantic");
            assert_eq!(manager.as_deref(), Some("pip"));
        }
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_install_package_rejects_unsafe_package() {
    let input =
        r#"{"name":"package__install","arguments":{"manager":"pip","package":"bad; rm -rf /"}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected validation error");
    assert!(err.to_string().contains("Invalid package identifier"));
}

#[test]
fn test_normalize_sys_change_directory() {
    let input = r#"{"name":"shell__cd","arguments":{"path":"../workspace"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysChangeDir { path } => assert_eq!(path, "../workspace"),
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_filesystem_edit_line_alias() {
    let input = r#"{"name":"file__replace_line","arguments":{"path":"/tmp/demo.txt","line_number":2,"content":"BETA"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "/tmp/demo.txt");
            assert_eq!(content, "BETA");
            assert_eq!(line_number, Some(2));
        }
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_filesystem_edit_line_rejects_invalid_line_number() {
    let input = r#"{"name":"file__replace_line","arguments":{"path":"/tmp/demo.txt","line_number":0,"content":"BETA"}}"#;
    let err = ToolNormalizer::normalize(input).expect_err("expected validation error");
    assert!(err.to_string().contains("line_number"));
}
