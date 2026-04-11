use super::*;
use ioi_types::app::agentic::{AgentTool, ScreenAction};
use serde_json::json;

#[test]
fn test_normalize_clean_json() {
    let input = r#"{"name": "computer", "arguments": {"action": "screenshot"}}"#;
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
fn test_normalize_sys_exec_single_underscore_alias() {
    let input = r#"{"name":"sys_exec","arguments":{"command":"ls"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysExec { command, .. } => assert_eq!(command, "ls"),
        other => panic!("Expected SysExec, got {:?}", other),
    }
}

#[test]
fn test_normalize_sys_exec_colon_alias() {
    let input = r#"{"name":"sys::exec","arguments":{"command":"pwd"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysExec { command, .. } => assert_eq!(command, "pwd"),
        other => panic!("Expected SysExec, got {:?}", other),
    }
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
fn test_normalize_anthropic_input_alias() {
    let input = r#"{"name":"shell__run","input":{"command":"echo","args":["hi"]}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysExec { command, args, .. } => {
            assert_eq!(command, "echo");
            assert_eq!(args, vec!["hi".to_string()]);
        }
        _ => panic!("Wrong tool type"),
    }
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
fn test_normalize_parameters_alias() {
    // LLM often outputs "parameters" instead of "arguments"
    let input = r#"{"name": "screen__type", "parameters": {"text": "hello"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::GuiType { text } => assert_eq!(text, "hello"),
        _ => panic!("Wrong tool type"),
    }
}

#[test]
fn test_normalize_functions_prefix() {
    // LLM outputs "functions.chat__reply"
    let input = r#"{"name": "functions.chat__reply", "arguments": {"message": "hello"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::ChatReply { message } => assert_eq!(message, "hello"),
        _ => panic!("Wrong tool type or failed to strip prefix"),
    }
}

#[test]
fn test_normalize_recipient_name() {
    // LLM outputs "recipient_name" instead of "name"
    let input =
        r#"{"recipient_name": "functions.computer", "parameters": {"action": "screenshot"}}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::Screen(ScreenAction::Screenshot) => {}
        _ => panic!("Wrong tool type or failed to handle recipient_name"),
    }
}

#[test]
fn test_infer_sys_exec_flat() {
    // Flat output without wrapper
    let input = r#"{"command": "gnome-calculator", "args": [], "detach": true}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::SysExec {
            command, detach, ..
        } => {
            assert_eq!(command, "gnome-calculator");
            assert_eq!(detach, true);
        }
        _ => panic!("Wrong tool type inferred"),
    }
}

#[test]
fn test_infer_agent_complete_from_result_only_payload() {
    let input = r#"{"result":"Timer has been scheduled."}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::AgentComplete { result } => assert_eq!(result, "Timer has been scheduled."),
        other => panic!("Expected AgentComplete, got {:?}", other),
    }
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
fn test_infer_nav_flat() {
    let input = r#"{"url":"https://news.ycombinator.com"}"#;
    let tool = ToolNormalizer::normalize(input).unwrap();
    match tool {
        AgentTool::BrowserNavigate { url } => {
            assert_eq!(url, "https://news.ycombinator.com");
        }
        _ => panic!("Wrong tool type inferred"),
    }
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
