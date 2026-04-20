use super::{
    browser_follow_up_activates_visible_control, browser_type_error_supports_selector_retry,
    click_follow_up_requires_post_action_observation, history_entry_json_value,
    normalize_browser_follow_up, normalize_hover_tracking_window,
    resolve_hover_target_from_transformed_trees, resolve_scoped_upload_paths,
    should_use_browser_side_hover_tracking, DEFAULT_BROWSER_HOVER_TRACK_INTERVAL_MS,
};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use ioi_types::app::agentic::AgentToolCall;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ioi_browser_handler_{}_{}_{}",
        name,
        std::process::id(),
        suffix
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn resolve_scoped_upload_paths_resolves_relative_files_within_scope() {
    let scope_root = temp_dir("scope_ok");
    let nested = scope_root.join("docs");
    fs::create_dir_all(&nested).expect("create nested dir");
    let file_path = nested.join("invoice.txt");
    fs::write(&file_path, b"ok").expect("write test file");

    let resolved = resolve_scoped_upload_paths(
        &[String::from("docs/invoice.txt")],
        Some(scope_root.to_string_lossy().as_ref()),
    )
    .expect("paths should resolve");

    let expected = fs::canonicalize(&file_path).expect("canonical file");
    assert_eq!(resolved, vec![expected.to_string_lossy().to_string()]);

    let _ = fs::remove_dir_all(&scope_root);
}

#[test]
fn resolve_scoped_upload_paths_rejects_absolute_paths_outside_scope() {
    let scope_root = temp_dir("scope_root");
    let outside_root = temp_dir("outside_root");
    let outside_file = outside_root.join("secret.txt");
    fs::write(&outside_file, b"nope").expect("write outside file");
    let outside_canonical = fs::canonicalize(&outside_file).expect("canonical outside file");

    let err = resolve_scoped_upload_paths(
        &[outside_canonical.to_string_lossy().to_string()],
        Some(scope_root.to_string_lossy().as_ref()),
    )
    .expect_err("outside path must fail");

    assert!(err.contains("outside allowed scope root"));

    let _ = fs::remove_dir_all(&scope_root);
    let _ = fs::remove_dir_all(&outside_root);
}

#[test]
fn browser_type_focus_errors_retry_with_alternate_selectors() {
    assert!(browser_type_error_supports_selector_retry(
        "Failed to focus selector '#inp_dispatch_note'"
    ));
    assert!(browser_type_error_supports_selector_retry(
        "Selector focus failed for '#inp_dispatch_note': hidden"
    ));
    assert!(!browser_type_error_supports_selector_retry(
        "Type failed: session crashed"
    ));
}

#[test]
fn normalize_browser_follow_up_accepts_click_element() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__click".to_string(),
            arguments: json!({ "id": "btn_two" }),
        },
        "browser__wait",
    )
    .expect("follow-up should normalize");

    match tool {
        ioi_types::app::agentic::AgentTool::BrowserClick {
            id,
            ids,
            delay_ms_between_ids,
            continue_with,
            ..
        } => {
            assert_eq!(id.as_deref(), Some("btn_two"));
            assert!(ids.is_empty());
            assert!(delay_ms_between_ids.is_none());
            assert!(continue_with.is_none());
        }
        other => panic!("expected BrowserClick, got {:?}", other),
    }
}

#[test]
fn normalize_browser_follow_up_accepts_timed_click_element_sequence() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__click".to_string(),
            arguments: json!({
                "ids": ["btn_one", "btn_two"],
                "delay_ms_between_ids": 2_000
            }),
        },
        "browser__click",
    )
    .expect("follow-up should normalize");

    match tool {
        ioi_types::app::agentic::AgentTool::BrowserClick {
            id,
            ids,
            delay_ms_between_ids,
            continue_with,
            ..
        } => {
            assert!(id.is_none());
            assert_eq!(ids, vec!["btn_one".to_string(), "btn_two".to_string()]);
            assert_eq!(delay_ms_between_ids, Some(2_000));
            assert!(continue_with.is_none());
        }
        other => panic!("expected BrowserClick, got {:?}", other),
    }
}

#[test]
fn normalize_browser_follow_up_accepts_wait_with_nested_click_element() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__wait".to_string(),
            arguments: json!({
                "ms": 2_000,
                "continue_with": {
                    "name": "browser__click",
                    "ids": ["btn_two"]
                }
            }),
        },
        "browser__click",
    )
    .expect("follow-up should normalize");

    match tool {
        ioi_types::app::agentic::AgentTool::BrowserWait {
            ms,
            condition,
            selector,
            query,
            scope,
            timeout_ms,
            continue_with,
        } => {
            assert_eq!(ms, Some(2_000));
            assert!(condition.is_none());
            assert!(selector.is_none());
            assert!(query.is_none());
            assert!(scope.is_none());
            assert!(timeout_ms.is_none());
            let continue_with = continue_with.expect("nested click follow-up");
            assert_eq!(continue_with.name, "browser__click");
            assert_eq!(continue_with.arguments["ids"], json!(["btn_two"]));
        }
        other => panic!("expected BrowserWait, got {:?}", other),
    }
}

#[test]
fn normalize_browser_follow_up_accepts_browser_key_with_nested_click_element() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__press_key".to_string(),
            arguments: json!({
                "key": "Home",
                "selector": "[id=\"text-area\"]",
                "modifiers": ["Control"],
                "continue_with": {
                    "name": "browser__click",
                    "arguments": {
                        "id": "btn_submit"
                    }
                }
            }),
        },
        "browser__wait",
    )
    .expect("follow-up should normalize");

    match tool {
        ioi_types::app::agentic::AgentTool::BrowserKey {
            key,
            selector,
            modifiers,
            continue_with,
        } => {
            assert_eq!(key, "Home");
            assert_eq!(selector.as_deref(), Some("[id=\"text-area\"]"));
            assert_eq!(modifiers.as_deref(), Some(&["Control".to_string()][..]));
            let continue_with = continue_with.expect("nested click follow-up");
            assert_eq!(continue_with.name, "browser__click");
            assert_eq!(continue_with.arguments["id"], json!("btn_submit"));
        }
        other => panic!("expected BrowserKey, got {:?}", other),
    }
}

#[test]
fn normalize_browser_follow_up_rejects_non_browser_action() {
    let err = normalize_browser_follow_up(
        &AgentToolCall {
            name: "agent__complete".to_string(),
            arguments: json!({ "result": "done" }),
        },
        "browser__click_at",
    )
    .expect_err("non-browser follow-up must fail");

    assert!(err.contains("only supports immediate browser interaction tools"));
}

#[test]
fn normalize_browser_follow_up_rejects_pointer_state_for_synthetic_click() {
    let err = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__pointer_down".to_string(),
            arguments: json!({}),
        },
        "browser__click_at",
    )
    .expect_err("pointer-state follow-up must fail");

    assert!(err.contains("does not support pointer button state changes"));
}

#[test]
fn normalize_browser_follow_up_accepts_browser_type() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__type".to_string(),
            arguments: json!({ "text": "annis" }),
        },
        "browser__click",
    )
    .expect("follow-up should normalize");

    match tool {
        ioi_types::app::agentic::AgentTool::BrowserType { text, selector } => {
            assert_eq!(text, "annis");
            assert!(selector.is_none());
        }
        other => panic!("expected BrowserType, got {:?}", other),
    }
}

#[test]
fn normalize_browser_follow_up_accepts_nested_synthetic_click() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__click_at".to_string(),
            arguments: json!({ "x": "85.012", "y": "105.824" }),
        },
        "browser__wait",
    )
    .expect("follow-up should normalize");

    match tool {
        ioi_types::app::agentic::AgentTool::BrowserSyntheticClick {
            id,
            x,
            y,
            continue_with,
        } => {
            assert!(id.is_none());
            assert!((x.expect("x") - 85.012).abs() < f64::EPSILON);
            assert!((y.expect("y") - 105.824).abs() < f64::EPSILON);
            assert!(continue_with.is_none());
        }
        other => panic!("expected BrowserSyntheticClick, got {:?}", other),
    }
}

#[test]
fn normalize_browser_follow_up_preserves_grounded_synthetic_click_coordinates() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__click_at".to_string(),
            arguments: json!({
                "id": "grp_click_canvas",
                "x": "51",
                "y": 116
            }),
        },
        "browser__wait",
    )
    .expect("follow-up should normalize");

    match tool {
        ioi_types::app::agentic::AgentTool::BrowserSyntheticClick {
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
        other => panic!("expected BrowserSyntheticClick, got {:?}", other),
    }
}

#[test]
fn browser_follow_up_activates_visible_control_for_direct_click_element() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__click".to_string(),
            arguments: json!({ "id": "btn_submit" }),
        },
        "browser__click_at",
    )
    .expect("follow-up should normalize");

    assert!(browser_follow_up_activates_visible_control(&tool).expect("policy check"));
}

#[test]
fn browser_follow_up_activates_visible_control_for_wait_wrapped_click_chain() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__wait".to_string(),
            arguments: json!({
                "ms": 100,
                "continue_with": {
                    "name": "browser__click",
                    "arguments": {
                        "id": "btn_submit"
                    }
                }
            }),
        },
        "browser__click_at",
    )
    .expect("follow-up should normalize");

    assert!(browser_follow_up_activates_visible_control(&tool).expect("policy check"));
}

#[test]
fn browser_follow_up_activates_visible_control_for_key_wrapped_click_chain() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__press_key".to_string(),
            arguments: json!({
                "key": "Home",
                "selector": "[id=\"text-area\"]",
                "modifiers": ["Control"],
                "continue_with": {
                    "name": "browser__click",
                    "arguments": {
                        "id": "btn_submit"
                    }
                }
            }),
        },
        "browser__click_at",
    )
    .expect("follow-up should normalize");

    assert!(browser_follow_up_activates_visible_control(&tool).expect("policy check"));
}

#[test]
fn browser_follow_up_activates_visible_control_ignores_geometry_only_chain() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__click_at".to_string(),
            arguments: json!({ "id": "grp_blue_circle" }),
        },
        "browser__click_at",
    )
    .expect("follow-up should normalize");

    assert!(!browser_follow_up_activates_visible_control(&tool).expect("policy check"));
}

#[test]
fn history_entry_json_value_preserves_json_and_falls_back_to_string() {
    assert_eq!(
        history_entry_json_value(Some("{\"clicked\":true}")),
        json!({ "clicked": true })
    );
    assert_eq!(
        history_entry_json_value(Some("Clicked element 'btn_two'")),
        json!("Clicked element 'btn_two'")
    );
}

#[test]
fn click_follow_up_requires_post_action_observation_for_geometry_backed_visible_control() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__click".to_string(),
            arguments: json!({ "selector": "#submit" }),
        },
        "browser__click",
    )
    .expect("follow-up should normalize");
    let entry = r#"Clicked element 'grp_geometry_target_at_77107' via geometry fallback. verify={"method":"geometry_center","postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#;

    assert!(
        click_follow_up_requires_post_action_observation(Some(entry), &tool).expect("policy check"),
    );
}

#[test]
fn click_follow_up_allows_visible_control_after_dom_backed_click() {
    let tool = normalize_browser_follow_up(
        &AgentToolCall {
            name: "browser__click".to_string(),
            arguments: json!({ "id": "btn_submit" }),
        },
        "browser__click",
    )
    .expect("follow-up should normalize");
    let entry = r#"Clicked element 'btn_next'. verify={"method":"backend_dom_node_id","postcondition":{"met":true,"tree_changed":true,"url_changed":false}}"#;

    assert!(
        !click_follow_up_requires_post_action_observation(Some(entry), &tool)
            .expect("policy check"),
    );
}

#[test]
fn resolve_hover_target_uses_recent_snapshot_when_current_tree_blinks() {
    let current_tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 160,
            height: 210,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };
    let recent_tree = AccessibilityNode {
        children: vec![AccessibilityNode {
            id: "grp_circ".to_string(),
            role: "generic".to_string(),
            name: Some("large circle centered at 110,103 radius 22".to_string()),
            value: None,
            rect: Rect {
                x: 88,
                y: 81,
                width: 44,
                height: 44,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("dom_id".to_string(), "circ".to_string()),
                ("selector".to_string(), "[id=\"circ\"]".to_string()),
            ]),
            som_id: None,
        }],
        ..current_tree.clone()
    };

    let resolved = resolve_hover_target_from_transformed_trees(
        "grp_circ",
        Some(&current_tree),
        Some(&recent_tree),
    )
    .expect("recent snapshot should resolve hover target");

    assert_eq!((resolved.x, resolved.y), (110.0, 103.0));
    assert_eq!(
        resolved
            .target
            .get("resolved_from")
            .and_then(serde_json::Value::as_str),
        Some("recent_accessibility_snapshot")
    );
}

#[test]
fn hover_tracking_window_rejects_interval_without_duration() {
    let err = normalize_hover_tracking_window(None, Some(75))
        .expect_err("interval without duration must fail");
    assert!(err.contains("requires duration_ms"));
}

#[test]
fn hover_tracking_window_defaults_resample_interval() {
    assert_eq!(
        normalize_hover_tracking_window(Some(2_500), None).expect("tracking window"),
        Some((2_500, DEFAULT_BROWSER_HOVER_TRACK_INTERVAL_MS))
    );
}

#[test]
fn browser_side_hover_tracking_prefers_explicit_zero_interval_without_pressed_buttons() {
    assert!(should_use_browser_side_hover_tracking(
        Some((30_000, 0)),
        Some("[id=\"circ\"]"),
        0,
    ));
}

#[test]
fn browser_side_hover_tracking_skips_default_interval_drag_state_and_missing_selector() {
    assert!(!should_use_browser_side_hover_tracking(
        Some((30_000, 16)),
        Some("[id=\"circ\"]"),
        0,
    ));
    assert!(!should_use_browser_side_hover_tracking(
        Some((30_000, 0)),
        Some("[id=\"circ\"]"),
        1,
    ));
    assert!(!should_use_browser_side_hover_tracking(
        Some((30_000, DEFAULT_BROWSER_HOVER_TRACK_INTERVAL_MS)),
        None,
        0,
    ));
}
