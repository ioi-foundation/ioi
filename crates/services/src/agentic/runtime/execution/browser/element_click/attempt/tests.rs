use super::{
    find_focused_semantic_target, find_nearest_semantic_target_by_point,
    semantic_target_verification_json, ToolExecutionResult,
};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

fn node(
    id: &str,
    role: &str,
    attrs: &[(&str, &str)],
    children: Vec<AccessibilityNode>,
) -> AccessibilityNode {
    AccessibilityNode {
        id: id.to_string(),
        role: role.to_string(),
        name: None,
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 20,
        },
        children,
        is_visible: true,
        attributes: attrs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>(),
        som_id: None,
    }
}

#[test]
fn click_dispatch_settle_schedule_includes_delayed_tail_probe() {
    assert_eq!(
        super::CLICK_DISPATCH_SETTLE_MS_GEOMETRY_ONLY,
        [0, 80, 160, 320, 640]
    );
    assert_eq!(
        super::CLICK_DISPATCH_SETTLE_MS_DOM_BACKED,
        [0, 120, 240, 900]
    );
}

#[tokio::test]
async fn browser_tool_strategy_timeout_returns_error() {
    let result =
        super::run_browser_tool_strategy_with_timeout_for(Duration::from_millis(10), async {
            sleep(Duration::from_millis(25)).await;
            ToolExecutionResult::success("late")
        })
        .await;

    match result {
        Ok(result) => panic!("expected timeout error, got success: {result:?}"),
        Err(error) => assert_eq!(error, "strategy timed out after 10 ms"),
    }
}

#[tokio::test]
async fn browser_tool_strategy_timeout_returns_completed_result() {
    let result =
        super::run_browser_tool_strategy_with_timeout_for(Duration::from_millis(25), async {
            sleep(Duration::from_millis(1)).await;
            ToolExecutionResult::success("done")
        })
        .await
        .expect("completed result");

    assert!(result.success);
    assert_eq!(result.history_entry.as_deref(), Some("done"));
    assert_eq!(result.error, None);
}

#[test]
fn material_semantic_success_refreshes_recent_snapshot() {
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: true,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: true,
        semantic_change_delta: 11,
    };

    assert!(super::should_refresh_recent_accessibility_snapshot_after_success(&postcondition));
}

#[test]
fn editable_focus_success_does_not_force_recent_snapshot_refresh() {
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: true,
        tree_changed: false,
        url_changed: false,
        material_semantic_change: true,
        semantic_change_delta: 1,
    };

    assert!(!super::should_refresh_recent_accessibility_snapshot_after_success(&postcondition));
}

#[test]
fn semantic_target_is_actionable_for_recent_geometry_only_targets() {
    let target = super::BrowserSemanticTarget {
        center_point: Some((63.0, 154.0)),
        selector: Some("#area_svg > rect:nth-of-type(1)".to_string()),
        ..Default::default()
    };

    assert!(super::semantic_target_is_actionable(&target));
}

#[test]
fn semantic_target_is_actionable_for_selector_backed_targets() {
    let target = super::BrowserSemanticTarget {
        selector: Some("[id=\"buy\"]".to_string()),
        dom_id: Some("buy".to_string()),
        ..Default::default()
    };

    assert!(super::semantic_target_is_actionable(&target));
}

#[test]
fn geometry_only_targets_use_shorter_click_verification_tail() {
    let target = super::BrowserSemanticTarget {
        center_point: Some((52.0, 69.0)),
        selector: Some("#area_svg > rect:nth-of-type(1)".to_string()),
        tag_name: Some("rect".to_string()),
        ..Default::default()
    };

    assert!(super::uses_geometry_only_click_verification(&target));
    assert_eq!(
        super::click_dispatch_settle_schedule(&target),
        &[0, 80, 160, 320, 640]
    );
}

#[test]
fn dom_backed_targets_keep_delayed_tail_probe() {
    let target = super::BrowserSemanticTarget {
        dom_id: Some("submit".to_string()),
        backend_dom_node_id: Some("backend-17".to_string()),
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };

    assert!(!super::uses_geometry_only_click_verification(&target));
    assert_eq!(
        super::click_dispatch_settle_schedule(&target),
        &[0, 120, 240, 900]
    );
}

#[tokio::test]
async fn browser_dispatch_timeout_returns_timeout_error() {
    let result =
        super::run_browser_dispatch_with_timeout_for(Duration::from_millis(10), async {
            sleep(Duration::from_millis(25)).await;
            Ok::<(), &'static str>(())
        })
        .await;

    let error = result.expect_err("dispatch should time out");
    assert!(
        error.contains("dispatch timed out after 10 ms. Retry the action."),
        "{error}"
    );
}

#[tokio::test]
async fn browser_dispatch_timeout_preserves_underlying_error() {
    let result =
        super::run_browser_dispatch_with_timeout_for(Duration::from_millis(10), async {
            Err::<(), _>("backend failed")
        })
        .await;

    assert_eq!(result.unwrap_err(), "backend failed");
}

#[test]
fn browser_session_unstable_error_matches_reset_retry_messages() {
    assert!(super::browser_session_unstable_error(
        "Browser accessibility snapshot timed out after 1.5s. Retry the action."
    ));
    assert!(super::browser_session_unstable_error(
        "selector click for '#buy' timed out after 2000ms. Browser session reset; retry the action."
    ));
    assert!(!super::browser_session_unstable_error(
        "dispatch timed out after 2000 ms. Retry the action."
    ));
    assert!(!super::browser_session_unstable_error(
        "Typing had no observable effect on '#email'"
    ));
}

#[test]
fn click_result_marks_browser_session_unstable_from_verify_payload() {
    let result = ToolExecutionResult::failure(
        "ERROR_CLASS=TimeoutOrHang Click element 'btn_buy' could not continue. verify={\"browser_session_unstable\":true}",
    );

    assert!(super::click_result_marks_browser_session_unstable(&result));
}

#[test]
fn click_result_does_not_mark_regular_noeffect_as_browser_unstable() {
    let result = ToolExecutionResult::failure(
        "ERROR_CLASS=NoEffectAfterAction Failed to click element 'btn_buy'. verify={\"browser_session_unstable\":false}",
    );

    assert!(!super::click_result_marks_browser_session_unstable(&result));
}

#[test]
fn current_tree_actionable_target_beats_prompt_tree_locator_tie() {
    let mut current_target = node(
        "ax_buy",
        "button",
        &[
            ("backend_dom_node_id", "42"),
            ("tag_name", "button"),
            ("center_x_precise", "80"),
            ("center_y_precise", "25"),
        ],
        Vec::new(),
    );
    current_target.name = Some("Buy".to_string());

    let mut prompt_target = node(
        "btn_buy",
        "button",
        &[
            ("dom_id", "buy"),
            ("selector", "[id=\"buy\"]"),
            ("tag_name", "button"),
            ("center_x_precise", "80"),
            ("center_y_precise", "150"),
        ],
        Vec::new(),
    );
    prompt_target.name = Some("Buy".to_string());

    let current_tree = node("root", "root", &[], vec![current_target]);
    let prompt_tree = node("root", "root", &[], vec![prompt_target]);

    let (resolved, source) = super::resolve_semantic_target_from_current_or_prompt_tree(
        Some(&current_tree),
        Some(&prompt_tree),
        "buy",
    )
    .expect("buy should resolve from prompt or current tree");

    assert_eq!(source, "current_accessibility_tree");
    assert_eq!(resolved.backend_dom_node_id.as_deref(), Some("42"));
}

#[test]
fn semantic_id_lookup_prefers_dom_id_before_earlier_semantic_alias_match() {
    let tree = node(
        "root",
        "root",
        &[],
        vec![
            node(
                "grp_buy_yjv_stock_when_the_price_i",
                "generic",
                &[
                    ("dom_id", "query"),
                    ("semantic_aliases", "buy grp_buy_yjv_stock_when_the_price_i"),
                ],
                Vec::new(),
            ),
            node(
                "btn_buy",
                "button",
                &[
                    ("dom_id", "buy"),
                    ("selector", "[id=\"buy\"]"),
                    ("tag_name", "button"),
                ],
                Vec::new(),
            ),
        ],
    );

    let target = super::find_semantic_target_by_id(&tree, "buy").expect("buy target");
    assert_eq!(target.semantic_id.as_deref(), Some("btn_buy"));
    assert_eq!(target.dom_id.as_deref(), Some("buy"));
    assert_eq!(target.selector.as_deref(), Some("[id=\"buy\"]"));
}

#[test]
fn semantic_id_lookup_keeps_exact_semantic_id_over_alias_candidate() {
    let tree = node(
        "root",
        "root",
        &[],
        vec![
            node(
                "btn_buy",
                "button",
                &[
                    ("tag_name", "button"),
                    ("center_x_precise", "80"),
                    ("center_y_precise", "25"),
                ],
                Vec::new(),
            ),
            node(
                "ax_buy",
                "button",
                &[
                    ("dom_id", "buy"),
                    ("selector", "[id=\"buy\"]"),
                    ("tag_name", "button"),
                    ("center_x_precise", "80"),
                    ("center_y_precise", "150"),
                ],
                Vec::new(),
            ),
        ],
    );

    let target = super::find_semantic_target_by_id(&tree, "btn_buy").expect("buy target");
    assert_eq!(target.semantic_id.as_deref(), Some("btn_buy"));
    assert_eq!(target.dom_id.as_deref(), None);
    assert_eq!(target.selector.as_deref(), None);
}

#[test]
fn semantic_id_lookup_does_not_replace_exact_button_with_instruction_alias() {
    let tree = node(
        "root",
        "root",
        &[],
        vec![
            node(
                "grp_click_on_the_okay_button_dot",
                "generic",
                &[
                    ("dom_id", "query"),
                    ("selector", "#query"),
                    ("semantic_aliases", "okay btn_okay"),
                    ("center_x_precise", "80"),
                    ("center_y_precise", "25"),
                ],
                Vec::new(),
            ),
            node(
                "btn_okay",
                "button",
                &[
                    ("tag_name", "button"),
                    ("center_x_precise", "25"),
                    ("center_y_precise", "137"),
                ],
                Vec::new(),
            ),
        ],
    );

    let target = super::find_semantic_target_by_id(&tree, "btn_okay").expect("okay button");
    assert_eq!(target.semantic_id.as_deref(), Some("btn_okay"));
    assert_eq!(target.tag_name.as_deref(), Some("button"));
}

#[test]
fn large_container_targets_use_safe_inset_click_point() {
    let target = super::BrowserSemanticTarget {
        tag_name: Some("div".to_string()),
        rect_bounds: Some((0, 0, 160, 210)),
        center_point: Some((80.0, 105.0)),
        ..Default::default()
    };

    assert_eq!(super::safe_inset_click_point(&target), Some((80.0, 24.0)));
}

#[test]
fn native_controls_do_not_use_safe_inset_click_point() {
    let target = super::BrowserSemanticTarget {
        tag_name: Some("button".to_string()),
        rect_bounds: Some((27, 84, 95, 31)),
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };

    assert_eq!(super::safe_inset_click_point(&target), None);
}

#[test]
fn resolve_semantic_target_from_current_or_prompt_tree_prefers_current_tree_when_equally_rich()
{
    let current_tree = node(
        "root",
        "root",
        &[],
        vec![node(
            "btn_submit",
            "button",
            &[("dom_id", "subbtn"), ("tag_name", "button")],
            Vec::new(),
        )],
    );
    let prompt_tree = node(
        "root_prompt",
        "root",
        &[],
        vec![node(
            "btn_submit",
            "button",
            &[("dom_id", "old-subbtn"), ("tag_name", "button")],
            Vec::new(),
        )],
    );

    let (target, resolved_from) = super::resolve_semantic_target_from_current_or_prompt_tree(
        Some(&current_tree),
        Some(&prompt_tree),
        "btn_submit",
    )
    .expect("current tree target");

    assert_eq!(resolved_from, "current_accessibility_tree");
    assert_eq!(target.dom_id.as_deref(), Some("subbtn"));
}

#[test]
fn resolve_semantic_target_from_current_or_prompt_tree_merges_prompt_dom_metadata() {
    let current_tree = node(
        "root",
        "root",
        &[],
        vec![node(
            "btn_buy",
            "button",
            &[("backend_dom_node_id", "backend-buy")],
            Vec::new(),
        )],
    );
    let prompt_tree = node(
        "root_prompt",
        "root",
        &[],
        vec![node(
            "btn_buy",
            "button",
            &[
                ("dom_id", "buy"),
                ("selector", "[id=\"buy\"]"),
                ("tag_name", "button"),
                ("dom_clickable", "true"),
            ],
            Vec::new(),
        )],
    );

    let (target, resolved_from) = super::resolve_semantic_target_from_current_or_prompt_tree(
        Some(&current_tree),
        Some(&prompt_tree),
        "btn_buy",
    )
    .expect("merged target");

    assert_eq!(resolved_from, "current_accessibility_tree+prompt_metadata");
    assert_eq!(target.backend_dom_node_id.as_deref(), Some("backend-buy"));
    assert_eq!(target.dom_id.as_deref(), Some("buy"));
    assert_eq!(target.selector.as_deref(), Some("[id=\"buy\"]"));
    assert_eq!(target.tag_name.as_deref(), Some("button"));
    assert!(target.dom_clickable);
}

#[test]
fn resolve_semantic_target_from_current_or_prompt_tree_falls_back_to_prompt_tree() {
    let current_tree = node("root", "root", &[], Vec::new());
    let prompt_tree = node(
        "root_prompt",
        "root",
        &[],
        vec![node(
            "grp_start",
            "generic",
            &[
                ("dom_id", "sync-task-cover"),
                ("selector", "[id=\"sync-task-cover\"]"),
                ("tag_name", "div"),
            ],
            Vec::new(),
        )],
    );

    let (target, resolved_from) = super::resolve_semantic_target_from_current_or_prompt_tree(
        Some(&current_tree),
        Some(&prompt_tree),
        "grp_start",
    )
    .expect("prompt tree fallback");

    assert_eq!(resolved_from, "prompt_observation_tree");
    assert_eq!(target.dom_id.as_deref(), Some("sync-task-cover"));
    assert_eq!(target.selector.as_deref(), Some("[id=\"sync-task-cover\"]"));
}

#[test]
fn find_focused_semantic_target_prefers_focused_descendant_metadata() {
    let tree = node(
        "grp_scroll_wrapper",
        "generic",
        &[("dom_id", "wrap")],
        vec![node(
            "inp_text_area",
            "textbox",
            &[
                ("dom_id", "text-area"),
                ("selector", "[id=\"text-area\"]"),
                ("tag_name", "textarea"),
                ("focused", "true"),
                ("scroll_top", "257"),
                ("scroll_height", "565"),
                ("client_height", "104"),
                ("can_scroll_up", "true"),
                ("can_scroll_down", "true"),
            ],
            Vec::new(),
        )],
    );

    let focused = find_focused_semantic_target(&tree).expect("focused descendant");
    assert_eq!(focused.dom_id.as_deref(), Some("text-area"));
    assert_eq!(focused.tag_name.as_deref(), Some("textarea"));
    assert_eq!(focused.scroll_top, Some(257));
    assert_eq!(focused.can_scroll_up, Some(true));
    assert_eq!(focused.can_scroll_down, Some(true));
}

#[test]
fn semantic_target_verification_json_includes_focused_scroll_metadata() {
    let focused = find_focused_semantic_target(&node(
        "inp_text_area",
        "textbox",
        &[
            ("dom_id", "text-area"),
            ("selector", "[id=\"text-area\"]"),
            ("tag_name", "textarea"),
            ("focused", "true"),
            ("scroll_top", "0"),
            ("scroll_height", "565"),
            ("client_height", "104"),
            ("can_scroll_up", "false"),
            ("can_scroll_down", "true"),
        ],
        Vec::new(),
    ))
    .expect("focused node");

    let json = semantic_target_verification_json(Some(&focused));
    assert_eq!(json["dom_id"], "text-area");
    assert_eq!(json["selector"], "[id=\"text-area\"]");
    assert_eq!(json["tag_name"], "textarea");
    assert_eq!(json["scroll_top"], 0);
    assert_eq!(json["can_scroll_up"], false);
    assert_eq!(json["can_scroll_down"], true);
}

#[test]
fn semantic_target_verification_json_includes_selection_state_metadata() {
    let target = super::find_semantic_target_by_id(
        &node(
            "radio_target",
            "radio",
            &[
                ("dom_id", "choice-1"),
                ("selector", "[id=\"choice-1\"]"),
                ("tag_name", "input"),
                ("checked", "true"),
            ],
            Vec::new(),
        ),
        "radio_target",
    )
    .expect("semantic target");

    let json = semantic_target_verification_json(Some(&target));
    assert_eq!(json["dom_id"], "choice-1");
    assert_eq!(json["checked"], true);
    assert_eq!(json["selected"], serde_json::Value::Null);
}

#[test]
fn verification_prefers_exact_element_hash_match_before_weaker_locators() {
    let tree = node(
        "root",
        "root",
        &[],
        vec![
            node(
                "btn_stable_only",
                "button",
                &[
                    ("tag_name", "button"),
                    ("stable_hash", "111"),
                    ("element_hash", "999"),
                ],
                Vec::new(),
            ),
            node(
                "btn_exact_hash",
                "button",
                &[
                    ("tag_name", "button"),
                    ("stable_hash", "111"),
                    ("element_hash", "222"),
                ],
                Vec::new(),
            ),
        ],
    );

    let target = super::BrowserSemanticTarget {
        tag_name: Some("button".to_string()),
        element_hash: Some(222),
        stable_hash: Some(111),
        ..Default::default()
    };

    let found = super::find_semantic_target_for_verification(&tree, &target).expect("target");
    assert_eq!(found.semantic_id.as_deref(), Some("btn_exact_hash"));
}

#[test]
fn verification_falls_back_to_attribute_identity_when_hashes_and_xpath_fail() {
    let tree = node(
        "root",
        "root",
        &[],
        vec![
            node(
                "btn_other",
                "button",
                &[
                    ("tag_name", "button"),
                    ("aria-label", "Cancel"),
                    ("name", "cancel"),
                ],
                Vec::new(),
            ),
            node(
                "btn_submit",
                "button",
                &[
                    ("tag_name", "button"),
                    ("aria-label", "Submit"),
                    ("name", "submit"),
                ],
                Vec::new(),
            ),
        ],
    );

    let mut target = super::BrowserSemanticTarget {
        tag_name: Some("button".to_string()),
        x_path: Some("/html/body/div[9]/button[2]".to_string()),
        ax_name: Some("Mismatched accessible name".to_string()),
        ..Default::default()
    };
    target
        .identity_attributes
        .insert("aria-label".to_string(), "Submit".to_string());

    let found = super::find_semantic_target_for_verification(&tree, &target).expect("target");
    assert_eq!(found.semantic_id.as_deref(), Some("btn_submit"));
}

#[test]
fn semantic_target_verification_json_includes_browser_use_identity_attributes() {
    let target = super::find_semantic_target_by_id(
        &node(
            "btn_submit",
            "button",
            &[
                ("tag_name", "button"),
                ("name", "submit"),
                ("aria-label", "Submit"),
                ("element_hash", "222"),
            ],
            Vec::new(),
        ),
        "btn_submit",
    )
    .expect("semantic target");

    let json = semantic_target_verification_json(Some(&target));
    assert_eq!(json["identity_attributes"]["name"], "submit");
    assert_eq!(json["identity_attributes"]["aria-label"], "Submit");
    assert_eq!(json["element_hash"], 222);
}

#[test]
fn nearest_semantic_target_by_point_prefers_contained_geometry_target() {
    let tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: None,
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 200,
            height: 200,
        },
        children: vec![
            AccessibilityNode {
                id: "btn_submit".to_string(),
                role: "button".to_string(),
                name: Some("Submit".to_string()),
                value: None,
                rect: Rect {
                    x: 70,
                    y: 180,
                    width: 60,
                    height: 20,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::from([
                    ("dom_id".to_string(), "subbtn".to_string()),
                    ("selector".to_string(), "#subbtn".to_string()),
                    ("tag_name".to_string(), "button".to_string()),
                ]),
                som_id: None,
            },
            AccessibilityNode {
                id: "grp_blue_circle".to_string(),
                role: "generic".to_string(),
                name: Some("blue circle".to_string()),
                value: None,
                rect: Rect {
                    x: 49,
                    y: 114,
                    width: 8,
                    height: 8,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::from([
                    ("selector".to_string(), "#blue-circle".to_string()),
                    ("tag_name".to_string(), "circle".to_string()),
                ]),
                som_id: None,
            },
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let target = find_nearest_semantic_target_by_point(&tree, 51.0, 116.0).expect("target");
    assert_eq!(target.semantic_id.as_deref(), Some("grp_blue_circle"));
    assert_eq!(target.selector.as_deref(), Some("#blue-circle"));
}

#[test]
fn nearest_semantic_target_by_point_prefers_grounded_locator_when_centers_tie() {
    let tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: None,
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 200,
            height: 200,
        },
        children: vec![
            AccessibilityNode {
                id: "grp_vertex_alias".to_string(),
                role: "generic".to_string(),
                name: Some("vertex alias".to_string()),
                value: None,
                rect: Rect {
                    x: 27,
                    y: 104,
                    width: 8,
                    height: 8,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::from([("tag_name".to_string(), "circle".to_string())]),
                som_id: None,
            },
            AccessibilityNode {
                id: "grp_blue_circle".to_string(),
                role: "generic".to_string(),
                name: Some("blue circle".to_string()),
                value: None,
                rect: Rect {
                    x: 27,
                    y: 104,
                    width: 8,
                    height: 8,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::from([
                    ("dom_id".to_string(), "blue-circle".to_string()),
                    ("selector".to_string(), "#blue-circle".to_string()),
                    ("tag_name".to_string(), "circle".to_string()),
                ]),
                som_id: None,
            },
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let target = find_nearest_semantic_target_by_point(&tree, 31.0, 108.0).expect("target");
    assert_eq!(target.semantic_id.as_deref(), Some("grp_blue_circle"));
    assert_eq!(target.dom_id.as_deref(), Some("blue-circle"));
}

#[test]
fn stale_semantic_id_recovers_unique_data_index_target() {
    let tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: None,
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 160,
            height: 160,
        },
        children: vec![
            AccessibilityNode {
                id: "grp_rect_a".to_string(),
                role: "generic".to_string(),
                name: Some("4".to_string()),
                value: None,
                rect: Rect {
                    x: 40,
                    y: 60,
                    width: 20,
                    height: 20,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::from([
                    ("data_index".to_string(), "4".to_string()),
                    ("shape_kind".to_string(), "rectangle".to_string()),
                ]),
                som_id: None,
            },
            AccessibilityNode {
                id: "grp_rect_b".to_string(),
                role: "generic".to_string(),
                name: Some("5".to_string()),
                value: None,
                rect: Rect {
                    x: 70,
                    y: 90,
                    width: 20,
                    height: 20,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::from([
                    ("data_index".to_string(), "5".to_string()),
                    ("shape_kind".to_string(), "rectangle".to_string()),
                ]),
                som_id: None,
            },
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let target = super::find_semantic_target_by_id(&tree, "grp_4").expect("target");
    assert_eq!(target.semantic_id.as_deref(), Some("grp_rect_a"));
    assert_eq!(target.center_point, Some((50.0, 70.0)));
}

#[test]
fn semantic_target_prefers_precise_center_point_attributes_over_rect_center() {
    let node = AccessibilityNode {
        id: "grp_precise_center_target".to_string(),
        role: "generic".to_string(),
        name: Some("precise center target".to_string()),
        value: None,
        rect: Rect {
            x: 85,
            y: 101,
            width: 8,
            height: 8,
        },
        children: Vec::new(),
        is_visible: true,
        attributes: HashMap::from([
            ("center_x".to_string(), "89".to_string()),
            ("center_y".to_string(), "105".to_string()),
            ("center_x_precise".to_string(), "88.804735".to_string()),
            ("center_y_precise".to_string(), "105.372527".to_string()),
        ]),
        som_id: None,
    };

    let target =
        super::find_semantic_target_by_id(&node, "grp_precise_center_target").expect("target");
    assert_eq!(target.center_point, Some((88.804735, 105.372527)));
}

#[test]
fn stale_semantic_id_recovers_unique_hyphenated_data_index_target() {
    let tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: None,
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 160,
            height: 160,
        },
        children: vec![
            AccessibilityNode {
                id: "grp_rect_a".to_string(),
                role: "generic".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 40,
                    y: 60,
                    width: 20,
                    height: 20,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::from([
                    ("data-index".to_string(), "4".to_string()),
                    ("shape_kind".to_string(), "rectangle".to_string()),
                ]),
                som_id: None,
            },
            AccessibilityNode {
                id: "grp_rect_b".to_string(),
                role: "generic".to_string(),
                name: None,
                value: None,
                rect: Rect {
                    x: 70,
                    y: 90,
                    width: 20,
                    height: 20,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::from([
                    ("data-index".to_string(), "5".to_string()),
                    ("shape_kind".to_string(), "rectangle".to_string()),
                ]),
                som_id: None,
            },
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let target = super::find_semantic_target_by_id(&tree, "grp_4").expect("target");
    assert_eq!(target.semantic_id.as_deref(), Some("grp_rect_a"));
    assert_eq!(target.center_point, Some((50.0, 70.0)));
}

#[test]
fn stale_semantic_id_does_not_guess_ambiguous_name_alias() {
    let tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: None,
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 160,
            height: 160,
        },
        children: vec![
            AccessibilityNode {
                id: "grp_submit_primary".to_string(),
                role: "button".to_string(),
                name: Some("Submit".to_string()),
                value: None,
                rect: Rect {
                    x: 10,
                    y: 10,
                    width: 20,
                    height: 20,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
            },
            AccessibilityNode {
                id: "grp_submit_secondary".to_string(),
                role: "button".to_string(),
                name: Some("Submit".to_string()),
                value: None,
                rect: Rect {
                    x: 40,
                    y: 10,
                    width: 20,
                    height: 20,
                },
                children: Vec::new(),
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
            },
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    assert!(super::find_semantic_target_by_id(&tree, "btn_submit").is_none());
}

#[test]
fn click_element_postcondition_rejects_stable_button_tree_change_without_semantic_delta() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: false,
        semantic_change_delta: 0,
    };

    assert!(!super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_rejects_stable_button_tree_change_without_activation_signal() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: false,
        semantic_change_delta: 1,
    };

    assert!(!super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_rejects_button_focus_loss_without_other_change() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        focused: true,
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        focused: false,
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: false,
        semantic_change_delta: 0,
    };

    assert!(!super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_rejects_button_focus_gain_without_other_change() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        focused: false,
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        focused: true,
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: false,
        semantic_change_delta: 0,
    };

    assert!(!super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_accepts_stable_button_material_change_without_focus_activation()
{
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        center_point: Some((49.5, 180.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        center_point: Some((50.0, 180.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: true,
        semantic_change_delta: 28,
    };

    assert!(super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_rejects_small_non_link_material_change_without_activation_signal(
) {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_buy".to_string()),
        dom_id: Some("buy".to_string()),
        selector: Some("#buy".to_string()),
        tag_name: Some("button".to_string()),
        center_point: Some((70.5, 150.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_buy".to_string()),
        dom_id: Some("buy".to_string()),
        selector: Some("#buy".to_string()),
        tag_name: Some("button".to_string()),
        center_point: Some((70.5, 150.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: true,
        semantic_change_delta: 4,
    };

    assert!(!super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_rejects_stable_editable_material_change_without_focus_or_commit()
{
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("inp_tt".to_string()),
        dom_id: Some("tt".to_string()),
        selector: Some("#tt".to_string()),
        tag_name: Some("input".to_string()),
        editable: true,
        center_point: Some((76.0, 123.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("inp_tt".to_string()),
        dom_id: Some("tt".to_string()),
        selector: Some("#tt".to_string()),
        tag_name: Some("input".to_string()),
        editable: true,
        center_point: Some((76.0, 123.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: true,
        semantic_change_delta: 6,
    };

    assert!(!super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_accepts_editable_focus_transition() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("inp_query".to_string()),
        dom_id: Some("query".to_string()),
        selector: Some("#query".to_string()),
        tag_name: Some("input".to_string()),
        editable: true,
        focused: false,
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("inp_query".to_string()),
        dom_id: Some("query".to_string()),
        selector: Some("#query".to_string()),
        tag_name: Some("input".to_string()),
        editable: true,
        focused: true,
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: true,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: false,
        semantic_change_delta: 0,
    };

    assert!(super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_accepts_stable_button_material_change_with_focus_activation() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        focused: false,
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let post_target = super::BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: Some("subbtn".to_string()),
        selector: Some("#subbtn".to_string()),
        tag_name: Some("button".to_string()),
        focused: true,
        center_point: Some((74.5, 99.5)),
        ..Default::default()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: false,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: true,
        semantic_change_delta: 29,
    };

    assert!(super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        Some(&post_target),
        Some(&post_target),
        &postcondition,
    ));
}

#[test]
fn geometry_only_target_disappearance_counts_as_postcondition() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("grp_2".to_string()),
        selector: Some("#area_svg > rect:nth-of-type(1)".to_string()),
        tag_name: Some("rect".to_string()),
        center_point: Some((40.0, 110.0)),
        ..Default::default()
    };

    let postcondition = super::click_element_postcondition_met(
        "<root><generic id=\"grp_2\" name=\"2\" /></root>",
        &pre_target,
        Some("file:///tmp/miniwob/ascending-numbers.1.html"),
        "<root><generic id=\"grp_3\" name=\"3\" /></root>",
        None,
        Some("file:///tmp/miniwob/ascending-numbers.1.html"),
    );

    assert!(postcondition.target_disappeared);
    assert!(super::click_element_postcondition_counts_as_success(
        &pre_target,
        None,
        None,
        None,
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_rejects_popup_dismissal_without_editable_value_commit() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("grp_williston".to_string()),
        selector: Some("#ui-id-2 > li".to_string()),
        tag_name: Some("li".to_string()),
        center_point: Some((60.5, 137.5)),
        ..Default::default()
    };
    let pre_focused_control = super::BrowserSemanticTarget {
        semantic_id: Some("inp_to".to_string()),
        dom_id: Some("flight-to".to_string()),
        selector: Some("#flight-to".to_string()),
        tag_name: Some("input".to_string()),
        value: Some("ISN".to_string()),
        focused: true,
        editable: true,
        center_point: Some((67.0, 117.5)),
        ..Default::default()
    };
    let post_focused_control = pre_focused_control.clone();
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: true,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: false,
        semantic_change_delta: 0,
    };

    assert!(!super::click_element_postcondition_counts_as_success(
        &pre_target,
        Some(&pre_focused_control),
        None,
        Some(&post_focused_control),
        &postcondition,
    ));
}

#[test]
fn click_element_postcondition_accepts_popup_commit_when_editable_value_changes() {
    let pre_target = super::BrowserSemanticTarget {
        semantic_id: Some("grp_williston".to_string()),
        selector: Some("#ui-id-2 > li".to_string()),
        tag_name: Some("li".to_string()),
        center_point: Some((60.5, 137.5)),
        ..Default::default()
    };
    let pre_focused_control = super::BrowserSemanticTarget {
        semantic_id: Some("inp_to".to_string()),
        dom_id: Some("flight-to".to_string()),
        selector: Some("#flight-to".to_string()),
        tag_name: Some("input".to_string()),
        value: Some("ISN".to_string()),
        focused: true,
        editable: true,
        center_point: Some((67.0, 117.5)),
        ..Default::default()
    };
    let post_focused_control = super::BrowserSemanticTarget {
        value: Some("Williston, ND (ISN)".to_string()),
        ..pre_focused_control.clone()
    };
    let postcondition = super::ClickElementPostcondition {
        target_disappeared: true,
        editable_focus_transition: false,
        tree_changed: true,
        url_changed: false,
        material_semantic_change: false,
        semantic_change_delta: 0,
    };

    assert!(super::click_element_postcondition_counts_as_success(
        &pre_target,
        Some(&pre_focused_control),
        None,
        Some(&post_focused_control),
        &postcondition,
    ));
}

#[test]
fn click_selector_fallback_locator_prefers_explicit_selector() {
    let target = super::BrowserSemanticTarget {
        selector: Some("[id=\"subbtn\"]".to_string()),
        dom_id: Some("subbtn".to_string()),
        ..Default::default()
    };

    assert_eq!(
        super::click_selector_fallback_locator(&target).as_deref(),
        Some("[id=\"subbtn\"]"),
    );
}

#[test]
fn click_selector_fallback_locator_derives_selector_from_dom_id() {
    let target = super::BrowserSemanticTarget {
        dom_id: Some("subbtn".to_string()),
        ..Default::default()
    };

    assert_eq!(
        super::click_selector_fallback_locator(&target).as_deref(),
        Some("[id=\"subbtn\"]"),
    );
}

#[test]
fn prefers_selector_click_path_for_native_dom_control() {
    let target = super::BrowserSemanticTarget {
        dom_id: Some("buy".to_string()),
        tag_name: Some("button".to_string()),
        ..Default::default()
    };

    assert!(super::prefers_selector_click_path(&target));
}

#[test]
fn does_not_prefer_selector_click_path_for_non_dom_custom_target() {
    let target = super::BrowserSemanticTarget {
        selector: Some("[id=\"chart\"]".to_string()),
        tag_name: Some("canvas".to_string()),
        ..Default::default()
    };

    assert!(!super::prefers_selector_click_path(&target));
}

#[test]
fn dispatch_error_timeout_detection_matches_click_wrapper_timeout() {
    assert!(super::dispatch_error_is_timeout(
        "dispatch timed out after 2500 ms. Retry the action."
    ));
    assert!(!super::dispatch_error_is_timeout(
        "selector click failed: Element not found"
    ));
}

#[test]
fn live_tree_refresh_preferred_for_cached_native_dom_target_without_execution_ids() {
    let target = super::BrowserSemanticTarget {
        dom_id: Some("buy".to_string()),
        tag_name: Some("button".to_string()),
        dom_clickable: true,
        ..Default::default()
    };

    assert!(super::target_prefers_live_tree_refresh_before_dispatch(
        &target,
        "recent_accessibility_snapshot",
    ));
}

#[test]
fn live_tree_refresh_not_preferred_for_geometry_only_canvas_target() {
    let target = super::BrowserSemanticTarget {
        selector: Some("[id=\"chart\"]".to_string()),
        tag_name: Some("canvas".to_string()),
        center_point: Some((70.5, 150.5)),
        ..Default::default()
    };

    assert!(!super::target_prefers_live_tree_refresh_before_dispatch(
        &target,
        "recent_accessibility_snapshot",
    ));
}

#[test]
fn geometry_dispatch_point_snaps_native_dom_targets_to_integral_pixels() {
    let target = super::BrowserSemanticTarget {
        dom_id: Some("buy".to_string()),
        tag_name: Some("button".to_string()),
        dom_clickable: true,
        rect_bounds: Some((20, 100, 101, 51)),
        ..Default::default()
    };

    assert_eq!(
        super::geometry_dispatch_point(&target, (70.5, 150.5)),
        (71.0, 149.0),
    );
}

#[test]
fn geometry_dispatch_point_preserves_fractional_geometry_only_targets() {
    let target = super::BrowserSemanticTarget {
        selector: Some("[id=\"chart\"]".to_string()),
        tag_name: Some("canvas".to_string()),
        rect_bounds: Some((20, 100, 101, 51)),
        ..Default::default()
    };

    assert_eq!(
        super::geometry_dispatch_point(&target, (70.5, 150.5)),
        (70.5, 150.5),
    );
}
