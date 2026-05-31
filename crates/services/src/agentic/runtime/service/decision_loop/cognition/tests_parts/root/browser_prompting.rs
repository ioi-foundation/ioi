#[test]
fn tool_routing_contract_prefers_specific_workspace_tools_over_shell() {
    let contract = build_tool_routing_contract(false, IntentScopeProfile::WorkspaceOps);
    assert!(contract.contains("Prefer the most specific typed workspace tool"));
    assert!(contract.contains("`file__search` only when the path is still unknown"));
    assert!(contract.contains("`file__info` for timestamps and metadata"));
    assert!(contract.contains("generic shell commands"));
}

#[test]
fn tool_routing_contract_prefers_browser_semantic_tools_for_browser_steps() {
    let contract = build_tool_routing_contract(true, IntentScopeProfile::UiInteraction);
    assert!(contract.contains("grounded browser tool"));
    assert!(contract.contains("`browser__inspect`"));
    assert!(contract.contains("`browser__select_option`"));
    assert!(contract.contains("`screen__click_at`"));
    assert!(contract.contains("`web__search` / `web__read`"));
}

#[test]
fn command_execution_does_not_require_clipboard() {
    let tools = vec![tool("shell__run")];
    assert!(preflight_missing_capability(
        None,
        IntentScopeProfile::CommandExecution,
        false,
        &tools
    )
    .is_none());
}

#[test]
fn tiny_screenshot_is_not_meaningful_visual_context() {
    let screenshot = encode_png_base64(1, 1);
    assert!(!has_meaningful_visual_context(Some(&screenshot)));
}

#[test]
fn larger_screenshot_is_meaningful_visual_context() {
    let screenshot = encode_png_base64(32, 32);
    assert!(has_meaningful_visual_context(Some(&screenshot)));
}

#[test]
fn browser_surface_requires_visual_grounding_for_svg_geometry_snapshot() {
    let snapshot = r#"<svg id="svg-grid" tag_name="svg"><generic shape_kind="circle" geometry_role="vertex" /></svg>"#;
    assert!(browser_surface_requires_visual_grounding(
        Some(snapshot),
        "RECENT BROWSER OBSERVATION:"
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_ignores_plain_browser_forms() {
    let snapshot = r#"<root><button id="btn_submit" tag_name="button">Submit</button></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\nbtn_submit tag=button name=Submit";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_ignores_canvas_wrapper_when_dom_targets_exist() {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><button id="btn_submit" tag_name="button">Submit</button></root>"#;
    let observation =
        "RECENT BROWSER OBSERVATION:\nbtn_submit tag=button name=Submit selector=[id=\"submit\"] dom_clickable=true\ngrp_click_canvas tag=generic name=click canvas";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_ignores_packed_canvas_wrapper_when_dom_targets_exist()
{
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><button id="btn_submit" tag_name="button">Submit</button></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\n<root> IMPORTANT TARGETS: btn_submit tag=button name=Submit selector=[id=\"submit\"] dom_clickable=true | grp_click_canvas tag=generic name=click canvas | root_dom_fallback_tree tag=root name=DOM fallback tree </root>";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_requires_canvas_when_only_wrapper_is_grounded() {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\ngrp_click_canvas tag=generic name=click canvas";
    assert!(browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_skips_grounded_shape_targets() {
    let snapshot = r#"<root><svg id="area_svg" tag_name="svg"><generic id="grp_5" name="5" shape_kind="rectangle" center="63,154" /></svg></root>"#;
    let observation =
        "RECENT BROWSER OBSERVATION:\ngrp_5 tag=generic name=5 shape_kind=rectangle center=63,154";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_surface_requires_visual_grounding_ignores_canvas_wrapper_when_shape_target_is_grounded()
{
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><svg id="area_svg" tag_name="svg"><generic id="grp_circ" name="large circle" shape_kind="circle" center="84,141" /></svg></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\n<root> IMPORTANT TARGETS: grp_circ tag=generic name=large circle centered at 84,141 radius 22 dom_id=circ selector=[id=\"circ\"] shape_kind=circle center=84,141 radius=22 | grp_click_canvas tag=generic name=click canvas dom_id=click-canvas selector=[id=\"click-canvas\"] | root_dom_fallback_tree tag=root name=DOM fallback tree </root>";
    assert!(!browser_surface_requires_visual_grounding(
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_prompt_visual_grounding_required_drops_dom_form_screenshot() {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><button id="btn_submit" tag_name="button">Submit</button></root>"#;
    let observation =
        "RECENT BROWSER OBSERVATION:\nbtn_submit tag=button name=Submit selector=[id=\"submit\"] dom_clickable=true\ngrp_click_canvas tag=generic name=click canvas";
    assert!(!browser_prompt_visual_grounding_required(
        true,
        AttentionMode::VisualAction,
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_prompt_visual_grounding_required_keeps_canvas_screenshot() {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas></root>"#;
    assert!(browser_prompt_visual_grounding_required(
        true,
        AttentionMode::VisualAction,
        Some(snapshot),
        "RECENT BROWSER OBSERVATION:\ngrp_click_canvas tag=generic name=click canvas"
    ));
}

#[test]
fn browser_prompt_visual_grounding_required_drops_canvas_screenshot_when_shape_target_is_grounded()
{
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><svg id="area_svg" tag_name="svg"><generic id="grp_circ" name="large circle" shape_kind="circle" center="84,141" /></svg></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\n<root> IMPORTANT TARGETS: grp_circ tag=generic name=large circle centered at 84,141 radius 22 dom_id=circ selector=[id=\"circ\"] shape_kind=circle center=84,141 radius=22 | grp_click_canvas tag=generic name=click canvas dom_id=click-canvas selector=[id=\"click-canvas\"] | root_dom_fallback_tree tag=root name=DOM fallback tree </root>";
    assert!(!browser_prompt_visual_grounding_required(
        true,
        AttentionMode::VisualAction,
        Some(snapshot),
        observation
    ));
}

#[test]
fn browser_prompt_visual_grounding_required_drops_canvas_screenshot_when_start_gate_is_first_priority_target(
) {
    let snapshot = r#"<root><canvas id="click-canvas" tag_name="canvas"></canvas><generic id="grp_start" name="START" dom_id="sync-task-cover" dom_clickable="true"></generic></root>"#;
    let observation = "RECENT BROWSER OBSERVATION:\n<root> IMPORTANT TARGETS: grp_start tag=generic name=START dom_id=sync-task-cover selector=[id=\"sync-task-cover\"] dom_clickable=true | grp_click_canvas tag=generic name=click canvas dom_id=click-canvas selector=[id=\"click-canvas\"] </root>";
    assert!(!browser_prompt_visual_grounding_required(
        true,
        AttentionMode::VisualAction,
        Some(snapshot),
        observation
    ));
}

#[test]
fn encoded_browser_prompt_screenshot_stays_meaningful() {
    let screenshot = encode_png_base64(160, 120);
    let raw_bytes = BASE64.decode(screenshot).expect("decode png");
    let encoded = encode_browser_prompt_screenshot(&raw_bytes).expect("encode prompt jpeg");
    assert!(has_meaningful_visual_context(Some(&encoded)));
}

#[test]
fn encoded_browser_prompt_screenshot_does_not_upscale_small_inputs() {
    let screenshot = encode_png_base64(160, 120);
    let raw_bytes = BASE64.decode(screenshot).expect("decode png");
    let encoded = encode_browser_prompt_screenshot(&raw_bytes).expect("encode prompt jpeg");
    let encoded_bytes = BASE64.decode(encoded).expect("decode jpeg");
    let image = image::load_from_memory(&encoded_bytes).expect("load jpeg");
    assert_eq!((image.width(), image.height()), (160, 120));
}

#[test]
fn browser_prompt_uses_trimmed_browser_tool_surface() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("screen"),
            tool("screen__click"),
            tool("agent__complete"),
            tool("agent__escalate"),
        ],
        None,
        true,
        "",
        "",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "browser__inspect",
            "browser__click",
            "agent__complete",
            "agent__escalate",
        ]
    );
}

#[test]
fn browser_prompt_compacts_structured_tool_schema_metadata() {
    let filtered = filter_cognition_tools(
        &[tool_with_schema(
            "browser__hover",
            "Move the pointer onto a grounded browser target.",
            r#"{
                "type":"object",
                "description":"Hover arguments",
                "properties":{
                    "id":{
                        "type":"string",
                        "description":"Semantic target id",
                        "examples":["grp_circ"]
                    },
                    "duration_ms":{
                        "type":"integer",
                        "title":"Duration",
                        "description":"How long to track the hover target."
                    }
                },
                "required":["id"]
            }"#,
        )],
        None,
        true,
        "",
        "",
        "",
    );
    let tool = filtered.first().expect("browser tool should remain");

    assert_eq!(
        tool.description,
        "Move the pointer onto a grounded browser target."
    );
    assert!(
        tool.parameters.contains("\"description\""),
        "{}",
        tool.parameters
    );
    assert!(
        !tool.parameters.contains("\"title\""),
        "{}",
        tool.parameters
    );
    assert!(
        !tool.parameters.contains("\"examples\""),
        "{}",
        tool.parameters
    );
    assert!(tool.parameters.contains("\"required\":[\"id\"]"));
    assert!(tool.parameters.contains("\"duration_ms\""));
}

#[test]
fn browser_prompt_hides_synthetic_click_when_shape_targets_are_semantically_grounded() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click_at"),
            tool("agent__complete"),
        ],
        None,
        true,
        "",
        "RECENT BROWSER OBSERVATION:\ngrp_1 tag=generic name=1 shape_kind=digit center=125,96",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["browser__inspect", "browser__click", "agent__complete"]
    );
}

#[test]
fn browser_prompt_keeps_synthetic_click_when_only_canvas_wrapper_is_grounded() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click_at"),
            tool("agent__complete"),
        ],
        None,
        true,
        "",
        "RECENT BROWSER OBSERVATION:\ngrp_click_canvas tag=generic name=click canvas",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "browser__inspect",
            "browser__click",
            "browser__click_at",
            "agent__complete"
        ]
    );
}

#[test]
fn browser_prompt_keeps_synthetic_click_for_grounded_geometry_targets() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click_at"),
            tool("agent__complete"),
        ],
        None,
        true,
        "",
        concat!(
            "RECENT BROWSER OBSERVATION:\n",
            "grp_vertex tag=generic name=small blue circle at 31,108 radius 4 ",
            "shape_kind=circle geometry_role=vertex connected_line_angles=-24|23deg ",
            "angle_mid=0deg center=31,108"
        ),
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "browser__inspect",
            "browser__click",
            "browser__click_at",
            "agent__complete"
        ]
    );
}

#[test]
fn browser_operating_rules_do_not_inject_geometry_degree_heuristics() {
    let rules = build_browser_operating_rules(
        "",
        concat!(
            "RECENT BROWSER OBSERVATION:\n",
            "grp_vertex tag=generic name=vertex shape_kind=circle geometry_role=vertex connected_line_angles=-24|23deg angle_mid=-1deg angle_span=47deg | ",
            "grp_blue_circle tag=generic name=endpoint shape_kind=circle geometry_role=endpoint target_angle_mid=-1deg angle_mid_offset=6deg angle_mid_delta=6deg | ",
            "grp_line tag=generic name=line shape_kind=line line_angle=5deg"
        ),
        "",
        "",
    );

    assert!(
        !rules.contains("Geometry degree fields are directly comparable"),
        "{rules}"
    );
}

#[test]
fn browser_prompt_hides_synthetic_click_while_start_gate_is_pending() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click_at"),
            tool("agent__complete"),
        ],
        None,
        true,
        "",
        concat!(
            "RECENT BROWSER OBSERVATION:\n",
            "btn_submit tag=button name=Submit selector=#subbtn"
        ),
        "RECENT PENDING BROWSER STATE:\nA visible start gate `grp_start` is still covering the task surface.\n",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["browser__inspect", "browser__click", "agent__complete"]
    );
}

#[test]
fn browser_prompt_reduces_tool_surface_for_sustained_hover_goals() {
    let filtered = filter_cognition_tools(
        &[
            tool("browser__navigate"),
            tool("browser__hover"),
            tool("browser__move_pointer"),
            tool("browser__wait"),
            tool("browser__inspect"),
            tool("browser__click"),
            tool("browser__click"),
            tool("browser__press_key"),
            tool("agent__complete"),
            tool("agent__escalate"),
        ],
        None,
        true,
        "Keep your mouse inside the circle as it moves around.",
        "",
        "",
    );
    let names = filtered
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "browser__hover",
            "browser__move_pointer",
            "browser__wait",
            "browser__inspect",
            "browser__click",
            "agent__complete",
            "agent__escalate",
        ]
    );
}

#[test]
fn compact_browser_action_prompt_is_eligible_for_grounded_hover_state() {
    assert!(compact_browser_action_prompt_eligible(
        true,
        false,
        "Keep your mouse inside the circle as it moves around.",
        "RECENT BROWSER OBSERVATION:\ngrp_circ tag=generic name=large circle shape_kind=circle center=95,135",
        "",
        "",
    ));
}
