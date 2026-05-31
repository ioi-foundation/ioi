use super::*;

pub(super) fn has_meaningful_visual_context(screenshot_base64: Option<&str>) -> bool {
    let Some(screenshot_base64) = screenshot_base64 else {
        return false;
    };
    let Ok(bytes) = BASE64.decode(screenshot_base64) else {
        return true;
    };
    let Ok(image) = image::load_from_memory(&bytes) else {
        return true;
    };
    let (width, height) = image.dimensions();
    width > 8 && height > 8 && width.saturating_mul(height) > 64
}

fn should_prefer_browser_semantics(is_browser: bool, tools: &[LlmToolDefinition]) -> bool {
    is_browser && tools.iter().any(|tool| tool.name.starts_with("browser__"))
}

pub(crate) fn reply_safe_browser_semantics_enabled(
    is_browser: bool,
    tools: &[LlmToolDefinition],
    resolved_intent: Option<&ResolvedIntentState>,
) -> bool {
    if resolved_intent
        .map(|intent| intent.intent_id == "conversation.reply")
        .unwrap_or(false)
    {
        return false;
    }

    if resolved_intent
        .map(|intent| {
            intent.intent_id == "browser.interact"
                || intent
                    .required_capabilities
                    .iter()
                    .any(|capability| capability.as_str().starts_with("browser."))
        })
        .unwrap_or(false)
    {
        return tools.iter().any(|tool| tool.name.starts_with("browser__"));
    }

    should_prefer_browser_semantics(is_browser, tools)
}

pub(super) fn goal_prefers_sustained_hover_browser_surface(goal: &str) -> bool {
    browser_rule_relevant(
        goal,
        &[
            "keep your mouse",
            "keep the mouse",
            "keep mouse",
            "keep the pointer",
            "keep pointer",
            "keep the cursor",
            "hold the mouse",
            "hold the pointer",
            "hold the cursor",
            "stay inside",
            "stay on",
            "follow",
            "moves around",
            "moving target",
            "as it moves",
        ],
    )
}

pub(super) fn browser_surface_requires_visual_grounding(
    current_browser_snapshot: Option<&str>,
    browser_observation_context: &str,
) -> bool {
    let fragments = [
        current_browser_snapshot.unwrap_or_default(),
        browser_observation_context,
    ];
    let has_canvas_surface = fragments
        .iter()
        .any(|fragment| fragment.contains("tag_name=\"canvas\""));
    if has_canvas_surface
        && !browser_observation_has_grounded_non_canvas_targets(browser_observation_context)
    {
        return true;
    }

    let has_explicit_geometry_role = fragments.iter().any(|fragment| {
        fragment.contains(" geometry_role=\"") || fragment.contains(" geometry_role=")
    });
    if has_explicit_geometry_role {
        return true;
    }

    let has_shape_surface = fragments.iter().any(|fragment| {
        fragment.contains("tag_name=\"svg\"")
            || fragment.contains(" shape_kind=\"")
            || fragment.contains(" shape_kind=")
    });
    if !has_shape_surface {
        return false;
    }

    let grounded_shape_targets =
        browser_observation_has_grounded_shape_targets(browser_observation_context);

    !grounded_shape_targets
}

pub(super) fn browser_prompt_visual_grounding_required(
    prefer_browser_semantics: bool,
    mode: AttentionMode,
    current_browser_snapshot: Option<&str>,
    browser_observation_context: &str,
) -> bool {
    prefer_browser_semantics
        && matches!(mode, AttentionMode::VisualAction)
        && browser_surface_requires_visual_grounding(
            current_browser_snapshot,
            browser_observation_context,
        )
}

pub(super) fn browser_observation_has_grounded_shape_targets(
    browser_observation_context: &str,
) -> bool {
    browser_observation_context.lines().any(|line| {
        line.contains("shape_kind=")
            && line.contains("center=")
            && line.contains(" name=")
            && line.contains(" tag=")
    })
}

pub(super) fn browser_observation_has_grounded_geometry_targets(
    browser_observation_context: &str,
) -> bool {
    browser_observation_context.lines().any(|line| {
        line.contains("shape_kind=")
            && line.contains("center=")
            && (line.contains("geometry_role=")
                || line.contains("connected_line_angles=")
                || line.contains("angle_mid="))
    })
}

fn browser_observation_has_grounded_non_canvas_targets(browser_observation_context: &str) -> bool {
    browser_observation_context
        .lines()
        .flat_map(|line| line.split('|'))
        .any(|fragment| {
            let compact = fragment
                .split_once("IMPORTANT TARGETS:")
                .map(|(_, tail)| tail)
                .unwrap_or(fragment)
                .trim()
                .trim_end_matches("</root>")
                .trim();
            if compact.is_empty()
                || compact.starts_with("RECENT BROWSER OBSERVATION:")
                || compact.contains(" tag=root")
                || compact.contains(" name=click canvas")
            {
                return false;
            }

            let has_action_tag = [
                "button", "checkbox", "radio", "textbox", "link", "combobox", "listbox", "option",
                "menuitem", "tab", "switch", "slider",
            ]
            .iter()
            .any(|tag| compact.contains(&format!(" tag={tag}")));
            let has_locator = compact.contains(" selector=")
                || compact.contains(" dom_id=")
                || compact.contains(" center=");
            let dom_clickable = compact.contains(" dom_clickable=true");
            let grounded_shape_target =
                compact.contains(" shape_kind=") && compact.contains(" center=");

            (has_action_tag || dom_clickable || grounded_shape_target) && has_locator
        })
}

pub(super) fn encode_browser_prompt_screenshot(raw_bytes: &[u8]) -> Option<String> {
    let image = image::load_from_memory(raw_bytes).ok()?;
    let resized = if image.width() <= BROWSER_PROMPT_SCREENSHOT_MAX_DIM
        && image.height() <= BROWSER_PROMPT_SCREENSHOT_MAX_DIM
    {
        image
    } else {
        image.thumbnail(
            BROWSER_PROMPT_SCREENSHOT_MAX_DIM,
            BROWSER_PROMPT_SCREENSHOT_MAX_DIM,
        )
    };
    let mut buf = Vec::new();
    let mut cursor = Cursor::new(&mut buf);
    JpegEncoder::new_with_quality(&mut cursor, BROWSER_PROMPT_SCREENSHOT_JPEG_QUALITY)
        .encode_image(&resized)
        .ok()?;
    Some(BASE64.encode(&buf))
}

pub(super) async fn maybe_capture_browser_prompt_screenshot(
    service: &RuntimeAgentService,
    current_browser_snapshot: Option<&str>,
    browser_observation_context: &str,
) -> Option<String> {
    if !browser_surface_requires_visual_grounding(
        current_browser_snapshot,
        browser_observation_context,
    ) {
        return None;
    }

    let raw_bytes = service.browser.capture_tab_screenshot(false).await.ok()?;
    encode_browser_prompt_screenshot(&raw_bytes)
}

pub(super) fn top_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowUp"
    } else {
        "Control+Home"
    }
}

pub(super) fn resolve_browser_observation_context(
    full_history: &[ChatMessage],
    current_browser_snapshot: Option<&str>,
    prefer_browser_semantics: bool,
) -> String {
    if prefer_browser_semantics {
        if let Some(snapshot) = current_browser_snapshot {
            let current_context = build_browser_observation_context_from_snapshot_with_history(
                snapshot,
                full_history,
            );
            if !current_context.is_empty() {
                return current_context;
            }
        }
    }

    let recent_context = build_recent_browser_observation_context(full_history);
    if !recent_context.is_empty() || !prefer_browser_semantics {
        return recent_context;
    }

    current_browser_snapshot
        .map(|snapshot| {
            build_browser_observation_context_from_snapshot_with_history(snapshot, full_history)
        })
        .unwrap_or_default()
}

#[allow(dead_code)]
pub(super) fn top_edge_jump_tool_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__press_key {"key":"ArrowUp","modifiers":["Meta"]}"#
    } else {
        r#"browser__press_key {"key":"Home","modifiers":["Control"]}"#
    }
}

pub(super) fn top_edge_jump_tool_call_with_grounded_selector() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__press_key {"key":"ArrowUp","modifiers":["Meta"],"selector":"<grounded selector>"}"#
    } else {
        r#"browser__press_key {"key":"Home","modifiers":["Control"],"selector":"<grounded selector>"}"#
    }
}

#[allow(dead_code)]
fn bottom_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowDown"
    } else {
        "Control+End"
    }
}

#[allow(dead_code)]
fn bottom_edge_jump_tool_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__press_key {"key":"ArrowDown","modifiers":["Meta"]}"#
    } else {
        r#"browser__press_key {"key":"End","modifiers":["Control"]}"#
    }
}

pub(crate) async fn current_browser_observation_snapshot(
    service: &RuntimeAgentService,
) -> Option<String> {
    let raw_tree = if let Some((_, tree)) = service
        .browser
        .recent_prompt_observation_snapshot(CURRENT_BROWSER_OBSERVATION_CACHE_MAX_AGE)
        .await
    {
        tree
    } else if let Some((_, tree)) = service
        .browser
        .recent_accessibility_snapshot(CURRENT_BROWSER_OBSERVATION_CACHE_MAX_AGE)
        .await
    {
        tree
    } else {
        match tokio::time::timeout(
            CURRENT_BROWSER_OBSERVATION_TIMEOUT,
            service.browser.get_prompt_observation_tree(),
        )
        .await
        {
            Ok(Ok(tree)) => tree,
            Ok(Err(err)) => {
                log::warn!(
                    "Current browser observation fetch failed before timeout: {}",
                    err
                );
                return None;
            }
            Err(_) => {
                log::warn!(
                    "Current browser observation fetch timed out after {:?}.",
                    CURRENT_BROWSER_OBSERVATION_TIMEOUT
                );
                return None;
            }
        }
    };
    let lens = AutoLens;
    let transformed = lens.transform(&raw_tree).unwrap_or(raw_tree);
    Some(serialize_tree_to_xml(&transformed, 0))
}
