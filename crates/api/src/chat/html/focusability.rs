fn html_open_tag_name(open_tag_lower: &str) -> Option<&str> {
    let trimmed = open_tag_lower.trim_start();
    let stripped = trimmed.strip_prefix('<')?;
    let end = stripped
        .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
        .unwrap_or(stripped.len());
    let tag_name = &stripped[..end];
    if tag_name.is_empty() {
        None
    } else {
        Some(tag_name)
    }
}

fn html_tag_is_natively_focusable(open_tag_lower: &str, tag_name: &str) -> bool {
    match tag_name {
        "button" | "select" | "textarea" | "summary" => true,
        "a" => open_tag_lower.contains("href="),
        "input" => {
            !(open_tag_lower.contains("type=\"hidden\"")
                || open_tag_lower.contains("type='hidden'"))
        }
        _ => false,
    }
}

pub(super) fn html_has_unfocusable_rollover_marks(html_lower: &str) -> bool {
    if !html_lower.contains("data-detail=") {
        return false;
    }

    let relies_on_focus_behavior = [
        "addeventlistener(\"focus\"",
        "addeventlistener('focus'",
        "addeventlistener(\"focusin\"",
        "addeventlistener('focusin'",
        "onfocus=",
        "onfocusin=",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle));
    if !relies_on_focus_behavior {
        return false;
    }

    let mut cursor = 0usize;
    while let Some(relative_open_start) = html_lower[cursor..].find('<') {
        let open_start = cursor + relative_open_start;
        let Some(relative_open_end) = html_lower[open_start..].find('>') else {
            break;
        };
        let open_end = open_start + relative_open_end + 1;
        let open_tag = &html_lower[open_start..open_end];
        if open_tag.starts_with("<script") || open_tag.starts_with("<style") {
            let close_tag = if open_tag.starts_with("<script") {
                "</script>"
            } else {
                "</style>"
            };
            if let Some(relative_close) = html_lower[open_end..].find(close_tag) {
                cursor = open_end + relative_close + close_tag.len();
                continue;
            }
        }
        if !open_tag.contains("data-detail=") || open_tag.starts_with("</") {
            cursor = open_end;
            continue;
        }
        let Some(tag_name) = html_open_tag_name(open_tag) else {
            cursor = open_end;
            continue;
        };
        if !html_tag_is_natively_focusable(open_tag, tag_name) && !open_tag.contains("tabindex=") {
            return true;
        }
        cursor = open_end;
    }

    false
}

pub(super) fn brief_required_interaction_goal_count(brief: &ChatArtifactBrief) -> usize {
    brief.required_interaction_goal_count()
}

pub(super) fn brief_requires_response_region(brief: &ChatArtifactBrief) -> bool {
    brief.requires_response_region()
}

pub(super) fn brief_requires_rollover_detail(brief: &ChatArtifactBrief) -> bool {
    brief.query_profile.as_ref().is_some_and(|profile| {
        profile.has_interaction_kind(ChatArtifactInteractionGoalKind::DetailInspect)
    })
}

pub(super) fn brief_requires_sequence_browsing(brief: &ChatArtifactBrief) -> bool {
    brief.query_profile.as_ref().is_some_and(|profile| {
        profile.has_interaction_kind(ChatArtifactInteractionGoalKind::SequenceBrowse)
    })
}

pub(super) fn brief_requires_view_switching(brief: &ChatArtifactBrief) -> bool {
    if let Some(profile) = brief.query_profile.as_ref() {
        return profile.has_interaction_kind(ChatArtifactInteractionGoalKind::StateSwitch);
    }
    false
}

pub(crate) fn chat_artifact_interaction_contract(brief: &ChatArtifactBrief) -> serde_json::Value {
    json!({
        "requiredInteractionGoalCount": brief_required_interaction_goal_count(brief),
        "viewSwitchingRequired": brief_requires_view_switching(brief),
        "rolloverDetailRequired": brief_requires_rollover_detail(brief),
        "sequenceBrowsingRequired": brief_requires_sequence_browsing(brief),
        "responseRegionRequired": brief_requires_response_region(brief),
        "queryProfile": brief.query_profile,
    })
}

pub(super) fn extract_html_attribute_values(html_lower: &str, attr_name: &str) -> Vec<String> {
    let mut values = Vec::<String>::new();

    for quote in ['"', '\''] {
        let needle = format!("{attr_name}={quote}");
        let mut cursor = 0usize;
        while let Some(relative_start) = html_lower[cursor..].find(&needle) {
            let value_start = cursor + relative_start + needle.len();
            let Some(relative_end) = html_lower[value_start..].find(quote) else {
                break;
            };
            let value = html_lower[value_start..value_start + relative_end].trim();
            if !value.is_empty() {
                values.push(value.to_string());
            }
            cursor = value_start + relative_end + 1;
        }
    }

    values
}

pub(super) fn normalize_html_selector_token(token: &str) -> Option<String> {
    let normalized = token.trim().trim_start_matches('#').trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_ascii_lowercase())
    }
}

pub(super) fn html_contains_click_activation_behavior(html_lower: &str) -> bool {
    [
        "addeventlistener(\"click\"",
        "addeventlistener('click'",
        "addeventlistener(\"change\"",
        "addeventlistener('change'",
        "onclick=",
        "onchange=",
        "onkeydown=",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle))
}

pub(super) fn html_contains_view_switch_state_mutation(html_lower: &str) -> bool {
    let mutates_panel_state = [
        ".hidden =",
        ".hidden=",
        "toggleattribute(\"hidden\"",
        "toggleattribute('hidden'",
        "setattribute(\"hidden\"",
        "setattribute('hidden'",
        "removeattribute(\"hidden\"",
        "removeattribute('hidden'",
        "setattribute(\"aria-hidden\"",
        "setattribute('aria-hidden'",
        "removeattribute(\"aria-hidden\"",
        "removeattribute('aria-hidden'",
        "setattribute(\"aria-selected\"",
        "setattribute('aria-selected'",
        "removeattribute(\"aria-selected\"",
        "removeattribute('aria-selected'",
        "classlist.add(",
        "classlist.remove(",
        "classlist.toggle(",
        "style.display",
        "style.visibility",
        "dataset.active",
        "dataset.selected",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle));
    let references_panel_mapping = [
        "queryselectorall('[data-view-panel]')",
        "queryselectorall(\"[data-view-panel]\")",
        "queryselectorall('[data-panel]')",
        "queryselectorall(\"[data-panel]\")",
        "queryselectorall('[role=\"tabpanel\"]')",
        "queryselectorall(\"[role='tabpanel']\")",
        "getattribute('aria-controls')",
        "getattribute(\"aria-controls\")",
        "getattribute('data-target')",
        "getattribute(\"data-target\")",
        "dataset.view",
        "dataset.target",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle));

    mutates_panel_state && references_panel_mapping
}

pub(super) fn html_contains_view_switching_control_behavior(html_lower: &str) -> bool {
    let data_view_targets = extract_html_attribute_values(html_lower, "data-view");
    let aria_control_targets = extract_html_attribute_values(html_lower, "aria-controls");
    let data_target_targets = extract_html_attribute_values(html_lower, "data-target");
    let has_multiple_view_controls = data_view_targets.len() >= 2
        || aria_control_targets.len() >= 2
        || data_target_targets.len() >= 2
        || html_lower.contains("role=\"tab\"")
        || html_lower.contains("role='tab'");

    has_multiple_view_controls
        && html_contains_click_activation_behavior(html_lower)
        && html_contains_view_switch_state_mutation(html_lower)
        && html_contains_control_targeted_view_switch_behavior(html_lower)
}

fn html_contains_control_targeted_view_switch_behavior(html_lower: &str) -> bool {
    [
        "queryselectorall('button[data-view]')",
        "queryselectorall(\"button[data-view]\")",
        "queryselectorall('button[data-view], [role=\"tab\"][data-view]')",
        "queryselectorall(\"button[data-view], [role='tab'][data-view]\")",
        "queryselectorall('[role=\"tab\"][data-view]')",
        "queryselectorall(\"[role='tab'][data-view]\")",
        "closest('button[data-view]')",
        "closest(\"button[data-view]\")",
        "closest('[role=\"tab\"][data-view]')",
        "closest(\"[role='tab'][data-view]\")",
        "matches('button[data-view]')",
        "matches(\"button[data-view]\")",
        "matches('[role=\"tab\"][data-view]')",
        "matches(\"[role='tab'][data-view]\")",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle))
}

fn html_open_tag_is_mapped_panel(open_tag_lower: &str, control_targets: &HashSet<String>) -> bool {
    let ids = extract_html_attribute_values(open_tag_lower, "id");
    open_tag_lower.contains("data-view-panel=")
        || open_tag_lower.contains("data-panel=")
        || open_tag_lower.contains("role=\"tabpanel\"")
        || open_tag_lower.contains("role='tabpanel'")
        || ids
            .iter()
            .filter_map(|value| normalize_html_selector_token(value))
            .any(|value| control_targets.contains(&value))
}

fn html_view_panel_control_targets(html_lower: &str) -> HashSet<String> {
    extract_html_attribute_values(html_lower, "data-view")
        .into_iter()
        .chain(extract_html_attribute_values(html_lower, "aria-controls"))
        .chain(extract_html_attribute_values(html_lower, "data-target"))
        .filter_map(|value| normalize_html_selector_token(&value))
        .collect()
}

pub(super) fn html_contains_container_attribute_value(
    html_lower: &str,
    attr_name: &str,
    token: &str,
) -> bool {
    for tag in ["section", "article", "aside", "div", "figure"] {
        let open_tag = format!("<{tag}");
        for quote in ['"', '\''] {
            let attr = format!("{attr_name}={quote}{token}{quote}");
            let mut cursor = 0usize;
            while let Some(relative_start) = html_lower[cursor..].find(&open_tag) {
                let start = cursor + relative_start;
                let Some(relative_end) = html_lower[start..].find('>') else {
                    break;
                };
                let end = start + relative_end + 1;
                if html_lower[start..end].contains(&attr) {
                    return true;
                }
                cursor = end;
            }
        }
    }

    false
}

pub(super) fn html_has_static_view_mapping_markers(html_lower: &str) -> bool {
    let container_ids = extract_html_attribute_values(html_lower, "id")
        .into_iter()
        .filter_map(|value| normalize_html_selector_token(&value))
        .filter(|value| html_contains_container_attribute_value(html_lower, "id", value))
        .collect::<HashSet<_>>();
    let data_view_panels = extract_html_attribute_values(html_lower, "data-view-panel")
        .into_iter()
        .chain(extract_html_attribute_values(html_lower, "data-panel"))
        .filter_map(|value| normalize_html_selector_token(&value))
        .filter(|value| {
            html_contains_container_attribute_value(html_lower, "data-view-panel", value)
                || html_contains_container_attribute_value(html_lower, "data-panel", value)
        })
        .collect::<HashSet<_>>();
    let mut explicit_panel_targets = container_ids.clone();
    explicit_panel_targets.extend(data_view_panels);
    let data_view_targets = extract_html_attribute_values(html_lower, "data-view")
        .into_iter()
        .filter_map(|value| normalize_html_selector_token(&value))
        .collect::<HashSet<_>>();
    if data_view_targets
        .intersection(&explicit_panel_targets)
        .count()
        >= 2
    {
        return true;
    }

    let aria_control_targets = extract_html_attribute_values(html_lower, "aria-controls")
        .into_iter()
        .filter_map(|value| normalize_html_selector_token(&value))
        .collect::<HashSet<_>>();
    if aria_control_targets.intersection(&container_ids).count() >= 2 {
        return true;
    }

    let data_target_targets = extract_html_attribute_values(html_lower, "data-target")
        .into_iter()
        .filter_map(|value| normalize_html_selector_token(&value))
        .collect::<HashSet<_>>();
    data_target_targets.intersection(&container_ids).count() >= 2
}

pub(super) fn html_open_tag_hides_first_paint(open_tag: &str) -> bool {
    open_tag.contains(" hidden")
        || open_tag.contains("\thidden")
        || open_tag.contains("\nhidden")
        || open_tag.contains("hidden=")
        || open_tag.contains("aria-hidden=\"true\"")
        || open_tag.contains("aria-hidden='true'")
        || open_tag.contains("display:none")
        || open_tag.contains("display: none")
}

pub(super) fn count_empty_html_mapped_view_panels(html_lower: &str) -> usize {
    let control_targets = html_view_panel_control_targets(html_lower);
    let mut total = 0usize;

    for tag in ["section", "article", "div", "aside", "figure"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        let mut cursor = 0usize;

        while let Some(relative_start) = html_lower[cursor..].find(&open_pattern) {
            let start = cursor + relative_start;
            let Some(relative_open_end) = html_lower[start..].find('>') else {
                break;
            };
            let open_end = start + relative_open_end + 1;
            let open_tag = &html_lower[start..open_end];
            if !html_open_tag_is_mapped_panel(open_tag, &control_targets) {
                cursor = open_end;
                continue;
            }

            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                total += 1;
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &html_lower[open_end..close_start];
            if !html_fragment_has_detail_content(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn html_uses_custom_font_family_without_loading(html_lower: &str) -> bool {
    if !html_lower.contains("font-family") {
        return false;
    }
    if html_lower.contains("fonts.googleapis.com")
        || html_lower.contains("@font-face")
        || html_lower.contains("font-face")
        || html_lower.contains("local(")
    {
        return false;
    }

    let mut cursor = 0usize;
    while let Some(relative_start) = html_lower[cursor..].find("font-family") {
        let start = cursor + relative_start;
        let Some(relative_colon) = html_lower[start..].find(':') else {
            break;
        };
        let value_start = start + relative_colon + 1;
        let declaration_end = html_lower[value_start..]
            .find(';')
            .map(|offset| value_start + offset)
            .or_else(|| {
                html_lower[value_start..]
                    .find('}')
                    .map(|offset| value_start + offset)
            })
            .unwrap_or(html_lower.len());
        let declaration = html_lower[value_start..declaration_end].trim();
        if declaration
            .split(',')
            .map(|segment| segment.trim().trim_matches('\'').trim_matches('"'))
            .filter(|segment| !segment.is_empty())
            .any(|segment| {
                !matches!(
                    segment,
                    "serif"
                        | "sans-serif"
                        | "monospace"
                        | "cursive"
                        | "fantasy"
                        | "system-ui"
                        | "ui-sans-serif"
                        | "ui-serif"
                        | "ui-monospace"
                        | "-apple-system"
                        | "blinkmacsystemfont"
                        | "segoe ui"
                        | "arial"
                        | "helvetica"
                        | "roboto"
                        | "georgia"
                        | "times new roman"
                        | "courier new"
                )
            })
        {
            return true;
        }
        cursor = declaration_end;
    }

    false
}

pub(super) fn normalize_html_custom_font_family_fallbacks(html: &str) -> String {
    let html_lower = html.to_ascii_lowercase();
    if !html_uses_custom_font_family_without_loading(&html_lower) {
        return html.to_string();
    }

    let mut normalized = String::with_capacity(html.len());
    let mut cursor = 0usize;

    while let Some(relative_start) = html_lower[cursor..].find("font-family") {
        let start = cursor + relative_start;
        normalized.push_str(&html[cursor..start]);

        let Some(relative_colon) = html_lower[start..].find(':') else {
            normalized.push_str(&html[start..]);
            return normalized;
        };
        let colon = start + relative_colon;
        normalized.push_str(&html[start..=colon]);

        let value_start = colon + 1;
        let declaration_end = html_lower[value_start..]
            .find(';')
            .map(|offset| value_start + offset)
            .or_else(|| {
                html_lower[value_start..]
                    .find('}')
                    .map(|offset| value_start + offset)
            })
            .unwrap_or(html.len());
        let declaration = &html[value_start..declaration_end];
        normalized.push_str(&safe_font_family_fallback_for_declaration(declaration));
        cursor = declaration_end;
    }

    normalized.push_str(&html[cursor..]);
    normalized
}
