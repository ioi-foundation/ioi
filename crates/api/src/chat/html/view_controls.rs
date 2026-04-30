fn collect_html_explicit_panel_id_targets(html_lower: &str) -> HashSet<String> {
    extract_html_attribute_values(html_lower, "aria-controls")
        .into_iter()
        .chain(extract_html_attribute_values(html_lower, "data-target"))
        .filter_map(|value| normalize_html_selector_token(&value))
        .collect()
}

fn preferred_missing_panel_id(
    panel: &HtmlMappedViewPanelDescriptor,
    missing_refs: &HashSet<String>,
) -> Option<String> {
    let token = normalize_html_selector_token(&panel.token).unwrap_or_else(|| panel.token.clone());
    let exact_candidates = vec![
        panel.id.clone(),
        token.clone(),
        format!("{token}-panel"),
        sanitize_html_view_panel_id(&token),
    ];

    for candidate in exact_candidates {
        if missing_refs.contains(&candidate) {
            return Some(candidate);
        }
    }

    missing_refs.iter().find_map(|missing| {
        let normalized = normalize_html_selector_token(missing)?;
        let stripped_panel = normalized.strip_suffix("-panel").unwrap_or(&normalized);
        let stripped_chat = normalized
            .strip_prefix("chat-view-panel-")
            .unwrap_or(&normalized);
        if normalized == token || stripped_panel == token || stripped_chat == token {
            Some(normalized)
        } else {
            None
        }
    })
}

pub(super) fn ensure_html_view_switch_contract(html: &str) -> String {
    let modal_first = chat_modal_first_html_enabled();
    let mut normalized = if modal_first {
        html.to_string()
    } else {
        let mut normalized = ensure_html_promoted_view_panels_from_controls(html);
        normalized = ensure_html_synthesized_view_controls(&normalized);
        ensure_first_visible_mapped_view_panel(&normalized)
    };
    let lower = normalized.to_ascii_lowercase();
    if lower.contains("data-chat-view-switch-repair=\"true\"")
        || !html_has_static_view_mapping_markers(&lower)
    {
        return normalized;
    }
    if html_contains_view_switching_control_behavior(&lower) {
        return normalized;
    }

    let script = r#"<script data-chat-normalized="true" data-chat-view-switch-repair="true">(() => {
  const controls = Array.from(document.querySelectorAll('button[data-view], [role="tab"][data-view]'));
  if (controls.length < 2) {
    return;
  }
  const explicitPanels = Array.from(document.querySelectorAll('[data-view-panel]'));
  const mappedPanels = controls
    .map((button) => {
      const ariaTarget = button.getAttribute('aria-controls');
      if (ariaTarget) {
        return document.getElementById(ariaTarget);
      }
      const dataTarget = button.getAttribute('data-target') || '';
      if (dataTarget.startsWith('#')) {
        return document.querySelector(dataTarget);
      }
      return null;
    })
    .filter((panel, index, panels) => panel && panels.indexOf(panel) === index);
  const panels = explicitPanels.length
    ? explicitPanels
    : (mappedPanels.length
      ? mappedPanels
      : Array.from(document.querySelectorAll('[data-panel], [role="tabpanel"]')));
  if (panels.length < 2) {
    return;
  }
  const detailCopy = document.getElementById('detail-copy');
  const summarizePanel = (panel, fallbackLabel) => {
    if (!panel) {
      return fallbackLabel ? `${fallbackLabel} selected.` : '';
    }
    const heading = panel.querySelector('h2, h3, strong, figcaption');
    const detail = panel.querySelector('p, li, td');
    const headingText = heading && heading.textContent ? heading.textContent.trim() : '';
    const detailText = detail && detail.textContent ? detail.textContent.trim() : '';
    if (headingText && detailText) {
      return `${headingText}: ${detailText}`;
    }
    if (headingText) {
      return `${headingText} selected.`;
    }
    if (detailText) {
      return detailText;
    }
    return fallbackLabel ? `${fallbackLabel} selected.` : '';
  };
  const selectView = (activeControl) => {
    const targetView = activeControl.dataset.view || '';
    const rawTarget = activeControl.getAttribute('data-target') || '';
    const targetId = activeControl.getAttribute('aria-controls') || (rawTarget.startsWith('#') ? rawTarget.slice(1) : rawTarget);
    let activePanel = null;
    panels.forEach((panel) => {
      const panelView = panel.dataset.viewPanel || panel.dataset.panel || '';
      const panelId = panel.id || '';
      const isActive = (targetView && panelView === targetView) || (targetId && panelId === targetId);
      panel.hidden = !isActive;
      panel.setAttribute('aria-hidden', String(!isActive));
      if (isActive) {
        activePanel = panel;
      }
    });
    controls.forEach((control) => {
      control.setAttribute('aria-selected', String(control === activeControl));
    });
    if (detailCopy) {
      const fallbackLabel = activeControl.textContent ? activeControl.textContent.trim() : '';
      detailCopy.textContent = summarizePanel(activePanel, fallbackLabel);
    }
  };
  controls.forEach((button) => {
    button.addEventListener('click', () => selectView(button));
  });
  const defaultControl = controls.find((button) => button.getAttribute('aria-selected') === 'true') || controls[0];
  if (defaultControl) {
    selectView(defaultControl);
  }
})();</script>"#;

    normalized = insert_html_before_body_close(&normalized, script);
    if modal_first {
        normalized
    } else {
        ensure_first_visible_mapped_view_panel(&normalized)
    }
}

#[derive(Clone)]
struct HtmlMappedViewPanelDescriptor {
    token: String,
    id: String,
    label: String,
    open_start: usize,
    open_end: usize,
    visible_on_first_paint: bool,
    content_score: usize,
    control_only: bool,
}

struct HtmlViewControlDescriptor {
    target: String,
    open_start: usize,
    open_end: usize,
}

struct HtmlButtonDescriptor {
    open_start: usize,
    open_end: usize,
    label: String,
    view_target: Option<String>,
    selected_on_first_paint: bool,
}

struct HtmlPromotableRegionDescriptor {
    open_start: usize,
    open_end: usize,
    visible_on_first_paint: bool,
}

struct HtmlPromptExampleView {
    token: String,
    id: String,
    label: String,
}

struct HtmlPromptExampleScaffold {
    views: Vec<HtmlPromptExampleView>,
    detail_label: String,
}

fn ensure_html_promoted_view_panels_from_controls(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if lower.contains("data-chat-view-panel-repair=\"true\"")
        || html_has_static_view_mapping_markers(&lower)
    {
        return html.to_string();
    }

    let controls = collect_html_view_controls(html);
    if controls.len() < 2 {
        return html.to_string();
    }

    let first_control_start = controls
        .iter()
        .map(|control| control.open_start)
        .min()
        .unwrap_or(0);
    let regions = collect_html_promotable_view_regions(html, first_control_start);
    if regions.len() < controls.len() {
        return html.to_string();
    }

    let default_region_index = regions
        .iter()
        .position(|region| region.visible_on_first_paint)
        .unwrap_or(0);
    let mut replacements = Vec::<(usize, usize, String)>::new();

    for (index, control) in controls.iter().enumerate() {
        let panel_id = sanitize_html_view_panel_id(&control.target);
        let open_tag = &html[control.open_start..control.open_end];
        let repaired = inject_html_attributes_into_open_tag(
            open_tag,
            &[
                ("data-view", &control.target),
                ("aria-controls", &panel_id),
                (
                    "aria-selected",
                    if index == default_region_index {
                        "true"
                    } else {
                        "false"
                    },
                ),
            ],
        );
        replacements.push((control.open_start, control.open_end, repaired));
    }

    for (index, (control, region)) in controls.iter().zip(regions.iter()).enumerate() {
        let panel_id = sanitize_html_view_panel_id(&control.target);
        let open_tag = &html[region.open_start..region.open_end];
        let mut repaired = inject_html_attributes_into_open_tag(
            open_tag,
            &[
                ("id", &panel_id),
                ("data-view-panel", &control.target),
                ("data-chat-view-panel-repair", "true"),
            ],
        );
        if index == default_region_index {
            repaired = strip_first_paint_hiding_from_open_tag(&repaired);
            repaired = replace_case_insensitive(
                &repaired,
                "aria-hidden=\"true\"",
                "aria-hidden=\"false\"",
            );
            repaired =
                replace_case_insensitive(&repaired, "aria-hidden='true'", "aria-hidden='false'");
        } else {
            repaired = ensure_html_open_tag_hidden(&repaired);
        }
        replacements.push((region.open_start, region.open_end, repaired));
    }

    replacements.sort_by_key(|(start, _, _)| *start);
    let mut rebuilt = String::with_capacity(html.len() + replacements.len() * 64);
    let mut cursor = 0usize;
    for (start, end, replacement) in replacements {
        if start < cursor {
            continue;
        }
        rebuilt.push_str(&html[cursor..start]);
        rebuilt.push_str(&replacement);
        cursor = end;
    }
    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

fn ensure_html_synthesized_view_controls(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if lower.contains("data-chat-view-controls-repair=\"true\"")
        || html_has_static_view_mapping_markers(&lower)
        || count_html_explicit_view_controls(&lower) >= 2
    {
        return html.to_string();
    }

    let panels = collect_html_mapped_view_panels(html);
    if panels.len() < 2 {
        return html.to_string();
    }
    let filtered_panels = panels
        .iter()
        .filter(|panel| !panel.control_only)
        .cloned()
        .collect::<Vec<_>>();
    let panels = if filtered_panels.len() >= 2 {
        filtered_panels
    } else {
        panels
    };

    let visible_panel_index = panels
        .iter()
        .position(|panel| panel.visible_on_first_paint)
        .filter(|index| panels[*index].content_score > 1);
    let richest_panel_index = panels
        .iter()
        .enumerate()
        .max_by_key(|(_, panel)| panel.content_score)
        .map(|(index, _)| index)
        .unwrap_or(0);
    let default_panel_index = visible_panel_index.unwrap_or(richest_panel_index);
    let first_panel_start = panels[0].open_start;
    let mut rebuilt = String::with_capacity(html.len() + 256 + panels.len().saturating_mul(128));
    rebuilt.push_str(&html[..first_panel_start]);
    rebuilt.push_str(&build_html_view_controls_repair_markup(
        &panels,
        default_panel_index,
    ));

    let mut cursor = first_panel_start;
    for (index, panel) in panels.iter().enumerate() {
        rebuilt.push_str(&html[cursor..panel.open_start]);
        let open_tag = &html[panel.open_start..panel.open_end];
        let mut repaired = inject_html_attributes_into_open_tag(
            open_tag,
            &[("id", &panel.id), ("data-view-panel", &panel.token)],
        );
        if index == default_panel_index {
            repaired = strip_first_paint_hiding_from_open_tag(&repaired);
            repaired = replace_case_insensitive(
                &repaired,
                "aria-hidden=\"true\"",
                "aria-hidden=\"false\"",
            );
            repaired =
                replace_case_insensitive(&repaired, "aria-hidden='true'", "aria-hidden='false'");
        } else {
            repaired = ensure_html_open_tag_hidden(&repaired);
        }
        rebuilt.push_str(&repaired);
        cursor = panel.open_end;
    }

    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

pub(super) fn ensure_minimum_html_mapped_panel_content(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if count_empty_html_mapped_view_panels(&lower) == 0 {
        return html.to_string();
    }

    let control_targets = html_view_panel_control_targets(&lower);
    let mut replacements = Vec::<(usize, usize, String)>::new();

    for tag in ["section", "article", "div", "aside", "figure"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        let mut cursor = 0usize;

        while let Some(relative_start) = lower[cursor..].find(&open_pattern) {
            let start = cursor + relative_start;
            let Some(relative_open_end) = lower[start..].find('>') else {
                break;
            };
            let open_end = start + relative_open_end + 1;
            let open_tag_lower = &lower[start..open_end];
            if !html_open_tag_is_mapped_panel(open_tag_lower, &control_targets) {
                cursor = open_end;
                continue;
            }

            let Some(relative_close) = lower[open_end..].find(&close_pattern) else {
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &lower[open_end..close_start];
            if html_fragment_has_detail_content(inner) {
                cursor = close_start + close_pattern.len();
                continue;
            }

            let label = mapped_panel_label_from_open_tag(open_tag_lower);
            let fallback = build_mapped_panel_fallback_markup(&label);
            replacements.push((
                open_end,
                close_start,
                format!("{fallback}{}", &html[open_end..close_start]),
            ));
            cursor = close_start + close_pattern.len();
        }
    }

    if replacements.is_empty() {
        return html.to_string();
    }

    replacements.sort_by_key(|(start, _, _)| *start);
    let mut rebuilt = String::with_capacity(html.len() + replacements.len() * 256);
    let mut cursor = 0usize;
    for (start, end, replacement) in replacements {
        if start < cursor {
            continue;
        }
        rebuilt.push_str(&html[cursor..start]);
        rebuilt.push_str(&replacement);
        cursor = end;
    }
    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

fn mapped_panel_label_from_open_tag(open_tag_lower: &str) -> String {
    let token = extract_html_attribute_values(open_tag_lower, "data-view-panel")
        .into_iter()
        .chain(extract_html_attribute_values(open_tag_lower, "data-panel"))
        .chain(extract_html_attribute_values(open_tag_lower, "id"))
        .next()
        .unwrap_or_else(|| "view".to_string());
    humanize_html_view_token(token.trim_matches('#').trim_end_matches("-panel"))
}

fn build_mapped_panel_fallback_markup(label: &str) -> String {
    format!(
        "<article data-chat-normalized=\"true\" data-chat-empty-panel-repair=\"true\" class=\"chat-view-panel-fallback\"><h2>{label}</h2><p>{label} stays available as a pre-rendered editorial launch view on first paint.</p><ul><li>{label} keeps one concrete evidence surface visible before any click.</li><li>The control bar can switch between pre-rendered views without rebuilding the page shell.</li><li>The shared detail panel can compare the active view with the rest of the launch story.</li></ul></article>",
        label = xml_escape(label)
    )
}

fn count_html_explicit_view_controls(html_lower: &str) -> usize {
    let mut controls = HashSet::<String>::new();
    for attr in ["data-view", "aria-controls", "data-target"] {
        controls.extend(
            extract_html_attribute_values(html_lower, attr)
                .into_iter()
                .filter_map(|value| normalize_html_selector_token(&value)),
        );
    }
    controls.len()
}

fn collect_html_view_controls(html: &str) -> Vec<HtmlViewControlDescriptor> {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut seen = HashSet::<String>::new();
    let mut controls = Vec::<HtmlViewControlDescriptor>::new();

    while let Some(relative_start) = lower[cursor..].find("<button") {
        let start = cursor + relative_start;
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let open_tag_lower = &lower[start..open_end];
        let target = extract_html_attribute_values(open_tag_lower, "data-view")
            .into_iter()
            .chain(
                extract_html_attribute_values(open_tag_lower, "aria-controls")
                    .into_iter()
                    .filter_map(|value| normalize_html_selector_token(&value)),
            )
            .chain(
                extract_html_attribute_values(open_tag_lower, "data-target")
                    .into_iter()
                    .filter_map(|value| normalize_html_selector_token(&value)),
            )
            .next()
            .or_else(|| {
                let close_start = lower[open_end..]
                    .find("</button>")
                    .map(|offset| open_end + offset)?;
                let label = normalize_inline_text(&strip_html_tags(&html[open_end..close_start]));
                slugify_html_view_token(&label)
            });

        if let Some(target) = target {
            if seen.insert(target.clone()) {
                controls.push(HtmlViewControlDescriptor {
                    target,
                    open_start: start,
                    open_end,
                });
            }
        }

        cursor = open_end;
    }

    controls
}

fn collect_html_buttons(html: &str) -> Vec<HtmlButtonDescriptor> {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut buttons = Vec::<HtmlButtonDescriptor>::new();

    while let Some(relative_start) = lower[cursor..].find("<button") {
        let start = cursor + relative_start;
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let open_tag_lower = &lower[start..open_end];
        let close_start = lower[open_end..]
            .find("</button>")
            .map(|offset| open_end + offset)
            .unwrap_or(open_end);
        let label = normalize_inline_text(&strip_html_tags(&html[open_end..close_start]));
        let view_target = extract_html_attribute_values(open_tag_lower, "data-view")
            .into_iter()
            .filter_map(|value| normalize_html_selector_token(&value))
            .next()
            .or_else(|| {
                extract_html_attribute_values(open_tag_lower, "aria-controls")
                    .into_iter()
                    .filter_map(|value| normalize_html_selector_token(&value))
                    .next()
            })
            .or_else(|| {
                extract_html_attribute_values(open_tag_lower, "data-target")
                    .into_iter()
                    .filter_map(|value| normalize_html_selector_token(&value))
                    .next()
            });
        let selected_on_first_paint = open_tag_lower.contains("aria-selected=\"true\"")
            || open_tag_lower.contains("aria-selected='true'");
        buttons.push(HtmlButtonDescriptor {
            open_start: start,
            open_end,
            label,
            view_target,
            selected_on_first_paint,
        });
        cursor = open_end;
    }

    buttons
}

pub(super) fn ensure_html_button_accessibility_contract(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if !lower.contains("<button") {
        return html.to_string();
    }

    let buttons = collect_html_buttons(html);
    if buttons.is_empty() {
        return html.to_string();
    }

    let view_control_indexes = buttons
        .iter()
        .enumerate()
        .filter_map(|(index, button)| button.view_target.as_ref().map(|_| index))
        .collect::<Vec<_>>();
    let default_view_index = view_control_indexes
        .iter()
        .copied()
        .find(|index| buttons[*index].selected_on_first_paint)
        .or_else(|| view_control_indexes.first().copied());
    let primary_action_index = if lower.contains("data-chat-render-primary-action=") {
        None
    } else {
        view_control_indexes
            .iter()
            .copied()
            .find(|index| Some(*index) != default_view_index)
            .or(default_view_index)
    };

    let mut rebuilt = String::with_capacity(html.len() + buttons.len() * 48);
    let mut cursor = 0usize;
    let mut changed = false;

    for (index, button) in buttons.iter().enumerate() {
        rebuilt.push_str(&html[cursor..button.open_start]);
        let open_tag = &html[button.open_start..button.open_end];
        let open_tag_lower = &lower[button.open_start..button.open_end];
        let mut repaired = open_tag.to_string();

        if !open_tag_lower.contains("type=") {
            repaired = inject_html_attributes_into_open_tag(&repaired, &[("type", "button")]);
            changed = true;
        }

        if !open_tag_lower.contains("aria-label=") {
            let derived_label = if !button.label.is_empty() {
                Some(button.label.clone())
            } else {
                button
                    .view_target
                    .as_deref()
                    .map(|value| humanize_html_view_token(value.trim_end_matches("-panel")))
                    .filter(|value| !value.is_empty())
            };
            if let Some(label) = derived_label.as_deref() {
                repaired =
                    inject_html_attributes_into_open_tag(&repaired, &[("aria-label", label)]);
                changed = true;
            }
        }

        if button.view_target.is_some() && !open_tag_lower.contains("aria-selected=") {
            let selected = if Some(index) == default_view_index {
                "true"
            } else {
                "false"
            };
            repaired =
                inject_html_attributes_into_open_tag(&repaired, &[("aria-selected", selected)]);
            changed = true;
        }

        if Some(index) == primary_action_index
            && !open_tag_lower.contains("data-chat-render-primary-action=")
        {
            repaired = inject_html_attributes_into_open_tag(
                &repaired,
                &[("data-chat-render-primary-action", "true")],
            );
            changed = true;
        }

        rebuilt.push_str(&repaired);
        cursor = button.open_end;
    }

    if !changed {
        return html.to_string();
    }

    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

fn collect_html_mapped_view_panels(html: &str) -> Vec<HtmlMappedViewPanelDescriptor> {
    let lower = html.to_ascii_lowercase();
    let tag_patterns = ["<section", "<article", "<div", "<aside", "<figure"];
    let control_targets = html_view_panel_control_targets(&lower);
    let mut seen_tokens = HashSet::<String>::new();
    let mut cursor = 0usize;
    let mut panels = Vec::<HtmlMappedViewPanelDescriptor>::new();

    while cursor < html.len() {
        let next_tag = tag_patterns
            .iter()
            .filter_map(|pattern| lower[cursor..].find(pattern).map(|offset| cursor + offset))
            .min();
        let Some(start) = next_tag else {
            break;
        };
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let open_tag_lower = &lower[start..open_end];
        let role_panel = open_tag_lower.contains("role=\"tabpanel\"")
            || open_tag_lower.contains("role='tabpanel'");
        let existing_id = extract_html_attribute_values(open_tag_lower, "id")
            .into_iter()
            .filter_map(|value| normalize_html_selector_token(&value))
            .next();
        let panel_token = extract_html_attribute_values(open_tag_lower, "data-view-panel")
            .into_iter()
            .chain(extract_html_attribute_values(open_tag_lower, "data-panel"))
            .filter_map(|value| normalize_html_selector_token(&value))
            .next()
            .or_else(|| {
                if role_panel {
                    existing_id.clone()
                } else if existing_id
                    .as_ref()
                    .is_some_and(|value| control_targets.contains(value))
                {
                    existing_id.clone()
                } else {
                    None
                }
            });

        if let Some(token) = panel_token {
            if seen_tokens.insert(token.clone()) {
                let tag_name = html_container_tag_name(open_tag_lower).unwrap_or("section");
                let close_pattern = format!("</{tag_name}>");
                let close_start = lower[open_end..]
                    .find(&close_pattern)
                    .map(|offset| open_end + offset)
                    .unwrap_or_else(|| html.len().min(open_end + 800));
                let panel_inner = &html[open_end..close_start];
                let label = extract_html_panel_label(panel_inner, &token);
                let content_score = score_html_panel_content(panel_inner);
                let control_only = html_panel_is_control_only(panel_inner);
                let id = existing_id
                    .clone()
                    .unwrap_or_else(|| sanitize_html_view_panel_id(&token));
                panels.push(HtmlMappedViewPanelDescriptor {
                    token,
                    id,
                    label,
                    open_start: start,
                    open_end,
                    visible_on_first_paint: !html_open_tag_hides_first_paint(open_tag_lower),
                    content_score,
                    control_only,
                });
            }
        }

        cursor = open_end;
    }

    panels
}

fn collect_html_promotable_view_regions(
    html: &str,
    first_control_start: usize,
) -> Vec<HtmlPromotableRegionDescriptor> {
    let lower = html.to_ascii_lowercase();
    let tag_patterns = ["<section", "<article", "<div", "<aside", "<figure"];
    let mut cursor = 0usize;
    let mut regions = Vec::<HtmlPromotableRegionDescriptor>::new();

    while cursor < html.len() {
        let next_tag = tag_patterns
            .iter()
            .filter_map(|pattern| lower[cursor..].find(pattern).map(|offset| cursor + offset))
            .min();
        let Some(start) = next_tag else {
            break;
        };
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let open_tag_lower = &lower[start..open_end];
        cursor = open_end;

        if start <= first_control_start
            || open_tag_lower.contains("data-view-panel=")
            || open_tag_lower.contains("data-panel=")
            || open_tag_lower.contains("role=\"tabpanel\"")
            || open_tag_lower.contains("role='tabpanel'")
        {
            continue;
        }

        let tag_name = html_container_tag_name(open_tag_lower).unwrap_or("section");
        let close_pattern = format!("</{tag_name}>");
        let close_start = lower[open_end..]
            .find(&close_pattern)
            .map(|offset| open_end + offset)
            .unwrap_or_else(|| html.len().min(open_end + 800));
        let inner_lower = &lower[open_end..close_start];
        if inner_lower.contains("id=\"detail-copy\"")
            || inner_lower.contains("id='detail-copy'")
            || inner_lower.contains("data-chat-shared-detail=")
            || inner_lower.contains("data-chat-view-controls-repair=")
            || inner_lower.contains("button")
                && (inner_lower.contains("data-view=") || inner_lower.contains("aria-controls="))
        {
            continue;
        }

        let visible_content =
            !normalize_inline_text(&strip_html_tags(&html[open_end..close_start])).is_empty();
        if !visible_content && !html_fragment_has_chart_implementation(inner_lower) {
            continue;
        }

        regions.push(HtmlPromotableRegionDescriptor {
            open_start: start,
            open_end,
            visible_on_first_paint: !html_open_tag_hides_first_paint(open_tag_lower),
        });
    }

    regions
}

fn html_container_tag_name(open_tag_lower: &str) -> Option<&'static str> {
    ["section", "article", "div", "aside", "figure"]
        .into_iter()
        .find(|tag| open_tag_lower.starts_with(&format!("<{tag}")))
}

fn extract_html_panel_label(panel_inner: &str, fallback_token: &str) -> String {
    for tag in ["h2", "h3", "h1", "p", "text", "li"] {
        if let Some(label) = extract_html_text_nodes_for_tag(panel_inner, tag, 1)
            .into_iter()
            .next()
        {
            return label;
        }
    }

    humanize_html_view_token(fallback_token)
}

fn html_panel_is_control_only(panel_inner: &str) -> bool {
    let lower = panel_inner.to_ascii_lowercase();
    if lower.matches("<button").count() < 2 {
        return false;
    }
    if html_fragment_has_chart_implementation(&lower)
        || lower.contains("<p")
        || lower.contains("<table")
        || lower.contains("<ul")
        || lower.contains("<ol")
        || lower.contains("<li")
    {
        return false;
    }
    normalize_inline_text(&strip_html_tags(panel_inner))
        .split_whitespace()
        .count()
        <= 8
}

fn score_html_panel_content(panel_inner: &str) -> usize {
    let lower = panel_inner.to_ascii_lowercase();
    let visible_text = normalize_inline_text(&strip_html_tags(panel_inner));
    let mut score = 0usize;

    if html_fragment_has_chart_implementation(&lower) {
        score += 4;
    }
    if lower.contains("<table") || lower.contains("<ul") || lower.contains("<ol") {
        score += 3;
    }
    if lower.contains("<p") && visible_text.chars().count() > 40 {
        score += 2;
    }
    if lower.contains("<h1") || lower.contains("<h2") || lower.contains("<h3") {
        score += 1;
    }
    if html_panel_is_control_only(panel_inner) {
        score = score.saturating_sub(4);
    }

    score
}

fn humanize_html_view_token(token: &str) -> String {
    let words = token
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|fragment| !fragment.is_empty())
        .map(|fragment| {
            let mut chars = fragment.chars();
            let mut word = String::new();
            if let Some(first) = chars.next() {
                word.push(first.to_ascii_uppercase());
            }
            word.push_str(chars.as_str());
            word
        })
        .collect::<Vec<_>>();
    if words.is_empty() {
        "View".to_string()
    } else {
        words.join(" ")
    }
}

fn sanitize_html_view_panel_id(token: &str) -> String {
    let mut normalized = String::with_capacity(token.len());
    let mut last_dash = false;
    for ch in token.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            normalized.push('-');
            last_dash = true;
        }
    }
    let trimmed = normalized.trim_matches('-');
    if trimmed.is_empty() {
        "chat-view-panel".to_string()
    } else {
        format!("chat-view-panel-{trimmed}")
    }
}

fn sanitize_html_prompt_token(value: &str, fallback: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut last_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            normalized.push('-');
            last_dash = true;
        }
    }
    let trimmed = normalized.trim_matches('-');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn slugify_html_view_token(value: &str) -> Option<String> {
    let normalized = sanitize_html_prompt_token(value, "");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn compact_html_prompt_label(value: &str) -> String {
    let normalized = normalize_inline_text(value);
    if normalized.is_empty() {
        return "View".to_string();
    }
    if normalized.chars().count() <= 36 {
        return normalized;
    }
    let compact = normalized
        .split_whitespace()
        .take(4)
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        normalized.chars().take(36).collect()
    } else {
        compact
    }
}

fn html_prompt_example_scaffold(brief: &ChatArtifactBrief) -> HtmlPromptExampleScaffold {
    let mut topics = Vec::<String>::new();
    let mut seen = HashSet::<String>::new();

    for collection in [
        &brief.factual_anchors,
        &brief.required_concepts,
        &brief.reference_hints,
    ] {
        for item in collection {
            for fragment in item
                .split(|ch| matches!(ch, ',' | ';' | '\n'))
                .map(str::trim)
                .filter(|fragment| !fragment.is_empty())
            {
                let key = fragment.to_ascii_lowercase();
                if seen.insert(key) {
                    topics.push(fragment.to_string());
                }
            }
            if topics.len() >= 3 {
                break;
            }
        }
        if topics.len() >= 3 {
            break;
        }
    }

    while topics.len() < 3 {
        topics.push(format!("Evidence view {}", topics.len() + 1));
    }

    let detail_label = topics
        .first()
        .cloned()
        .unwrap_or_else(|| "Key evidence point".to_string());
    let views = topics
        .into_iter()
        .take(3)
        .enumerate()
        .map(|(index, topic)| {
            let label = compact_html_prompt_label(&topic);
            let token = sanitize_html_prompt_token(&label, &format!("view-{}", index + 1));
            let id = format!("{token}-panel");
            HtmlPromptExampleView { token, id, label }
        })
        .collect();

    HtmlPromptExampleScaffold {
        views,
        detail_label,
    }
}

pub(super) fn html_prompt_rollover_mark_example(brief: &ChatArtifactBrief) -> String {
    let scaffold = html_prompt_example_scaffold(brief);
    format!(
        "<rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" tabindex=\"0\" data-detail=\"{}\"></rect>",
        xml_escape(&scaffold.detail_label)
    )
}

pub(super) fn html_prompt_exact_view_scaffold(brief: &ChatArtifactBrief) -> String {
    let scaffold = html_prompt_example_scaffold(brief);
    let first = &scaffold.views[0];
    let second = &scaffold.views[1];
    let third = &scaffold.views[2];
    format!(
        "<button type=\"button\" data-view=\"{}\" aria-controls=\"{}\">{}</button> plus <section id=\"{}\" data-view-panel=\"{}\">...</section>, <section id=\"{}\" data-view-panel=\"{}\" hidden>...</section>, and <section id=\"{}\" data-view-panel=\"{}\" hidden>...</section>",
        xml_escape(&first.token),
        xml_escape(&first.id),
        xml_escape(&first.label),
        xml_escape(&first.id),
        xml_escape(&first.token),
        xml_escape(&second.id),
        xml_escape(&second.token),
        xml_escape(&third.id),
        xml_escape(&third.token),
    )
}

pub(super) fn html_prompt_two_view_example(brief: &ChatArtifactBrief) -> String {
    let scaffold = html_prompt_example_scaffold(brief);
    let first = &scaffold.views[0];
    let second = &scaffold.views[1];
    format!(
        "<section data-view-panel=\"{}\">...<svg>labeled marks for {}</svg>...</section> with a visible comparison rail, score table, or metric-card article for {}.",
        xml_escape(&first.token),
        xml_escape(&first.label),
        xml_escape(&second.label),
    )
}

pub(super) fn html_prompt_view_mapping_pattern(brief: &ChatArtifactBrief) -> String {
    let scaffold = html_prompt_example_scaffold(brief);
    let second = &scaffold.views[1];
    format!(
        "data-view=\"{}\" on the control plus data-view-panel=\"{}\" or id=\"{}\" on the panel",
        xml_escape(&second.token),
        xml_escape(&second.token),
        xml_escape(&second.id),
    )
}

fn build_html_view_controls_repair_markup(
    panels: &[HtmlMappedViewPanelDescriptor],
    default_panel_index: usize,
) -> String {
    let controls = panels
        .iter()
        .enumerate()
        .map(|(index, panel)| {
            format!(
                "<button type=\"button\" data-view=\"{}\" aria-controls=\"{}\" aria-selected=\"{}\">{}</button>",
                xml_escape(&panel.token),
                xml_escape(&panel.id),
                if index == default_panel_index {
                    "true"
                } else {
                    "false"
                },
                xml_escape(&panel.label),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<nav data-chat-normalized=\"true\" data-chat-view-controls-repair=\"true\" aria-label=\"Artifact views\"><div class=\"chat-view-switch-controls\">{controls}</div></nav>"
    )
}

fn ensure_html_open_tag_hidden(open_tag: &str) -> String {
    let mut repaired = open_tag.to_string();
    if !html_open_tag_hides_first_paint(&repaired.to_ascii_lowercase()) {
        repaired = inject_html_attributes_into_open_tag(&repaired, &[("hidden", "hidden")]);
    }
    repaired = replace_case_insensitive(&repaired, "aria-hidden=\"false\"", "aria-hidden=\"true\"");
    repaired = replace_case_insensitive(&repaired, "aria-hidden='false'", "aria-hidden='true'");
    if !repaired.to_ascii_lowercase().contains("aria-hidden=") {
        repaired = inject_html_attributes_into_open_tag(&repaired, &[("aria-hidden", "true")]);
    }
    repaired
}

pub(super) fn ensure_first_visible_mapped_view_panel(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if !html_has_static_view_mapping_markers(&lower) {
        return html.to_string();
    }

    let panels = collect_html_mapped_view_panels(html);
    if panels.len() < 2 {
        return html.to_string();
    }

    let visible_populated_count = panels
        .iter()
        .filter(|panel| panel.visible_on_first_paint && panel.content_score > 0)
        .count();
    let visible_count = panels
        .iter()
        .filter(|panel| panel.visible_on_first_paint)
        .count();
    if visible_count == 1 && visible_populated_count == 1 {
        return html.to_string();
    }

    let target_open_start = panels
        .iter()
        .find(|panel| panel.visible_on_first_paint && panel.content_score > 0)
        .or_else(|| panels.iter().find(|panel| panel.content_score > 0))
        .or_else(|| panels.iter().find(|panel| panel.visible_on_first_paint))
        .or_else(|| panels.first())
        .map(|panel| panel.open_start);

    let Some(target_open_start) = target_open_start else {
        return html.to_string();
    };

    let mut rebuilt = String::with_capacity(html.len());
    let mut cursor = 0usize;
    for panel in panels {
        rebuilt.push_str(&html[cursor..panel.open_start]);
        let open_tag = &html[panel.open_start..panel.open_end];
        if panel.open_start == target_open_start {
            rebuilt.push_str(&strip_first_paint_hiding_from_open_tag(open_tag));
        } else {
            rebuilt.push_str(&ensure_html_open_tag_hidden(open_tag));
        }
        cursor = panel.open_end;
    }
    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

pub(super) fn ensure_html_rollover_detail_contract(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if lower.contains("data-chat-rollover-repair=\"true\"")
        || html_contains_rollover_detail_behavior(&lower)
        || !lower.contains("data-detail=")
        || count_populated_html_detail_regions(&lower) == 0
    {
        return html.to_string();
    }

    let script = r#"<script data-chat-normalized="true" data-chat-rollover-repair="true">(() => {
  const detailCopy = document.getElementById('detail-copy');
  if (!detailCopy) {
    return;
  }
  document.querySelectorAll('[data-detail]').forEach((mark) => {
    if (!mark.hasAttribute('tabindex')) {
      mark.setAttribute('tabindex', '0');
    }
    const updateDetail = () => {
      const detail = mark.getAttribute('data-detail') || '';
      if (detail) {
        detailCopy.textContent = detail;
      }
    };
    mark.addEventListener('click', updateDetail);
    mark.addEventListener('mouseenter', updateDetail);
    mark.addEventListener('focus', updateDetail);
  });
})();</script>"#;

    let repaired = insert_html_before_body_close(html, script);
    ensure_focusable_html_rollover_marks(&repaired)
}

pub(super) fn ensure_focusable_html_rollover_marks(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if !html_has_unfocusable_rollover_marks(&lower) {
        return html.to_string();
    }

    let mut rebuilt = String::with_capacity(html.len() + 128);
    let mut cursor = 0usize;

    while let Some(relative_open_start) = lower[cursor..].find('<') {
        let open_start = cursor + relative_open_start;
        let Some(relative_open_end) = lower[open_start..].find('>') else {
            break;
        };
        let open_end = open_start + relative_open_end + 1;
        let open_tag = &html[open_start..open_end];
        let open_tag_lower = &lower[open_start..open_end];
        if open_tag_lower.starts_with("<script") || open_tag_lower.starts_with("<style") {
            let close_tag = if open_tag_lower.starts_with("<script") {
                "</script>"
            } else {
                "</style>"
            };
            if let Some(relative_close) = lower[open_end..].find(close_tag) {
                let close_end = open_end + relative_close + close_tag.len();
                rebuilt.push_str(&html[cursor..close_end]);
                cursor = close_end;
                continue;
            }
        }
        if !open_tag_lower.contains("data-detail=") || open_tag_lower.starts_with("</") {
            rebuilt.push_str(&html[cursor..open_end]);
            cursor = open_end;
            continue;
        }

        rebuilt.push_str(&html[cursor..open_start]);
        let repaired = html_open_tag_name(open_tag_lower)
            .map(|tag_name| {
                let mut repaired = open_tag.to_string();
                let non_native_focus_target =
                    !html_tag_is_natively_focusable(open_tag_lower, &tag_name);
                if non_native_focus_target && !open_tag_lower.contains("tabindex=") {
                    repaired =
                        inject_html_attributes_into_open_tag(&repaired, &[("tabindex", "0")]);
                }
                if non_native_focus_target && !open_tag_lower.contains("role=") {
                    repaired =
                        inject_html_attributes_into_open_tag(&repaired, &[("role", "button")]);
                }
                if non_native_focus_target && !open_tag_lower.contains("aria-label=") {
                    if let Some(detail_label) =
                        extract_html_attribute_values(open_tag_lower, "data-detail")
                            .into_iter()
                            .map(|value| normalize_inline_text(&value))
                            .find(|value| !value.is_empty())
                    {
                        repaired = inject_html_attributes_into_open_tag(
                            &repaired,
                            &[("aria-label", detail_label.as_str())],
                        );
                    }
                }
                repaired
            })
            .unwrap_or_else(|| open_tag.to_string());
        rebuilt.push_str(&repaired);
        cursor = open_end;
    }

    rebuilt.push_str(&html[cursor..]);
    rebuilt
}
