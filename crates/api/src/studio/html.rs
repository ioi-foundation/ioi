use super::*;

pub(super) fn normalize_html_semantic_structure(html: &str) -> String {
    if studio_modal_first_html_enabled() {
        return html.to_string();
    }
    let with_main = ensure_html_main_region(html);
    ensure_minimum_html_sectioning_elements(&with_main)
}

pub(super) fn normalize_html_terminal_closure(html: &str) -> String {
    let trimmed = html.trim_end();
    if trimmed.is_empty() {
        return html.to_string();
    }

    if html_has_trailing_fragment(trimmed) {
        return html.to_string();
    }

    let lower = trimmed.to_ascii_lowercase();
    let has_html = lower.contains("<html");
    if !has_html {
        return html.to_string();
    }

    let has_body = lower.contains("<body");
    let has_main = lower.contains("<main");
    let has_close_html = lower.contains("</html>");
    let has_close_body = lower.contains("</body>");
    let has_close_main = !has_main || lower.contains("</main>");

    let mut normalized = trimmed.to_string();
    if has_close_html {
        if has_main && has_close_main {
            let lower_normalized = normalized.to_ascii_lowercase();
            if let Some(insert_at) = lower_normalized.rfind("</main>") {
                let suffix =
                    close_unclosed_html_elements_for_truncated_suffix(&normalized[..insert_at]);
                if !suffix.is_empty() {
                    normalized.insert_str(insert_at, &suffix);
                }
            }
        }

        if has_body && has_close_body {
            let lower_normalized = normalized.to_ascii_lowercase();
            if let Some(insert_at) = lower_normalized.rfind("</body>") {
                let suffix =
                    close_unclosed_html_elements_for_truncated_suffix(&normalized[..insert_at]);
                if !suffix.is_empty() {
                    normalized.insert_str(insert_at, &suffix);
                }
            }
        }

        let lower_normalized = normalized.to_ascii_lowercase();
        let Some(insert_at) = lower_normalized.rfind("</html>") else {
            return html.to_string();
        };
        let mut suffix =
            close_unclosed_html_elements_for_truncated_suffix(&normalized[..insert_at]);
        if has_main && !lower_normalized.contains("</main>") {
            suffix.push_str("</main>");
        }
        if has_body && !lower_normalized.contains("</body>") {
            suffix.push_str("</body>");
        }
        if !suffix.is_empty() {
            normalized.insert_str(insert_at, &suffix);
        }
        return normalized;
    }

    normalized.push_str(&close_unclosed_html_elements_for_truncated_suffix(
        &normalized,
    ));
    if has_main && !has_close_main {
        normalized.push_str("</main>");
    }
    if has_body && !has_close_body {
        normalized.push_str("</body>");
    }
    normalized.push_str("</html>");
    normalized
}

fn close_unclosed_html_elements_for_truncated_suffix(html: &str) -> String {
    let mut stack = Vec::<String>::new();
    let mut cursor = 0usize;

    while let Some(relative_start) = html[cursor..].find('<') {
        let start = cursor + relative_start;
        let Some(relative_end) = html[start..].find('>') else {
            break;
        };
        let end = start + relative_end;
        let tag = html[start + 1..end].trim();
        cursor = end + 1;

        if tag.is_empty() || tag.starts_with('!') || tag.starts_with('?') || tag.starts_with('%') {
            continue;
        }

        if let Some(rest) = tag.strip_prefix('/') {
            let name = rest
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()
                .unwrap_or_default()
                .trim_matches('/');
            if name.is_empty() {
                continue;
            }
            let normalized_name = name.to_ascii_lowercase();
            if let Some(position) = stack.iter().rposition(|entry| entry == &normalized_name) {
                stack.truncate(position);
            }
            continue;
        }

        let name = tag
            .split(|c: char| c.is_whitespace() || c == '/' || c == '>')
            .next()
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let normalized_name = name.to_ascii_lowercase();
        if matches!(normalized_name.as_str(), "html" | "body" | "main")
            || html_void_element(&normalized_name)
            || tag.ends_with('/')
        {
            continue;
        }
        stack.push(normalized_name);
    }

    if stack.is_empty() {
        return String::new();
    }

    let mut suffix = String::new();
    for tag in stack.iter().rev() {
        suffix.push_str("</");
        suffix.push_str(tag);
        suffix.push('>');
    }
    suffix
}

fn html_void_element(tag: &str) -> bool {
    matches!(
        tag,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

pub(super) fn normalize_html_interactions(html: &str) -> String {
    let modal_first = studio_modal_first_html_enabled();
    let lower = html.to_ascii_lowercase();
    let had_alert = lower.contains("alert(");
    let mut normalized = normalize_html_external_runtime_dependencies(html);
    normalized = replace_case_insensitive(
        &replace_case_insensitive(&normalized, "window.alert(", "console.info("),
        "alert(",
        "console.info(",
    );
    let _ = had_alert;
    if modal_first {
        return normalized;
    }
    normalized = ensure_html_button_accessibility_contract(&normalized);
    normalized = ensure_html_mapped_panels_define_referenced_ids(&normalized);
    normalized = ensure_html_view_switch_contract(&normalized);
    normalized = ensure_minimum_html_shared_detail_region(&normalized);
    normalized = ensure_minimum_html_mapped_panel_content(&normalized);
    normalized = ensure_minimum_html_rollover_detail_payloads(&normalized);
    normalized = ensure_grouped_html_rollover_detail_marks(&normalized);
    normalized = ensure_focusable_html_rollover_marks(&normalized);
    normalized = ensure_html_interaction_polish_styles(&normalized);
    normalized = ensure_html_rollover_detail_contract(&normalized);
    normalized
}

fn html_has_trailing_fragment(html: &str) -> bool {
    let trimmed = html.trim_end();
    if trimmed.is_empty() {
        return true;
    }
    let Some(last_gt) = trimmed.rfind('>') else {
        return true;
    };
    !trimmed[last_gt + 1..].trim().is_empty()
}

pub(super) fn ensure_html_mapped_panels_define_referenced_ids(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let defined_ids = collect_html_attribute_ids(&lower);
    let mut missing_refs = collect_html_referenced_ids(&lower)
        .into_iter()
        .filter(|id| !defined_ids.contains(id))
        .collect::<HashSet<_>>();
    missing_refs.extend(
        collect_html_explicit_panel_id_targets(&lower)
            .into_iter()
            .filter(|id| !defined_ids.contains(id)),
    );
    if missing_refs.is_empty() {
        return html.to_string();
    }

    let panels = collect_html_mapped_view_panels(html);
    if panels.is_empty() {
        return html.to_string();
    }

    let mut replacements = Vec::<(usize, usize, String)>::new();
    for panel in panels {
        let open_tag = &html[panel.open_start..panel.open_end];
        let open_tag_lower = &lower[panel.open_start..panel.open_end];
        if open_tag_lower.contains("id=") {
            continue;
        }

        let preferred_id = preferred_missing_panel_id(&panel, &missing_refs);
        let Some(preferred_id) = preferred_id else {
            continue;
        };

        let repaired = inject_html_attributes_into_open_tag(
            open_tag,
            &[("id", &preferred_id), ("data-view-panel", &panel.token)],
        );
        replacements.push((panel.open_start, panel.open_end, repaired));
    }

    if replacements.is_empty() {
        return html.to_string();
    }

    replacements.sort_by_key(|(start, _, _)| *start);
    let mut rebuilt = String::with_capacity(html.len() + replacements.len() * 48);
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
        let stripped_studio = normalized
            .strip_prefix("studio-view-panel-")
            .unwrap_or(&normalized);
        if normalized == token || stripped_panel == token || stripped_studio == token {
            Some(normalized)
        } else {
            None
        }
    })
}

pub(super) fn ensure_html_view_switch_contract(html: &str) -> String {
    let modal_first = studio_modal_first_html_enabled();
    let mut normalized = if modal_first {
        html.to_string()
    } else {
        let mut normalized = ensure_html_promoted_view_panels_from_controls(html);
        normalized = ensure_html_synthesized_view_controls(&normalized);
        ensure_first_visible_mapped_view_panel(&normalized)
    };
    let lower = normalized.to_ascii_lowercase();
    if lower.contains("data-studio-view-switch-repair=\"true\"")
        || !html_has_static_view_mapping_markers(&lower)
    {
        return normalized;
    }
    if html_contains_view_switching_control_behavior(&lower) {
        return normalized;
    }

    let script = r#"<script data-studio-normalized="true" data-studio-view-switch-repair="true">(() => {
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
    if lower.contains("data-studio-view-panel-repair=\"true\"")
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
                ("data-studio-view-panel-repair", "true"),
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
    if lower.contains("data-studio-view-controls-repair=\"true\"")
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
        "<article data-studio-normalized=\"true\" data-studio-empty-panel-repair=\"true\" class=\"studio-view-panel-fallback\"><h2>{label}</h2><p>{label} stays available as a pre-rendered editorial launch view on first paint.</p><ul><li>{label} keeps one concrete evidence surface visible before any click.</li><li>The control bar can switch between pre-rendered views without rebuilding the page shell.</li><li>The shared detail panel can compare the active view with the rest of the launch story.</li></ul></article>",
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
    let primary_action_index = if lower.contains("data-studio-render-primary-action=") {
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
            && !open_tag_lower.contains("data-studio-render-primary-action=")
        {
            repaired = inject_html_attributes_into_open_tag(
                &repaired,
                &[("data-studio-render-primary-action", "true")],
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
            || inner_lower.contains("data-studio-shared-detail=")
            || inner_lower.contains("data-studio-view-controls-repair=")
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
        "studio-view-panel".to_string()
    } else {
        format!("studio-view-panel-{trimmed}")
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

fn html_prompt_example_scaffold(brief: &StudioArtifactBrief) -> HtmlPromptExampleScaffold {
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

pub(super) fn html_prompt_rollover_mark_example(brief: &StudioArtifactBrief) -> String {
    let scaffold = html_prompt_example_scaffold(brief);
    format!(
        "<rect x=\"24\" y=\"54\" width=\"42\" height=\"62\" tabindex=\"0\" data-detail=\"{}\"></rect>",
        xml_escape(&scaffold.detail_label)
    )
}

pub(super) fn html_prompt_exact_view_scaffold(brief: &StudioArtifactBrief) -> String {
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

pub(super) fn html_prompt_two_view_example(brief: &StudioArtifactBrief) -> String {
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

pub(super) fn html_prompt_view_mapping_pattern(brief: &StudioArtifactBrief) -> String {
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
        "<nav data-studio-normalized=\"true\" data-studio-view-controls-repair=\"true\" aria-label=\"Artifact views\"><div class=\"studio-view-switch-controls\">{controls}</div></nav>"
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
    if lower.contains("data-studio-rollover-repair=\"true\"")
        || html_contains_rollover_detail_behavior(&lower)
        || !lower.contains("data-detail=")
        || count_populated_html_detail_regions(&lower) == 0
    {
        return html.to_string();
    }

    let script = r#"<script data-studio-normalized="true" data-studio-rollover-repair="true">(() => {
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

fn html_fragment_is_loose_rollover_detail_mark(fragment: &str) -> bool {
    if html_fragment_has_sectioning_root(fragment) {
        return false;
    }
    let lower = fragment.to_ascii_lowercase();
    lower.contains("data-detail=")
        || lower.contains("class=\"data-detail\"")
        || lower.contains("class='data-detail'")
}

fn flush_loose_rollover_detail_mark_group(
    rebuilt: &mut String,
    pending_marks: &mut String,
    wrapped_any: &mut bool,
) {
    if pending_marks.trim().is_empty() {
        pending_marks.clear();
        return;
    }

    *wrapped_any = true;
    rebuilt.push_str(
        "<section data-studio-normalized=\"true\" data-studio-rollover-chip-rail=\"true\"><h2>Evidence highlights</h2><div class=\"studio-rollover-chip-rail\">",
    );
    rebuilt.push_str(pending_marks);
    rebuilt.push_str(
        "</div><p>Select, hover, or focus a highlight to inspect the shared detail panel.</p></section>",
    );
    pending_marks.clear();
}

pub(super) fn ensure_grouped_html_rollover_detail_marks(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if lower.contains("data-studio-rollover-chip-rail=\"true\"")
        || (!lower.contains("class=\"data-detail\"") && !lower.contains("class='data-detail'"))
    {
        return html.to_string();
    }

    let Some((main_content_start, main_content_end)) = html_tag_content_range(html, "main") else {
        return html.to_string();
    };
    let main_inner = &html[main_content_start..main_content_end];
    let fragments = split_top_level_html_fragments(main_inner);
    if fragments.is_empty() {
        return html.to_string();
    }

    let mut rebuilt_inner = String::with_capacity(main_inner.len() + 256);
    let mut pending_marks = String::new();
    let mut wrapped_any = false;

    for fragment in fragments {
        if html_fragment_is_loose_rollover_detail_mark(fragment.trim()) {
            pending_marks.push_str(&fragment);
            continue;
        }
        flush_loose_rollover_detail_mark_group(
            &mut rebuilt_inner,
            &mut pending_marks,
            &mut wrapped_any,
        );
        rebuilt_inner.push_str(&fragment);
    }
    flush_loose_rollover_detail_mark_group(
        &mut rebuilt_inner,
        &mut pending_marks,
        &mut wrapped_any,
    );

    if !wrapped_any {
        return html.to_string();
    }

    format!(
        "{}{}{}",
        &html[..main_content_start],
        rebuilt_inner,
        &html[main_content_end..],
    )
}

fn brief_rollover_detail_labels(brief: &StudioArtifactBrief) -> Vec<String> {
    let mut labels = Vec::<String>::new();
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
                let normalized = compact_html_prompt_label(fragment);
                let key = normalized.to_ascii_lowercase();
                if seen.insert(key) {
                    labels.push(normalized);
                }
                if labels.len() >= 3 {
                    return labels;
                }
            }
        }
    }

    while labels.len() < 3 {
        labels.push(format!("Evidence point {}", labels.len() + 1));
    }

    labels
}

pub(super) fn count_html_rollover_detail_marks(html_lower: &str) -> usize {
    extract_html_attribute_values(html_lower, "data-detail").len()
}

pub(super) fn ensure_minimum_brief_rollover_detail_marks(
    html: &str,
    brief: &StudioArtifactBrief,
) -> String {
    let lower = html.to_ascii_lowercase();
    let has_detail_region = count_populated_html_detail_regions(&lower) > 0;
    let has_chart_surface =
        count_populated_html_chart_regions(&lower) > 0 || count_html_svg_regions(&lower) > 0;
    let should_add_detail_targets = brief_requires_rollover_detail(brief)
        || (brief.has_required_interaction_goals() && has_detail_region && has_chart_surface);
    if !should_add_detail_targets {
        return html.to_string();
    }

    let existing_count = count_html_rollover_detail_marks(&lower);
    if existing_count >= 3 {
        return html.to_string();
    }

    let existing_labels = extract_html_attribute_values(&lower, "data-detail")
        .into_iter()
        .collect::<HashSet<_>>();
    let labels = brief_rollover_detail_labels(brief)
        .into_iter()
        .filter(|label| !existing_labels.contains(&label.to_ascii_lowercase()))
        .take(3usize.saturating_sub(existing_count))
        .collect::<Vec<_>>();
    if labels.is_empty() {
        return html.to_string();
    }

    let controls = labels
        .iter()
        .map(|label| {
            format!(
                "<button type=\"button\" class=\"studio-rollover-chip\" data-detail=\"{}\">{}</button>",
                xml_escape(label),
                xml_escape(label),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let snippet = format!(
        "<section data-studio-normalized=\"true\" data-studio-rollover-chip-rail=\"true\"><h2>Evidence highlights</h2><div class=\"studio-rollover-chip-rail\">{controls}</div><p>Select, hover, or focus a highlight to inspect the shared detail panel.</p></section>"
    );

    let lower = html.to_ascii_lowercase();
    if let Some(main_close_start) = lower.rfind("</main>") {
        format!(
            "{}{}{}",
            &html[..main_close_start],
            snippet,
            &html[main_close_start..],
        )
    } else {
        insert_html_before_body_close(html, &snippet)
    }
}

pub(super) fn ensure_minimum_html_rollover_detail_payloads(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if lower.contains("data-detail=") || count_populated_html_detail_regions(&lower) == 0 {
        return html.to_string();
    }

    let labels = extract_html_rollover_detail_labels(html);
    if labels.is_empty() {
        return html.to_string();
    }

    let mark_patterns = [
        "<rect",
        "<circle",
        "<path",
        "<line",
        "<ellipse",
        "<polygon",
        "<polyline",
    ];
    let mut rebuilt = String::with_capacity(html.len() + 256);
    let mut cursor = 0usize;
    let lower = html.to_ascii_lowercase();
    let mut applied = 0usize;

    while applied < 3 && cursor < html.len() {
        let next_mark = mark_patterns
            .iter()
            .filter_map(|pattern| {
                lower[cursor..]
                    .find(pattern)
                    .map(|offset| (cursor + offset, *pattern))
            })
            .min_by_key(|(start, _)| *start);
        let Some((start, _)) = next_mark else {
            break;
        };
        let Some(relative_end) = lower[start..].find('>') else {
            break;
        };
        let end = start + relative_end + 1;
        let open_tag = &html[start..end];
        let open_tag_lower = &lower[start..end];
        rebuilt.push_str(&html[cursor..start]);
        if open_tag_lower.contains("data-detail=") {
            rebuilt.push_str(open_tag);
        } else {
            let label = labels
                .get(applied)
                .cloned()
                .unwrap_or_else(|| format!("Evidence point {}", applied + 1));
            rebuilt.push_str(&inject_html_attributes_into_open_tag(
                open_tag,
                &[("tabindex", "0"), ("data-detail", &label)],
            ));
            applied += 1;
        }
        cursor = end;
    }

    if applied == 0 {
        return ensure_minimum_html_dom_rollover_detail_payloads(html, &labels);
    }

    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

fn ensure_minimum_html_dom_rollover_detail_payloads(html: &str, labels: &[String]) -> String {
    let lower = html.to_ascii_lowercase();
    let mut rebuilt = String::with_capacity(html.len() + 256);
    let mut cursor = 0usize;
    let mut applied = 0usize;

    while applied < 3 && cursor < html.len() {
        let Some(relative_start) = lower[cursor..].find("<li") else {
            break;
        };
        let start = cursor + relative_start;
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let Some(relative_close) = lower[open_end..].find("</li>") else {
            break;
        };
        let close_start = open_end + relative_close;
        let open_tag = &html[start..open_end];
        let open_tag_lower = &lower[start..open_end];
        rebuilt.push_str(&html[cursor..start]);
        if open_tag_lower.contains("data-detail=") {
            rebuilt.push_str(open_tag);
            cursor = open_end;
            continue;
        }
        let visible_text = normalize_inline_text(&strip_html_tags(&html[open_end..close_start]));
        if visible_text.is_empty() {
            rebuilt.push_str(open_tag);
            cursor = open_end;
            continue;
        }
        let detail_label = labels
            .get(applied)
            .cloned()
            .unwrap_or_else(|| visible_text.clone());
        let mut repaired =
            inject_html_attributes_into_open_tag(open_tag, &[("data-detail", &detail_label)]);
        if !open_tag_lower.contains("tabindex=") {
            repaired = inject_html_attributes_into_open_tag(&repaired, &[("tabindex", "0")]);
        }
        rebuilt.push_str(&repaired);
        applied += 1;
        cursor = open_end;
    }

    if applied == 0 {
        return html.to_string();
    }

    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

pub(super) fn ensure_minimum_html_shared_detail_region(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if !contains_html_interaction_hooks(&lower) {
        return html.to_string();
    }
    let default_focus = default_html_detail_focus_label(html);
    let normalized =
        ensure_existing_html_detail_regions_have_first_paint_copy(html, &default_focus);
    let lower = normalized.to_ascii_lowercase();
    let has_populated_detail_region = count_populated_html_detail_regions(&lower) > 0;
    let has_detail_copy_id =
        lower.contains("id=\"detail-copy\"") || lower.contains("id='detail-copy'");
    if has_populated_detail_region && has_detail_copy_id {
        return normalized;
    }

    let detail_region = format!(
        "<aside data-studio-normalized=\"true\" data-studio-shared-detail=\"true\"><h2>Detail</h2><p id=\"detail-copy\">{} is selected by default.</p></aside>",
        xml_escape(&default_focus)
    );

    if let Some(main_close_start) = lower.rfind("</main>") {
        return format!(
            "{}{}{}",
            &normalized[..main_close_start],
            detail_region,
            &normalized[main_close_start..],
        );
    }

    insert_html_before_body_close(&normalized, &detail_region)
}

fn default_html_detail_focus_label(html: &str) -> String {
    extract_html_text_nodes_for_tag(html, "button", 1)
        .into_iter()
        .next()
        .or_else(|| {
            extract_html_text_nodes_for_tag(html, "h2", 1)
                .into_iter()
                .next()
        })
        .unwrap_or_else(|| "Artifact detail".to_string())
}

fn build_html_default_detail_copy_markup(
    default_focus: &str,
    include_detail_copy_id: bool,
) -> String {
    let detail_copy_id = if include_detail_copy_id {
        " id=\"detail-copy\""
    } else {
        ""
    };
    format!(
        "<p{detail_copy_id}>{} is selected by default.</p>",
        xml_escape(default_focus)
    )
}

fn ensure_existing_html_detail_regions_have_first_paint_copy(
    html: &str,
    default_focus: &str,
) -> String {
    let lower = html.to_ascii_lowercase();
    let mut replacements = Vec::<(usize, usize, String)>::new();
    let mut assigned_detail_copy =
        lower.contains("id=\"detail-copy\"") || lower.contains("id='detail-copy'");

    for tag in ["aside", "section", "article", "div"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        let mut cursor = 0usize;

        while let Some(relative_start) = lower[cursor..].find(&open_pattern) {
            let start = cursor + relative_start;
            let Some(relative_open_end) = lower[start..].find('>') else {
                break;
            };
            let open_end = start + relative_open_end + 1;
            let open_tag = &html[start..open_end];
            let open_tag_lower = &lower[start..open_end];
            if tag != "aside" && !detail_region_hint_present(open_tag_lower) {
                cursor = open_end;
                continue;
            }

            let Some(relative_close) = lower[open_end..].find(&close_pattern) else {
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let close_end = close_start + close_pattern.len();
            let inner = &html[open_end..close_start];
            let inner_lower = &lower[open_end..close_start];
            let has_detail_content = html_fragment_has_detail_content(inner_lower);
            if has_detail_content && assigned_detail_copy {
                cursor = close_end;
                continue;
            }

            let repaired_open_tag = if open_tag_lower.contains("data-studio-shared-detail=") {
                open_tag.to_string()
            } else {
                inject_html_attributes_into_open_tag(
                    open_tag,
                    &[("data-studio-shared-detail", "true")],
                )
            };
            let fallback =
                build_html_default_detail_copy_markup(default_focus, !assigned_detail_copy);
            assigned_detail_copy = true;
            replacements.push((
                start,
                close_start,
                format!("{repaired_open_tag}{fallback}{inner}"),
            ));
            cursor = close_end;
        }
    }

    if replacements.is_empty() {
        return html.to_string();
    }

    replacements.sort_by_key(|(start, _, _)| *start);
    let mut rebuilt = String::with_capacity(html.len() + replacements.len() * 128);
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

pub(super) fn extract_html_rollover_detail_labels(html: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut seen = HashSet::<String>::new();
    for tag in ["text", "button", "h2", "h3", "li"] {
        for label in extract_html_text_nodes_for_tag(html, tag, 6) {
            let normalized = normalize_inline_text(&label);
            if normalized.is_empty() {
                continue;
            }
            let key = normalized.to_ascii_lowercase();
            if seen.insert(key) {
                labels.push(normalized);
            }
            if labels.len() >= 6 {
                return labels;
            }
        }
    }
    labels
}

pub(super) fn extract_html_text_nodes_for_tag(html: &str, tag: &str, limit: usize) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let open_pattern = format!("<{tag}");
    let close_pattern = format!("</{tag}>");
    let mut cursor = 0usize;
    let mut values = Vec::new();

    while values.len() < limit {
        let Some(relative_start) = lower[cursor..].find(&open_pattern) else {
            break;
        };
        let start = cursor + relative_start;
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let Some(relative_close) = lower[open_end..].find(&close_pattern) else {
            break;
        };
        let close_start = open_end + relative_close;
        let text = normalize_inline_text(&strip_html_tags(&html[open_end..close_start]));
        if !text.is_empty() {
            values.push(text);
        }
        cursor = close_start + close_pattern.len();
    }

    values
}

pub(super) fn normalize_inline_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn inject_html_attributes_into_open_tag(
    open_tag: &str,
    attrs: &[(&str, &str)],
) -> String {
    let lower = open_tag.to_ascii_lowercase();
    let Some(tag_end) = open_tag.rfind('>') else {
        return open_tag.to_string();
    };
    let insertion_at = if open_tag[..tag_end].trim_end().ends_with('/') {
        open_tag[..tag_end].rfind('/').unwrap_or(tag_end)
    } else {
        tag_end
    };
    let mut rebuilt = String::from(&open_tag[..insertion_at]);
    for (name, value) in attrs {
        if lower.contains(&format!("{name}=")) {
            continue;
        }
        rebuilt.push(' ');
        rebuilt.push_str(name);
        rebuilt.push_str("=\"");
        rebuilt.push_str(&xml_escape(value));
        rebuilt.push('"');
    }
    rebuilt.push_str(&open_tag[insertion_at..]);
    rebuilt
}

pub(super) fn strip_first_paint_hiding_from_open_tag(open_tag: &str) -> String {
    let mut repaired = open_tag.to_string();
    for needle in [
        " hidden",
        "\thidden",
        "\nhidden",
        "hidden=\"hidden\"",
        "hidden='hidden'",
        "hidden=\"true\"",
        "hidden='true'",
    ] {
        repaired = replace_case_insensitive(&repaired, needle, "");
    }
    repaired = replace_case_insensitive(&repaired, "aria-hidden=\"true\"", "aria-hidden=\"false\"");
    repaired = replace_case_insensitive(&repaired, "aria-hidden='true'", "aria-hidden='false'");
    for needle in [
        "display:none;",
        "display: none;",
        "display:none",
        "display: none",
    ] {
        repaired = replace_case_insensitive(&repaired, needle, "");
    }
    repaired
}

pub(super) fn insert_html_before_body_close(html: &str, snippet: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if let Some(body_close_start) = lower.rfind("</body>") {
        return format!(
            "{}{}{}",
            &html[..body_close_start],
            snippet,
            &html[body_close_start..],
        );
    }
    if let Some(html_close_start) = lower.rfind("</html>") {
        return format!(
            "{}{}{}",
            &html[..html_close_start],
            snippet,
            &html[html_close_start..],
        );
    }
    format!("{html}{snippet}")
}

fn insert_html_before_head_close_or_body_close(html: &str, snippet: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if let Some(head_close_start) = lower.rfind("</head>") {
        return format!(
            "{}{}{}",
            &html[..head_close_start],
            snippet,
            &html[head_close_start..],
        );
    }
    insert_html_before_body_close(html, snippet)
}

pub(super) fn ensure_html_interaction_polish_styles(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let needs_polish = lower.contains("<button")
        || lower.contains("data-view-panel=")
        || lower.contains("data-panel=")
        || lower.contains("data-detail=")
        || lower.contains("class=\"evidence-surface\"")
        || lower.contains("class='evidence-surface'");
    if !needs_polish || lower.contains("data-studio-interaction-polish=\"true\"") {
        return html.to_string();
    }

    let style = r#"<style data-studio-interaction-polish="true">
:root { color-scheme: light; }
body { line-height: 1.5; color: #0f172a; }
header { padding: 32px 24px; text-align: left; }
header > * { max-width: 1120px; margin-left: auto; margin-right: auto; }
header h1, header p { margin-left: 0; margin-right: 0; }
main {
  max-width: 1120px;
  margin: 0 auto;
  padding: 24px;
  display: grid;
  gap: 24px;
  box-sizing: border-box;
}
main > section,
main > nav,
main > aside,
main > footer {
  width: 100%;
  margin: 0;
  box-sizing: border-box;
}
.control-bar,
.studio-view-switch-controls,
main nav {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-start;
  align-items: center;
  gap: 12px;
  margin: 0;
}
.studio-rollover-chip-rail {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 12px;
  align-items: stretch;
}
button,
[role="tab"][data-view] {
  font: inherit;
  transition: transform 160ms ease, box-shadow 160ms ease, background-color 160ms ease, color 160ms ease, border-color 160ms ease;
}
button[data-view],
.control-bar button,
.studio-view-switch-controls button,
[role="tab"][data-view] {
  padding: 0.75rem 1rem;
  border-radius: 999px;
  border: 1px solid rgba(15, 23, 42, 0.14);
  background: rgba(255, 255, 255, 0.96);
  color: #0f172a;
  font-weight: 600;
}
button[data-view][aria-selected="true"],
.control-bar button[aria-selected="true"],
.studio-view-switch-controls button[aria-selected="true"],
[role="tab"][data-view][aria-selected="true"] {
  background: #0f172a;
  color: #ffffff;
  border-color: #0f172a;
  box-shadow: 0 14px 32px rgba(15, 23, 42, 0.18);
}
button:hover,
button:focus-visible,
[role="tab"][data-view]:hover,
[role="tab"][data-view]:focus-visible {
  transform: translateY(-1px);
  box-shadow: 0 12px 24px rgba(15, 23, 42, 0.12);
  outline: none;
}
.evidence-surface,
[data-view-panel],
[data-panel],
[role="tabpanel"],
.shared-detail,
[data-studio-shared-detail="true"],
[data-studio-rollover-chip-rail="true"] {
  border-radius: 20px;
  border: 1px solid rgba(15, 23, 42, 0.08);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(248, 250, 252, 0.94));
  box-shadow: 0 18px 42px rgba(15, 23, 42, 0.07);
  padding: 24px;
  transition: transform 160ms ease, border-color 160ms ease, box-shadow 160ms ease, background-color 160ms ease;
}
.evidence-surface:hover,
.evidence-surface:focus-within,
[data-view-panel]:hover,
[data-view-panel]:focus-within,
[data-panel]:hover,
[data-panel]:focus-within,
[role="tabpanel"]:hover,
[role="tabpanel"]:focus-within,
.shared-detail:hover,
.shared-detail:focus-within,
[data-studio-shared-detail="true"]:hover,
[data-studio-shared-detail="true"]:focus-within,
[data-studio-rollover-chip-rail="true"]:hover,
[data-studio-rollover-chip-rail="true"]:focus-within {
  transform: translateY(-1px);
  border-color: rgba(37, 99, 235, 0.28);
  box-shadow: 0 24px 56px rgba(15, 23, 42, 0.12);
}
.evidence-surface h1,
.evidence-surface h2,
.evidence-surface h3,
[data-view-panel] h1,
[data-view-panel] h2,
[data-view-panel] h3,
.shared-detail h1,
.shared-detail h2,
.shared-detail h3,
[data-studio-shared-detail="true"] h1,
[data-studio-shared-detail="true"] h2,
[data-studio-shared-detail="true"] h3 {
  margin-top: 0;
  text-align: left;
}
.evidence-surface svg,
[data-view-panel] svg {
  display: block;
  width: 100%;
  max-width: 100%;
  height: auto;
  margin: 16px 0 0;
}
[data-detail]:hover,
[data-detail]:focus-visible,
.studio-rollover-chip:hover,
.studio-rollover-chip:focus-visible {
  cursor: pointer;
  filter: brightness(0.96);
  outline: 2px solid rgba(37, 99, 235, 0.28);
  outline-offset: 2px;
}
.studio-rollover-chip,
.studio-rollover-chip-rail > [data-detail],
.studio-rollover-chip-rail > .data-detail,
main > [data-detail],
main > .data-detail {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  min-height: 44px;
  margin: 0;
  padding: 0.75rem 1rem;
  border-radius: 16px;
  border: 1px solid rgba(15, 23, 42, 0.14);
  background: rgba(255, 255, 255, 0.96);
  color: #0f172a;
  font-weight: 600;
  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);
  text-decoration: none;
  box-sizing: border-box;
}
.studio-rollover-chip-rail > .data-detail strong,
main > .data-detail strong {
  font: inherit;
}
[hidden] { display: none !important; }
@media (max-width: 720px) {
  header { padding: 24px 16px; }
  main { padding: 16px; gap: 16px; }
  .control-bar,
  .studio-view-switch-controls,
  main nav { gap: 8px; }
  .evidence-surface,
  [data-view-panel],
  [data-panel],
  [role="tabpanel"],
  .shared-detail,
  [data-studio-shared-detail="true"],
  [data-studio-rollover-chip-rail="true"] { padding: 18px; }
}
</style>"#;

    insert_html_before_head_close_or_body_close(html, style)
}

pub(super) fn normalize_html_external_runtime_dependencies(html: &str) -> String {
    if !html_uses_external_runtime_dependency(&html.to_ascii_lowercase()) {
        return html.to_string();
    }

    let mut normalized =
        strip_external_tag_blocks(html, "script", |tag_lower| tag_lower.contains("src="));
    normalized =
        strip_external_tag_blocks(&normalized, "link", |tag_lower| tag_lower.contains("rel="));
    normalized = strip_external_dependency_scripts(&normalized);

    let lower = normalized.to_ascii_lowercase();
    if (lower.contains("<canvas") || lower.contains("chart"))
        && !lower.contains("<svg")
        && lower.contains("<main")
    {
        normalized = inject_inline_svg_chart_fallback(&normalized);
    }

    normalized
}

pub(super) fn strip_html_comments(html: &str) -> String {
    let mut rebuilt = String::with_capacity(html.len());
    let mut cursor = 0usize;

    while let Some(relative_start) = html[cursor..].find("<!--") {
        let start = cursor + relative_start;
        rebuilt.push_str(&html[cursor..start]);
        let Some(relative_end) = html[start + 4..].find("-->") else {
            cursor = start;
            break;
        };
        cursor = start + 4 + relative_end + 3;
    }

    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

pub(super) fn strip_external_tag_blocks<F>(html: &str, tag: &str, predicate: F) -> String
where
    F: Fn(&str) -> bool,
{
    let lower = html.to_ascii_lowercase();
    let mut rebuilt = String::with_capacity(html.len());
    let mut cursor = 0usize;
    let opening = format!("<{tag}");
    let closing = format!("</{tag}>");

    while let Some(relative_start) = lower[cursor..].find(&opening) {
        let start = cursor + relative_start;
        let Some(relative_tag_end) = lower[start..].find('>') else {
            break;
        };
        let tag_end = start + relative_tag_end + 1;
        let tag_lower = &lower[start..tag_end];
        if !predicate(tag_lower) {
            rebuilt.push_str(&html[cursor..tag_end]);
            cursor = tag_end;
            continue;
        }

        rebuilt.push_str(&html[cursor..start]);
        let end = if tag == "link" || tag_lower.ends_with("/>") {
            tag_end
        } else {
            lower[tag_end..]
                .find(&closing)
                .map(|offset| tag_end + offset + closing.len())
                .unwrap_or(tag_end)
        };
        cursor = end;
    }

    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

pub(super) fn strip_external_dependency_scripts(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut rebuilt = String::with_capacity(html.len());
    let mut cursor = 0usize;

    while let Some(relative_start) = lower[cursor..].find("<script") {
        let start = cursor + relative_start;
        let Some(relative_open_end) = lower[start..].find('>') else {
            break;
        };
        let open_end = start + relative_open_end + 1;
        let Some(relative_close) = lower[open_end..].find("</script>") else {
            break;
        };
        let close_end = open_end + relative_close + "</script>".len();
        let script_lower = &lower[start..close_end];
        let references_external_runtime =
            script_lower.contains("d3.") || script_lower.contains("new chart(");

        rebuilt.push_str(&html[cursor..start]);
        if !references_external_runtime {
            rebuilt.push_str(&html[start..close_end]);
        }
        cursor = close_end;
    }

    rebuilt.push_str(&html[cursor..]);
    rebuilt
}

pub(super) fn inject_inline_svg_chart_fallback(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let Some(main_close_start) = lower.rfind("</main>") else {
        return html.to_string();
    };
    let fallback = "<section data-studio-normalized=\"true\" class=\"studio-inline-chart-fallback\"><h2>Inline chart fallback</h2><svg width=\"320\" height=\"180\" viewBox=\"0 0 320 180\" xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"Inline fallback chart\"><rect x=\"24\" y=\"48\" width=\"44\" height=\"96\" rx=\"10\" fill=\"#63b3ed\"/><rect x=\"94\" y=\"28\" width=\"44\" height=\"116\" rx=\"10\" fill=\"#4fd1c5\"/><rect x=\"164\" y=\"68\" width=\"44\" height=\"76\" rx=\"10\" fill=\"#f6ad55\"/><rect x=\"234\" y=\"38\" width=\"44\" height=\"106\" rx=\"10\" fill=\"#f56565\"/><text x=\"46\" y=\"162\" text-anchor=\"middle\" font-size=\"12\">Plan</text><text x=\"116\" y=\"162\" text-anchor=\"middle\" font-size=\"12\">Adopt</text><text x=\"186\" y=\"162\" text-anchor=\"middle\" font-size=\"12\">Prove</text><text x=\"256\" y=\"162\" text-anchor=\"middle\" font-size=\"12\">Ship</text></svg><p>This inline SVG keeps the chart renderable without external runtime dependencies.</p></section>";
    format!(
        "{}{}{}",
        &html[..main_close_start],
        fallback,
        &html[main_close_start..],
    )
}

pub(super) fn replace_case_insensitive(source: &str, needle: &str, replacement: &str) -> String {
    let needle_lower = needle.to_ascii_lowercase();
    let source_lower = source.to_ascii_lowercase();
    let mut rebuilt = String::with_capacity(source.len());
    let mut search_start = 0usize;

    while let Some(relative) = source_lower[search_start..].find(&needle_lower) {
        let match_start = search_start + relative;
        let match_end = match_start + needle.len();
        rebuilt.push_str(&source[search_start..match_start]);
        rebuilt.push_str(replacement);
        search_start = match_end;
    }

    rebuilt.push_str(&source[search_start..]);
    rebuilt
}

pub(super) fn ensure_svg_accessibility_metadata(svg: &str, brief: &StudioArtifactBrief) -> String {
    let lower = svg.to_ascii_lowercase();
    let has_title = lower.contains("<title>");
    let has_desc = lower.contains("<desc>");
    if has_title && has_desc {
        return svg.to_string();
    }
    let Some(insert_at) = svg.find('>').map(|index| index + 1) else {
        return svg.to_string();
    };

    let mut metadata = String::new();
    if !has_title {
        metadata.push_str("<title>");
        metadata.push_str(&xml_escape(&svg_accessibility_title(brief)));
        metadata.push_str("</title>");
    }
    if !has_desc {
        metadata.push_str("<desc>");
        metadata.push_str(&xml_escape(&svg_accessibility_description(brief)));
        metadata.push_str("</desc>");
    }

    format!("{}{}{}", &svg[..insert_at], metadata, &svg[insert_at..])
}

pub(super) fn svg_accessibility_title(brief: &StudioArtifactBrief) -> String {
    let audience = brief.audience.trim();
    let domain = brief.subject_domain.trim();
    if !audience.is_empty() && !domain.is_empty() {
        format!("{audience} - {domain}")
    } else if !audience.is_empty() {
        audience.to_string()
    } else if !domain.is_empty() {
        domain.to_string()
    } else {
        "Studio SVG artifact".to_string()
    }
}

pub(super) fn svg_accessibility_description(brief: &StudioArtifactBrief) -> String {
    let mut parts = Vec::new();
    if !brief.artifact_thesis.trim().is_empty() {
        parts.push(brief.artifact_thesis.trim().to_string());
    }
    if !brief.required_concepts.is_empty() {
        parts.push(format!(
            "Key concepts: {}.",
            brief.required_concepts.join(", ")
        ));
    }
    if !brief.factual_anchors.is_empty() {
        parts.push(format!("Anchors: {}.", brief.factual_anchors.join(", ")));
    }
    if parts.is_empty() {
        brief.subject_domain.trim().to_string()
    } else {
        parts.join(" ")
    }
}

pub(super) fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub(super) fn ensure_html_main_region(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if lower.contains("<main") {
        return html.to_string();
    }
    if let Some((body_start, body_end)) = html_tag_content_range(html, "body") {
        return format!(
            "{}<main data-studio-normalized=\"true\">{}</main>{}",
            &html[..body_start],
            &html[body_start..body_end],
            &html[body_end..],
        );
    }
    if let Some(head_close_end) = lower.find("</head>").map(|index| index + "</head>".len()) {
        let html_close_start = lower.rfind("</html>").unwrap_or(html.len());
        if head_close_end < html_close_start {
            let trailing = &html[head_close_end..html_close_start];
            if !trailing.trim().is_empty() {
                return format!(
                    "{}<body data-studio-normalized=\"true\"><main data-studio-normalized=\"true\">{}</main></body>{}",
                    &html[..head_close_end],
                    trailing,
                    &html[html_close_start..],
                );
            }
        }
    }
    html.to_string()
}

pub(super) fn ensure_minimum_html_sectioning_elements(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if count_html_sectioning_elements(&lower) >= 3 {
        return html.to_string();
    }
    let Some((main_start, main_end)) = html_tag_content_range(html, "main") else {
        return html.to_string();
    };
    let main_inner = &html[main_start..main_end];
    let fragments = split_top_level_html_fragments(main_inner);
    let Some(normalized_inner) = normalize_html_top_level_fragments(&fragments, 0) else {
        return html.to_string();
    };
    let candidate = format!(
        "{}{}{}",
        &html[..main_start],
        normalized_inner,
        &html[main_end..],
    );
    if count_html_sectioning_elements(&candidate.to_ascii_lowercase()) >= 3 {
        candidate
    } else {
        html.to_string()
    }
}

pub(super) fn normalize_html_top_level_fragments(
    fragments: &[String],
    depth: usize,
) -> Option<String> {
    if fragments.is_empty() {
        return None;
    }

    let mut normalized = String::new();
    let mut pending_section = String::new();
    let mut pending_kind = None::<HtmlTopLevelSectioningGroupKind>;
    for fragment in fragments {
        let trimmed = fragment.trim();
        if trimmed.is_empty() {
            pending_section.push_str(fragment);
            continue;
        }
        if html_fragment_is_script_like(trimmed) {
            flush_html_sectioning_group(&mut normalized, &mut pending_section);
            pending_kind = None;
            normalized.push_str(fragment);
            continue;
        }
        if depth < 2 {
            if let Some(inner) = html_fragment_inner_for_resection(trimmed) {
                let nested_fragments = split_top_level_html_fragments(inner);
                if nested_fragments.len() >= 2 {
                    if let Some(expanded) =
                        normalize_html_top_level_fragments(&nested_fragments, depth + 1)
                    {
                        flush_html_sectioning_group(&mut normalized, &mut pending_section);
                        pending_kind = None;
                        normalized.push_str(&expanded);
                        continue;
                    }
                }
            }
        }
        if html_fragment_has_sectioning_root(trimmed) {
            flush_html_sectioning_group(&mut normalized, &mut pending_section);
            pending_kind = None;
            normalized.push_str(fragment);
        } else {
            let fragment_kind = html_fragment_sectioning_group_kind(trimmed);
            let should_flush = pending_kind.is_some_and(|kind| {
                kind != fragment_kind
                    && !(kind == HtmlTopLevelSectioningGroupKind::Narrative
                        && fragment_kind == HtmlTopLevelSectioningGroupKind::DetailMarks)
            });
            if should_flush {
                flush_html_sectioning_group(&mut normalized, &mut pending_section);
                pending_kind = None;
            }
            if pending_section.trim().is_empty() {
                pending_kind = Some(fragment_kind);
            } else if pending_kind == Some(HtmlTopLevelSectioningGroupKind::Narrative)
                && fragment_kind == HtmlTopLevelSectioningGroupKind::DetailMarks
            {
                pending_kind = Some(HtmlTopLevelSectioningGroupKind::DetailMarks);
            }
            pending_section.push_str(fragment);
        }
    }
    flush_html_sectioning_group(&mut normalized, &mut pending_section);

    if count_html_sectioning_elements(&normalized.to_ascii_lowercase()) >= 3 {
        Some(normalized)
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HtmlTopLevelSectioningGroupKind {
    Narrative,
    Control,
    Panel,
    DetailMarks,
    SharedDetail,
}

fn html_fragment_sectioning_group_kind(fragment: &str) -> HtmlTopLevelSectioningGroupKind {
    let lower = fragment.to_ascii_lowercase();
    if lower.contains("shared-detail")
        || lower.contains("detail-copy")
        || lower.contains("data-studio-shared-detail=")
    {
        HtmlTopLevelSectioningGroupKind::SharedDetail
    } else if lower.contains("data-detail=")
        || lower.contains("class=\"data-detail\"")
        || lower.contains("class='data-detail'")
    {
        HtmlTopLevelSectioningGroupKind::DetailMarks
    } else if lower.contains("data-view-panel=")
        || lower.contains("data-panel=")
        || lower.contains("role=\"tabpanel\"")
        || lower.contains("role='tabpanel'")
        || lower.contains("class=\"evidence\"")
        || lower.contains("class='evidence'")
    {
        HtmlTopLevelSectioningGroupKind::Panel
    } else if lower.contains("<button")
        || lower.contains("data-view=")
        || lower.contains("aria-controls=")
        || lower.contains("control-bar")
    {
        HtmlTopLevelSectioningGroupKind::Control
    } else {
        HtmlTopLevelSectioningGroupKind::Narrative
    }
}

fn flush_html_sectioning_group(normalized: &mut String, pending_section: &mut String) {
    if pending_section.trim().is_empty() {
        normalized.push_str(pending_section);
        pending_section.clear();
        return;
    }

    normalized.push_str("<section data-studio-normalized=\"true\">");
    normalized.push_str(pending_section);
    normalized.push_str("</section>");
    pending_section.clear();
}

pub(super) fn split_top_level_html_fragments(inner: &str) -> Vec<String> {
    let mut fragments = Vec::new();
    let mut depth = 0usize;
    let mut start = None;
    let mut index = 0usize;

    while index < inner.len() {
        let rest = &inner[index..];
        if rest.starts_with("<!--") {
            let end = rest
                .find("-->")
                .map(|offset| index + offset + 3)
                .unwrap_or(inner.len());
            if depth == 0 && start.is_none() {
                start = Some(index);
            }
            index = end;
            if depth == 0 {
                if let Some(fragment_start) = start.take() {
                    fragments.push(inner[fragment_start..index].to_string());
                }
            }
            continue;
        }

        if rest.starts_with('<') {
            let Some(tag_close_offset) = rest.find('>') else {
                break;
            };
            let tag_end = index + tag_close_offset + 1;
            let tag_source = &inner[index + 1..tag_end - 1];
            let trimmed = tag_source.trim();

            if trimmed.starts_with('!') || trimmed.starts_with('?') {
                if depth == 0 && start.is_none() {
                    start = Some(index);
                }
                index = tag_end;
                if depth == 0 {
                    if let Some(fragment_start) = start.take() {
                        fragments.push(inner[fragment_start..index].to_string());
                    }
                }
                continue;
            }

            let closing = trimmed.starts_with('/');
            let tag_name = html_tag_name_from_source(trimmed);

            if depth == 0 && start.is_none() {
                start = Some(index);
            }

            if !closing && matches!(tag_name.as_deref(), Some("script") | Some("style")) {
                let Some(name) = tag_name.as_deref() else {
                    break;
                };
                let closing_tag = format!("</{name}>");
                let rest_lower = rest.to_ascii_lowercase();
                let end = rest_lower
                    .find(&closing_tag)
                    .map(|offset| index + offset + closing_tag.len())
                    .unwrap_or(tag_end);
                index = end;
                if depth == 0 {
                    if let Some(fragment_start) = start.take() {
                        fragments.push(inner[fragment_start..index].to_string());
                    }
                }
                continue;
            }

            let self_closing =
                trimmed.ends_with('/') || tag_name.as_deref().is_some_and(is_html_void_tag);
            if closing {
                depth = depth.saturating_sub(1);
                index = tag_end;
                if depth == 0 {
                    if let Some(fragment_start) = start.take() {
                        fragments.push(inner[fragment_start..index].to_string());
                    }
                }
                continue;
            }

            index = tag_end;
            if self_closing {
                if depth == 0 {
                    if let Some(fragment_start) = start.take() {
                        fragments.push(inner[fragment_start..index].to_string());
                    }
                }
                continue;
            }

            depth += 1;
            continue;
        }

        let advance = rest.chars().next().map(|ch| ch.len_utf8()).unwrap_or(1);
        if !rest.chars().next().is_some_and(char::is_whitespace) && start.is_none() {
            start = Some(index);
        }
        index += advance;
    }

    if let Some(fragment_start) = start {
        fragments.push(inner[fragment_start..].to_string());
    }

    fragments
}

pub(super) fn html_fragment_has_sectioning_root(fragment: &str) -> bool {
    matches!(
        html_fragment_root_tag_name(fragment).as_deref(),
        Some("section" | "article" | "nav" | "aside" | "footer")
    )
}

pub(super) fn html_fragment_is_script_like(fragment: &str) -> bool {
    matches!(
        html_fragment_root_tag_name(fragment).as_deref(),
        Some("script" | "style")
    )
}

pub(super) fn html_fragment_root_tag_name(fragment: &str) -> Option<String> {
    let trimmed = fragment.trim_start();
    if !trimmed.starts_with('<') || trimmed.starts_with("</") {
        return None;
    }
    let tag_end = trimmed.find('>')?;
    html_tag_name_from_source(trimmed.get(1..tag_end)?.trim())
}

pub(super) fn html_fragment_inner_for_resection(fragment: &str) -> Option<&str> {
    let tag_name = html_fragment_root_tag_name(fragment)?;
    if tag_name != "div" {
        return None;
    }
    let (content_start, content_end) = html_tag_content_range(fragment, &tag_name)?;
    if content_end >= fragment.len() {
        return None;
    }
    let closing = fragment[content_end..].trim();
    if !closing.eq_ignore_ascii_case("</div>") {
        return None;
    }
    Some(&fragment[content_start..content_end])
}

pub(super) fn html_tag_content_range(html: &str, tag: &str) -> Option<(usize, usize)> {
    let lower = html.to_ascii_lowercase();
    let opening = format!("<{tag}");
    let closing = format!("</{tag}>");
    let open_start = lower.find(&opening)?;
    let open_end = lower[open_start..].find('>')?;
    let content_start = open_start + open_end + 1;
    let close_start = lower[content_start..].rfind(&closing)?;
    Some((content_start, content_start + close_start))
}

pub(super) fn html_tag_name_from_source(source: &str) -> Option<String> {
    let trimmed = source.trim_start_matches('/').trim();
    let name: String = trimmed
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == ':')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name.to_ascii_lowercase())
    }
}

pub(super) fn is_html_void_tag(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

pub(super) fn studio_artifact_materialization_failure_directives(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    failure: &str,
) -> String {
    if request.renderer != StudioRendererKind::HtmlIframe {
        let mut directives = vec![
            "- Repair only the cited schema failures while preserving the strongest request-specific content.".to_string(),
        ];
        let failure_lower = failure.to_ascii_lowercase();
        if failure_lower.contains("missing json payload") {
            directives.push(
                "- Return the artifact inside the exact JSON schema; do not answer with raw document text or prose outside the JSON object.".to_string(),
            );
        }
        if request.renderer == StudioRendererKind::PdfEmbed {
            directives.push(
                "- For pdf_embed, keep the full document text inside files[0].body and keep the primary path ending in .pdf.".to_string(),
            );
            if failure_lower.contains("clearer sections") {
                directives.push(
                    "- Use at least five short standalone section headings on their own lines, separated by blank lines, so the rendered PDF keeps visible section breaks."
                        .to_string(),
                );
                directives.push(
                    "- Keep headings concrete and compact, such as Executive Summary, Project Scope, Target Audience, Marketing Strategy, Timeline and Milestones, and Next Steps and Risks."
                        .to_string(),
                );
            }
            if failure_lower.contains("placeholder") {
                directives.push(
                    "- Replace every bracketed template token with concrete request-grounded bullets, milestones, owners, risks, or decisions; do not leave [Detailed description]-style filler anywhere in the document."
                        .to_string(),
                );
            }
        }
        return directives.join("\n");
    }

    let mut directives = vec![
        "- Return one complete self-contained .html file with inline CSS and inline JS only.".to_string(),
        "- Keep the strongest request-specific copy, labels, chart concepts, and interaction intent from the prior attempt.".to_string(),
        "- If several controls, cards, or marks share behavior, select them as a real collection before iterating and only target views that already exist in the markup.".to_string(),
    ];
    let exact_view_scaffold = html_prompt_exact_view_scaffold(brief);
    let rollover_mark_example = html_prompt_rollover_mark_example(brief);
    let two_view_example = html_prompt_two_view_example(brief);
    let view_mapping_pattern = html_prompt_view_mapping_pattern(brief);
    let failure_lower = failure.to_ascii_lowercase();
    if failure_lower.contains("missing json payload") {
        directives.push(
            "- Return the artifact inside the exact JSON schema; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object."
                .to_string(),
        );
        directives.push(
            "- Keep the complete HTML document in files[0].body with the existing primary file path and mime instead of emitting a naked document."
                .to_string(),
        );
    }
    if failure_lower.contains("sectioning elements") {
        directives.push(
            "- Ensure <main> contains at least three sectioning elements with visible first-paint content. A valid pattern is hero <section>, detail <section>, and either <aside> or <footer>."
                .to_string(),
        );
        directives.push(
            "- Give every sectioning region its own heading plus visible body content, data marks, scorecards, or explanatory detail before any script runs; do not leave a section as a control-only wrapper or empty chart mount."
                .to_string(),
        );
    }
    if failure_lower.contains("<main> region") {
        directives.push(
            "- Include a real <main> region that contains the primary artifact composition."
                .to_string(),
        );
        directives.push(
            "- Start from a safe scaffold like <!doctype html><html><body><main>...visible sections, articles, asides, and footers...</main><script>...interactive wiring...</script></body></html>."
                .to_string(),
        );
        directives.push(
            "- Keep visible artifact markup inside <main> before the script tag; do not spend the head on a long script block before the first surfaced section."
                .to_string(),
        );
    }
    if failure_lower.contains("alert()") {
        directives.push(
            "- Replace alert-only controls with on-page state changes, revealed details, filtering, comparison, or step transitions."
                .to_string(),
        );
    }
    if failure_lower.contains("external libraries") || failure_lower.contains("undefined globals") {
        directives.push(
            "- Replace external libraries or undefined globals with inline SVG, canvas, or DOM/CSS implementations."
                .to_string(),
        );
    }
    if failure_lower.contains("placeholder-grade")
        || failure_lower.contains("placeholder copy")
        || failure_lower.contains("placeholder comments")
    {
        directives.push(
            "- Remove placeholder comments, TODO markers, and filler labels entirely; every visible mark, comment-free region, and handler must be production-ready."
                .to_string(),
        );
        directives.push(
            "- Do not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy."
                .to_string(),
        );
    }
    if failure_lower.contains("real svg marks or labels on first paint") {
        directives.push(
            "- Replace empty chart shells with inline SVG that already contains bars, lines, labels, legends, or callout text on first paint."
                .to_string(),
        );
    }
    if failure_lower.contains("visible labels, legends, or aria labels") {
        directives.push(
            "- Replace decorative SVG geometry with labeled charts or diagrams. Include <text>, legend copy, or aria-label/title metadata tied to the visible marks."
                .to_string(),
        );
    }
    if failure_lower.contains("visible chart content on first paint")
        || failure_lower.contains("chart containers are empty placeholder shells")
    {
        directives.push(
            "- Replace empty chart containers or blank canvases with visible first-paint content such as inline SVG marks, labels, legends, tables, or explanatory callouts."
                .to_string(),
        );
        directives.push(
            "- Put the default chart and supporting detail directly in the markup before the script tag, then let interaction handlers switch or annotate that visible state."
                .to_string(),
        );
        directives.push(
            "- Do not use DOMContentLoaded, innerHTML, appendChild, createElement, or canvas drawing to create the very first visible chart or comparison content from an empty region."
                .to_string(),
        );
    }
    if failure_lower.contains("shared detail or comparison regions are empty")
        || failure_lower.contains("populate them on first paint")
    {
        directives.push(
            "- Populate the shared detail, comparison, or explanation panel with meaningful default copy before any interaction occurs."
                .to_string(),
        );
        directives.push(
            "- Update that same populated panel inline when controls, marks, or cards are activated; do not leave it empty or comment-only."
                .to_string(),
        );
    }
    if failure_lower.contains(
        "required interactions must include a populated shared detail or comparison region",
    ) {
        directives.push(
            "- Add a shared detail, comparison, or explanation panel with meaningful default copy on first paint. Buttons, marks, or cards should update that same panel inline."
                .to_string(),
        );
        directives.push(
            "- Keep the shared detail region visible beside the controls and evidence views instead of hiding it behind a later interaction."
                .to_string(),
        );
    }
    if failure_lower.contains("charted evidence must surface at least two populated evidence views")
    {
        directives.push(
            "- Surface at least two populated evidence views on first paint: a primary chart or evidence article plus a secondary comparison card, legend table, supporting chart, or evidence article."
                .to_string(),
        );
        directives.push(
            "- Do not collapse the artifact into one chart and a footer. Keep the secondary evidence region visible before any click."
                .to_string(),
        );
        directives.push(
            "- Empty mount divs like <div id=\"usage-chart\"></div> or placeholder chart wrappers do not count as evidence views; populate the secondary surface with inline SVG marks, a comparison table, metric cards, or labeled evidence rows."
                .to_string(),
        );
        directives.push(
            "- A single sentence paragraph does not count as the secondary evidence surface; give it multiple labeled rows, bullets, cards, or a second SVG tied to a different brief concept."
                .to_string(),
        );
        directives.push(format!(
            "- A concrete repair shape is one visible {} Keep the sibling comparison rail, score table, or evidence article visible on first paint.",
            two_view_example
        ));
    }
    if failure_lower.contains("call for clickable view switching")
        || failure_lower.contains("controls to pre-rendered view panels")
        || failure_lower.contains("controls to pre-rendered views")
    {
        directives.push(
            "- Use explicit static mappings for clickable navigation: buttons or tabs with data-view/aria-controls/data-target values and pre-rendered panels that already exist in the markup."
                .to_string(),
        );
        directives.push(format!(
            "- Prefer a pattern like {}, then toggle hidden, data-active, or aria-selected state.",
            view_mapping_pattern
        ));
        directives.push(
            "- Keep data-view-panel as a literal HTML attribute on the panel element itself; a CSS class like class=\"data-view-panel\" does not satisfy the mapped-panel contract."
                .to_string(),
        );
        directives.push(
            "- Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quotes."
                .to_string(),
        );
        directives.push(
            "- Static data-view, aria-controls, or data-target attributes do not count on their own; wire button or tab click handlers that toggle hidden, aria-selected, aria-hidden, or comparable panel state."
                .to_string(),
        );
        directives.push(
            "- Do not use class names like class=\"overview-panel\" or class=\"data-view-panel\" as a substitute for actual panel ids or data-view-panel attributes on the panel wrapper."
                .to_string(),
        );
        directives.push(
            "- A reliable scaffold is a control bar with buttons[data-view], a matching pre-rendered panel for each view such as <section data-view-panel=\"satisfaction\">...</section> and <section data-view-panel=\"usage\" hidden>...</section>, one shared detail aside like #detail-copy, and a script that selects all [data-view-panel] nodes before toggling hidden state."
                .to_string(),
        );
        directives.push(format!(
            "- A safe exact scaffold is {}.",
            exact_view_scaffold
        ));
        directives.push(
            "- If you use aria-controls, point it at a section, article, div, aside, or figure panel wrapper in the markup, not directly at an SVG, canvas, or inner chart node."
                .to_string(),
        );
        directives.push(
            "- Keep exactly one mapped panel visibly selected in the raw HTML before any script runs; the other mapped panels may start hidden."
                .to_string(),
        );
        directives.push(
            "- Do not point every button at the shared detail panel with aria-controls alone; the shared detail panel complements the per-view panels and does not replace them."
                .to_string(),
        );
        directives.push(
            "- Do not synthesize target ids by concatenating button ids or other runtime strings."
                .to_string(),
        );
    }
    if failure_lower.contains("call for rollover detail must wire hover or focus handlers")
        || failure_lower.contains("keyboard-focusable")
        || failure_lower.contains("focus-based detail behavior")
    {
        directives.push(
            "- Patch the existing scaffold in place: keep the current <main>, populated sectioning regions, mapped view panels, and shared detail aside while you repair focusability."
                .to_string(),
        );
        directives.push(
            "- Add at least three visible marks or cards with data-detail text plus mouseenter, mouseover, or focus handlers that rewrite the shared detail panel inline."
                .to_string(),
        );
        directives.push(
            "- Preserve a meaningful default detail state on first paint, then replace it when a user hovers or focuses a specific evidence mark."
                .to_string(),
        );
        directives.push(
            "- Select those marks as a real collection such as querySelectorAll('[data-detail]') and make non-focusable marks focusable with tabindex=\"0\" before attaching focus handlers."
                .to_string(),
        );
        if brief_requires_view_switching(brief) {
            directives.push(
                "- Do not delete or replace the mapped panel scaffold while fixing focusability; preserve the existing buttons[data-view], [data-view-panel] containers, and #detail-copy region."
                    .to_string(),
            );
        }
        directives.push(format!(
            "- A concrete repair shape is {} inside a visible chart plus const detailCopy = document.getElementById('detail-copy'); document.querySelectorAll('[data-detail]').forEach((mark) => {{ mark.addEventListener('mouseenter', () => {{ detailCopy.textContent = mark.dataset.detail; }}); mark.addEventListener('focus', () => {{ detailCopy.textContent = mark.dataset.detail; }}); }});",
            rollover_mark_example
        ));
    }
    if failure_lower
        .contains("call for rollover detail must surface at least three visible data-detail marks")
    {
        directives.push(
            "- Surface at least three visible rollover targets on first paint; a single generic bar, dot, or heading is not enough."
                .to_string(),
        );
        directives.push(
            "- Use request-grounded labels from factual anchors, required concepts, or reference hints for those data-detail values instead of generic labels like Overview."
                .to_string(),
        );
        directives.push(
            "- If the chart only has one mark, add a visible chip rail, comparison list, or evidence card group with data-detail payloads so hover/focus still exposes multiple editorial details."
                .to_string(),
        );
    }
    if failure_lower.contains("interactive controls or handlers") {
        directives.push(
            "- Add visible controls with working event handlers and first-paint content so the artifact is actually interactive."
                .to_string(),
        );
        directives.push(
            "- For click interactions, render at least one real <button>, <details>/<summary>, or similarly obvious control on first paint and wire it with click handlers that mutate visible inline state."
                .to_string(),
        );
        directives.push(
            "- For drag-style interactions, prefer a range input, slider, scrubber, or draggable handle that updates labels, diagrams, captions, or comparison state while the user drags; describe the state change in the DOM instead of only animating decoration."
                .to_string(),
        );
        directives.push(
            "- Keep the repair concrete: include the actual control element in the HTML plus inline JavaScript such as addEventListener('click', ...) or addEventListener('input', ...) that rewrites visible text, classes, transforms, or comparison state."
                .to_string(),
        );
    }
    if failure_lower.contains("missing dom ids") {
        directives.push(
            "- Every getElementById or querySelector target used by the script must correspond to an element id that already exists in the HTML markup."
                .to_string(),
        );
        directives.push(
            "- Remove dead selector references instead of pointing interaction handlers at future or nonexistent targets."
                .to_string(),
        );
    }
    if failure_lower.contains("rollover") || failure_lower.contains("tooltip") {
        directives.push(
            "- Add mouseenter, mouseover, focus, or pointerenter handlers on visible marks or cards so rollover detail updates a shared explanation region inline."
                .to_string(),
        );
        directives.push(
            "- Keep the hovered or focused detail region populated on first paint, then rewrite it when the user hovers or focuses a specific chart mark."
                .to_string(),
        );
    }
    if failure_lower.contains("scroll")
        || failure_lower.contains("jump")
        || failure_lower.contains("log")
    {
        directives.push(
            "- Replace scrollIntoView, console-only, or jump-only controls with handlers that update shared detail, comparison, explanation, or chart state inline."
                .to_string(),
        );
        directives.push(
            "- At least one control should rewrite visible on-page copy, labels, chart state, or comparison content rather than only moving the viewport."
                .to_string(),
        );
        directives.push(
            "- If the brief needs sequence browsing or timeline traversal, add a visible progression control such as previous/next buttons, a scrubber, stepper, or scroll-snap rail instead of relying on a static timeline illustration."
                .to_string(),
        );
    }

    directives.join("\n")
}

pub(super) fn studio_artifact_candidate_refinement_directives(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    validation: &StudioArtifactValidationResult,
) -> String {
    let mut directives = vec![
        "- Patch the current artifact instead of restarting from a new shell.".to_string(),
        "- Preserve working file paths and any strong request-specific copy, labels, and structure already present.".to_string(),
    ];
    let modal_first_html =
        request.renderer == StudioRendererKind::HtmlIframe && studio_modal_first_html_enabled();
    let exact_view_scaffold = html_prompt_exact_view_scaffold(brief);
    let rollover_mark_example = html_prompt_rollover_mark_example(brief);

    if request.renderer == StudioRendererKind::HtmlIframe {
        directives.push(
            "- Keep at least three populated sectioning regions on first paint. Empty wrappers do not count as artifact structure."
                .to_string(),
        );
        directives.push(
            "- Ensure each sectioning region carries its own visible heading plus content, scorecards, labels, chart marks, or explanatory copy on first paint; a section that only mounts future script output is still empty."
                .to_string(),
        );
        if modal_first_html {
            directives.push(
                "- Preserve or strengthen the artifact's chosen interaction grammar instead of forcing a dashboard shell; tabs, sceneboards, steppers, inline simulators, inspectable diagrams, annotated cards, and other truthful patterns are all valid."
                    .to_string(),
            );
            directives.push(
                "- Keep the primary interaction on-page: controls or marks should change inline evidence, simulation state, comparison state, callouts, or explanatory copy. A detached shared-detail panel is optional, not required."
                    .to_string(),
            );
        } else {
            directives.push(
                "- Use a named control bar plus a shared detail or comparison panel; anchor-only navigation is not enough for the primary interaction model."
                    .to_string(),
            );
        }
        directives.push(
            "- Keep the hero request-specific instead of repeating the thesis verbatim, and surface differentiating concepts across section headings and evidence labels."
                .to_string(),
        );
        directives.push(
            "- Replace scrollIntoView, jump-link, or console-only handlers with controls that rewrite visible detail, comparison, or chart state in place."
                .to_string(),
        );
        if modal_first_html {
            directives.push(
                "- Do not regress into anchor-only jumps, generic app chrome, or a left-nav shell; the primary interaction should keep the page feeling authored and request-specific."
                    .to_string(),
            );
        } else {
            directives.push(
                "- Do not regress into anchor-only section jumps or top-nav shells; the primary controls must change inline evidence or detail state."
                    .to_string(),
            );
        }
        directives.push(
            "- Keep the default selected chart, label, and detail state directly in the markup before any script runs; do not bootstrap the only visible content from empty targets."
                .to_string(),
        );
        directives.push(
            "- Avoid DOMContentLoaded, innerHTML, appendChild, or createElement as the only source of first-paint chart/detail content. Use them only to update already-rendered regions."
                .to_string(),
        );
        directives.push(
            "- Keep scripts comment-free and production-ready; do not leave placeholder comments or dead DOM references in the surfaced artifact."
                .to_string(),
        );
    }

    if validation.request_faithfulness <= 3 || validation.concept_coverage <= 3 {
        directives.push(
            "- Surface the requiredConcepts in visible headings, labels, legends, captions, or explanatory copy, not only in the title."
                .to_string(),
        );
    }

    if request.renderer == StudioRendererKind::HtmlIframe && brief.has_required_interaction_goals()
    {
        directives.push(
            "- Realize requiredInteractions with visible controls that update on-page state, reveal deeper detail, filter views, or compare scenarios."
                .to_string(),
        );
        if brief_requires_sequence_browsing(brief) {
            directives.push(
                "- When a requiredInteraction implies sequence browsing, timeline traversal, or scrolling through staged evidence, expose a visible progression mechanism such as previous/next controls, a scrubber, a stepper, or a scrollable evidence rail. A static chart plus unrelated panel toggles does not satisfy sequence browsing."
                    .to_string(),
            );
        }
        if modal_first_html {
            directives.push(
                "- Prefer controls that update labeled inline evidence, comparison state, captions, callouts, or contextual explanation instead of acting like navigation-only buttons."
                    .to_string(),
            );
        } else {
            directives.push(
                "- Prefer controls that update a shared detail, comparison, or explanation region instead of navigation-only buttons."
                    .to_string(),
            );
        }
        directives.push(
            "- Give the default selected control a fully populated response region on first paint before any user action."
                .to_string(),
        );
        directives.push(
            "- Keep at least one secondary evidence view, comparison card, or preview visible on first paint so the artifact reads as multi-view rather than a single chart with generic prose."
                .to_string(),
        );
        directives.push(
            "- Prefer pre-rendered evidence sections, comparison cards, or detail blocks already present in the DOM; controls should toggle or annotate them instead of rebuilding the only evidence view with innerHTML."
                .to_string(),
        );
        directives.push(
            "- Do not count a one-line paragraph as a secondary evidence view; use structured evidence such as comparison bullets, a score table, a metric-card rail, or a second SVG with labeled marks."
                .to_string(),
        );
        if let Some(primary_anchor) = brief
            .factual_anchors
            .iter()
            .map(|item| item.trim())
            .find(|item| !item.is_empty())
        {
            directives.push(format!(
                "- Dedicate one named first-paint evidence surface directly to this factual anchor: {primary_anchor}. Make it visible through labels, marks, timeline items, metric cards, annotations, or comparison rows rather than generic overview copy."
            ));
        }
        if let Some(secondary_anchor) = brief
            .factual_anchors
            .iter()
            .skip(1)
            .map(|item| item.trim())
            .find(|item| !item.is_empty())
        {
            directives.push(format!(
                "- Dedicate a second named evidence surface, comparison rail, or preview directly to this factual anchor: {secondary_anchor}. Keep it visible on first paint instead of burying it inside one generic shared summary."
            ));
        }
        if brief.required_interaction_goal_count() >= 2 {
            if modal_first_html {
                directives.push(
                    "- Spread multiple interaction requirements across the artifact: keep one explicit authored state-change seam and at least one in-evidence inspection, hover/focus, or input behavior on visible marks, cards, chips, form fields, or list items."
                        .to_string(),
                );
                directives.push(
                    "- Do not satisfy a multi-interaction brief with only one button row and one thin state swap; let interactions change more than one visible region or explanatory surface."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Spread multiple interaction requirements across the artifact: keep one explicit control-bar behavior and at least one in-evidence inspection or input behavior on visible marks, cards, chips, form fields, or list items."
                        .to_string(),
                );
                directives.push(
                    "- Do not satisfy a multi-interaction brief with only one button row and a single shared panel toggle."
                        .to_string(),
                );
            }
        }
        if brief_requires_view_switching(brief) {
            if modal_first_html {
                directives.push(
                    "- For clickable navigation, keep at least two authored states, scenes, or sections in the markup and make the switch visibly change the page. Mapped panels are allowed, not mandatory."
                        .to_string(),
                );
                directives.push(
                    "- If you do use mapped panels, use explicit identifiers such as data-view plus data-view-panel or aria-controls tied to real authored states rather than synthesized selector math."
                        .to_string(),
                );
                directives.push(
                    "- Keep one authored state clearly active on first paint and make each click reveal a visibly different evidence or explanation state, not just a relabeled pill."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- For clickable navigation, use explicit static control-to-panel mappings such as data-view plus data-view-panel, aria-controls, or data-target tied to pre-rendered views."
                        .to_string(),
                );
                directives.push(
                    "- Keep data-view-panel as a literal HTML attribute on each panel element; a CSS class like class=\"data-view-panel\" does not count as a mapped pre-rendered panel."
                        .to_string(),
                );
                directives.push(
                    "- Keep at least two pre-rendered view panels in the markup and toggle hidden, data-active, or aria-selected state instead of deriving target ids from button ids at runtime."
                        .to_string(),
                );
                directives.push(
                    "- If you need Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first."
                        .to_string(),
                );
                directives.push(
                    "- Static data-view, aria-controls, or data-target attributes do not count on their own; wire click handlers that actually toggle panel visibility or selected state on the mapped panel wrappers."
                        .to_string(),
                );
                directives.push(
                    "- Do not use class names like class=\"overview-panel\" or class=\"data-view-panel\" as a substitute for actual id/data-view-panel attributes on the panel wrapper."
                        .to_string(),
                );
                directives.push(
                    "- Use a concrete scaffold when needed: buttons[data-view], matching <section data-view-panel=\"...\"> containers for each view, one populated default panel, one shared detail aside such as #detail-copy, and a panels collection selected before toggling hidden state."
                        .to_string(),
                );
                directives.push(format!(
                    "- A safe exact scaffold is {}.",
                    exact_view_scaffold
                ));
                directives.push(
                    "- If you use aria-controls, target the enclosing section/article/div panel rather than an inner SVG node or chart mark."
                        .to_string(),
                );
                directives.push(
                    "- Keep exactly one mapped panel visible in the raw markup before any script runs; the remaining mapped panels may start hidden."
                        .to_string(),
                );
                directives.push(
                    "- Do not wire every control only to the shared detail panel; the shared detail panel is supplementary and does not replace the pre-rendered view panels."
                        .to_string(),
                );
            }
        }
        if brief_requires_rollover_detail(brief) {
            if modal_first_html {
                directives.push(
                    "- Implement at least one hover or focus interaction on a visible chart mark, metric card, or timeline item that rewrites inline captioning, a callout, a contextual note, or another authored response region."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Implement at least one hover or focus interaction on a visible chart mark, metric card, or timeline item that rewrites a shared detail panel inline."
                        .to_string(),
                );
            }
        }
        if brief_requires_view_switching(brief) && brief_requires_rollover_detail(brief) {
            if modal_first_html {
                directives.push(
                    "- Keep both interaction families simultaneously: preserve at least two authored view states for switching and at least three visible inspectable marks or cards whose hover/focus behavior changes a visible response region."
                        .to_string(),
                );
                directives.push(
                    "- Do not satisfy clickable navigation by deleting inspectable detail behavior, and do not satisfy inspection by collapsing the authored view changes."
                        .to_string(),
                );
                directives.push(format!(
                    "- A strong repair shape is a visible view-switching seam plus inspectable marks such as {}, with default explanatory state already visible on first paint.",
                    rollover_mark_example
                ));
            } else {
                directives.push(
                    "- Keep both interaction families simultaneously: use at least two pre-rendered view panels for button-driven switching and at least three visible data-detail marks or cards with hover/focus behavior that update the same shared detail panel."
                        .to_string(),
                );
                directives.push(
                    "- Do not satisfy clickable navigation by deleting rollover detail, and do not satisfy rollover detail by collapsing the pre-rendered view panels."
                        .to_string(),
                );
                directives.push(format!(
                    "- A strong repair shape is buttons[data-view] -> [data-view-panel] plus [data-detail] -> #detail-copy, with one populated default panel, default detail state already visible on first paint, and a visible rollover mark such as {}.",
                    rollover_mark_example
                ));
            }
        }
    }

    if validation.interaction_relevance <= 2 {
        directives.push(
            "- Strengthen interaction density with actual handlers and response regions; a single disclosure or dead control is not enough."
                .to_string(),
        );
        directives.push(
            "- Make click and hover/focus behaviors rewrite meaningful request-grounded detail copy, not only selection labels or view ids."
                .to_string(),
        );
    }

    if validation.layout_coherence <= 3 || validation.completeness <= 3 {
        directives.push(
            "- Increase first-paint completeness by filling each primary region with visible content, not placeholders or deferred shells."
                .to_string(),
        );
    }

    if validation.generic_shell_detected || validation.trivial_shell_detected {
        directives.push(
            "- Remove placeholder-grade filler and generic shell patterns; the artifact should only fit this request, not nearby prompts."
                .to_string(),
        );
        directives.push(
            "- Replace nav-shell behavior with a chart-plus-detail composition that is already useful on first paint."
                .to_string(),
        );
    }

    if let Some(contradiction) = validation.strongest_contradiction.as_ref() {
        let contradiction_lower = contradiction.to_ascii_lowercase();
        directives.push(format!(
            "- Resolve this contradiction directly: {}",
            contradiction
        ));
        if contradiction_lower.contains("interactive elements")
            || contradiction_lower.contains("data visualizations")
            || contradiction_lower.contains("chart")
        {
            if modal_first_html {
                directives.push(
                    "- Add at least one inline SVG or DOM data visualization with visible marks, numeric labels, and a visible explanatory response region that updates inline."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Add at least one inline SVG or DOM data visualization with visible marks, numeric labels, and a shared detail panel that updates inline."
                        .to_string(),
                );
            }
            directives.push(
                "- Expand the first paint into at least two distinct evidence views or chart families tied to different brief concepts or reference hints; do not collapse everything into one generic chart."
                    .to_string(),
            );
            directives.push(
                "- Keep a secondary evidence view visible before interaction as a comparison card, preview panel, legend table, or supporting article."
                    .to_string(),
            );
            directives.push(
                "- Do not treat a bare sentence or overview paragraph as that secondary evidence view; populate it with multiple labeled rows, bullets, cards, or a second SVG."
                    .to_string(),
            );
            directives.push(
                "- Replace single-mark or unlabeled SVG shells with multiple request-grounded marks, rows, or milestone steps plus visible labels, captions, or legends on first paint."
                    .to_string(),
            );
            if modal_first_html {
                directives.push(
                    "- Update a visible explanatory response region with the selected metric, milestone, or evidence sentence from data-detail or control metadata; do not only echo the raw view id or button label."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Update the shared detail panel with the selected metric, milestone, or evidence sentence from data-detail or control metadata; do not only echo the raw view id or button label."
                        .to_string(),
                );
            }
        }
        if contradiction_lower.contains("navigation")
            || contradiction_lower.contains("pre-rendered views")
            || contradiction_lower.contains("view switching")
        {
            if modal_first_html {
                directives.push(
                    "- Replace implicit selector math with explicit authored states: controls should target real scenes, sections, or panels that already exist in the markup."
                        .to_string(),
                );
                directives.push(
                    "- If you use mapped panels, keep data-view-panel or aria-controls as literal attributes on the authored state wrappers and toggle visible state directly."
                        .to_string(),
                );
                directives.push(
                    "- Keep at least two authored view states in the DOM and make the click visibly change evidence or explanation rather than only switching a label."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Replace implicit selector math with explicit static mappings: controls should use data-view, aria-controls, or data-target values that point at pre-rendered panels already present in the markup."
                        .to_string(),
                );
                directives.push(
                    "- Keep data-view-panel as a literal HTML attribute on the panel element itself; a class token like class=\"data-view-panel\" does not satisfy the mapping."
                        .to_string(),
                );
                directives.push(
                    "- Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quotes."
                        .to_string(),
                );
                directives.push(
                    "- If you need Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first."
                        .to_string(),
                );
                directives.push(
                    "- Keep at least two pre-rendered view panels in the DOM and toggle hidden or data-active state instead of calling getElementById on a synthesized id string."
                        .to_string(),
                );
                directives.push(
                    "- Static data-view, aria-controls, or data-target attributes alone are not enough; the click handler must mutate hidden, aria-selected, aria-hidden, or comparable panel state on the mapped panels."
                        .to_string(),
                );
                directives.push(
                    "- Do not substitute class=\"overview-panel\" or class=\"data-view-panel\" for the literal id/data-view-panel mapping on the panel wrapper."
                        .to_string(),
                );
                directives.push(
                    "- Point aria-controls at the panel wrapper itself, not the inner SVG or chart node, and keep one mapped panel visibly selected before any script runs."
                        .to_string(),
                );
            }
        }
        if contradiction_lower.contains("rollover")
            || contradiction_lower.contains("hover")
            || contradiction_lower.contains("tooltip")
        {
            if modal_first_html {
                directives.push(
                    "- Implement hover or focus behavior on visible marks or metric cards so an authored inline response region updates when the user points at or focuses a chart element."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Implement hover or focus behavior on visible marks or metric cards so a shared detail panel updates inline when the user points at or focuses a chart element."
                        .to_string(),
                );
            }
        }
        if contradiction_lower.contains("missing dom ids") {
            directives.push(
                "- Keep every scripted selector aligned with real ids in the markup; if a view does not exist on first paint, do not reference it."
                    .to_string(),
            );
        }
        if contradiction_lower.contains("placeholder") {
            directives.push(
                "- Remove placeholder comments and replace empty SVGs or shells with labeled first-paint marks and explanatory detail."
                    .to_string(),
            );
        }
        if contradiction_lower.contains("detail") || contradiction_lower.contains("comparison") {
            if modal_first_html {
                directives.push(
                    "- Keep the chosen detail, comparison, or explanatory response region populated with default copy on first paint, then update that same region inline."
                        .to_string(),
                );
            } else {
                directives.push(
                    "- Keep the shared detail or comparison panel populated with default explanatory copy on first paint, then update that same region inline."
                        .to_string(),
                );
            }
        }
    }

    directives.join("\n")
}

pub(super) fn count_html_sectioning_elements(html_lower: &str) -> usize {
    ["<section", "<article", "<nav", "<aside", "<footer"]
        .iter()
        .map(|needle| html_lower.matches(needle).count())
        .sum()
}

pub(super) fn strip_html_tags(fragment: &str) -> String {
    let mut plain = String::with_capacity(fragment.len());
    let mut in_tag = false;
    for ch in fragment.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => plain.push(ch),
            _ => {}
        }
    }
    plain
}

fn html_inline_text_has_meaningful_signal(text: &str) -> bool {
    normalize_inline_text(text)
        .chars()
        .any(|ch| ch.is_alphanumeric())
}

pub(super) fn html_fragment_has_first_paint_content(fragment_lower: &str) -> bool {
    let mut cleaned = strip_external_tag_blocks(fragment_lower, "script", |_| true);
    cleaned = strip_external_tag_blocks(&cleaned, "style", |_| true);
    if html_fragment_is_comment_or_whitespace(&cleaned) {
        return false;
    }

    if html_inline_text_has_meaningful_signal(&strip_html_tags(&cleaned)) {
        return true;
    }

    [
        "<svg",
        "<canvas",
        "<img",
        "<table",
        "<button",
        "<input",
        "<select",
        "<textarea",
        "<details",
        "<summary",
        "<figure",
        "<ul",
        "<ol",
        "<li",
    ]
    .iter()
    .any(|needle| cleaned.contains(needle))
}

pub(super) fn html_fragment_has_detail_content(fragment_lower: &str) -> bool {
    let mut cleaned = strip_external_tag_blocks(fragment_lower, "script", |_| true);
    cleaned = strip_external_tag_blocks(&cleaned, "style", |_| true);
    if html_fragment_is_comment_or_whitespace(&cleaned) {
        return false;
    }

    let mut detail_body = cleaned.clone();
    for tag in ["h1", "h2", "h3", "h4", "h5", "h6", "header"] {
        detail_body = strip_external_tag_blocks(&detail_body, tag, |_| true);
    }

    if html_inline_text_has_meaningful_signal(&strip_html_tags(&detail_body)) {
        return true;
    }

    [
        "<table",
        "<ul",
        "<ol",
        "<dl",
        "<figure",
        "<svg",
        "<meter",
        "<progress",
    ]
    .iter()
    .any(|needle| cleaned.contains(needle))
}

pub(super) fn count_empty_html_sectioning_elements(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["section", "article", "nav", "aside", "footer"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        let mut cursor = 0usize;

        while let Some(relative_start) = html_lower[cursor..].find(&open_pattern) {
            let start = cursor + relative_start;
            let Some(relative_open_end) = html_lower[start..].find('>') else {
                break;
            };
            let open_end = start + relative_open_end + 1;

            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                total += 1;
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &html_lower[open_end..close_start];
            if !html_fragment_has_first_paint_content(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn count_html_nonempty_sectioning_elements(html_lower: &str) -> usize {
    count_html_sectioning_elements(html_lower)
        .saturating_sub(count_empty_html_sectioning_elements(html_lower))
}

pub(super) fn count_html_svg_regions(html_lower: &str) -> usize {
    html_lower.matches("<svg").count()
}

pub(super) fn count_html_svg_content_elements(html_lower: &str) -> usize {
    [
        "<path",
        "<rect",
        "<circle",
        "<ellipse",
        "<polygon",
        "<polyline",
        "<line",
        "<text",
    ]
    .iter()
    .map(|needle| html_lower.matches(needle).count())
    .sum()
}

pub(super) fn count_html_svg_label_elements(html_lower: &str) -> usize {
    ["<text", "<title", "<desc", "aria-label="]
        .iter()
        .map(|needle| html_lower.matches(needle).count())
        .sum()
}

pub(super) fn html_contains_placeholder_svg_regions(html_lower: &str) -> bool {
    let svg_regions = count_html_svg_regions(html_lower);
    svg_regions > 0 && count_html_svg_content_elements(html_lower) < svg_regions
}

pub(super) fn html_contains_unlabeled_chart_svg_regions(html_lower: &str) -> bool {
    let svg_regions = count_html_svg_regions(html_lower);
    svg_regions > 0
        && chart_region_hint_present(html_lower)
        && count_html_svg_content_elements(html_lower) >= svg_regions
        && count_html_svg_label_elements(html_lower) < svg_regions
}

pub(super) fn chart_region_hint_present(fragment_lower: &str) -> bool {
    ["chart", "graph", "diagram", "plot", "viz", "visualization"]
        .iter()
        .any(|needle| fragment_lower.contains(needle))
}

pub(super) fn detail_region_hint_present(fragment_lower: &str) -> bool {
    [
        "detail",
        "compare",
        "comparison",
        "explain",
        "explanation",
        "summary",
    ]
    .iter()
    .any(|needle| fragment_lower.contains(needle))
}

pub(super) fn placeholder_marker_hits(text_lower: &str) -> usize {
    let mut hits = 0usize;

    if text_lower.contains("<!--") && text_lower.contains("-->") {
        hits += 1;
    }

    for needle in [
        "lorem ipsum",
        "todo",
        "tbd",
        "coming soon",
        "replace this",
        "sample text",
        "add your css here",
        "add your javascript here",
        "add your js here",
        "add your html here",
        "placeholder copy",
        "placeholder content",
        "placeholder text",
        "placeholder media",
        "placeholder image",
        "placeholder images",
        "placeholder svg",
        "placeholder chart",
        "placeholder graphic",
        "placeholder shell",
        "placeholder region",
        "placeholder panel",
        "placeholder comment",
        "chart goes here",
    ]
    .iter()
    {
        let mut cursor = 0usize;
        while let Some(relative_start) = text_lower[cursor..].find(needle) {
            let start = cursor + relative_start;
            if !placeholder_marker_hit_is_negated(text_lower, start) {
                hits += 1;
            }
            cursor = start + needle.len();
        }
    }

    hits
}

fn placeholder_marker_hit_is_negated(text_lower: &str, match_start: usize) -> bool {
    let window_start = match_start.saturating_sub(40);
    let context = &text_lower[window_start..match_start];
    let clause_start = context
        .rfind(|ch| matches!(ch, '.' | '!' | '?' | '\n' | ';' | ':'))
        .map(|index| index + 1)
        .unwrap_or(0);
    let clause = context[clause_start..].trim();
    clause.contains("no ") || clause.contains("without ")
}

pub(super) fn html_contains_placeholder_markers(html_lower: &str) -> bool {
    placeholder_marker_hits(html_lower) > 0
}

pub(super) fn collect_html_attribute_ids(html_lower: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    for pattern in ["id=\"", "id='"] {
        let mut cursor = 0usize;
        let quote = pattern.chars().last().unwrap_or('"');
        while let Some(relative_start) = html_lower[cursor..].find(pattern) {
            let start = cursor + relative_start + pattern.len();
            let Some(relative_end) = html_lower[start..].find(quote) else {
                break;
            };
            let end = start + relative_end;
            let value = html_lower[start..end].trim();
            if !value.is_empty() {
                ids.insert(value.to_string());
            }
            cursor = end + 1;
        }
    }
    ids
}

pub(super) fn collect_call_argument_literals(
    html_lower: &str,
    pattern: &str,
    closing_quote: char,
) -> Vec<String> {
    let mut values = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative_start) = html_lower[cursor..].find(pattern) {
        let start = cursor + relative_start + pattern.len();
        let Some(relative_end) = html_lower[start..].find(closing_quote) else {
            break;
        };
        let end = start + relative_end;
        let value = html_lower[start..end].trim();
        if !value.is_empty() {
            values.push(value.to_string());
        }
        cursor = end + 1;
    }
    values
}

pub(super) fn extract_selector_ids(selector_lower: &str) -> Vec<String> {
    let bytes = selector_lower.as_bytes();
    let mut ids = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'#' {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len() {
            let ch = bytes[end] as char;
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                end += 1;
            } else {
                break;
            }
        }
        if end > start {
            ids.push(selector_lower[start..end].to_string());
        }
        index = end.max(start);
    }
    ids
}

pub(super) fn collect_html_referenced_ids(html_lower: &str) -> HashSet<String> {
    let mut ids = HashSet::new();
    for value in collect_call_argument_literals(html_lower, "getelementbyid(\"", '"')
        .into_iter()
        .chain(collect_call_argument_literals(
            html_lower,
            "getelementbyid('",
            '\'',
        ))
    {
        ids.insert(value);
    }
    for selector in collect_call_argument_literals(html_lower, "queryselector(\"", '"')
        .into_iter()
        .chain(collect_call_argument_literals(
            html_lower,
            "queryselector('",
            '\'',
        ))
        .chain(collect_call_argument_literals(
            html_lower,
            "queryselectorall(\"",
            '"',
        ))
        .chain(collect_call_argument_literals(
            html_lower,
            "queryselectorall('",
            '\'',
        ))
    {
        for id in extract_selector_ids(&selector) {
            ids.insert(id);
        }
    }
    ids
}

pub(super) fn html_references_missing_dom_ids(html_lower: &str) -> bool {
    let defined_ids = collect_html_attribute_ids(html_lower);
    collect_html_referenced_ids(html_lower)
        .into_iter()
        .any(|id| !defined_ids.contains(&id))
}

pub(super) fn html_fragment_contains_numeric_signal(fragment_lower: &str) -> bool {
    strip_html_tags(fragment_lower)
        .chars()
        .any(|ch| ch.is_ascii_digit())
}

pub(super) fn html_fragment_has_chart_implementation(fragment_lower: &str) -> bool {
    let mut cleaned = strip_external_tag_blocks(fragment_lower, "script", |_| true);
    cleaned = strip_external_tag_blocks(&cleaned, "style", |_| true);

    if [
        "<svg",
        "<table",
        "<meter",
        "<progress",
        "data-value=",
        "aria-valuenow=",
    ]
    .iter()
    .any(|needle| cleaned.contains(needle))
    {
        return true;
    }

    let list_like_marks = cleaned.matches("<li").count() + cleaned.matches("<dd").count();
    let data_bar_marks = cleaned.matches("data-bar").count()
        + cleaned.matches("class=\"bar").count()
        + cleaned.matches("class='bar").count();
    (list_like_marks >= 2 || data_bar_marks >= 2) && html_fragment_contains_numeric_signal(&cleaned)
}

pub(super) fn html_fragment_has_structured_evidence_content(fragment_lower: &str) -> bool {
    let mut cleaned = strip_external_tag_blocks(fragment_lower, "script", |_| true);
    cleaned = strip_external_tag_blocks(&cleaned, "style", |_| true);

    if html_fragment_has_chart_implementation(&cleaned) {
        return true;
    }

    let visible_words = normalize_inline_text(&strip_html_tags(&cleaned))
        .split_whitespace()
        .count();
    let list_items = cleaned.matches("<li").count();
    let table_rows = cleaned.matches("<tr").count();
    let definition_items = cleaned
        .matches("<dt")
        .count()
        .min(cleaned.matches("<dd").count());
    let interactive_marks = cleaned.matches("data-detail=").count()
        + cleaned.matches("data-value=").count()
        + cleaned.matches("aria-valuenow=").count()
        + cleaned.matches("<meter").count()
        + cleaned.matches("<progress").count();

    (cleaned.contains("<table") && table_rows >= 2 && visible_words >= 8)
        || ((cleaned.contains("<ul") || cleaned.contains("<ol"))
            && list_items >= 2
            && visible_words >= 8)
        || (cleaned.contains("<dl") && definition_items >= 2 && visible_words >= 8)
        || (interactive_marks >= 2 && visible_words >= 8)
}

pub(super) fn html_fragment_is_comment_or_whitespace(fragment_lower: &str) -> bool {
    let mut cursor = 0usize;

    while let Some(relative_start) = fragment_lower[cursor..].find("<!--") {
        let start = cursor + relative_start;
        if !fragment_lower[cursor..start].trim().is_empty() {
            return false;
        }
        let Some(relative_end) = fragment_lower[start + 4..].find("-->") else {
            return false;
        };
        cursor = start + 4 + relative_end + 3;
    }

    fragment_lower[cursor..].trim().is_empty()
}

pub(super) fn count_empty_html_chart_container_regions(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["div", "section", "article", "figure", "aside", "canvas"] {
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
            if !chart_region_hint_present(open_tag) {
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
            if !html_fragment_has_chart_implementation(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn count_populated_html_chart_regions(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["div", "section", "article", "figure", "aside"] {
        let open_pattern = format!("<{tag}");
        let close_pattern = format!("</{tag}>");
        let mut cursor = 0usize;

        while let Some(relative_start) = html_lower[cursor..].find(&open_pattern) {
            let start = cursor + relative_start;
            let Some(relative_open_end) = html_lower[start..].find('>') else {
                break;
            };
            let open_end = start + relative_open_end + 1;
            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &html_lower[open_end..close_start];
            if html_fragment_has_chart_implementation(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn count_populated_html_evidence_regions(html_lower: &str) -> usize {
    let mut regions = Vec::<(usize, usize)>::new();

    for tag in ["section", "article", "aside", "div", "figure"] {
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
            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let close_end = close_start + close_pattern.len();
            let inner = &html_lower[open_end..close_start];

            if open_tag.contains("data-studio-shared-detail=")
                || open_tag.contains("data-studio-rollover-chip-rail=")
                || open_tag.contains("data-studio-view-controls-repair=")
                || inner.contains("id=\"detail-copy\"")
                || inner.contains("id='detail-copy'")
            {
                cursor = open_end;
                continue;
            }

            if html_fragment_has_structured_evidence_content(inner) {
                regions.push((start, close_end));
            }
            cursor = open_end;
        }
    }

    regions.sort_unstable();
    regions.dedup();
    regions
        .iter()
        .filter(|(start, end)| {
            !regions
                .iter()
                .any(|(other_start, other_end)| other_start > start && other_end < end)
        })
        .count()
}

pub(super) fn html_contains_empty_chart_container_regions(html_lower: &str) -> bool {
    if html_lower.contains("studio-inline-chart-fallback") {
        return false;
    }
    count_empty_html_chart_container_regions(html_lower) > 0
}

pub(super) fn count_empty_html_detail_regions(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["aside", "section", "article", "div"] {
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
            if tag != "aside" && !detail_region_hint_present(open_tag) {
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

pub(super) fn html_contains_empty_detail_regions(html_lower: &str) -> bool {
    count_empty_html_detail_regions(html_lower) > 0
}

pub(super) fn count_populated_html_detail_regions(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["aside", "section", "article", "div"] {
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
            if tag != "aside" && !detail_region_hint_present(open_tag) {
                cursor = open_end;
                continue;
            }

            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &html_lower[open_end..close_start];
            if html_fragment_has_detail_content(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn count_populated_html_response_regions(html_lower: &str) -> usize {
    let mut total = 0usize;

    for tag in ["aside", "section", "article", "div"] {
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
            let response_hint_present = tag == "aside"
                || open_tag.contains("aria-live=")
                || open_tag.contains("role=\"status\"")
                || open_tag.contains("role='status'")
                || open_tag.contains("role=\"region\"")
                || open_tag.contains("role='region'")
                || open_tag.contains("role=\"alert\"")
                || open_tag.contains("role='alert'");
            if !response_hint_present {
                cursor = open_end;
                continue;
            }

            let Some(relative_close) = html_lower[open_end..].find(&close_pattern) else {
                cursor = open_end;
                continue;
            };
            let close_start = open_end + relative_close;
            let inner = &html_lower[open_end..close_start];
            if html_fragment_has_detail_content(inner) {
                total += 1;
            }
            cursor = close_start + close_pattern.len();
        }
    }

    total
}

pub(super) fn count_html_actionable_affordances(html_lower: &str) -> usize {
    [
        "<button",
        "<input",
        "<select",
        "<textarea",
        "<summary",
        "role=\"button\"",
        "role='button'",
        "role=\"tab\"",
        "role='tab'",
        "role=\"switch\"",
        "role='switch'",
        "role=\"checkbox\"",
        "role='checkbox'",
        "role=\"radio\"",
        "role='radio'",
    ]
    .iter()
    .map(|needle| html_lower.matches(needle).count())
    .sum()
}

pub(super) fn html_contains_state_mutation_behavior(html_lower: &str) -> bool {
    [
        "textcontent =",
        "textcontent=",
        "innertext =",
        "innertext=",
        "innerhtml =",
        "innerhtml=",
        "setattribute(",
        "removeattribute(",
        "toggleattribute(",
        "classlist.add(",
        "classlist.remove(",
        "classlist.toggle(",
        "style.",
        ".hidden =",
        ".hidden=",
        ".open =",
        ".open=",
        ".value =",
        ".value=",
        ".checked =",
        ".checked=",
        ".selectedindex =",
        ".selectedindex=",
        "appendchild(",
        "replacechildren(",
        "insertadjacent",
        "dataset.",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle))
}

pub(super) fn html_interactions_are_navigation_only(html_lower: &str) -> bool {
    contains_html_interaction_hooks(html_lower)
        && [
            "scrollintoview(",
            "window.scrollto(",
            "scrollto(",
            "location.hash",
            "console.info(",
            "console.log(",
            "console.warn(",
        ]
        .iter()
        .any(|needle| html_lower.contains(needle))
        && !html_contains_state_mutation_behavior(html_lower)
}

pub(super) fn contains_html_interaction_hooks(html_lower: &str) -> bool {
    [
        "<button",
        "<input",
        "<select",
        "<textarea",
        "<details",
        "<summary",
        "addeventlistener(",
        "onclick=",
        "onchange=",
        "oninput=",
        "onmouseover=",
        "onmouseenter=",
        "type=\"range\"",
        "type='range'",
        "role=\"tab\"",
        "role='tab'",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle))
}

pub(super) fn html_contains_stateful_interaction_behavior(html_lower: &str) -> bool {
    contains_html_interaction_hooks(html_lower) && html_contains_state_mutation_behavior(html_lower)
}

pub(super) fn html_contains_rollover_detail_behavior(html_lower: &str) -> bool {
    let has_hover_or_focus_handlers = [
        "addeventlistener(\"mouseenter\"",
        "addeventlistener('mouseenter'",
        "addeventlistener(\"mouseover\"",
        "addeventlistener('mouseover'",
        "addeventlistener(\"pointerenter\"",
        "addeventlistener('pointerenter'",
        "addeventlistener(\"focus\"",
        "addeventlistener('focus'",
        "onmouseenter=",
        "onmouseover=",
        "onfocus=",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle));

    has_hover_or_focus_handlers
        && count_html_actionable_affordances(html_lower) > 0
        && (count_populated_html_response_regions(html_lower) > 0
            || count_populated_html_detail_regions(html_lower) > 0)
        && html_contains_state_mutation_behavior(html_lower)
}

pub(super) fn html_contains_state_transition_behavior(html_lower: &str) -> bool {
    [
        "addeventlistener(\"click\"",
        "addeventlistener('click'",
        "addeventlistener(\"change\"",
        "addeventlistener('change'",
        "addeventlistener(\"input\"",
        "addeventlistener('input'",
        "onclick=",
        "onchange=",
        "oninput=",
        "onkeydown=",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle))
        && html_contains_state_mutation_behavior(html_lower)
}

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

pub(super) fn brief_required_interaction_goal_count(brief: &StudioArtifactBrief) -> usize {
    brief.required_interaction_goal_count()
}

pub(super) fn brief_requires_response_region(brief: &StudioArtifactBrief) -> bool {
    brief.requires_response_region()
}

pub(super) fn brief_requires_rollover_detail(brief: &StudioArtifactBrief) -> bool {
    brief.query_profile.as_ref().is_some_and(|profile| {
        profile.has_interaction_kind(StudioArtifactInteractionGoalKind::DetailInspect)
    })
}

pub(super) fn brief_requires_sequence_browsing(brief: &StudioArtifactBrief) -> bool {
    brief.query_profile.as_ref().is_some_and(|profile| {
        profile.has_interaction_kind(StudioArtifactInteractionGoalKind::SequenceBrowse)
    })
}

pub(super) fn brief_requires_view_switching(brief: &StudioArtifactBrief) -> bool {
    if let Some(profile) = brief.query_profile.as_ref() {
        return profile.has_interaction_kind(StudioArtifactInteractionGoalKind::StateSwitch);
    }
    false
}

pub(crate) fn studio_artifact_interaction_contract(
    brief: &StudioArtifactBrief,
) -> serde_json::Value {
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

fn safe_font_family_fallback_for_declaration(declaration: &str) -> String {
    let normalized_segments = declaration
        .split(',')
        .map(|segment| segment.trim().trim_matches('\'').trim_matches('"'))
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_ascii_lowercase())
        .collect::<Vec<_>>();

    if normalized_segments.iter().any(|segment| {
        matches!(
            segment.as_str(),
            "ui-monospace" | "monospace" | "courier new"
        )
    }) {
        return " ui-monospace, monospace".to_string();
    }

    if normalized_segments.iter().any(|segment| {
        matches!(
            segment.as_str(),
            "serif" | "ui-serif" | "georgia" | "times new roman"
        )
    }) {
        return " ui-serif, serif".to_string();
    }

    " system-ui, sans-serif".to_string()
}

pub(super) fn html_uses_external_runtime_dependency(html_lower: &str) -> bool {
    if html_lower.contains("<script src=")
        || html_lower.contains("<script src='")
        || html_lower.contains("<link rel=")
        || html_lower.contains("<link rel='")
    {
        return true;
    }

    let d3_defined_locally = ["const d3", "let d3", "var d3", "function d3", "class d3"]
        .iter()
        .any(|needle| html_lower.contains(needle));
    if html_lower.contains("d3.") && !d3_defined_locally {
        return true;
    }

    let chart_defined_locally = [
        "const chart",
        "let chart",
        "var chart",
        "function chart",
        "class chart",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle));
    html_lower.contains("new chart(") && !chart_defined_locally
}
