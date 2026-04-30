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
        "<section data-chat-normalized=\"true\" data-chat-rollover-chip-rail=\"true\"><h2>Evidence highlights</h2><div class=\"chat-rollover-chip-rail\">",
    );
    rebuilt.push_str(pending_marks);
    rebuilt.push_str(
        "</div><p>Select, hover, or focus a highlight to inspect the shared detail panel.</p></section>",
    );
    pending_marks.clear();
}

pub(super) fn ensure_grouped_html_rollover_detail_marks(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if lower.contains("data-chat-rollover-chip-rail=\"true\"")
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

fn brief_rollover_detail_labels(brief: &ChatArtifactBrief) -> Vec<String> {
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
    brief: &ChatArtifactBrief,
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
                "<button type=\"button\" class=\"chat-rollover-chip\" data-detail=\"{}\">{}</button>",
                xml_escape(label),
                xml_escape(label),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let snippet = format!(
        "<section data-chat-normalized=\"true\" data-chat-rollover-chip-rail=\"true\"><h2>Evidence highlights</h2><div class=\"chat-rollover-chip-rail\">{controls}</div><p>Select, hover, or focus a highlight to inspect the shared detail panel.</p></section>"
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
        "<aside data-chat-normalized=\"true\" data-chat-shared-detail=\"true\"><h2>Detail</h2><p id=\"detail-copy\">{} is selected by default.</p></aside>",
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

    for tag in ["aside", "section", "article", "div", "p"] {
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

            let repaired_open_tag = if open_tag_lower.contains("data-chat-shared-detail=") {
                open_tag.to_string()
            } else {
                inject_html_attributes_into_open_tag(
                    open_tag,
                    &[("data-chat-shared-detail", "true")],
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
    if !needs_polish || lower.contains("data-chat-interaction-polish=\"true\"") {
        return html.to_string();
    }

    let style = r#"<style data-chat-interaction-polish="true">
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
.chat-view-switch-controls,
main nav {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-start;
  align-items: center;
  gap: 12px;
  margin: 0;
}
.chat-rollover-chip-rail {
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
.chat-view-switch-controls button,
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
.chat-view-switch-controls button[aria-selected="true"],
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
[data-chat-shared-detail="true"],
[data-chat-rollover-chip-rail="true"] {
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
[data-chat-shared-detail="true"]:hover,
[data-chat-shared-detail="true"]:focus-within,
[data-chat-rollover-chip-rail="true"]:hover,
[data-chat-rollover-chip-rail="true"]:focus-within {
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
[data-chat-shared-detail="true"] h1,
[data-chat-shared-detail="true"] h2,
[data-chat-shared-detail="true"] h3 {
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
.chat-rollover-chip:hover,
.chat-rollover-chip:focus-visible {
  cursor: pointer;
  filter: brightness(0.96);
  outline: 2px solid rgba(37, 99, 235, 0.28);
  outline-offset: 2px;
}
.chat-rollover-chip,
.chat-rollover-chip-rail > [data-detail],
.chat-rollover-chip-rail > .data-detail,
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
.chat-rollover-chip-rail > .data-detail strong,
main > .data-detail strong {
  font: inherit;
}
[hidden] { display: none !important; }
@media (max-width: 720px) {
  header { padding: 24px 16px; }
  main { padding: 16px; gap: 16px; }
  .control-bar,
  .chat-view-switch-controls,
  main nav { gap: 8px; }
  .evidence-surface,
  [data-view-panel],
  [data-panel],
  [role="tabpanel"],
  .shared-detail,
  [data-chat-shared-detail="true"],
  [data-chat-rollover-chip-rail="true"] { padding: 18px; }
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
    let fallback = "<section data-chat-normalized=\"true\" class=\"chat-inline-chart-fallback\"><h2>Inline chart fallback</h2><svg width=\"320\" height=\"180\" viewBox=\"0 0 320 180\" xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"Inline fallback chart\"><rect x=\"24\" y=\"48\" width=\"44\" height=\"96\" rx=\"10\" fill=\"#63b3ed\"/><rect x=\"94\" y=\"28\" width=\"44\" height=\"116\" rx=\"10\" fill=\"#4fd1c5\"/><rect x=\"164\" y=\"68\" width=\"44\" height=\"76\" rx=\"10\" fill=\"#f6ad55\"/><rect x=\"234\" y=\"38\" width=\"44\" height=\"106\" rx=\"10\" fill=\"#f56565\"/><text x=\"46\" y=\"162\" text-anchor=\"middle\" font-size=\"12\">Plan</text><text x=\"116\" y=\"162\" text-anchor=\"middle\" font-size=\"12\">Adopt</text><text x=\"186\" y=\"162\" text-anchor=\"middle\" font-size=\"12\">Prove</text><text x=\"256\" y=\"162\" text-anchor=\"middle\" font-size=\"12\">Ship</text></svg><p>This inline SVG keeps the chart renderable without external runtime dependencies.</p></section>";
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

pub(super) fn ensure_svg_accessibility_metadata(svg: &str, brief: &ChatArtifactBrief) -> String {
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

pub(super) fn svg_accessibility_title(brief: &ChatArtifactBrief) -> String {
    let audience = brief.audience.trim();
    let domain = brief.subject_domain.trim();
    if !audience.is_empty() && !domain.is_empty() {
        format!("{audience} - {domain}")
    } else if !audience.is_empty() {
        audience.to_string()
    } else if !domain.is_empty() {
        domain.to_string()
    } else {
        "Chat SVG artifact".to_string()
    }
}

pub(super) fn svg_accessibility_description(brief: &ChatArtifactBrief) -> String {
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
            "{}<main data-chat-normalized=\"true\">{}</main>{}",
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
                    "{}<body data-chat-normalized=\"true\"><main data-chat-normalized=\"true\">{}</main></body>{}",
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
