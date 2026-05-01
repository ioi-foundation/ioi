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

            if open_tag.contains("data-chat-shared-detail=")
                || open_tag.contains("data-chat-rollover-chip-rail=")
                || open_tag.contains("data-chat-view-controls-repair=")
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
    if html_lower.contains("chat-inline-chart-fallback") {
        return false;
    }
    if html_lower.contains("chart-shell\"></div>")
        || html_lower.contains("chart-shell'></div>")
        || html_lower.contains("chart-shell\"></canvas>")
        || html_lower.contains("chart-shell'></canvas>")
    {
        return true;
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

    for tag in ["aside", "section", "article", "div", "p", "span", "output"] {
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
                || open_tag.contains("class=\"detail")
                || open_tag.contains("class='detail")
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

    let has_equivalent_detail_activation = html_contains_state_transition_behavior(html_lower)
        && (html_lower.contains("data-detail=")
            || html_lower.contains("detail-copy")
            || html_lower.contains("feedback")
            || html_lower.contains("status-text")
            || html_lower.contains("response-panel"))
        && html_contains_state_mutation_behavior(html_lower);

    (has_hover_or_focus_handlers || has_equivalent_detail_activation)
        && count_html_actionable_affordances(html_lower) > 0
        && (count_populated_html_response_regions(html_lower) > 0
            || count_populated_html_detail_regions(html_lower) > 0)
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
