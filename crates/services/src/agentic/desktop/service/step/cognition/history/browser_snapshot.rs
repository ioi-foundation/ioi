use super::*;

pub(super) fn top_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowUp"
    } else {
        "Control+Home"
    }
}

pub(super) fn top_edge_jump_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__key {"key":"ArrowUp","modifiers":["Meta"]}"#
    } else {
        r#"browser__key {"key":"Home","modifiers":["Control"]}"#
    }
}

pub(super) fn bottom_edge_jump_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Meta+ArrowDown"
    } else {
        "Control+End"
    }
}

pub(super) fn bottom_edge_jump_call() -> &'static str {
    if cfg!(target_os = "macos") {
        r#"browser__key {"key":"ArrowDown","modifiers":["Meta"]}"#
    } else {
        r#"browser__key {"key":"End","modifiers":["Control"]}"#
    }
}

pub(super) fn compact_ws_for_prompt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn looks_like_browser_snapshot_payload(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("<root") && trimmed.contains("id=\"") && trimmed.contains("rect=\"")
}

pub(super) fn browser_snapshot_payload(message: &ChatMessage) -> Option<&str> {
    if message.role != "tool" {
        return None;
    }

    let trimmed = message.content.trim();
    let payload = trimmed
        .strip_prefix(BROWSER_SNAPSHOT_TOOL_PREFIX)
        .unwrap_or(trimmed)
        .trim();
    looks_like_browser_snapshot_payload(payload).then_some(payload)
}

pub(super) fn decode_browser_xml_text(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

pub(super) fn extract_browser_xml_attr(fragment: &str, attr: &str) -> Option<String> {
    let marker = format!(r#"{attr}=""#);
    let mut search_start = 0usize;

    while let Some(relative_start) = fragment[search_start..].find(&marker) {
        let start = search_start + relative_start;
        let prefix_valid = start == 0
            || fragment[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_whitespace() || ch == '<');
        if !prefix_valid {
            search_start = start + 1;
            continue;
        }

        let value_start = start + marker.len();
        let rest = &fragment[value_start..];
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }

    None
}

pub(super) fn extract_compact_jsonish_string_field(text: &str, key: &str) -> Option<String> {
    let marker = format!("\"{}\":\"", key);
    let start = text.find(&marker)? + marker.len();
    let rest = &text[start..];
    let mut value = String::new();
    let mut escaped = false;

    for ch in rest.chars() {
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '"' => return Some(value),
            _ => value.push(ch),
        }
    }

    None
}

pub(super) fn extract_scoped_compact_jsonish_string_field(
    text: &str,
    scope_marker: &str,
    key: &str,
) -> Option<String> {
    let scope_start = text.find(scope_marker)? + scope_marker.len();
    extract_compact_jsonish_string_field(&text[scope_start..], key)
}

pub(super) fn extract_compact_jsonish_number_field(text: &str, key: &str) -> Option<f64> {
    let marker = format!("\"{}\":", key);
    let start = text.find(&marker)? + marker.len();
    let rest = &text[start..];
    let token = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '-'))
        .collect::<String>();
    (!token.is_empty())
        .then(|| token.parse::<f64>().ok())
        .flatten()
}

pub(super) fn extract_scoped_compact_jsonish_number_field(
    text: &str,
    scope_marker: &str,
    key: &str,
) -> Option<f64> {
    let scope_start = text.find(scope_marker)? + scope_marker.len();
    extract_compact_jsonish_number_field(&text[scope_start..], key)
}

pub(super) fn format_prompt_number(value: f64) -> String {
    if value.fract() == 0.0 {
        return format!("{}", value as i64);
    }

    format!("{value}")
}

pub(super) fn focused_home_should_jump_to_top_edge(compact: &str) -> Option<String> {
    let scroll_top = extract_compact_jsonish_number_field(compact, "scroll_top")?;
    if scroll_top <= 0.0 {
        return None;
    }

    let client_height = extract_compact_jsonish_number_field(compact, "client_height")?;
    (scroll_top >= client_height).then(|| format_prompt_number(scroll_top))
}

pub(super) fn extract_json_object_fragment(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    (start < end).then_some(&text[start..=end])
}

pub(super) fn parse_json_value_from_message(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    serde_json::from_str::<Value>(trimmed)
        .ok()
        .or_else(|| {
            extract_json_object_fragment(trimmed)
                .and_then(|fragment| serde_json::from_str::<Value>(fragment).ok())
        })
        .or_else(|| {
            extract_json_object_fragment(trimmed).and_then(|fragment| {
                let unescaped = fragment.replace("\\\"", "\"");
                serde_json::from_str::<Value>(&unescaped).ok()
            })
        })
}

pub(super) fn extract_assistive_browser_hints(snapshot: &str) -> Vec<String> {
    let mut hints = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.contains("assistive_hint=\"true\"") {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name") else {
            continue;
        };
        let name = compact_ws_for_prompt(&decode_browser_xml_text(&name));
        if name.is_empty() || hints.iter().any(|existing| existing == &name) {
            continue;
        }
        hints.push(name);
        if hints.len() >= 3 {
            break;
        }
    }

    hints
}

pub(super) fn browser_fragment_scroll_target_summary(fragment: &str) -> Option<String> {
    if !fragment.contains(" scroll_top=\"") || !fragment.contains(" client_height=\"") {
        return None;
    }

    if !(fragment.contains(" can_scroll_up=\"true\"")
        || fragment.contains(" can_scroll_down=\"true\""))
    {
        return None;
    }

    let tag_name = browser_fragment_tag_name(fragment)?;
    let semantic_id = extract_browser_xml_attr(fragment, "id")?;
    let dom_id = extract_browser_xml_attr(fragment, "dom_id")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());

    let mut summary = format!("{semantic_id} tag={tag_name}");
    if let Some(dom_id) = dom_id {
        summary.push_str(&format!(" dom_id={dom_id}"));
    }

    Some(summary)
}

pub(super) fn unique_visible_scroll_target_summary(snapshot: &str) -> Option<String> {
    let mut candidate = None;

    for fragment in snapshot.split('<') {
        let Some(summary) = browser_fragment_scroll_target_summary(fragment) else {
            continue;
        };

        if fragment.contains(" focused=\"true\"") {
            return None;
        }

        if candidate.replace(summary).is_some() {
            return None;
        }
    }

    candidate
}

fn history_requests_scroll_surface(history: &[ChatMessage]) -> bool {
    if history.is_empty() {
        return true;
    }

    history.iter().rev().take(6).any(|message| {
        let compact = compact_ws_for_prompt(&message.content).to_ascii_lowercase();
        compact.contains("scroll")
            || compact.contains("pageup")
            || compact.contains("page up")
            || compact.contains("pagedown")
            || compact.contains("page down")
            || compact.contains("control+home")
            || compact.contains("control+end")
            || compact.contains("meta+arrowup")
            || compact.contains("meta+arrowdown")
            || compact.contains(" top of ")
            || compact.contains(" bottom of ")
    })
}

pub(super) fn extract_scroll_target_focus_hint(snapshot: &str) -> Option<String> {
    let summary = unique_visible_scroll_target_summary(snapshot)?;
    Some(format!(
        "Visible scroll target `{summary}` is already on the page. If the goal requires interacting with that control, use control-local actions there; for scroll-specific keys like `Home` or `End`, focus that control instead of sending page-level edge keys."
    ))
}

pub(super) fn extract_scroll_target_focus_hint_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    if !history_requests_scroll_surface(history) {
        return None;
    }
    extract_scroll_target_focus_hint(snapshot)
}

pub(super) fn browser_fragment_tag_name(fragment: &str) -> Option<&str> {
    let trimmed = fragment.trim_start();
    if trimmed.is_empty() || trimmed.starts_with("!--") || trimmed.starts_with('/') {
        return None;
    }

    let end = trimmed
        .find(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
        .unwrap_or(trimmed.len());
    Some(&trimmed[..end])
}

pub(super) fn browser_fragment_looks_like_instruction_context(
    fragment: &str,
    tag_name: &str,
) -> bool {
    if !matches!(
        tag_name,
        "generic" | "group" | "presentation" | "statictext" | "labeltext" | "text" | "label"
    ) {
        return false;
    }

    let dom_id = extract_browser_xml_attr(fragment, "dom_id")
        .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase())
        .unwrap_or_default();
    let selector = extract_browser_xml_attr(fragment, "selector")
        .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase())
        .unwrap_or_default();
    let name = extract_browser_xml_attr(fragment, "name")
        .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase())
        .unwrap_or_default();

    let instruction_hint = [
        "query",
        "instruction",
        "prompt",
        "goal",
        "task",
        "directions",
    ]
    .iter()
    .any(|hint| dom_id.contains(hint) || selector.contains(hint));
    let wrapper_hint = matches!(dom_id.as_str(), "wrap" | "wrapper" | "container")
        || selector.contains("[id=\"wrap\"]")
        || selector.contains("[id=\"wrapper\"]");
    let imperative_name = [
        "find ", "click ", "select ", "choose ", "enter ", "type ", "press ",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
        && name.split_whitespace().count() >= 4;

    if matches!(tag_name, "generic" | "group" | "presentation") {
        instruction_hint || wrapper_hint || imperative_name
    } else {
        instruction_hint || imperative_name
    }
}

fn browser_fragment_stateful_class_hint(fragment: &str) -> bool {
    ["class_name", "class"].iter().any(|attr| {
        extract_browser_xml_attr(fragment, attr)
            .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase())
            .is_some_and(|value| {
                ["active", "selected", "current", "focused"]
                    .iter()
                    .any(|hint| value.contains(hint))
            })
    })
}

fn browser_fragment_stateful_match_hint(fragment: &str) -> bool {
    browser_fragment_stateful_class_hint(fragment)
        || fragment.contains(r#" focused="true""#)
        || fragment.contains(r#" checked="true""#)
        || fragment.contains(r#" selected="true""#)
}

fn browser_fragment_rect_area(fragment: &str) -> Option<f64> {
    let rect = extract_browser_xml_attr(fragment, "rect")?;
    let mut parts = rect.split(',');
    let _x = parts.next()?;
    let _y = parts.next()?;
    let width = parts.next()?.parse::<f64>().ok()?;
    let height = parts.next()?.parse::<f64>().ok()?;
    if parts.next().is_some() || width <= 0.0 || height <= 0.0 {
        return None;
    }
    Some(width * height)
}

fn browser_fragment_visual_area_bucket(fragment: &str) -> u8 {
    match browser_fragment_rect_area(fragment).unwrap_or_default() {
        area if area >= 2500.0 => 3,
        area if area >= 1000.0 => 2,
        area if area >= 200.0 => 1,
        _ => 0,
    }
}

fn browser_text_has_passive_metric_token(text: &str) -> bool {
    const TOKENS: &[&str] = &[
        "avg",
        "average",
        "countdown",
        "elapsed",
        "episode",
        "episodes",
        "progress",
        "remaining",
        "reward",
        "rewards",
        "score",
        "scores",
        "timer",
    ];
    const PHRASES: &[&str] = &[
        "episodes done",
        "last reward",
        "points earned",
        "scoreboard",
        "time left",
        "time remaining",
    ];

    let lower = text.to_ascii_lowercase();
    if PHRASES.iter().any(|phrase| lower.contains(phrase)) {
        return true;
    }

    lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| !token.is_empty() && TOKENS.contains(&token))
}

fn browser_fragment_looks_like_passive_metric(
    fragment: &str,
    tag_name: &str,
    normalized_name: Option<&str>,
    has_grounded_geometry: bool,
) -> bool {
    if browser_fragment_is_actionable_goal_target(fragment, tag_name)
        || has_grounded_geometry
        || normalized_name.is_some_and(browser_name_looks_like_month_year_label)
    {
        return false;
    }

    if !matches!(
        tag_name,
        "generic" | "label" | "status" | "text" | "statictext"
    ) {
        return false;
    }

    normalized_name.is_some_and(browser_text_has_passive_metric_token)
        || extract_browser_xml_attr(fragment, "dom_id").is_some_and(|value| {
            browser_text_has_passive_metric_token(&decode_browser_xml_text(&value))
        })
        || extract_browser_xml_attr(fragment, "selector").is_some_and(|value| {
            browser_text_has_passive_metric_token(&decode_browser_xml_text(&value))
        })
        || extract_browser_xml_attr(fragment, "class_name").is_some_and(|value| {
            browser_text_has_passive_metric_token(&decode_browser_xml_text(&value))
        })
}

pub(super) fn browser_fragment_priority_score(fragment: &str, tag_name: &str) -> Option<u8> {
    if browser_fragment_looks_like_instruction_context(fragment, tag_name) {
        return None;
    }

    let mut score = 0u8;
    let normalized_name = extract_browser_xml_attr(fragment, "name")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    let has_direct_locator = fragment.contains(" dom_id=\"")
        || fragment.contains(" selector=\"")
        || fragment.contains(" dom_clickable=\"true\"");
    let has_grounded_geometry = fragment.contains(" shape_kind=\"")
        && (fragment.contains(" center_x=\"") || fragment.contains(" line_x1=\""));
    let stateful_class_hint = browser_fragment_stateful_match_hint(fragment);
    let area_bucket = browser_fragment_visual_area_bucket(fragment);
    let passive_metric = browser_fragment_looks_like_passive_metric(
        fragment,
        tag_name,
        normalized_name.as_deref(),
        has_grounded_geometry,
    );
    if passive_metric {
        return None;
    }

    if fragment.contains(" dom_id=\"") {
        score = score.saturating_add(8);
    }
    if fragment.contains(" selector=\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" dom_clickable=\"true\"") {
        score = score.saturating_add(6);
    }
    if fragment.contains(" shape_kind=\"") {
        score = score.saturating_add(5);
    }
    if fragment.contains(" center_x=\"") || fragment.contains(" line_x1=\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" geometry_role=\"vertex\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" connected_points=\"") {
        score = score.saturating_add(1);
    }
    if fragment.contains(" line_angle_deg=\"") {
        score = score.saturating_add(1);
    }
    if fragment.contains(" angle_mid_deg=\"") {
        score = score.saturating_add(2);
    }
    // Geometry without a direct DOM locator is otherwise easy to crowd out with passive
    // telemetry. Promote it so synthetic-click tasks retain grounded scene structure.
    if has_grounded_geometry && !has_direct_locator {
        score = score.saturating_add(4);
    }
    if stateful_class_hint {
        score = score.saturating_add(6);
    }
    if score > 0 {
        score = score.saturating_add(area_bucket.saturating_mul(2));
    }
    if normalized_name
        .as_deref()
        .is_some_and(browser_name_looks_like_navigation_control)
    {
        score = score.saturating_add(8);
    }
    if normalized_name
        .as_deref()
        .is_some_and(browser_name_looks_like_month_year_label)
    {
        score = score.saturating_add(14);
    }
    if matches!(
        tag_name,
        "button"
            | "link"
            | "textbox"
            | "combobox"
            | "checkbox"
            | "radio"
            | "searchbox"
            | "menuitem"
            | "option"
    ) {
        score = score.saturating_add(6);
    } else if tag_name == "listitem" {
        score = score.saturating_add(2);
    }
    if fragment.contains(" focused=\"true\"")
        || fragment.contains(" checked=\"true\"")
        || fragment.contains(" selected=\"true\"")
    {
        score = score.saturating_add(4);
    }
    if fragment.contains(" assistive_hint=\"true\"") {
        score = score.saturating_add(2);
    }
    if fragment.contains(" omitted=\"true\"") {
        score = score.saturating_add(1);
    }

    (score > 0).then_some(score)
}

fn browser_name_looks_like_navigation_control(name: &str) -> bool {
    matches!(
        name.trim(),
        "<" | ">" | "<<" | ">>" | "prev" | "previous" | "previous month" | "next" | "next month"
    )
}

fn browser_name_looks_like_reusable_navigation_control(name: &str) -> bool {
    matches!(
        name.trim(),
        "prev"
            | "previous"
            | "previous month"
            | "previous year"
            | "next"
            | "next month"
            | "next year"
    )
}

fn browser_name_looks_like_month_year_label(name: &str) -> bool {
    const MONTH_NAMES: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];

    let has_month = MONTH_NAMES.iter().any(|month| name.contains(month));
    let has_year = name
        .split_whitespace()
        .any(|token| token.len() == 4 && token.chars().all(|ch| ch.is_ascii_digit()));
    has_month && has_year
}

fn browser_context_looks_like_dense_numeric_noise(context: &str) -> bool {
    let mut numeric_tokens = 0usize;
    let mut alphabetic_tokens = 0usize;
    let mut total_tokens = 0usize;

    for token in context.split_whitespace() {
        let normalized = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
        if normalized.is_empty() {
            continue;
        }
        total_tokens += 1;
        if normalized.chars().all(|ch| ch.is_ascii_digit()) {
            numeric_tokens += 1;
        }
        if normalized.chars().any(|ch| ch.is_ascii_alphabetic()) {
            alphabetic_tokens += 1;
        }
    }

    total_tokens >= 8 && numeric_tokens >= 6 && alphabetic_tokens <= 2
}

fn summarized_browser_fragment_context(name: Option<&str>, context: &str) -> Option<String> {
    let compact = compact_ws_for_prompt(context);
    if compact.is_empty() {
        return None;
    }

    let short_numeric_name = name.is_some_and(|value| {
        let trimmed = value.trim();
        !trimmed.is_empty()
            && trimmed.chars().count() <= 2
            && trimmed.chars().all(|ch| ch.is_ascii_digit())
    });
    if short_numeric_name
        && (compact.contains("<REDACTED:")
            || browser_context_looks_like_dense_numeric_noise(&compact))
    {
        return None;
    }

    Some(safe_truncate(&compact, 72))
}

pub(super) fn browser_fragment_priority_summary(fragment: &str) -> Option<(String, u8, String)> {
    let id = extract_browser_xml_attr(fragment, "id")?;
    let tag_name = browser_fragment_tag_name(fragment)?;
    let score = browser_fragment_priority_score(fragment, tag_name)?;

    let name = extract_browser_xml_attr(fragment, "name")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let dom_id = extract_browser_xml_attr(fragment, "dom_id")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let selector = extract_browser_xml_attr(fragment, "selector")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let class_name = extract_browser_xml_attr(fragment, "class_name")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let context = extract_browser_xml_attr(fragment, "context")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty())
        .and_then(|value| summarized_browser_fragment_context(name.as_deref(), &value));
    let shape_kind = extract_browser_xml_attr(fragment, "shape_kind")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let geometry_role = extract_browser_xml_attr(fragment, "geometry_role")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());
    let connected_lines = extract_browser_xml_attr(fragment, "connected_lines");
    let connected_points = extract_browser_xml_attr(fragment, "connected_points");
    let connected_line_angles_deg = extract_browser_xml_attr(fragment, "connected_line_angles_deg");
    let center_x = extract_browser_xml_attr(fragment, "center_x");
    let center_y = extract_browser_xml_attr(fragment, "center_y");
    let radius = extract_browser_xml_attr(fragment, "radius");
    let line_x1 = extract_browser_xml_attr(fragment, "line_x1");
    let line_y1 = extract_browser_xml_attr(fragment, "line_y1");
    let line_x2 = extract_browser_xml_attr(fragment, "line_x2");
    let line_y2 = extract_browser_xml_attr(fragment, "line_y2");
    let line_length = extract_browser_xml_attr(fragment, "line_length");
    let line_angle_deg = extract_browser_xml_attr(fragment, "line_angle_deg");
    let angle_mid_deg = extract_browser_xml_attr(fragment, "angle_mid_deg");
    let angle_span_deg = extract_browser_xml_attr(fragment, "angle_span_deg");

    let mut summary = format!("{id} tag={tag_name}");
    if let Some(name) = name {
        summary.push_str(&format!(" name={}", name));
    }
    if let Some(dom_id) = dom_id {
        summary.push_str(&format!(" dom_id={}", dom_id));
    }
    if let Some(selector) = selector {
        summary.push_str(&format!(" selector={}", selector));
    }
    if let Some(class_name) = class_name {
        summary.push_str(&format!(" class_name={}", class_name));
    }
    if let Some(context) = context {
        summary.push_str(&format!(" context={}", context));
    }
    if let Some(ref shape_kind) = shape_kind {
        summary.push_str(&format!(" shape_kind={shape_kind}"));
    }
    if let Some(geometry_role) = geometry_role {
        summary.push_str(&format!(" geometry_role={geometry_role}"));
    }
    if let Some(connected_lines) = connected_lines {
        summary.push_str(&format!(" connected_lines={connected_lines}"));
    }
    if let Some(connected_points) = connected_points {
        summary.push_str(&format!(" connected_points={connected_points}"));
    }
    if let Some(connected_line_angles_deg) = connected_line_angles_deg {
        summary.push_str(&format!(
            " connected_line_angles={connected_line_angles_deg}deg"
        ));
    }
    if shape_kind.as_deref() != Some("line") {
        if let (Some(center_x), Some(center_y)) = (center_x, center_y) {
            summary.push_str(&format!(" center={center_x},{center_y}"));
        }
    }
    if let Some(radius) = radius {
        summary.push_str(&format!(" radius={radius}"));
    }
    if let (Some(line_x1), Some(line_y1), Some(line_x2), Some(line_y2)) =
        (line_x1, line_y1, line_x2, line_y2)
    {
        summary.push_str(&format!(" line={line_x1},{line_y1}->{line_x2},{line_y2}"));
    }
    if let Some(line_length) = line_length {
        summary.push_str(&format!(" line_length={line_length}"));
    }
    if let Some(line_angle_deg) = line_angle_deg {
        summary.push_str(&format!(" line_angle={line_angle_deg}deg"));
    }
    if let Some(angle_mid_deg) = angle_mid_deg {
        summary.push_str(&format!(" angle_mid={angle_mid_deg}deg"));
    }
    if let Some(angle_span_deg) = angle_span_deg {
        summary.push_str(&format!(" angle_span={angle_span_deg}deg"));
    }
    if fragment.contains(" dom_clickable=\"true\"") {
        summary.push_str(" dom_clickable=true");
    }
    if fragment.contains(" focused=\"true\"") {
        summary.push_str(" focused=true");
    }
    if fragment.contains(" checked=\"true\"") {
        summary.push_str(" checked=true");
    }
    if fragment.contains(" selected=\"true\"") {
        summary.push_str(" selected=true");
    }
    if fragment.contains(" readonly=\"true\"") {
        summary.push_str(" readonly=true");
    }
    if fragment.contains(" omitted=\"true\"") {
        summary.push_str(" omitted");
    }

    Some((id, score, summary))
}

fn prioritized_browser_target_entries(snapshot: &str) -> Vec<(u8, usize, String)> {
    let mut seen_ids = HashSet::new();
    let mut targets = Vec::new();
    let mut order = 0usize;

    for fragment in snapshot.split('<') {
        let Some((id, score, summary)) = browser_fragment_priority_summary(fragment) else {
            continue;
        };
        if !seen_ids.insert(id) {
            continue;
        }
        targets.push((score, order, summary));
        order += 1;
    }

    for (id, score, summary) in extract_compact_priority_browser_targets(snapshot) {
        if !seen_ids.insert(id) {
            continue;
        }
        targets.push((score, order, summary));
        order += 1;
    }

    targets.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    targets
}

fn join_priority_targets_within_budget(
    summaries: impl IntoIterator<Item = String>,
    budget: usize,
) -> String {
    let mut joined = Vec::new();
    let mut used = 0usize;

    for summary in summaries {
        let summary_len = summary.chars().count();
        let addition = if joined.is_empty() {
            summary_len
        } else {
            3 + summary_len
        };

        if !joined.is_empty() && used + addition > budget {
            break;
        }

        if joined.is_empty() && summary_len > budget {
            joined.push(safe_truncate(&summary, budget));
            break;
        }

        used += addition;
        joined.push(summary);
    }

    joined.join(" | ")
}

pub(super) fn compact_priority_target_looks_like_instruction_context(summary: &str) -> bool {
    let lower = summary.to_ascii_lowercase();
    lower.contains(" dom_id=query")
        || lower.contains(" selector=[id=\"query\"]")
        || lower.contains(" dom_id=instruction")
        || lower.contains(" dom_id=prompt")
        || lower.contains(" dom_id=goal")
        || lower.contains(" dom_id=task")
        || lower.contains(" dom_id=wrap")
        || lower.contains(" selector=[id=\"wrap\"]")
        || lower.contains(" name=find ")
        || lower.contains(" name=click ")
        || lower.contains(" name=select ")
        || lower.contains(" name=choose ")
        || lower.contains(" name=enter ")
        || lower.contains(" name=type ")
}

pub(super) fn compact_priority_target_score(summary: &str) -> Option<u8> {
    if compact_priority_target_looks_like_instruction_context(summary) {
        return None;
    }

    let tag_name = priority_target_tag(summary)?;
    let mut score = 0u8;
    let has_direct_locator = summary.contains(" dom_id=")
        || summary.contains(" selector=")
        || summary.contains(" dom_clickable=true");
    let has_grounded_geometry = summary.contains(" shape_kind=")
        && (summary.contains(" center=") || summary.contains(" line="));
    let passive_metric = !matches!(
        tag_name,
        "button"
            | "link"
            | "textbox"
            | "combobox"
            | "checkbox"
            | "radio"
            | "searchbox"
            | "menuitem"
            | "option"
            | "tab"
    ) && !has_grounded_geometry
        && browser_text_has_passive_metric_token(summary);
    if passive_metric {
        return None;
    }

    if summary.contains(" dom_id=") {
        score = score.saturating_add(8);
    }
    if summary.contains(" selector=") {
        score = score.saturating_add(2);
    }
    if summary.contains(" dom_clickable=true") {
        score = score.saturating_add(6);
    }
    if summary.contains(" shape_kind=") {
        score = score.saturating_add(5);
    }
    if summary.contains(" center=") || summary.contains(" line=") {
        score = score.saturating_add(2);
    }
    if summary.contains(" geometry_role=vertex") {
        score = score.saturating_add(2);
    }
    if summary.contains(" line_angle=") {
        score = score.saturating_add(1);
    }
    if has_grounded_geometry && !has_direct_locator {
        score = score.saturating_add(4);
    }
    if summary.to_ascii_lowercase().contains(" class_name=")
        && ["active", "selected", "current", "focused"]
            .iter()
            .any(|hint| summary.to_ascii_lowercase().contains(hint))
    {
        score = score.saturating_add(6);
    }
    if matches!(
        tag_name,
        "button"
            | "link"
            | "textbox"
            | "combobox"
            | "checkbox"
            | "radio"
            | "searchbox"
            | "menuitem"
            | "option"
    ) {
        score = score.saturating_add(6);
    } else if tag_name == "listitem" {
        score = score.saturating_add(2);
    }
    if summary.contains(" focused=true")
        || summary.contains(" checked=true")
        || summary.contains(" selected=true")
        || summary.contains(" readonly=true")
    {
        score = score.saturating_add(4);
    }
    if summary.contains(" assistive_hint=") {
        score = score.saturating_add(2);
    }
    if summary.contains(" omitted") {
        score = score.saturating_add(1);
    }

    (score > 0).then_some(score)
}

pub(super) fn extract_compact_priority_browser_targets(
    snapshot: &str,
) -> Vec<(String, u8, String)> {
    let Some(start) = snapshot.find("IMPORTANT TARGETS:") else {
        return Vec::new();
    };
    let mut summary_block = &snapshot[start + "IMPORTANT TARGETS:".len()..];
    if let Some(end) = summary_block.find("</root>") {
        summary_block = &summary_block[..end];
    }

    summary_block
        .split('|')
        .filter_map(|entry| {
            let summary = compact_ws_for_prompt(&decode_browser_xml_text(entry.trim()));
            let semantic_id = priority_target_semantic_id(&summary)?.to_string();
            let score = compact_priority_target_score(&summary)?;
            Some((semantic_id, score, summary))
        })
        .collect()
}

pub(super) fn extract_priority_browser_targets(snapshot: &str, max_targets: usize) -> Vec<String> {
    prioritized_browser_target_entries(snapshot)
        .into_iter()
        .take(max_targets)
        .map(|(_, _, summary)| summary)
        .collect()
}

pub(super) fn browser_snapshot_root_summary(snapshot: &str) -> Option<String> {
    let trimmed = snapshot.trim();
    let start = trimmed.find("<root")?;
    let rest = &trimmed[start..];
    let end = rest.find('>')?;
    Some(compact_ws_for_prompt(&decode_browser_xml_text(
        &rest[..=end],
    )))
}

pub(super) fn compact_browser_observation(snapshot: &str) -> String {
    compact_browser_observation_with_history(snapshot, &[])
}

fn snapshot_priority_summary_for_semantic_id(snapshot: &str, semantic_id: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if extract_browser_xml_attr(fragment, "id").as_deref() != Some(semantic_id) {
            continue;
        }

        return browser_fragment_priority_summary(fragment).map(|(_, _, summary)| summary);
    }

    None
}

fn goal_aligned_priority_target_summary(snapshot: &str, history: &[ChatMessage]) -> Option<String> {
    if autocomplete_follow_up_pending_signal(history, Some(snapshot)).is_some() {
        return None;
    }

    let semantic_id = recent_goal_primary_target(history)
        .and_then(|target| snapshot_visible_exact_text_target(snapshot, &target))
        .or_else(|| snapshot_visible_goal_text_target(snapshot, history))
        .map(|candidate| candidate.semantic_id)?;
    snapshot_priority_summary_for_semantic_id(snapshot, &semantic_id)
}

pub(super) fn compact_browser_observation_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> String {
    let compact = compact_ws_for_prompt(snapshot.trim());
    if compact.chars().count() <= BROWSER_OBSERVATION_CONTEXT_MAX_CHARS {
        return compact;
    }

    let mut priority_targets = prioritized_browser_target_entries(snapshot)
        .into_iter()
        .filter(|(score, _, _)| *score >= 4)
        .map(|(_, _, summary)| summary)
        .collect::<Vec<_>>();
    if let Some(goal_summary) = goal_aligned_priority_target_summary(snapshot, history) {
        let goal_id = priority_target_semantic_id(&goal_summary);
        if let Some(existing_idx) = priority_targets.iter().position(|summary| {
            priority_target_semantic_id(summary)
                .zip(goal_id)
                .is_some_and(|(summary_id, goal_id)| summary_id == goal_id)
        }) {
            let existing = priority_targets.remove(existing_idx);
            priority_targets.insert(0, existing);
        } else {
            priority_targets.insert(0, goal_summary);
        }
    }
    if priority_targets.is_empty() {
        return safe_truncate(&compact, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS);
    }

    let root_summary =
        browser_snapshot_root_summary(snapshot).unwrap_or_else(|| safe_truncate(&compact, 96));
    let suffix_prefix = " IMPORTANT TARGETS: ";
    let closing = " </root>";
    let suffix_budget = BROWSER_OBSERVATION_CONTEXT_MAX_CHARS
        .saturating_sub(
            root_summary.chars().count() + suffix_prefix.chars().count() + closing.chars().count(),
        )
        .max(64);
    let suffix = join_priority_targets_within_budget(priority_targets, suffix_budget);
    if suffix.is_empty() {
        return safe_truncate(&compact, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS);
    }

    format!("{root_summary}{suffix_prefix}{suffix}{closing}")
}

pub(super) fn snapshot_lower_text(snapshot: &str) -> String {
    compact_ws_for_prompt(&decode_browser_xml_text(snapshot)).to_ascii_lowercase()
}

pub(super) fn snapshot_has_negative_selection_instruction(snapshot: &str) -> bool {
    let lower = snapshot_lower_text(snapshot);
    [
        "select nothing",
        "select none",
        "choose nothing",
        "choose none",
        "check nothing",
        "check none",
        "leave unchecked",
        "leave unselected",
        "keep unchecked",
        "keep unselected",
        "select no items",
        "select no options",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}

pub(super) fn snapshot_has_selectable_controls(snapshot: &str) -> bool {
    let lower = snapshot.to_ascii_lowercase();
    lower.contains("<checkbox ") || lower.contains("<radio ") || lower.contains("<option ")
}

pub(super) fn snapshot_has_selected_controls(snapshot: &str) -> bool {
    let lower = snapshot.to_ascii_lowercase();
    lower.contains("checked=\"true\"") || lower.contains("selected=\"true\"")
}

fn snapshot_visible_submit_control_id_local(snapshot: &str) -> Option<String> {
    let mut best_match: Option<((u8, u8, u8, u8, u8), String)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        let omitted = fragment.contains(r#" omitted="true""#);
        if omitted && !browser_fragment_allows_omitted_action_target(fragment, semantic_role) {
            continue;
        }
        let normalized_name = extract_browser_xml_attr(fragment, "name")
            .map(|value| normalized_exact_target_text(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let semantic_id_submit_like = semantic_id_is_submit_like(&semantic_id);
        let submit_like_name = normalized_name
            .split_whitespace()
            .any(|token| token == "submit");
        if !(semantic_id_submit_like || submit_like_name) {
            continue;
        }

        let actionable = u8::from(browser_fragment_is_actionable_goal_target(
            fragment,
            semantic_role,
        ));
        let selector_present = u8::from(fragment.contains(r#" selector=""#));
        let focused = u8::from(fragment.contains(r#" focused="true""#));
        let candidate_rank = (
            actionable,
            u8::from(semantic_id_submit_like),
            u8::from(!omitted),
            selector_present,
            focused,
        );

        match best_match.as_ref() {
            Some((best_rank, best_id))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank && best_id <= &semantic_id) => {}
            _ => best_match = Some((candidate_rank, semantic_id)),
        }
    }

    best_match.map(|(_, semantic_id)| semantic_id)
}

pub(super) fn snapshot_visible_selectable_control_states(
    snapshot: &str,
) -> Vec<SnapshotSelectableControlState> {
    let mut seen_ids = HashSet::new();
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "checkbox" | "radio" | "option") {
            continue;
        }
        if fragment.contains(r#" omitted="true""#)
            && !browser_fragment_allows_omitted_action_target(fragment, semantic_role)
        {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !seen_ids.insert(semantic_id.clone()) {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        states.push(SnapshotSelectableControlState {
            semantic_id,
            name,
            selected: fragment.contains(r#" checked="true""#)
                || fragment.contains(r#" selected="true""#),
        });
    }

    states
}

pub(super) fn snapshot_select_submit_progress_pending_signal_for_requested_targets(
    snapshot: &str,
    requested_targets: &str,
) -> Option<String> {
    let selectable_controls = snapshot_visible_selectable_control_states(snapshot);
    if selectable_controls.is_empty() {
        return None;
    }

    let requested_controls = selectable_controls
        .iter()
        .filter(|control| normalized_text_contains_exact_phrase(&requested_targets, &control.name))
        .collect::<Vec<_>>();
    if requested_controls.is_empty() {
        return None;
    }

    let missing_controls = requested_controls
        .iter()
        .filter(|control| !control.selected)
        .collect::<Vec<_>>();
    if !missing_controls.is_empty() {
        let remaining = missing_controls
            .iter()
            .take(4)
            .map(|control| format!("`{}` (`{}`)", control.semantic_id, control.name))
            .collect::<Vec<_>>()
            .join(", ");
        let plural = if missing_controls.len() == 1 {
            "target"
        } else {
            "targets"
        };
        if missing_controls.len() > 1 {
            let batch_ids = missing_controls
                .iter()
                .map(|control| format!("`{}`", control.semantic_id))
                .collect::<Vec<_>>()
                .join(", ");
            return Some(format!(
                "Requested selectable {plural} still missing from current browser state: {remaining}. Use `browser__click_element` with `ids` [{batch_ids}] now to click the remaining visible targets in order. Do not re-click already selected controls or `Submit` yet."
            ));
        }
        return Some(format!(
            "Requested selectable {plural} still missing from current browser state: {remaining}. Click one missing visible target now. Do not re-click already selected controls or `Submit` yet."
        ));
    }

    let submit_id = snapshot_visible_submit_control_id_local(snapshot)?;
    Some(format!(
        "All requested selectable targets already appear checked or selected. Use `browser__click_element` on `{submit_id}` now. Do not spend another step re-clicking the same selections."
    ))
}

pub(super) fn snapshot_select_submit_progress_pending_signal(snapshot: &str) -> Option<String> {
    let decoded_snapshot = decode_browser_xml_text(snapshot);
    let requested_targets = extract_select_submit_target(&decoded_snapshot)?;
    snapshot_select_submit_progress_pending_signal_for_requested_targets(
        snapshot,
        &requested_targets,
    )
}

pub(super) fn browser_snapshot_pending_signal(snapshot: &str) -> Option<String> {
    browser_snapshot_pending_signal_with_history(snapshot, &[])
}

pub(super) fn browser_snapshot_pending_signal_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    if snapshot_has_negative_selection_instruction(snapshot)
        && snapshot_has_selectable_controls(snapshot)
        && snapshot_has_selected_controls(snapshot)
    {
        return Some("The page-visible instruction requires no selections, but current browser state already shows checked or selected controls. Do not submit yet. Clear those selections so the relevant controls return to unchecked or unselected, then continue with the next required control.".to_string());
    }

    if history_requests_scroll_surface(history) {
        if let Some(summary) = unique_visible_scroll_target_summary(snapshot) {
            return Some(format!(
                "Visible scroll target `{summary}` is already on the page. Use `browser__click_element` or `browser__click` there for `Home` or `End`; otherwise continue with the next required visible control."
            ));
        }
    }

    if let Some(signal) = snapshot_select_submit_progress_pending_signal(snapshot) {
        return Some(format!("{signal}"));
    }

    None
}

pub(super) fn browser_snapshot_success_signal(snapshot: &str) -> Option<&'static str> {
    if snapshot_has_negative_selection_instruction(snapshot)
        && snapshot_has_selectable_controls(snapshot)
        && !snapshot_has_selected_controls(snapshot)
    {
        return Some(
            "The page-visible instruction already requires no selections, and current browser state shows no checked or selected controls. Do not click any checkbox, radio, or option. Continue with the next required control (for example `Submit`) or verify once if the goal is already satisfied.",
        );
    }

    None
}

pub(super) fn extract_item_like_ids(text: &str) -> Vec<String> {
    let chars = text.chars().collect::<Vec<_>>();
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    let mut idx = 0usize;

    while idx < chars.len() {
        if !chars[idx].is_ascii_alphabetic() {
            idx += 1;
            continue;
        }

        let start = idx;
        while idx < chars.len() && chars[idx].is_ascii_alphabetic() {
            idx += 1;
        }
        if idx >= chars.len() || chars[idx] != '-' {
            continue;
        }
        idx += 1;
        let digits_start = idx;
        while idx < chars.len() && chars[idx].is_ascii_digit() {
            idx += 1;
        }
        if digits_start == idx {
            continue;
        }

        let token = chars[start..idx]
            .iter()
            .collect::<String>()
            .to_ascii_uppercase();
        if seen.insert(token.clone()) {
            ids.push(token);
        }
    }

    ids
}

pub(super) fn first_item_like_id(text: &str) -> Option<String> {
    extract_item_like_ids(text).into_iter().next()
}

pub(super) fn last_item_like_id(text: &str) -> Option<String> {
    extract_item_like_ids(text).into_iter().last()
}

pub(super) fn history_item_like_id_from_url(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    if let Some(ticket_idx) = lower.find("/tickets/") {
        let rest = &url[ticket_idx + "/tickets/".len()..];
        let candidate = rest.split('/').next().unwrap_or_default();
        if let Some(item_id) = first_item_like_id(candidate) {
            return Some(item_id);
        }
    }

    last_item_like_id(url)
}

pub(super) fn extract_first_quoted_value(text: &str) -> Option<String> {
    let start = text.find('"')? + 1;
    let end = text[start..].find('"')? + start;
    let value = compact_ws_for_prompt(&text[start..end]);
    (!value.is_empty()).then_some(value)
}

pub(super) fn trim_goal_target_value(text: &str) -> Option<String> {
    let compact = compact_ws_for_prompt(text);
    let value = compact.trim().trim_matches(|ch: char| {
        matches!(
            ch,
            '.' | ',' | ';' | ':' | '"' | '\'' | '`' | '(' | ')' | '[' | ']'
        )
    });
    if value.is_empty() {
        return None;
    }

    let normalized = normalized_exact_target_text(value);
    if matches!(
        normalized.as_str(),
        "nothing" | "none" | "no items" | "no options"
    ) {
        return None;
    }

    Some(value.to_string())
}

pub(super) fn extract_select_submit_target(text: &str) -> Option<String> {
    const PREFIXES: &[&str] = &["select ", "choose "];
    const SUFFIXES: &[&str] = &[
        " and click submit",
        " then click submit",
        " and hit submit",
        " then hit submit",
        " and submit",
        " then submit",
    ];

    let lower = text.to_ascii_lowercase();
    for prefix in PREFIXES {
        let Some(start) = lower.find(prefix) else {
            continue;
        };
        let value_start = start + prefix.len();
        let original_rest = &text[value_start..];
        let lower_rest = &lower[value_start..];

        for suffix in SUFFIXES {
            let Some(end) = lower_rest.find(suffix) else {
                continue;
            };
            let candidate = original_rest[..end]
                .trim_end()
                .strip_suffix(" as the date")
                .or_else(|| original_rest[..end].trim_end().strip_suffix(" as date"))
                .unwrap_or(&original_rest[..end]);
            if let Some(value) = trim_goal_target_value(candidate) {
                return Some(value);
            }
        }
    }

    None
}

fn extract_find_by_target(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let find_start = lower.find("find ")?;
    let search_window = &lower[find_start..];
    let by_marker = search_window.find(" by ")?;
    let value_start = find_start + by_marker + " by ".len();
    let original_rest = &text[value_start..];
    let lower_rest = &lower[value_start..];

    let mut end = original_rest.len();
    for marker in [" and ", " then ", ".", ",", ";", "\n"] {
        if let Some(idx) = lower_rest.find(marker) {
            end = end.min(idx);
        }
    }

    trim_goal_target_value(&original_rest[..end])
}

fn extract_message_source_target(text: &str) -> Option<String> {
    const MESSAGE_MARKERS: &[&str] = &["email", "e-mail", "mail", "message"];
    const SOURCE_PATTERNS: &[&str] = &[
        " that i got from ",
        " that i received from ",
        " that i have from ",
        " from ",
    ];
    const END_MARKERS: &[&str] = &[" and ", " then ", " to ", ".", ",", ";", "\n", "!", "?"];

    let lower = text.to_ascii_lowercase();

    for marker in MESSAGE_MARKERS {
        let mut search_start = 0usize;
        while let Some(relative_idx) = lower[search_start..].find(marker) {
            let message_end = search_start + relative_idx + marker.len();
            let original_rest = &text[message_end..];
            let lower_rest = &lower[message_end..];

            for pattern in SOURCE_PATTERNS {
                let Some(pattern_idx) = lower_rest.find(pattern) else {
                    continue;
                };
                let value_start = message_end + pattern_idx + pattern.len();
                let original_value_rest = &text[value_start..];
                let lower_value_rest = &lower[value_start..];

                let mut end = original_value_rest.len();
                for marker in END_MARKERS {
                    if let Some(idx) = lower_value_rest.find(marker) {
                        end = end.min(idx);
                    }
                }

                if let Some(target) = trim_goal_target_value(&original_value_rest[..end]) {
                    return Some(target);
                }
            }

            search_start = message_end;
        }
    }

    None
}

fn extract_message_recipient_target(text: &str) -> Option<String> {
    const MESSAGE_SUFFIXES: &[&str] = &[" the email", " the e-mail", " the mail", " the message"];
    const END_MARKERS: &[&str] = &[" and ", " then ", " to ", ".", ",", ";", "\n", "!", "?"];

    let lower = text.to_ascii_lowercase();

    if let Some(send_start) = lower.find("send ") {
        let value_start = send_start + "send ".len();
        let original_rest = &text[value_start..];
        let lower_rest = &lower[value_start..];
        let mut end = original_rest.len();

        for suffix in MESSAGE_SUFFIXES {
            if let Some(idx) = lower_rest.find(suffix) {
                end = end.min(idx);
            }
        }

        if end < original_rest.len() {
            if let Some(target) = trim_goal_target_value(&original_rest[..end]) {
                return Some(target);
            }
        }
    }

    if let Some(forward_start) = lower.find("forward ") {
        let value_start = forward_start + "forward ".len();
        let lower_rest = &lower[value_start..];
        if let Some(to_idx) = lower_rest.rfind(" to ") {
            let target_start = value_start + to_idx + " to ".len();
            let original_target_rest = &text[target_start..];
            let lower_target_rest = &lower[target_start..];
            let mut end = original_target_rest.len();

            for marker in END_MARKERS {
                if let Some(idx) = lower_target_rest.find(marker) {
                    end = end.min(idx);
                }
            }

            if let Some(target) = trim_goal_target_value(&original_target_rest[..end]) {
                return Some(target);
            }
        }
    }

    None
}

pub(super) fn normalized_exact_target_text(text: &str) -> String {
    compact_ws_for_prompt(text)
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
                .to_ascii_lowercase()
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalized_text_contains_exact_phrase(text: &str, phrase: &str) -> bool {
    let normalized_text = normalized_exact_target_text(text);
    let normalized_phrase = normalized_exact_target_text(phrase);
    if normalized_text.is_empty() || normalized_phrase.is_empty() {
        return false;
    }

    normalized_text == normalized_phrase
        || normalized_text.starts_with(&format!("{normalized_phrase} "))
        || normalized_text.ends_with(&format!(" {normalized_phrase}"))
        || normalized_text.contains(&format!(" {normalized_phrase} "))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RankedResultRequest {
    pub(super) rank: usize,
    pub(super) ordinal_text: String,
}

pub(super) fn parse_ordinal_token(token: &str) -> Option<usize> {
    let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
    let lower = trimmed.to_ascii_lowercase();
    let digits_len = lower.chars().take_while(|ch| ch.is_ascii_digit()).count();
    if digits_len == 0 {
        return None;
    }

    let (digits, suffix) = lower.split_at(digits_len);
    if !matches!(suffix, "st" | "nd" | "rd" | "th") {
        return None;
    }

    digits.parse::<usize>().ok().filter(|value| *value > 0)
}

pub(super) fn recent_requested_result_rank(history: &[ChatMessage]) -> Option<RankedResultRequest> {
    for message in history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
    {
        let tokens = message.content.split_whitespace().collect::<Vec<_>>();
        for (idx, token) in tokens.iter().enumerate() {
            let ordinal_text = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
            let Some(rank) = parse_ordinal_token(ordinal_text) else {
                continue;
            };
            let mentions_result = tokens
                .iter()
                .skip(idx + 1)
                .take(3)
                .map(|part| {
                    part.trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                        .to_ascii_lowercase()
                })
                .any(|part| part.starts_with("result"));
            if !mentions_result {
                continue;
            }

            return Some(RankedResultRequest {
                rank,
                ordinal_text: ordinal_text.to_string(),
            });
        }
    }

    None
}

pub(super) fn recent_requested_sort_label(history: &[ChatMessage]) -> Option<String> {
    const SORT_PATTERNS: &[&str] = &["sort to", "sort on", "sort by", "sort as"];

    for message in history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
    {
        let lower = message.content.to_ascii_lowercase();
        let mut best_match: Option<(usize, String)> = None;

        for pattern in SORT_PATTERNS {
            let mut search_start = 0usize;
            while let Some(relative_idx) = lower[search_start..].find(pattern) {
                let absolute_idx = search_start + relative_idx + pattern.len();
                if let Some(label) = extract_first_quoted_value(&message.content[absolute_idx..]) {
                    match best_match.as_ref() {
                        Some((best_idx, _)) if *best_idx >= absolute_idx => {}
                        _ => best_match = Some((absolute_idx, label)),
                    }
                }
                search_start = absolute_idx;
            }
        }

        if let Some((_, label)) = best_match {
            return Some(label);
        }
    }

    None
}

pub(super) fn recent_goal_primary_target(history: &[ChatMessage]) -> Option<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| {
            extract_find_by_target(&message.content)
                .or_else(|| extract_first_quoted_value(&message.content))
                .or_else(|| extract_select_submit_target(&message.content))
        })
}

pub(super) fn recent_goal_message_recipient_target(history: &[ChatMessage]) -> Option<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| extract_first_quoted_value(&message.content))
}

pub(super) fn recent_goal_mentions_submit(history: &[ChatMessage]) -> bool {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .any(|message| message.content.to_ascii_lowercase().contains("submit"))
}

fn normalized_goal_is_submit_only_action(goal: &str) -> bool {
    let normalized_goal = normalized_exact_target_text(goal);
    let remaining_tokens = normalized_goal
        .split_whitespace()
        .filter(|token| {
            !matches!(
                *token,
                "a" | "an"
                    | "and"
                    | "button"
                    | "click"
                    | "control"
                    | "hit"
                    | "icon"
                    | "now"
                    | "on"
                    | "please"
                    | "press"
                    | "tap"
                    | "the"
                    | "then"
                    | "use"
            )
        })
        .collect::<Vec<_>>();

    !remaining_tokens.is_empty()
        && remaining_tokens
            .iter()
            .all(|token| matches!(*token, "submit"))
}

fn snapshot_goal_text_match_is_premature_submit_fallback(
    semantic_id: &str,
    normalized_name: &str,
    matching_goals: &[&str],
) -> bool {
    let submit_like_name = normalized_name
        .split_whitespace()
        .any(|token| token == "submit");
    if !(semantic_id_is_submit_like(semantic_id) || submit_like_name) {
        return false;
    }

    !matching_goals.is_empty()
        && matching_goals
            .iter()
            .all(|goal| !normalized_goal_is_submit_only_action(goal))
}

pub(super) fn priority_target_semantic_id(summary: &str) -> Option<&str> {
    let token = summary.split_whitespace().next()?;
    if let Some(value) = token.strip_prefix("id=") {
        return Some(value);
    }
    token
        .split_once('#')
        .map(|(_, value)| value)
        .or(Some(token))
}

pub(super) fn priority_target_tag(summary: &str) -> Option<&str> {
    summary
        .split_whitespace()
        .find_map(|token| token.strip_prefix("tag="))
        .or_else(|| {
            summary
                .split_whitespace()
                .next()?
                .split_once('#')
                .map(|(tag, _)| tag)
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BrowserNavigationTransition {
    pub(super) semantic_id: Option<String>,
    pub(super) pre_url: Option<String>,
    pub(super) post_url: String,
}

pub(super) fn clicked_element_semantic_id(message: &ChatMessage) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    let rest = message.content.trim().strip_prefix("Clicked element '")?;
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

pub(super) fn recent_successful_click_semantic_id(history: &[ChatMessage]) -> Option<String> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success || !compact.contains("Clicked element") {
            return None;
        }

        clicked_element_semantic_id(message)
    })
}

pub(super) fn recent_successful_selected_control_semantic_id(
    history: &[ChatMessage],
) -> Option<String> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success
            || !compact.contains("Clicked element")
            || !(compact.contains("\"checked\":true") || compact.contains("\"selected\":true"))
        {
            return None;
        }

        clicked_element_semantic_id(message)
    })
}

pub(super) fn recent_successful_click_is_observed_in_later_snapshot(
    history: &[ChatMessage],
    semantic_id: &str,
) -> bool {
    let mut saw_later_snapshot = false;

    for message in history.iter().rev() {
        if browser_snapshot_payload(message).is_some() {
            saw_later_snapshot = true;
            continue;
        }
        if message.role != "tool" {
            continue;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success || !compact.contains("Clicked element") {
            continue;
        }
        if clicked_element_semantic_id(message).as_deref() == Some(semantic_id) {
            return saw_later_snapshot;
        }
    }

    false
}

pub(super) fn recent_successful_click_has_post_action_observation(
    history: &[ChatMessage],
    semantic_id: &str,
    current_snapshot: Option<&str>,
) -> bool {
    if recent_successful_click_is_observed_in_later_snapshot(history, semantic_id) {
        return true;
    }

    current_snapshot.is_some()
        && recent_successful_click_semantic_id(history).as_deref() == Some(semantic_id)
}

fn snapshot_semantic_id_name(snapshot: &str, semantic_id: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if extract_browser_xml_attr(fragment, "id").as_deref() != Some(semantic_id) {
            continue;
        }

        return extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
    }

    None
}

pub(super) fn snapshot_semantic_id_has_selected_state(snapshot: &str, semantic_id: &str) -> bool {
    let semantic_id_attr = format!(r#"id="{}""#, semantic_id);

    snapshot.split('<').any(|fragment| {
        fragment.contains(&semantic_id_attr)
            && (fragment.contains(r#" checked="true""#) || fragment.contains(r#" selected="true""#))
    })
}

fn snapshot_semantic_id_is_reusable_navigation_control(snapshot: &str, semantic_id: &str) -> bool {
    snapshot_semantic_id_name(snapshot, semantic_id)
        .map(|name| browser_name_looks_like_reusable_navigation_control(&name.to_ascii_lowercase()))
        .unwrap_or_else(|| {
            let lower = semantic_id.to_ascii_lowercase();
            lower.contains("prev") || lower.contains("next")
        })
}

pub(super) fn tree_change_link_reverification_pending_signal(
    history: &[ChatMessage],
) -> Option<String> {
    let latest_snapshot_idx = history
        .iter()
        .rposition(|message| browser_snapshot_payload(message).is_some());
    let search_start = latest_snapshot_idx.map_or(0, |idx| idx + 1);
    let prior_snapshot =
        latest_snapshot_idx.and_then(|idx| browser_snapshot_payload(&history[idx]));

    let clicked_id = history[search_start..].iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success
            || !compact.contains("Clicked element")
            || !compact.contains("\"tree_changed\":true")
            || compact.contains("\"url_changed\":true")
        {
            return None;
        }

        let clicked_id = clicked_element_semantic_id(message)?;
        let link_like = clicked_id.to_ascii_lowercase().starts_with("lnk_")
            || compact.contains(r#""tag_name":"a""#);
        link_like.then_some(clicked_id)
    })?;

    if prior_snapshot.is_some_and(|snapshot| {
        snapshot_semantic_id_is_reusable_navigation_control(snapshot, &clicked_id)
    }) {
        return Some(format!(
            "A recent click on navigation control `{clicked_id}` already changed the page state (`tree_changed=true`). The previous browser observation is stale for non-navigation targets, but `{clicked_id}` remains reusable. If the goal still requires more movement in that same direction, you may click `{clicked_id}` again now; otherwise use `browser__snapshot` before choosing newly visible content from the updated page."
        ));
    }

    Some(format!(
        "A recent click on `{clicked_id}` already changed the page state (`tree_changed=true`). Do not click `{clicked_id}` again or act on stale controls from the previous browser observation. Use `browser__snapshot` once now to ground the updated page before taking the next action."
    ))
}

pub(super) fn tree_change_link_reverification_pending_signal_with_current_snapshot(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let latest_snapshot = history.iter().rev().find_map(browser_snapshot_payload);
    if current_snapshot.is_some_and(|snapshot| latest_snapshot != Some(snapshot)) {
        return None;
    }

    tree_change_link_reverification_pending_signal(history)
}

pub(super) fn semantic_id_is_submit_like(semantic_id: &str) -> bool {
    let lower = semantic_id.to_ascii_lowercase();
    lower.contains("submit") || lower.contains("subbtn") || lower.contains("search")
}

pub(super) fn snapshot_contains_semantic_id(snapshot: &str, semantic_id: &str) -> bool {
    let semantic_id_attr = format!(r#"id="{}""#, semantic_id);
    let compact_summary = format!("#{semantic_id}");
    let compact_summary_raw = format!("{semantic_id} tag=");
    let compact_summary_attr = format!("id={semantic_id}");
    snapshot.contains(&semantic_id_attr)
        || snapshot.contains(&compact_summary)
        || snapshot.contains(&compact_summary_raw)
        || snapshot.contains(&compact_summary_attr)
}

pub(super) fn recent_confirmation_queue_return(history: &[ChatMessage]) -> bool {
    history.iter().rev().take(10).any(|message| {
        let Some(transition) = browser_navigation_transition(message) else {
            return false;
        };
        let Some(pre_url) = transition.pre_url else {
            return false;
        };

        pre_url.to_ascii_lowercase().contains("/confirmation")
            && transition.post_url.to_ascii_lowercase().contains("/queue")
    })
}

pub(super) fn browser_navigation_transition(
    message: &ChatMessage,
) -> Option<BrowserNavigationTransition> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_success = (compact.contains("\"postcondition\":{") && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");
    if !has_success {
        return None;
    }

    let pre_url = extract_compact_jsonish_string_field(&compact, "pre_url")
        .or_else(|| extract_scoped_compact_jsonish_string_field(&compact, "\"pre\":{", "url"));
    let post_url = extract_compact_jsonish_string_field(&compact, "post_url")
        .or_else(|| extract_scoped_compact_jsonish_string_field(&compact, "\"post\":{", "url"));
    let has_url_change = compact.contains("\"url_changed\":true")
        || pre_url
            .as_ref()
            .zip(post_url.as_ref())
            .is_some_and(|(pre, post)| pre != post);
    if !has_url_change {
        return None;
    }

    Some(BrowserNavigationTransition {
        semantic_id: clicked_element_semantic_id(message),
        pre_url,
        post_url: post_url.unwrap_or_else(|| "the new page".to_string()),
    })
}

pub(super) fn recent_unobserved_navigation_transition(
    history: &[ChatMessage],
) -> Option<BrowserNavigationTransition> {
    let latest_snapshot_idx = history
        .iter()
        .rposition(|message| browser_snapshot_payload(message).is_some());
    let search_start = latest_snapshot_idx.map_or(0, |idx| idx + 1);
    history[search_start..]
        .iter()
        .rev()
        .find_map(browser_navigation_transition)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotLinkState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) context: Option<String>,
    pub(super) visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotTabState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) controls_dom_id: Option<String>,
    pub(super) focused: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotTabPanelState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotVisibleTargetState {
    pub(super) semantic_id: String,
    pub(super) name: String,
    pub(super) semantic_role: String,
    pub(super) already_active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SnapshotSearchAffordanceKind {
    Field,
    Activator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotSearchAffordanceState {
    pub(super) semantic_id: String,
    pub(super) semantic_role: String,
    pub(super) kind: SnapshotSearchAffordanceKind,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotMessageRecipientControlState {
    pub(super) semantic_id: String,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotAutocompleteControlState {
    pub(super) semantic_id: String,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) controls_dom_id: Option<String>,
    pub(super) value: Option<String>,
    pub(super) has_active_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotSelectableControlState {
    pub(super) semantic_id: String,
    pub(super) name: String,
    pub(super) selected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RecentAutocompleteAction {
    Typed,
    Key(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecentAutocompleteToolState {
    pub(super) action: RecentAutocompleteAction,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
    pub(super) value: Option<String>,
    pub(super) has_active_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecentFindTextState {
    pub(super) query: String,
    pub(super) first_snippet: Option<String>,
}

pub(super) fn snapshot_link_states(snapshot: &str) -> Vec<SnapshotLinkState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("link ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let context = extract_browser_xml_attr(fragment, "context")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let visible = !fragment.contains(r#" visible="false""#);

        states.push(SnapshotLinkState {
            semantic_id,
            name,
            dom_id,
            selector,
            context,
            visible,
        });
    }

    states
}

pub(super) fn snapshot_tab_states(snapshot: &str) -> Vec<SnapshotTabState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("tab ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotTabState {
            semantic_id,
            name,
            dom_id,
            selector,
            controls_dom_id,
            focused: fragment.contains(r#" focused="true""#),
        });
    }

    states
}

pub(super) fn snapshot_tabpanel_states(snapshot: &str) -> Vec<SnapshotTabPanelState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("tabpanel ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotTabPanelState {
            semantic_id,
            name,
            dom_id,
            selector,
            visible: !fragment.contains(r#" visible="false""#),
        });
    }

    states
}

pub(super) fn visible_target_role_priority(semantic_role: &str) -> u8 {
    match semantic_role {
        "link" | "button" | "menuitem" | "option" | "tab" | "checkbox" | "radio" => 4,
        "generic" | "label" | "text" | "heading" => 3,
        "textbox" | "searchbox" | "combobox" => 2,
        _ => 1,
    }
}

fn snapshot_fragment_metadata_values(fragment: &str) -> Vec<String> {
    ["name", "dom_id", "selector", "class_name", "placeholder"]
        .into_iter()
        .filter_map(|attr| {
            extract_browser_xml_attr(fragment, attr)
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty())
        })
        .collect()
}

pub(super) fn snapshot_visible_search_affordance(
    snapshot: &str,
) -> Option<SnapshotSearchAffordanceState> {
    let mut best_match: Option<((u8, u8, u8, u8), SnapshotSearchAffordanceState)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment)
            .map(str::to_string)
            .filter(|role| !role.is_empty())
        else {
            continue;
        };
        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let search_metadata = snapshot_fragment_metadata_values(fragment);
        if !search_metadata
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("search"))
        {
            continue;
        }

        let kind = if matches!(semantic_role.as_str(), "textbox" | "searchbox" | "combobox") {
            SnapshotSearchAffordanceKind::Field
        } else if matches!(
            semantic_role.as_str(),
            "button" | "link" | "generic" | "menuitem"
        ) {
            SnapshotSearchAffordanceKind::Activator
        } else {
            continue;
        };

        let candidate = SnapshotSearchAffordanceState {
            semantic_id,
            semantic_role: semantic_role.clone(),
            kind: kind.clone(),
            dom_id,
            selector,
        };
        let candidate_rank = (
            u8::from(matches!(kind, SnapshotSearchAffordanceKind::Field)),
            u8::from(fragment.contains(r#" dom_clickable="true""#)),
            u8::from(candidate.selector.is_some()),
            visible_target_role_priority(&semantic_role),
        );

        match best_match.as_ref() {
            Some((best_rank, best_candidate))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank
                        && best_candidate.semantic_id <= candidate.semantic_id) => {}
            _ => best_match = Some((candidate_rank, candidate)),
        }
    }

    best_match.map(|(_, candidate)| candidate)
}

pub(super) fn snapshot_visible_message_recipient_control(
    snapshot: &str,
) -> Option<SnapshotMessageRecipientControlState> {
    let mut best_match: Option<((u8, u8, u8), SnapshotMessageRecipientControlState)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        let looks_like_recipient_field =
            snapshot_fragment_metadata_values(fragment)
                .iter()
                .any(|value| {
                    let normalized = normalized_exact_target_text(value);
                    normalized == "to"
                        || normalized == "recipient"
                        || normalized.contains(" recipient ")
                        || normalized.starts_with("recipient ")
                        || normalized.ends_with(" recipient")
                        || normalized == "forward sender"
                        || normalized.contains("forward sender")
                        || normalized == "reply recipient"
                        || normalized.contains("reply recipient")
                });
        if !looks_like_recipient_field {
            continue;
        }

        let candidate = SnapshotMessageRecipientControlState {
            semantic_id,
            dom_id,
            selector,
            value,
        };
        let candidate_rank = (
            u8::from(candidate.selector.is_some()),
            u8::from(candidate.dom_id.is_some()),
            u8::from(fragment.contains(r#" focused="true""#)),
        );

        match best_match.as_ref() {
            Some((best_rank, best_candidate))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank
                        && best_candidate.semantic_id <= candidate.semantic_id) => {}
            _ => best_match = Some((candidate_rank, candidate)),
        }
    }

    best_match.map(|(_, candidate)| candidate)
}

pub(super) fn snapshot_visible_exact_text_target(
    snapshot: &str,
    target: &str,
) -> Option<SnapshotVisibleTargetState> {
    let normalized_target = normalized_exact_target_text(target);
    if normalized_target.is_empty() {
        return None;
    }

    let mut best_match: Option<(
        (u8, u8, u8, u8, u8, u8, u8, usize),
        SnapshotVisibleTargetState,
    )> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment)
            .map(str::to_string)
            .filter(|role| !role.is_empty())
        else {
            continue;
        };
        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if normalized_exact_target_text(&name) != normalized_target {
            continue;
        }

        let instruction_context =
            browser_fragment_looks_like_instruction_context(fragment, &semantic_role);
        let actionable_target =
            browser_fragment_is_actionable_goal_target(fragment, &semantic_role);
        if instruction_context && !actionable_target {
            continue;
        }
        let stateful_class_hint = u8::from(browser_fragment_stateful_match_hint(fragment));
        let area_bucket = browser_fragment_visual_area_bucket(fragment);
        let dom_clickable = u8::from(fragment.contains(r#" dom_clickable="true""#));
        let selector_present = u8::from(fragment.contains(r#" selector=""#));
        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: name.clone(),
            semantic_role: semantic_role.clone(),
            already_active: stateful_class_hint > 0,
        };
        let candidate_rank = (
            u8::from(actionable_target),
            u8::from(!instruction_context),
            stateful_class_hint,
            visible_target_role_priority(&semantic_role),
            dom_clickable,
            selector_present,
            area_bucket,
            name.chars().count(),
        );

        match best_match.as_ref() {
            Some((best_rank, best_candidate))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank
                        && best_candidate.semantic_id <= candidate.semantic_id) => {}
            _ => best_match = Some((candidate_rank, candidate)),
        }
    }

    best_match.map(|(_, candidate)| candidate)
}

fn browser_fragment_is_start_gate_label(name: &str) -> bool {
    matches!(
        normalized_exact_target_text(name).as_str(),
        "start" | "begin" | "continue"
    )
}

fn browser_fragment_is_start_gate_role(semantic_role: &str) -> bool {
    matches!(
        semantic_role,
        "button"
            | "link"
            | "menuitem"
            | "statictext"
            | "text"
            | "label"
            | "labeltext"
            | "generic"
            | "group"
            | "presentation"
    )
}

pub(super) fn snapshot_visible_start_gate_target(
    snapshot: &str,
) -> Option<SnapshotVisibleTargetState> {
    let mut best_match: Option<((u8, u8, u8, u8, u8, usize), SnapshotVisibleTargetState)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment)
            .map(str::to_string)
            .filter(|role| !role.is_empty())
        else {
            continue;
        };
        if !browser_fragment_is_start_gate_role(&semantic_role) {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !browser_fragment_is_start_gate_label(&name) {
            continue;
        }

        let instruction_context =
            browser_fragment_looks_like_instruction_context(fragment, &semantic_role);
        let actionable_target =
            browser_fragment_is_actionable_goal_target(fragment, &semantic_role);
        let has_action_locator = browser_fragment_has_action_locator(fragment);
        let area_bucket = browser_fragment_visual_area_bucket(fragment);
        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: name.clone(),
            semantic_role: semantic_role.clone(),
            already_active: false,
        };
        let candidate_rank = (
            u8::from(has_action_locator),
            u8::from(actionable_target),
            area_bucket,
            visible_target_role_priority(&semantic_role),
            u8::from(!instruction_context),
            name.chars().count(),
        );

        match best_match.as_ref() {
            Some((best_rank, best_candidate))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank
                        && best_candidate.semantic_id <= candidate.semantic_id) => {}
            _ => best_match = Some((candidate_rank, candidate)),
        }
    }

    best_match.map(|(_, candidate)| candidate)
}

pub(super) fn snapshot_visible_goal_text_target(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<SnapshotVisibleTargetState> {
    let recent_goal_texts = history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .map(|message| normalized_exact_target_text(&message.content))
        .filter(|message| !message.is_empty())
        .collect::<Vec<_>>();
    if recent_goal_texts.is_empty() {
        return None;
    }

    let mut best_match: Option<(
        (u8, u8, u8, u8, u8, u8, u8, usize),
        SnapshotVisibleTargetState,
    )> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment)
            .map(str::to_string)
            .filter(|role| !role.is_empty())
        else {
            continue;
        };
        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let normalized_name = normalized_exact_target_text(&name);
        if normalized_name.is_empty() || normalized_goal_text_target_is_noise(&normalized_name) {
            continue;
        }
        let matching_goals = recent_goal_texts
            .iter()
            .filter(|goal| normalized_text_contains_exact_phrase(goal, &normalized_name))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if matching_goals.is_empty()
            || snapshot_goal_text_match_is_premature_submit_fallback(
                &semantic_id,
                &normalized_name,
                &matching_goals,
            )
        {
            continue;
        }

        let instruction_context =
            browser_fragment_looks_like_instruction_context(fragment, &semantic_role);
        let actionable_target =
            browser_fragment_is_actionable_goal_target(fragment, &semantic_role);
        if instruction_context && !actionable_target {
            continue;
        }
        let stateful_class_hint = u8::from(browser_fragment_stateful_match_hint(fragment));
        let area_bucket = browser_fragment_visual_area_bucket(fragment);
        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: name.clone(),
            semantic_role: semantic_role.clone(),
            already_active: stateful_class_hint > 0,
        };
        let candidate_rank = (
            u8::from(actionable_target),
            u8::from(!instruction_context),
            stateful_class_hint,
            u8::from(!matches!(
                semantic_role.as_str(),
                "generic" | "text" | "heading" | "label"
            )),
            area_bucket,
            u8::from(fragment.contains(r#" dom_clickable="true""#)),
            u8::from(fragment.contains(r#" selector=""#) || fragment.contains(r#" dom_id=""#)),
            name.chars().count(),
        );

        match best_match.as_ref() {
            Some((best_rank, best_candidate))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank
                        && best_candidate.semantic_id <= candidate.semantic_id) => {}
            _ => best_match = Some((candidate_rank, candidate)),
        }
    }

    best_match.map(|(_, candidate)| candidate)
}

fn normalized_goal_text_target_is_noise(normalized_name: &str) -> bool {
    let mut tokens = normalized_name.split_whitespace();
    let Some(first_token) = tokens.next() else {
        return true;
    };
    if tokens.next().is_some() {
        return false;
    }

    matches!(
        first_token,
        "a" | "an"
            | "and"
            | "at"
            | "by"
            | "for"
            | "from"
            | "in"
            | "into"
            | "of"
            | "on"
            | "or"
            | "the"
            | "to"
            | "with"
    )
}

fn browser_fragment_is_actionable_goal_target(fragment: &str, semantic_role: &str) -> bool {
    fragment.contains(r#" dom_clickable="true""#)
        || matches!(
            semantic_role,
            "button"
                | "link"
                | "textbox"
                | "searchbox"
                | "combobox"
                | "checkbox"
                | "radio"
                | "menuitem"
                | "option"
                | "tab"
        )
}

fn browser_fragment_has_action_locator(fragment: &str) -> bool {
    fragment.contains(r#" selector=""#) || fragment.contains(r#" dom_id=""#)
}

pub(super) fn browser_fragment_allows_omitted_action_target(
    fragment: &str,
    semantic_role: &str,
) -> bool {
    browser_fragment_is_actionable_goal_target(fragment, semantic_role)
        && (browser_fragment_has_action_locator(fragment)
            || fragment.contains(r#" dom_clickable="true""#))
}

pub(super) fn snapshot_focused_text_control_states(
    snapshot: &str,
) -> Vec<SnapshotAutocompleteControlState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || !fragment.contains(r#" focused="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotAutocompleteControlState {
            semantic_id,
            dom_id,
            selector,
            controls_dom_id,
            value,
            has_active_candidate: false,
        });
    }

    states
}

pub(super) fn snapshot_visible_text_control_states(
    snapshot: &str,
) -> Vec<SnapshotAutocompleteControlState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let active_descendant_dom_id =
            extract_browser_xml_attr(fragment, "active_descendant_dom_id")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotAutocompleteControlState {
            semantic_id,
            dom_id,
            selector,
            controls_dom_id,
            value,
            has_active_candidate: active_descendant_dom_id.is_some(),
        });
    }

    states
}

pub(super) fn snapshot_focused_autocomplete_control_state(
    snapshot: &str,
) -> Option<SnapshotAutocompleteControlState> {
    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || !fragment.contains(r#" focused="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let autocomplete = extract_browser_xml_attr(fragment, "autocomplete")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let active_descendant_dom_id =
            extract_browser_xml_attr(fragment, "active_descendant_dom_id")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty());
        if autocomplete.is_none() && controls_dom_id.is_none() && active_descendant_dom_id.is_none()
        {
            continue;
        }

        let semantic_id = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())?;
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        return Some(SnapshotAutocompleteControlState {
            semantic_id,
            dom_id,
            selector,
            controls_dom_id,
            value,
            has_active_candidate: active_descendant_dom_id.is_some(),
        });
    }

    None
}

fn selector_references_dom_id(selector: &str, dom_id: &str) -> bool {
    selector.contains(&format!("#{dom_id}"))
        || selector.contains(&format!(r#"[id="{dom_id}"]"#))
        || selector.contains(&format!(r#"[id='{dom_id}']"#))
}

fn normalized_control_locator(value: &str) -> String {
    let trimmed = compact_ws_for_prompt(value).trim().to_string();
    if let Some(token) = trimmed.strip_prefix('#') {
        return token.to_string();
    }
    if let Some(token) = trimmed
        .strip_prefix("[id=\"")
        .and_then(|value| value.strip_suffix("\"]"))
    {
        return token.to_string();
    }
    if let Some(token) = trimmed
        .strip_prefix("[id='")
        .and_then(|value| value.strip_suffix("']"))
    {
        return token.to_string();
    }
    trimmed
}

pub(super) fn autocomplete_control_locator_matches(
    selector: Option<&str>,
    dom_id: Option<&str>,
    control: &SnapshotAutocompleteControlState,
) -> bool {
    if dom_id
        .zip(control.dom_id.as_deref())
        .is_some_and(|(left, right)| left == right)
    {
        return true;
    }

    let control_selector = control
        .selector
        .as_deref()
        .map(normalized_control_locator)
        .unwrap_or_default();
    selector.is_some_and(|selector| normalized_control_locator(selector) == control_selector)
        || selector
            .zip(control.dom_id.as_deref())
            .is_some_and(|(selector, dom_id)| {
                normalized_control_locator(selector) == normalized_control_locator(dom_id)
            })
}

fn snapshot_visible_autocomplete_popup(
    snapshot: &str,
    control: &SnapshotAutocompleteControlState,
) -> bool {
    let Some(controls_dom_id) = control.controls_dom_id.as_deref() else {
        return false;
    };

    snapshot.split('<').any(|fragment| {
        if fragment.contains(r#" visible="false""#) || fragment.contains(r#" omitted="true""#) {
            return false;
        }

        let semantic_id = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
        if semantic_id.as_deref() == Some(control.semantic_id.as_str()) {
            return false;
        }

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
        if dom_id.as_deref() == Some(controls_dom_id) {
            return true;
        }

        extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .is_some_and(|selector| selector_references_dom_id(&selector, controls_dom_id))
    })
}

fn recent_typed_autocomplete_value_for_control(
    history: &[ChatMessage],
    control: &SnapshotAutocompleteControlState,
) -> Option<String> {
    history.iter().rev().find_map(|message| {
        let state = autocomplete_tool_state(message)?;
        if !matches!(state.action, RecentAutocompleteAction::Typed) {
            return None;
        }

        let matches_control = autocomplete_control_locator_matches(
            state.selector.as_deref(),
            state.dom_id.as_deref(),
            control,
        );
        matches_control.then_some(state.value).flatten()
    })
}

pub(super) fn autocomplete_value_looks_committed(
    history: &[ChatMessage],
    control: &SnapshotAutocompleteControlState,
) -> bool {
    let Some(current_value) = control.value.as_deref() else {
        return false;
    };
    let Some(typed_value) = recent_typed_autocomplete_value_for_control(history, control) else {
        return false;
    };

    let current_norm = normalized_exact_target_text(current_value);
    let typed_norm = normalized_exact_target_text(&typed_value);
    !current_norm.is_empty()
        && !typed_norm.is_empty()
        && current_norm != typed_norm
        && current_norm.contains(&typed_norm)
}

fn snapshot_visible_autocomplete_suggestion_target(
    snapshot: &str,
    control: &SnapshotAutocompleteControlState,
) -> Option<SnapshotVisibleTargetState> {
    let normalized_value = control
        .value
        .as_deref()
        .map(normalized_exact_target_text)
        .filter(|value| !value.is_empty())?;

    let mut best_match: Option<((u8, u8, u8, u8, u8, usize), SnapshotVisibleTargetState)> = None;
    let mut best_match_is_popup_container = false;
    let mut unnamed_popup_leaf_match: Option<(
        (u8, u8, u8, u8, usize),
        SnapshotVisibleTargetState,
    )> = None;
    let mut unnamed_popup_leaf_count = 0usize;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment)
            .map(str::to_string)
            .filter(|role| !role.is_empty())
        else {
            continue;
        };
        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if semantic_id == control.semantic_id {
            continue;
        }

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        let class_name = extract_browser_xml_attr(fragment, "class_name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let autocomplete_like = class_name.contains("autocomplete")
            || class_name.contains("ui-menu")
            || class_name.contains("ui-menu-item")
            || matches!(semantic_role.as_str(), "option" | "menuitem" | "listitem");
        let actionable = browser_fragment_is_actionable_goal_target(fragment, &semantic_role);
        if !autocomplete_like && !actionable {
            continue;
        }
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let omitted = fragment.contains(r#" omitted="true""#);
        if omitted
            && !(autocomplete_like
                && browser_fragment_allows_omitted_action_target(fragment, &semantic_role))
        {
            continue;
        }

        let normalized_name = name
            .as_deref()
            .map(normalized_exact_target_text)
            .unwrap_or_default();
        let is_name_match = !normalized_name.is_empty()
            && (normalized_name.contains(&normalized_value)
                || normalized_value.contains(&normalized_name));
        let popup_leaf_without_name = name.is_none()
            && control
                .controls_dom_id
                .as_deref()
                .is_some_and(|controls_dom_id| {
                    selector
                        .as_deref()
                        .is_some_and(|value| selector_references_dom_id(value, controls_dom_id))
                })
            && (class_name.contains("ui-menu-item")
                || matches!(semantic_role.as_str(), "option" | "menuitem" | "listitem"));
        let popup_container_match = control
            .controls_dom_id
            .as_deref()
            .zip(dom_id.as_deref())
            .is_some_and(|(controls_dom_id, candidate_dom_id)| {
                controls_dom_id == candidate_dom_id && !class_name.contains("ui-menu-item")
            });
        if !is_name_match && !popup_leaf_without_name {
            continue;
        }

        let candidate_name = name
            .or_else(|| control.value.as_deref().map(str::to_string))
            .unwrap_or_else(|| semantic_id.clone());
        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: candidate_name,
            semantic_role: semantic_role.clone(),
            already_active: browser_fragment_stateful_match_hint(fragment),
        };

        if popup_leaf_without_name {
            unnamed_popup_leaf_count += 1;
            let candidate_rank = (
                u8::from(!omitted),
                u8::from(class_name.contains("ui-menu-item-wrapper")),
                u8::from(class_name.contains("ui-menu-item") || class_name.contains("option")),
                u8::from(actionable),
                candidate.name.chars().count(),
            );
            match unnamed_popup_leaf_match.as_ref() {
                Some((best_rank, best_candidate))
                    if *best_rank > candidate_rank
                        || (*best_rank == candidate_rank
                            && best_candidate.semantic_id <= candidate.semantic_id) => {}
                _ => unnamed_popup_leaf_match = Some((candidate_rank, candidate)),
            }
            continue;
        }

        let candidate_rank = (
            u8::from(!omitted),
            u8::from(class_name.contains("ui-menu-item-wrapper")),
            u8::from(class_name.contains("ui-menu-item") || class_name.contains("option")),
            u8::from(actionable),
            visible_target_role_priority(&semantic_role),
            candidate.name.chars().count(),
        );

        match best_match.as_ref() {
            Some((best_rank, best_candidate))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank
                        && best_candidate.semantic_id <= candidate.semantic_id) => {}
            _ => {
                best_match = Some((candidate_rank, candidate));
                best_match_is_popup_container = popup_container_match;
            }
        }
    }

    if unnamed_popup_leaf_count == 1 && best_match_is_popup_container {
        return unnamed_popup_leaf_match.map(|(_, candidate)| candidate);
    }

    best_match.map(|(_, candidate)| candidate).or_else(|| {
        (unnamed_popup_leaf_count == 1)
            .then(|| unnamed_popup_leaf_match.map(|(_, candidate)| candidate))
            .flatten()
    })
}

pub(super) fn autocomplete_tool_state(
    message: &ChatMessage,
) -> Option<RecentAutocompleteToolState> {
    if message.role != "tool" {
        return None;
    }

    let payload = parse_json_value_from_message(&message.content)?;
    let (action, action_state) = if let Some(typed) = payload.get("typed") {
        (RecentAutocompleteAction::Typed, typed)
    } else {
        let key = payload
            .get("key")?
            .get("key")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty())?;
        (RecentAutocompleteAction::Key(key), payload.get("key")?)
    };
    let autocomplete = action_state.get("autocomplete")?;
    if autocomplete.is_null() {
        return None;
    }

    let dom_id = action_state
        .get("dom_id")
        .and_then(Value::as_str)
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty());
    let selector = action_state
        .get("selector")
        .and_then(Value::as_str)
        .or_else(|| {
            action_state
                .get("resolved_selector")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            action_state
                .get("requested_selector")
                .and_then(Value::as_str)
        })
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty());
    let value = action_state
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| action_state.get("text").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty());
    let has_active_candidate = autocomplete
        .get("active_descendant_dom_id")
        .and_then(Value::as_str)
        .map(compact_ws_for_prompt)
        .is_some_and(|value| !value.is_empty());

    Some(RecentAutocompleteToolState {
        action,
        dom_id,
        selector,
        value,
        has_active_candidate,
    })
}

pub(super) fn recent_autocomplete_tool_state(
    history: &[ChatMessage],
) -> Option<RecentAutocompleteToolState> {
    history.iter().rev().find_map(autocomplete_tool_state)
}

pub(super) fn recent_find_text_state(history: &[ChatMessage]) -> Option<RecentFindTextState> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let payload = parse_json_value_from_message(&message.content)?;
        let query = payload
            .get("query")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty())?;
        let result = payload.get("result")?;
        if !result
            .get("found")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return None;
        }

        let first_snippet = result
            .get("first_snippet")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty());

        Some(RecentFindTextState {
            query,
            first_snippet,
        })
    })
}

pub(super) fn autocomplete_hint_signals_single_result(hint: &str) -> bool {
    let lower = hint.to_ascii_lowercase();
    lower.contains("1 result is available")
        || lower.contains("1 suggestion is available")
        || lower.contains("1 option is available")
}

pub(super) fn autocomplete_follow_up_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let recent_autocomplete = recent_autocomplete_tool_state(history);
    let control = snapshot_focused_autocomplete_control_state(snapshot).or_else(|| {
        let recent = recent_autocomplete.as_ref()?;
        snapshot_focused_text_control_states(snapshot)
            .into_iter()
            .find(|control| {
                recent
                    .dom_id
                    .as_deref()
                    .zip(control.dom_id.as_deref())
                    .is_some_and(|(recent, current)| recent == current)
                    || recent
                        .selector
                        .as_deref()
                        .zip(control.selector.as_deref())
                        .is_some_and(|(recent, current)| recent == current)
                    || recent
                        .value
                        .as_deref()
                        .zip(control.value.as_deref())
                        .is_some_and(|(recent, current)| recent == current)
            })
    })?;
    let hints = extract_assistive_browser_hints(snapshot);
    let hint_has_single_result = hints
        .iter()
        .any(|hint| autocomplete_hint_signals_single_result(hint));
    let value = control.value.as_deref().map(compact_ws_for_prompt);
    let hint_mentions_value = value.as_deref().is_some_and(|value| {
        hints
            .iter()
            .any(|hint| contains_ascii_case_insensitive(hint, value))
    });
    let value_clause = value
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| format!(" with `{value}` in the field"))
        .unwrap_or_default();
    let visible_suggestion = snapshot_visible_autocomplete_suggestion_target(snapshot, &control);
    let visible_popup = control.has_active_candidate
        || visible_suggestion.is_some()
        || snapshot_visible_autocomplete_popup(snapshot, &control);
    let recent_navigation_highlighted = recent_autocomplete.as_ref().is_some_and(|state| {
        state.has_active_candidate
            || matches!(
                state.action,
                RecentAutocompleteAction::Key(ref key)
                    if key.eq_ignore_ascii_case("ArrowDown")
                        || key.eq_ignore_ascii_case("ArrowUp")
            )
    });
    let recent_enter_failed = recent_autocomplete.as_ref().is_some_and(|state| {
        matches!(
            state.action,
            RecentAutocompleteAction::Key(ref key) if key.eq_ignore_ascii_case("Enter")
        )
    });
    if !visible_popup && autocomplete_value_looks_committed(history, &control) {
        return None;
    }
    let highlighted_candidate = control.has_active_candidate || recent_navigation_highlighted;
    let guided_arrowdown_then_enter = hint_has_single_result || hint_mentions_value;

    if let Some(submit_id) = recent_successful_click_semantic_id(history)
        .filter(|semantic_id| semantic_id_is_submit_like(semantic_id))
        .filter(|semantic_id| {
            recent_successful_click_has_post_action_observation(
                history,
                semantic_id,
                current_snapshot,
            )
        })
    {
        if let Some(suggestion) = visible_suggestion.as_ref() {
            return Some(format!(
                "A recent `{submit_id}` click left autocomplete unresolved on `{}`{value_clause}. That submit does not finish the task. The visible suggestion `{}` already matches the field. Use `browser__click_element` on `{}` now to commit it in one step before submitting again.",
                control.semantic_id,
                suggestion.name,
                suggestion.semantic_id,
            ));
        }

        if highlighted_candidate {
            return Some(format!(
                "A recent `{submit_id}` click left autocomplete unresolved on `{}`{value_clause}. That submit does not finish the task. Use `browser__key` `Enter` now to commit the highlighted suggestion, then verify the widget is gone before submitting again.",
                control.semantic_id
            ));
        }

        if recent_enter_failed || guided_arrowdown_then_enter {
            return Some(format!(
                "A recent `{submit_id}` click left autocomplete unresolved on `{}`{value_clause}. That submit does not finish the task. Use `browser__key` `ArrowDown` now to highlight the suggestion, then `browser__key` `Enter` to commit it before submitting again.",
                control.semantic_id
            ));
        }

        return Some(format!(
            "A recent `{submit_id}` click left autocomplete unresolved on `{}`. That submit does not finish the task. Use `browser__key` with `ArrowDown` or `ArrowUp` to ground the intended suggestion, then `browser__key` `Enter` to commit it before submitting again.",
            control.semantic_id
        ));
    }

    if let Some(suggestion) = visible_suggestion.as_ref() {
        if recent_enter_failed {
            return Some(format!(
                "A recent `Enter` key left autocomplete unresolved on `{}`{value_clause}. That key did not commit the suggestion. The visible suggestion `{}` already matches the field. Use `browser__click_element` on `{}` now to commit it in one step.",
                control.semantic_id,
                suggestion.name,
                suggestion.semantic_id,
            ));
        }

        return Some(format!(
            "Autocomplete is still open on `{}`{value_clause}. The visible suggestion `{}` already matches it. Use `browser__click_element` on `{}` now to commit it in one step. Do not spend the next step on `ArrowDown`, `Enter`, or another `browser__snapshot`.",
            control.semantic_id,
            suggestion.name,
            suggestion.semantic_id,
        ));
    }

    if recent_enter_failed {
        return Some(format!(
            "A recent `Enter` key left autocomplete unresolved on `{}`{value_clause}. That key did not commit the suggestion. Do not submit or finish yet. Use `browser__key` `ArrowDown` now to highlight it, then `browser__key` `Enter` to commit it before submitting.",
            control.semantic_id
        ));
    }

    if highlighted_candidate {
        return Some(format!(
            "Autocomplete is still open on `{}`{value_clause}. Do not submit or finish yet. Use `browser__key` `Enter` now to commit the highlighted suggestion, then verify the widget is gone before submitting.",
            control.semantic_id
        ));
    }

    if guided_arrowdown_then_enter {
        return Some(format!(
            "Autocomplete is still open on `{}`{value_clause}. The suggestion is not committed yet. Do not submit or finish. Use `browser__key` `ArrowDown` now to highlight it, then `browser__key` `Enter` to commit it before submitting.",
            control.semantic_id
        ));
    }

    Some(format!(
        "Autocomplete is still open on `{}`. Do not submit or finish yet. Use `browser__key` with `ArrowDown` or `ArrowUp` to ground the intended suggestion, then `browser__key` `Enter` to commit it.",
        control.semantic_id
    ))
}
