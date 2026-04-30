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
    let rect = browser_fragment_rect(fragment)?;
    Some(rect.width * rect.height)
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
    if browser_fragment_is_actionable_goal_target(fragment, tag_name) || has_grounded_geometry {
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
        .is_some_and(browser_fragment_is_start_gate_label)
    {
        score = score.saturating_add(18);
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

fn parse_browser_point_list(value: &str) -> Vec<(f64, f64)> {
    value
        .split('|')
        .filter_map(|point| {
            let (x, y) = point.split_once(',')?;
            Some((x.parse::<f64>().ok()?, y.parse::<f64>().ok()?))
        })
        .collect()
}

fn browser_fragment_summary(_snapshot: &str, fragment: &str) -> Option<(String, String)> {
    let id = extract_browser_xml_attr(fragment, "id")?;
    let tag_name = browser_fragment_tag_name(fragment)?;
    let som_id = extract_browser_xml_attr(fragment, "som_id")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());

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
    if let Some(som_id) = som_id {
        summary.push_str(&format!(" som_id={som_id}"));
    }
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

    Some((id, summary))
}

pub(super) fn browser_fragment_priority_summary(
    snapshot: &str,
    fragment: &str,
) -> Option<(String, u8, String)> {
    let has_specific_grounded_geometry = snapshot_has_specific_grounded_geometry(snapshot);
    if has_specific_grounded_geometry && browser_fragment_is_surface_wrapper(fragment) {
        return None;
    }

    let tag_name = browser_fragment_tag_name(fragment)?;
    let mut score = browser_fragment_priority_score(fragment, tag_name)?;
    if has_specific_grounded_geometry
        && !fragment.contains(" shape_kind=\"")
        && matches!(
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
        )
    {
        score = score.saturating_sub(6);
    }
    if (tag_name == "svg"
        || extract_browser_xml_attr(fragment, "tag_name").as_deref() == Some("svg"))
        && !fragment.contains(" shape_kind=\"")
        && snapshot
            .split('<')
            .filter(|candidate| !candidate.is_empty() && *candidate != fragment)
            .any(|candidate| {
                candidate.contains(" shape_kind=\"")
                    && candidate.contains(" center_x=\"")
                    && extract_browser_xml_attr(candidate, "tag_name").as_deref() != Some("svg")
            })
    {
        score = score.saturating_sub(12);
    }
    let (id, summary) = browser_fragment_summary(snapshot, fragment)?;
    Some((id, score, summary))
}

fn snapshot_has_specific_grounded_geometry(snapshot: &str) -> bool {
    snapshot.split('<').any(|fragment| {
        !fragment.is_empty()
            && fragment.contains(" shape_kind=\"")
            && !matches!(
                extract_browser_xml_attr(fragment, "tag_name").as_deref(),
                Some("canvas" | "svg")
            )
    })
}

fn browser_fragment_is_surface_wrapper(fragment: &str) -> bool {
    if fragment.contains(" shape_kind=\"") {
        return false;
    }

    let tag_name = extract_browser_xml_attr(fragment, "tag_name")
        .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase());
    if matches!(tag_name.as_deref(), Some("canvas" | "svg")) {
        return true;
    }

    // Some DOM fallback nodes arrive without a preserved `tag_name`; keep surface detection
    // grounded in standard rendering-surface vocabulary rather than benchmark-local ids.
    ["name", "dom_id", "selector"].iter().any(|attr| {
        extract_browser_xml_attr(fragment, attr)
            .map(|value| decode_browser_xml_text(&value).to_ascii_lowercase())
            .is_some_and(|value| value.contains("canvas") || value.contains("svg"))
    })
}

pub(super) fn priority_target_looks_like_surface_wrapper(summary: &str) -> bool {
    let lower = summary.to_ascii_lowercase();
    !lower.contains(" shape_kind=") && (lower.contains("canvas") || lower.contains("svg"))
}

fn prioritized_browser_target_entries(snapshot: &str) -> Vec<(u8, usize, String)> {
    let mut seen_ids = HashSet::new();
    let mut targets = Vec::new();
    let mut order = 0usize;
    let start_gate_covered_ids = snapshot_visible_start_gate_covered_semantic_ids(snapshot);

    if let Some((semantic_id, summary)) = snapshot_visible_start_gate_priority_summary(snapshot) {
        seen_ids.insert(semantic_id);
        targets.push((u8::MAX, order, summary));
        order += 1;
    }

    for fragment in snapshot.split('<') {
        let Some((id, score, summary)) = browser_fragment_priority_summary(snapshot, fragment)
        else {
            continue;
        };
        if start_gate_covered_ids.contains(&id) {
            continue;
        }
        if !seen_ids.insert(id) {
            continue;
        }
        targets.push((score, order, summary));
        order += 1;
    }

    for (id, score, summary) in extract_compact_priority_browser_targets(snapshot) {
        if start_gate_covered_ids.contains(&id) {
            continue;
        }
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

    let parsed = summary_block
        .split('|')
        .filter_map(|entry| {
            let summary = compact_ws_for_prompt(&decode_browser_xml_text(entry.trim()));
            let semantic_id = priority_target_semantic_id(&summary)?.to_string();
            let score = compact_priority_target_score(&summary)?;
            Some((semantic_id, score, summary))
        })
        .collect::<Vec<_>>();

    let has_specific_grounded_geometry = snapshot_has_specific_grounded_geometry(snapshot)
        || parsed.iter().any(|(_, _, summary)| {
            summary.contains(" shape_kind=")
                && !summary.contains(" name=svg grid object")
                && !summary.contains(" name=click canvas")
        });

    parsed
        .into_iter()
        .filter(|(semantic_id, _, summary)| {
            if !has_specific_grounded_geometry {
                return true;
            }

            let fragment = snapshot.split('<').find(|fragment| {
                extract_browser_xml_attr(fragment, "id")
                    .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                    .as_deref()
                    == Some(semantic_id.as_str())
            });
            let surface_wrapper = fragment.is_some_and(browser_fragment_is_surface_wrapper)
                || (summary.contains(" name=svg grid object")
                    || summary.contains(" name=click canvas"))
                    && !summary.contains(" shape_kind=");

            !surface_wrapper
        })
        .map(|(semantic_id, mut score, summary)| {
            if has_specific_grounded_geometry
                && !summary.contains(" shape_kind=")
                && matches!(
                    priority_target_tag(&summary),
                    Some(
                        "button"
                            | "link"
                            | "textbox"
                            | "combobox"
                            | "checkbox"
                            | "radio"
                            | "searchbox"
                            | "menuitem"
                            | "option"
                    )
                )
            {
                score = score.saturating_sub(6);
            }
            (semantic_id, score, summary)
        })
        .collect()
}

pub(super) fn extract_priority_browser_targets(snapshot: &str, max_targets: usize) -> Vec<String> {
    if let Some((_, summary)) = snapshot_visible_start_gate_priority_summary(snapshot) {
        return vec![summary];
    }

    let has_specific_grounded_geometry = snapshot_has_specific_grounded_geometry(snapshot);
    prioritized_browser_target_entries(snapshot)
        .into_iter()
        .filter(|(_, _, summary)| {
            !has_specific_grounded_geometry || !priority_target_looks_like_surface_wrapper(summary)
        })
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
