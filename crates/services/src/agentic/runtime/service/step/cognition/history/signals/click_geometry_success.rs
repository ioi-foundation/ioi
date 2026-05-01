fn click_effect_text_from_message(message: &ChatMessage) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    parse_json_value_from_message(&message.content).and_then(|payload| {
        payload
            .get("click")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn verify_payload_from_text(text: &str) -> Option<Value> {
    if let Some(payload) = parse_json_value_from_message(text) {
        if payload.get("postcondition").is_some() || payload.get("postcondition_met").is_some() {
            return Some(payload);
        }
    }

    let compact = compact_ws_for_prompt(text);
    let (_, verify_text) = compact.split_once(" verify=")?;
    serde_json::from_str::<Value>(verify_text).ok()
}

pub(super) fn dropdown_success_signal_for_message(
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<String> {
    let (dropdown_id, selected_label) = dropdown_selection_details(message)?;

    if let Some(snapshot) = snapshot {
        if !snapshot_mentions_dropdown_locator(snapshot, &dropdown_id) {
            return None;
        }
    }

    let mut signal = format!(
        "A recent browser dropdown selection already succeeded: `{}` is now `{}`. Do not select the same dropdown again.",
        dropdown_id, selected_label
    );

    if let Some(snapshot) = snapshot {
        let next_controls = next_visible_follow_up_controls(snapshot, &[dropdown_id.as_str()]);
        if !next_controls.is_empty() {
            signal.push_str(&format!(
                " Continue with the next required action on another visible control such as `{}`.",
                next_controls.join("`, `")
            ));
        } else {
            signal.push_str(" Continue with the next required action on another visible control.");
        }
    } else {
        signal.push_str(" Continue with the next required action.");
    }

    Some(signal)
}

fn tool_message_verify_payload(message: &ChatMessage) -> Option<Value> {
    verify_payload_from_text(&message.content).or_else(|| {
        click_effect_text_from_message(message).and_then(|text| verify_payload_from_text(&text))
    })
}

fn text_has_postcondition_success(text: &str) -> bool {
    let compact = compact_ws_for_prompt(text);
    (compact.contains("\"postcondition\":{") && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true")
}

fn tool_message_has_postcondition_success(message: &ChatMessage) -> bool {
    if message.role != "tool" {
        return false;
    }

    text_has_postcondition_success(&message.content)
        || click_effect_text_from_message(message)
            .as_deref()
            .is_some_and(text_has_postcondition_success)
}

fn tool_message_is_click_success(message: &ChatMessage) -> bool {
    tool_message_has_postcondition_success(message)
        && clicked_element_semantic_id(message).is_some()
}

fn synthetic_click_target_semantic_id(message: &ChatMessage) -> Option<String> {
    let payload = tool_message_verify_payload(message)?;
    for field in ["post_target", "pre_target"] {
        let semantic_id = payload
            .get(field)
            .and_then(|value| value.get("semantic_id"))
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty());
        if semantic_id.is_some() {
            return semantic_id;
        }
    }
    None
}

fn synthetic_click_target_tag_name(message: &ChatMessage) -> Option<String> {
    let payload = tool_message_verify_payload(message)?;
    for field in ["post_target", "pre_target"] {
        let tag_name = payload
            .get(field)
            .and_then(|value| value.get("tag_name"))
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty());
        if tag_name.is_some() {
            return tag_name;
        }
    }
    None
}

fn click_changed_geometry(
    history: &[ChatMessage],
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<(String, String)> {
    let semantic_id = clicked_element_semantic_id(message)?;
    let current_snapshot = snapshot?;
    let current_summary = snapshot_priority_target_summary(current_snapshot, &semantic_id);
    let previous_summary = browser_snapshot_before_message(history, message)
        .and_then(|snapshot| snapshot_priority_target_summary(snapshot, &semantic_id));

    if !current_summary
        .as_deref()
        .is_some_and(summary_looks_geometric)
        && !previous_summary
            .as_deref()
            .is_some_and(summary_looks_geometric)
    {
        return None;
    }

    current_summary
        .or(previous_summary)
        .map(|summary| (semantic_id, summary))
}

fn summary_looks_geometric(summary: &str) -> bool {
    summary.contains(" shape_kind=")
        || summary.contains(" geometry_role=")
        || summary.contains(" center=")
        || summary.contains(" line=")
}

fn tag_name_looks_geometric(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "circle" | "ellipse" | "line" | "path" | "polygon" | "polyline" | "rect"
    )
}

fn snapshot_priority_target_summary(snapshot: &str, semantic_id: &str) -> Option<String> {
    extract_priority_browser_targets(snapshot, 16)
        .into_iter()
        .find(|summary| priority_target_semantic_id(summary) == Some(semantic_id))
}

fn target_summary_attr(summary: &str, key: &str) -> Option<String> {
    let marker = format!("{key}=");
    let (_, remainder) = summary.split_once(&marker)?;
    let value = remainder.split_whitespace().next()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn compact_geometry_signal_summary(summary: &str) -> String {
    for key in [
        "line",
        "center",
        "connected_points",
        "line_angle",
        "connected_line_angles",
        "angle_mid",
        "angle_span",
        "geometry_role",
    ] {
        if let Some(value) = target_summary_attr(summary, key) {
            return format!("{key}={value}");
        }
    }
    safe_truncate(summary, 56)
}

fn newly_revealed_priority_targets(
    current_snapshot: &str,
    previous_snapshot: Option<&str>,
    excluded_ids: &[&str],
) -> Vec<String> {
    let excluded = excluded_ids.iter().copied().collect::<HashSet<_>>();
    let previous_ids = previous_snapshot
        .map(|snapshot| {
            extract_priority_browser_targets(snapshot, 16)
                .into_iter()
                .filter_map(|summary| priority_target_semantic_id(&summary).map(str::to_string))
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    let mut revealed = extract_priority_browser_targets(current_snapshot, 16)
        .into_iter()
        .filter_map(|summary| {
            let semantic_id = priority_target_semantic_id(&summary)?.to_string();
            if excluded.contains(semantic_id.as_str())
                || previous_ids.contains(semantic_id.as_str())
                || priority_target_summary_is_history_like(&summary)
            {
                return None;
            }
            Some(semantic_id)
        })
        .collect::<Vec<_>>();

    if revealed.is_empty() && previous_snapshot.is_none() {
        revealed = extract_priority_browser_targets(current_snapshot, 16)
            .into_iter()
            .filter_map(|summary| {
                let semantic_id = priority_target_semantic_id(&summary)?.to_string();
                if excluded.contains(semantic_id.as_str())
                    || priority_target_summary_is_history_like(&summary)
                {
                    return None;
                }
                Some(semantic_id)
            })
            .collect();
    }

    revealed.truncate(3);
    revealed
}

fn click_opened_new_surface_success_signal(
    history: &[ChatMessage],
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if !((compact.contains("\"postcondition\":{") && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true"))
        || !compact.contains("Clicked element")
    {
        return None;
    }

    let current_snapshot = snapshot?;
    if select_submit_progress_pending_signal(history, Some(current_snapshot)).is_some()
        || visible_target_click_pending_signal(history, Some(current_snapshot)).is_some()
    {
        return None;
    }

    let clicked_id = clicked_element_semantic_id(message)?;
    if snapshot_priority_target_summary(current_snapshot, &clicked_id).is_some() {
        return None;
    }

    let revealed_targets = newly_revealed_priority_targets(
        current_snapshot,
        browser_snapshot_before_message(history, message),
        &[clicked_id.as_str()],
    );
    if revealed_targets.is_empty() {
        return None;
    }

    Some(format!(
        "A recent browser interaction exposed a different task surface. Continue with the newly visible targets such as `{}`. Do not repeat `{}`. Do not spend the next step on another `browser__inspect` just because the page opened or changed.",
        revealed_targets.join("`, `"),
        clicked_id
    ))
}

fn browser_snapshot_before_message<'a>(
    history: &'a [ChatMessage],
    message: &ChatMessage,
) -> Option<&'a str> {
    history
        .iter()
        .rev()
        .find(|candidate| candidate.timestamp < message.timestamp)
        .and_then(browser_snapshot_payload)
}

fn synthetic_click_changed_geometry(
    _history: &[ChatMessage],
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<(String, String)> {
    let semantic_id = synthetic_click_target_semantic_id(message)?;
    let summary = snapshot
        .and_then(|snapshot| snapshot_priority_target_summary(snapshot, &semantic_id))
        .unwrap_or_default();
    let tag_name = synthetic_click_target_tag_name(message).unwrap_or_default();
    if !summary_looks_geometric(&summary) && !tag_name_looks_geometric(tag_name.as_str()) {
        return None;
    }

    Some((semantic_id, summary))
}

fn geometry_progress_target_for_message(
    history: &[ChatMessage],
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<(String, String)> {
    if tool_message_is_synthetic_click_success(message) {
        return synthetic_click_changed_geometry(history, message, snapshot);
    }
    if tool_message_is_click_success(message) {
        return click_changed_geometry(history, message, snapshot);
    }
    None
}

fn geometry_progress_success_signal_for_message(
    history: &[ChatMessage],
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<String> {
    let (semantic_id, summary) = geometry_progress_target_for_message(history, message, snapshot)?;
    let synthetic_click = tool_message_is_synthetic_click_success(message);
    let mut signal = if synthetic_click {
        "Recent synthetic click changed grounded geometry.".to_string()
    } else {
        "Recent grounded geometry click changed grounded geometry.".to_string()
    };
    let compact_summary = compact_geometry_signal_summary(&summary);

    if !compact_summary.is_empty() {
        signal.push_str(&format!(
            " Updated grounded target `{semantic_id}`: `{compact_summary}`."
        ));
    }

    if let Some(current_snapshot) = snapshot {
        let next_controls = next_visible_follow_up_controls(current_snapshot, &[]);
        if !next_controls.is_empty() {
            signal.push_str(&format!(
                " Visible controls now include `{}`.",
                next_controls.join("`, `")
            ));
            signal.push_str(
                " If the updated browser observation already shows the intended change, use one of those visible controls next.",
            );
        }
        signal.push_str(
            " Re-check current browser observation before deciding whether to use a visible control, take another grounded geometry action, or finish.",
        );
    } else {
        signal.push_str(" Re-check current browser observation before choosing another action.");
    }

    if !semantic_id.is_empty() && compact_summary.is_empty() {
        signal.push_str(&format!(" Follow-up grounded target is `{semantic_id}`."));
    }
    if synthetic_click {
        signal.push_str(" Do not reuse the prior coordinate blindly.");
    } else {
        signal.push_str(" Do not repeat the same grounded geometry target blindly.");
    }

    Some(signal)
}
