pub(super) fn next_visible_follow_up_controls(
    snapshot: &str,
    excluded_ids: &[&str],
) -> Vec<String> {
    let excluded = excluded_ids.iter().copied().collect::<HashSet<_>>();
    let remaining_targets = extract_priority_browser_targets(snapshot, 8)
        .into_iter()
        .filter_map(|summary| {
            let semantic_id = priority_target_semantic_id(&summary)?;
            (!excluded.contains(semantic_id)).then_some(summary)
        })
        .collect::<Vec<_>>();
    let mut next_controls = Vec::new();

    for summary in &remaining_targets {
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if !priority_target_summary_is_actionable(summary)
            || priority_target_looks_like_surface_wrapper(summary)
            || !priority_target_summary_is_reusable_navigation(summary)
            || priority_target_summary_is_history_like(summary)
        {
            continue;
        }
        push_unique_control(&mut next_controls, semantic_id);
        if next_controls.len() == 3 {
            return next_controls;
        }
    }

    for summary in &remaining_targets {
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if !priority_target_summary_is_actionable(summary)
            || priority_target_looks_like_surface_wrapper(summary)
            || priority_target_summary_is_history_like(summary)
            || priority_target_summary_is_reusable_navigation(summary)
            || priority_target_tag(summary) == Some("link")
        {
            continue;
        }
        push_unique_control(&mut next_controls, semantic_id);
        if next_controls.len() == 3 {
            return next_controls;
        }
    }

    for summary in &remaining_targets {
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if !priority_target_summary_is_actionable(summary)
            || priority_target_looks_like_surface_wrapper(summary)
            || priority_target_summary_is_history_like(summary)
            || priority_target_summary_is_reusable_navigation(summary)
            || priority_target_tag(summary) != Some("link")
        {
            continue;
        }
        push_unique_control(&mut next_controls, semantic_id);
        if next_controls.len() == 3 {
            return next_controls;
        }
    }

    next_controls
}

fn snapshot_priority_summary_for_visible_semantic_id(
    snapshot: &str,
    semantic_id: &str,
) -> Option<String> {
    extract_priority_browser_targets(snapshot, 16)
        .into_iter()
        .find(|summary| priority_target_semantic_id(summary) == Some(semantic_id))
}

fn priority_target_summary_is_actionable(summary: &str) -> bool {
    matches!(
        priority_target_tag(summary),
        Some(
            "button"
                | "link"
                | "textbox"
                | "searchbox"
                | "combobox"
                | "checkbox"
                | "radio"
                | "option"
                | "tab"
        )
    ) || summary.contains(" dom_clickable=true")
}

fn priority_target_summary_is_history_like(summary: &str) -> bool {
    summary.contains("name=History")
}

fn priority_target_summary_is_reusable_navigation(summary: &str) -> bool {
    let Some(semantic_id) = priority_target_semantic_id(summary) else {
        return false;
    };
    let semantic_id_lower = semantic_id.to_ascii_lowercase();
    if semantic_id_lower.contains("prev") || semantic_id_lower.contains("next") {
        return true;
    }

    let summary_lower = summary.to_ascii_lowercase();
    summary_lower.contains("name=prev")
        || summary_lower.contains("name=next")
        || summary_lower.contains("name=previous")
        || summary_lower.contains("name=following")
}

pub(super) fn push_unique_control(controls: &mut Vec<String>, semantic_id: &str) {
    if controls.iter().any(|existing| existing == semantic_id) {
        return;
    }
    controls.push(semantic_id.to_string());
}

fn click_target_semantic_id_from_verify_payload(payload: &Value) -> Option<String> {
    for field in ["requested_target", "post_target", "pre_target"] {
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

    payload
        .get("id")
        .and_then(Value::as_str)
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())
}

fn click_attempt_target_semantic_id(message: &ChatMessage) -> Option<String> {
    clicked_element_semantic_id(message)
        .or_else(|| synthetic_click_target_semantic_id(message))
        .or_else(|| {
            tool_message_verify_payload(message)
                .and_then(|payload| click_target_semantic_id_from_verify_payload(&payload))
        })
}
