use super::*;

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
        "A recent browser interaction exposed a different task surface. Continue with the newly visible targets such as `{}`. Do not repeat `{}` or finish just because the page opened or changed.",
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

pub(super) fn autocomplete_commit_success_signal(
    history: &[ChatMessage],
    snapshot: &str,
) -> Option<String> {
    let recent_autocomplete = recent_autocomplete_tool_state(history)?;
    let control = snapshot_visible_text_control_states(snapshot)
        .into_iter()
        .find(|control| {
            autocomplete_control_locator_matches(
                recent_autocomplete.selector.as_deref(),
                recent_autocomplete.dom_id.as_deref(),
                control,
            )
        })
        .filter(|control| autocomplete_value_looks_committed(history, control))?;
    let committed_value = control.value.as_deref()?;

    let clicked_id = recent_successful_click_semantic_id(history)
        .filter(|semantic_id| !semantic_id_is_submit_like(semantic_id))
        .filter(|semantic_id| semantic_id != &control.semantic_id);
    let lingering_suggestion_id =
        snapshot_visible_autocomplete_suggestion_target(snapshot, &control)
            .map(|target| target.semantic_id);
    if clicked_id.as_deref().is_some_and(|semantic_id| {
        snapshot_contains_semantic_id(snapshot, semantic_id)
            && lingering_suggestion_id.as_deref() != Some(semantic_id)
    }) {
        return None;
    }

    let mut signal = if let Some(clicked_id) = clicked_id.as_deref() {
        format!(
            "A recent autocomplete selection already succeeded: `{}` is now `{}`. Do not click `{}` again or reopen `{}` unless the field changes.",
            control.semantic_id, committed_value, clicked_id, control.semantic_id
        )
    } else {
        format!(
            "A recent autocomplete selection already looks committed: `{}` is now `{}`. Do not type into or reopen `{}` again unless the field changes.",
            control.semantic_id, committed_value, control.semantic_id
        )
    };

    let mut excluded_ids = vec![control.semantic_id.as_str()];
    if let Some(clicked_id) = clicked_id.as_deref() {
        excluded_ids.push(clicked_id);
    }
    let mut next_controls = Vec::new();
    let has_unfilled_text_control = snapshot_visible_text_control_states(snapshot)
        .into_iter()
        .filter(|candidate| candidate.semantic_id != control.semantic_id)
        .filter(|candidate| {
            candidate
                .value
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        })
        .map(|candidate| candidate.semantic_id)
        .fold(false, |has_any, semantic_id| {
            push_unique_control(&mut next_controls, &semantic_id);
            has_any || !next_controls.is_empty()
        });
    let submit_id =
        snapshot_visible_submit_control_id(snapshot).filter(|id| id != &control.semantic_id);
    if !has_unfilled_text_control {
        if let Some(submit_id) = submit_id.as_deref() {
            push_unique_control(&mut next_controls, submit_id);
        }
    }
    for semantic_id in next_visible_follow_up_controls(snapshot, &excluded_ids) {
        push_unique_control(&mut next_controls, &semantic_id);
        if next_controls.len() == 3 {
            break;
        }
    }
    if has_unfilled_text_control {
        if let Some(submit_id) = submit_id.as_deref() {
            push_unique_control(&mut next_controls, submit_id);
        }
    }

    if !next_controls.is_empty() {
        signal.push_str(&format!(
            " Continue with the next required visible control such as `{}`.",
            next_controls.join("`, `")
        ));
    } else {
        signal.push_str(" Continue with the next required visible control.");
    }

    Some(signal)
}

fn snapshot_text_control_looks_filled_with_value(
    snapshot: &str,
    control: &SnapshotAutocompleteControlState,
    expected_value: Option<&str>,
) -> bool {
    if control
        .value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        return true;
    }

    let Some(expected_value) = expected_value else {
        return false;
    };
    let expected_value = normalized_exact_target_text(expected_value);
    if expected_value.is_empty() {
        return false;
    }

    snapshot_priority_summary_for_visible_semantic_id(snapshot, &control.semantic_id)
        .and_then(|summary| target_summary_attr(&summary, "name"))
        .is_some_and(|value| normalized_exact_target_text(&value) == expected_value)
}

fn recent_typed_text_follow_up_controls(
    history: &[ChatMessage],
    snapshot: &str,
) -> Option<Vec<String>> {
    let state = recent_typed_text_state(history)?;
    let controls = snapshot_visible_text_control_states(snapshot);
    let current_control = controls.iter().find(|control| {
        autocomplete_control_locator_matches(
            state.selector.as_deref(),
            state.dom_id.as_deref(),
            control,
        )
    })?;

    let mut excluded_ids = vec![current_control.semantic_id.as_str()];
    let mut next_controls = Vec::new();
    let mut has_unfilled_text_control = false;

    for control in &controls {
        if control.semantic_id == current_control.semantic_id {
            continue;
        }
        if snapshot_text_control_looks_filled_with_value(snapshot, control, state.value.as_deref())
        {
            continue;
        }
        push_unique_control(&mut next_controls, &control.semantic_id);
        excluded_ids.push(control.semantic_id.as_str());
        has_unfilled_text_control = true;
    }

    let submit_id = snapshot_visible_submit_control_id(snapshot)
        .filter(|id| id != &current_control.semantic_id);
    if !has_unfilled_text_control {
        if let Some(submit_id) = submit_id.as_deref() {
            push_unique_control(&mut next_controls, submit_id);
        }
    }

    for semantic_id in next_visible_follow_up_controls(snapshot, &excluded_ids) {
        push_unique_control(&mut next_controls, &semantic_id);
        if next_controls.len() == 3 {
            break;
        }
    }

    if has_unfilled_text_control {
        if let Some(submit_id) = submit_id.as_deref() {
            push_unique_control(&mut next_controls, submit_id);
        }
    }

    (!next_controls.is_empty()).then_some(next_controls)
}

fn recent_typed_text_follow_up_clause(history: &[ChatMessage], snapshot: &str) -> Option<String> {
    let next_controls = recent_typed_text_follow_up_controls(history, snapshot)?;
    let first_control = next_controls.first()?;
    if semantic_id_is_submit_like(first_control) {
        return Some(format!(" Use visible control `{first_control}` next."));
    }

    Some(format!(
        " Continue with the next required visible control such as `{}`.",
        next_controls.join("`, `")
    ))
}

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

pub(super) fn ranked_result_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let request = recent_requested_result_rank(history)?;
    let visible_results = snapshot_visible_result_links(snapshot);
    if visible_results.is_empty() {
        return None;
    }

    let instruction_token = snapshot_visible_exact_text_target(snapshot, &request.ordinal_text)
        .filter(|target| {
            matches!(
                target.semantic_role.as_str(),
                "generic" | "label" | "text" | "heading"
            )
        })?;
    let repeated_submit_clause = recent_successful_click_semantic_id(history)
        .filter(|semantic_id| {
            semantic_id_is_submit_like(semantic_id)
                || semantic_id.to_ascii_lowercase().contains("search")
        })
        .filter(|semantic_id| {
            recent_successful_click_has_post_action_observation(
                history,
                semantic_id,
                current_snapshot,
            )
        })
        .map(|semantic_id| {
            format!(" The search results are already updated, so do not use `{semantic_id}` again.")
        })
        .unwrap_or_default();
    let results_per_page = visible_results.len();
    let explicit_visible_ranks = visible_results
        .iter()
        .filter_map(snapshot_link_result_rank)
        .collect::<Vec<_>>();
    let (page_start_rank, page_end_rank) = if explicit_visible_ranks.is_empty() {
        let current_page = recent_clicked_pagination_page_number(history, snapshot).unwrap_or(1);
        let page_start_rank = current_page.saturating_sub(1) * results_per_page + 1;
        let page_end_rank = page_start_rank + results_per_page.saturating_sub(1);
        (page_start_rank, page_end_rank)
    } else {
        (
            *explicit_visible_ranks.iter().min()?,
            *explicit_visible_ranks.iter().max()?,
        )
    };

    if request.rank < page_start_rank || request.rank > page_end_rank {
        let target_page = (request.rank + results_per_page - 1) / results_per_page;
        let page_control = snapshot_pagination_link_for_page(snapshot, target_page)
            .or_else(|| snapshot_next_pagination_link(snapshot));
        let recent_instruction_click = recent_successful_click_semantic_id(history).as_deref()
            == Some(instruction_token.semantic_id.as_str());
        let page_hint = page_control
            .as_ref()
            .map(|link| {
                format!(
                    "Use `browser__click_element` on `{}` now to reach result {}.",
                    link.semantic_id, request.rank
                )
            })
            .unwrap_or_else(|| {
                format!(
                    "Use a visible pagination control now to reach result {}.",
                    request.rank
                )
            });
        let recovery_clause = if recent_instruction_click {
            " That recent click hit the instruction token, not a result, so do not finish."
        } else {
            ""
        };

        return Some(format!(
            "{} `{}` is the instruction token for `{}`, not a search result. Only {} actual result links are visible here (ranks {}-{}), so result {} is still off-screen. Do not click `{}`, do not use `browser__scroll`, and do not spend the next step on `browser__snapshot`.{}{}",
            page_hint,
            instruction_token.semantic_id,
            request.ordinal_text,
            results_per_page,
            page_start_rank,
            page_end_rank,
            request.rank,
            instruction_token.semantic_id,
            recovery_clause,
            repeated_submit_clause,
        ));
    }

    let target_result = visible_results
        .iter()
        .find(|link| snapshot_link_result_rank(link) == Some(request.rank))
        .or_else(|| {
            let local_index = request.rank.saturating_sub(page_start_rank);
            visible_results.get(local_index)
        })?;
    if recent_successful_click_has_post_action_observation(
        history,
        &target_result.semantic_id,
        current_snapshot,
    ) {
        return None;
    }

    let result_name = target_result
        .name
        .as_deref()
        .unwrap_or(target_result.semantic_id.as_str());
    let recent_instruction_click = recent_successful_click_semantic_id(history).as_deref()
        == Some(instruction_token.semantic_id.as_str());
    let recovery_clause = if recent_instruction_click {
        " The recent click on the instruction token did not satisfy the task, so do not finish."
    } else {
        ""
    };

    Some(format!(
        "Use `browser__click_element` on `{}` now. Result {} on this page is visible result link `{}` (`{}`). `{}` is the visible instruction token for `{}`, not the result to click. Do not use `browser__scroll`, do not spend the next step on `browser__snapshot`, and do not click `{}` or finish.{}{}",
        target_result.semantic_id,
        request.rank,
        target_result.semantic_id,
        result_name,
        instruction_token.semantic_id,
        request.ordinal_text,
        instruction_token.semantic_id,
        recovery_clause,
        repeated_submit_clause,
    ))
}

pub(super) fn instruction_only_find_text_pagination_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let recent_find = recent_find_text_state(history)?;
    if recent_find
        .first_snippet
        .as_deref()
        .is_some_and(|snippet| !contains_ascii_case_insensitive(snippet, &recent_find.query))
    {
        return None;
    }
    if snapshot_visible_exact_text_target(snapshot, &recent_find.query).is_some() {
        return None;
    }

    let instruction_token =
        snapshot_visible_instruction_query_target(snapshot, &recent_find.query)?;
    let page_control = snapshot_forward_pagination_link(snapshot)?;
    let current_heading = snapshot_primary_visible_heading(snapshot)
        .filter(|heading| !contains_ascii_case_insensitive(&heading.name, &recent_find.query));

    Some(match current_heading {
        Some(heading) => format!(
            "`{}` is not on the current record `{}`. Do not click this record's links. The only valid next `browser__click_element` id here is `{}`. Use it now. Do not invent ids or repeat `browser__find_text`.",
            recent_find.query,
            heading.name,
            page_control.semantic_id,
        ),
        None => format!(
            "Recent `browser__find_text` for `{}` matched instruction token `{}`, not the current record. The only valid next `browser__click_element` id here is `{}`. Use it now. Do not invent ids, repeat `browser__find_text`, or spend the next step on `browser__snapshot`.",
            recent_find.query,
            instruction_token.semantic_id,
            page_control.semantic_id,
        ),
    })
}

pub(super) fn alternate_tab_exploration_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let tabs = snapshot_tab_states(snapshot);
    if tabs.len() < 2 {
        return None;
    }

    let recent_tab_click_ids = recent_successful_tab_click_ids(history, snapshot);
    let focused_tab = tabs.iter().find(|tab| tab.focused).or_else(|| {
        recent_tab_click_ids
            .first()
            .and_then(|tab_id| tabs.iter().find(|tab| tab.semantic_id == *tab_id))
    })?;
    if !recent_tab_click_ids.contains(&focused_tab.semantic_id) {
        return None;
    }

    let target = recent_goal_primary_target(history)?;
    let panel_text = focused_tab
        .controls_dom_id
        .as_deref()
        .and_then(|controls_dom_id| {
            snapshot_tabpanel_states(snapshot)
                .into_iter()
                .find(|panel| panel.visible && panel.dom_id.as_deref() == Some(controls_dom_id))
                .and_then(|panel| panel.name)
        })?;
    if contains_ascii_case_insensitive(&panel_text, &target) {
        return None;
    }

    let mut candidate_tab_ids = tabs
        .iter()
        .filter(|tab| tab.semantic_id != focused_tab.semantic_id)
        .filter(|tab| !recent_tab_click_ids.contains(&tab.semantic_id))
        .map(|tab| tab.semantic_id.clone())
        .collect::<Vec<_>>();
    if candidate_tab_ids.is_empty() {
        candidate_tab_ids = tabs
            .iter()
            .filter(|tab| tab.semantic_id != focused_tab.semantic_id)
            .map(|tab| tab.semantic_id.clone())
            .collect();
    }
    if candidate_tab_ids.is_empty() {
        return None;
    }

    let focused_label = focused_tab
        .name
        .as_deref()
        .unwrap_or(focused_tab.semantic_id.as_str());
    let candidate_clause = candidate_tab_ids
        .iter()
        .take(3)
        .map(|tab_id| format!("`{tab_id}`"))
        .collect::<Vec<_>>()
        .join(" or ");

    Some(format!(
        "The currently expanded section `{focused_label}` does not show the target text `{target}`. Do not click `{}` again, and do not spend the next step on another `browser__snapshot`. Use another visible section tab such as {candidate_clause} now. When `{target}` becomes visible, click that target directly.",
        focused_tab.semantic_id,
    ))
}

fn snapshot_visible_submit_control_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        let Some(id) = extract_browser_xml_attr(fragment, "id") else {
            continue;
        };
        if semantic_id_is_submit_like(&id) {
            return Some(id);
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if name.eq_ignore_ascii_case("submit") || name.eq_ignore_ascii_case("search") {
            return Some(id);
        }
    }

    None
}

fn snapshot_visible_send_control_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(tag_name) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(tag_name, "button" | "link" | "menuitem" | "generic") {
            continue;
        }

        let Some(id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if id.to_ascii_lowercase().contains("send") && fragment.contains(r#" dom_clickable="true""#)
        {
            return Some(id);
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if normalized_exact_target_text(&name)
            .split_whitespace()
            .next()
            .is_some_and(|token| token == "send")
        {
            return Some(id);
        }
    }

    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotInvalidTextControl {
    semantic_id: String,
    selector: Option<String>,
    value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecentTypedTextState {
    dom_id: Option<String>,
    selector: Option<String>,
    value: Option<String>,
}

fn class_name_has_invalid_token(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| matches!(token, "error" | "invalid"))
}

fn snapshot_visible_invalid_text_controls(snapshot: &str) -> Vec<SnapshotInvalidTextControl> {
    let mut controls = Vec::new();

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(tag_name) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(tag_name, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let class_name = extract_browser_xml_attr(fragment, "class_name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        if !class_name_has_invalid_token(&class_name)
            && !fragment.contains(r#" error="true""#)
            && !fragment.contains(r#" invalid="true""#)
        {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        controls.push(SnapshotInvalidTextControl {
            semantic_id,
            selector,
            value,
        });
    }

    controls.sort_by(|left, right| {
        let left_empty = left
            .value
            .as_deref()
            .is_none_or(|value| value.trim().is_empty());
        let right_empty = right
            .value
            .as_deref()
            .is_none_or(|value| value.trim().is_empty());
        left_empty
            .cmp(&right_empty)
            .reverse()
            .then_with(|| left.semantic_id.cmp(&right.semantic_id))
    });
    controls
}

fn recent_typed_text_state(history: &[ChatMessage]) -> Option<RecentTypedTextState> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let payload = parse_json_value_from_message(&message.content)?;
        let typed = payload.get("typed")?;
        Some(RecentTypedTextState {
            dom_id: typed
                .get("dom_id")
                .and_then(Value::as_str)
                .map(compact_ws_for_prompt)
                .filter(|value| !value.is_empty()),
            selector: typed
                .get("selector")
                .and_then(Value::as_str)
                .map(compact_ws_for_prompt)
                .filter(|value| !value.is_empty()),
            value: typed
                .get("value")
                .and_then(Value::as_str)
                .map(compact_ws_for_prompt)
                .filter(|value| !value.is_empty()),
        })
    })
}

pub(super) fn visible_target_click_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if select_submit_progress_pending_signal(history, current_snapshot).is_some() {
        return None;
    }
    let (target, candidate) = recent_goal_primary_target(history)
        .and_then(|target| {
            snapshot_visible_exact_text_target(snapshot, &target)
                .map(|candidate| (target, candidate))
        })
        .or_else(|| {
            snapshot_visible_goal_text_target(snapshot, history)
                .map(|candidate| (candidate.name.clone(), candidate))
        })?;

    if recent_successful_selected_control_semantic_id(history).as_deref()
        == Some(candidate.semantic_id.as_str())
        || snapshot_semantic_id_has_selected_state(snapshot, &candidate.semantic_id)
    {
        return None;
    }

    if recent_successful_click_has_post_action_observation(
        history,
        &candidate.semantic_id,
        current_snapshot,
    ) {
        return None;
    }

    Some(format!(
        "The target text `{target}` is already visible as `{}`. Use `browser__click_element` on `{}` now. Do not click a surrounding container or panel, do not use `browser__find_text`, and do not spend the next step on another `browser__snapshot`.",
        candidate.semantic_id, candidate.semantic_id
    ))
}

pub(super) fn select_submit_progress_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let requested_targets = history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| extract_select_submit_target(&message.content))?;
    snapshot_select_submit_progress_pending_signal_for_requested_targets(
        snapshot,
        &requested_targets,
    )
}

pub(super) fn active_target_submit_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let target = recent_goal_primary_target(history)?;
    let candidate = snapshot_visible_exact_text_target(snapshot, &target)?;
    if !candidate.already_active {
        return None;
    }

    let submit_id = snapshot_visible_submit_control_id(snapshot)?;
    if recent_successful_click_has_post_action_observation(history, &submit_id, current_snapshot) {
        return None;
    }

    Some(format!(
        "Target text `{target}` is already active as `{}`. Use `browser__click_element` on `{submit_id}` now to commit the current page state. Do not click `{}` again, and do not call `agent__complete` before submission.",
        candidate.semantic_id, candidate.semantic_id
    ))
}

pub(super) fn visible_error_text_control_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let submit_id = recent_successful_click_semantic_id(history)
        .filter(|semantic_id| semantic_id_is_submit_like(semantic_id))
        .filter(|semantic_id| {
            recent_successful_click_has_post_action_observation(
                history,
                semantic_id,
                current_snapshot,
            )
        })?;
    let control = snapshot_visible_invalid_text_controls(snapshot)
        .into_iter()
        .next()?;

    let value_clause = control
        .value
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!(" It currently shows `{value}` and still needs correction."))
        .unwrap_or_else(|| " It is still empty or invalid.".to_string());

    Some(format!(
        "Recent submit `{submit_id}` left visible field `{}` marked invalid.{value_clause} Use `browser__click_element` on `{}` now so you can repair it before submitting again. Do not click `{submit_id}` again yet.",
        control.semantic_id,
        control.semantic_id,
    ))
}

fn search_affordance_locator_matches(
    selector: Option<&str>,
    dom_id: Option<&str>,
    affordance: &SnapshotSearchAffordanceState,
) -> bool {
    if dom_id
        .zip(affordance.dom_id.as_deref())
        .is_some_and(|(left, right)| left == right)
    {
        return true;
    }

    selector
        .zip(affordance.selector.as_deref())
        .is_some_and(|(left, right)| left == right)
}

fn recent_typed_text_matches_search_affordance(
    history: &[ChatMessage],
    affordance: &SnapshotSearchAffordanceState,
    target: &str,
) -> bool {
    let Some(state) = recent_typed_text_state(history) else {
        return false;
    };
    let Some(value) = state.value.as_deref() else {
        return false;
    };
    if normalized_exact_target_text(value) != normalized_exact_target_text(target) {
        return false;
    }

    search_affordance_locator_matches(
        state.selector.as_deref(),
        state.dom_id.as_deref(),
        affordance,
    )
}

fn recent_typed_text_matches_message_recipient_control(
    history: &[ChatMessage],
    control: &SnapshotMessageRecipientControlState,
    target: &str,
) -> bool {
    let Some(state) = recent_typed_text_state(history) else {
        return false;
    };
    let Some(value) = state.value.as_deref() else {
        return false;
    };
    if normalized_exact_target_text(value) != normalized_exact_target_text(target) {
        return false;
    }

    if state
        .dom_id
        .as_deref()
        .zip(control.dom_id.as_deref())
        .is_some_and(|(left, right)| left == right)
    {
        return true;
    }

    state
        .selector
        .as_deref()
        .zip(control.selector.as_deref())
        .is_some_and(|(left, right)| left == right)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PointerHoldGoalKind {
    Drag,
    Draw,
    Resize,
    Slider,
    ColorWheel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecentBrowserPointerActionState {
    action: String,
    target_semantic_id: Option<String>,
    target_selector: Option<String>,
}

fn recent_pointer_hold_goal_kind(history: &[ChatMessage]) -> Option<PointerHoldGoalKind> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| {
            let lower = message.content.to_ascii_lowercase();
            if lower.contains("drag") {
                Some(PointerHoldGoalKind::Drag)
            } else if lower.contains("draw") || lower.contains("trace") {
                Some(PointerHoldGoalKind::Draw)
            } else if lower.contains("resize") {
                Some(PointerHoldGoalKind::Resize)
            } else if lower.contains("slider") {
                Some(PointerHoldGoalKind::Slider)
            } else {
                None
            }
        })
}

fn pointer_action_state(message: &ChatMessage) -> Option<RecentBrowserPointerActionState> {
    if message.role != "tool" {
        return None;
    }

    let payload = parse_json_value_from_message(&message.content)?;
    let pointer = payload.get("pointer")?;
    Some(RecentBrowserPointerActionState {
        action: pointer.get("action")?.as_str()?.to_string(),
        target_semantic_id: pointer
            .get("target")
            .and_then(|target| target.get("id"))
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty()),
        target_selector: pointer
            .get("target")
            .and_then(|target| target.get("selector"))
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty()),
    })
}

fn recent_pointer_action_state(history: &[ChatMessage]) -> Option<RecentBrowserPointerActionState> {
    history.iter().rev().find_map(pointer_action_state)
}

fn recent_pointer_press_hold_state(history: &[ChatMessage]) -> Option<bool> {
    history.iter().rev().find_map(|message| {
        let action = pointer_action_state(message)?;
        match action.action.as_str() {
            "mouse_down" => Some(true),
            "mouse_up" => Some(false),
            _ => None,
        }
    })
}

fn recent_pointer_gesture_released_without_motion(history: &[ChatMessage]) -> bool {
    let mut saw_release = false;
    for message in history.iter().rev() {
        let Some(action) = pointer_action_state(message) else {
            continue;
        };
        match action.action.as_str() {
            "mouse_up" if !saw_release => saw_release = true,
            "move" | "hover" if saw_release => return false,
            "mouse_down" if saw_release => return true,
            _ => {}
        }
    }
    false
}

fn recent_pointer_release_point(history: &[ChatMessage]) -> Option<(f64, f64)> {
    history.iter().rev().find_map(|message| {
        let payload = parse_json_value_from_message(&message.content)?;
        let pointer = payload.get("pointer")?;
        if pointer.get("action")?.as_str()? != "mouse_up" {
            return None;
        }

        Some((pointer.get("x")?.as_f64()?, pointer.get("y")?.as_f64()?))
    })
}

fn pointer_action_target_label(
    action: &RecentBrowserPointerActionState,
    current_snapshot: Option<&str>,
) -> Option<String> {
    action
        .target_semantic_id
        .as_deref()
        .filter(|semantic_id| {
            current_snapshot
                .map(|snapshot| snapshot_contains_semantic_id(snapshot, semantic_id))
                .unwrap_or(true)
        })
        .map(|semantic_id| semantic_id.to_string())
        .or_else(|| action.target_selector.clone())
}

fn recent_goal_likely_needs_multiple_pointer_commits(history: &[ChatMessage]) -> bool {
    const MULTI_MARKERS: &[&str] = &[
        " items ",
        " numbers ",
        " shapes ",
        " sequence ",
        " sort ",
        " each ",
        " every ",
        " all ",
        " grid ",
        " list ",
        " lists ",
        " rows ",
        " columns ",
    ];

    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .any(|message| {
            let padded = format!(" {} ", message.content.to_ascii_lowercase());
            MULTI_MARKERS.iter().any(|marker| padded.contains(marker))
        })
}

pub(super) fn pointer_hold_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let goal_kind = recent_pointer_hold_goal_kind(history)?;
    let latest_action = recent_pointer_action_state(history)?;
    let pointer_held = recent_pointer_press_hold_state(history).unwrap_or(false);

    if !pointer_held {
        if !matches!(latest_action.action.as_str(), "hover" | "move") {
            return None;
        }

        let target_clause = pointer_action_target_label(&latest_action, current_snapshot)
            .map(|target| format!(" on `{target}`"))
            .unwrap_or_default();
        let repeat_clause = if latest_action.action == "hover" {
            " Do not repeat `browser__hover` on the same target."
        } else {
            " Do not spend the next step on another positioning move."
        };
        let action_clause = match goal_kind {
            PointerHoldGoalKind::Drag => "begin the drag",
            PointerHoldGoalKind::Draw => "begin the pointer trace",
            PointerHoldGoalKind::Resize => "begin the resize gesture",
            PointerHoldGoalKind::Slider => "grab the slider handle",
            PointerHoldGoalKind::ColorWheel => "begin the color-wheel gesture",
        };

        return Some(format!(
            "The pointer is already positioned{target_clause} for the requested pointer task. Use `browser__mouse_down` now to {action_clause}.{repeat_clause}"
        ));
    }

    match goal_kind {
        PointerHoldGoalKind::Drag if latest_action.action == "hover" => {
            let target = pointer_action_target_label(&latest_action, current_snapshot)?;
            Some(format!(
                "A browser drag is already in progress and the pointer is grounded on `{target}`. Use `browser__mouse_up` now to release there. Do not repeat `browser__hover` on `{target}` or click submit yet."
            ))
        }
        PointerHoldGoalKind::Drag if latest_action.action == "mouse_down" => Some(
            "A browser drag is already in progress. Move to the intended drop target with `browser__hover` when a grounded target is visible, or use `browser__move_mouse` if you only have coordinates, then finish with `browser__mouse_up`. Do not click submit yet.".to_string(),
        ),
        PointerHoldGoalKind::Draw if latest_action.action == "mouse_down" => Some(
            "A browser pointer trace is already in progress. The next action must be `browser__move_mouse` or `browser__hover` to extend the stroke; do not use `browser__mouse_up` yet. Finish with `browser__mouse_up` only after the pointer has moved. Do not submit yet.".to_string(),
        ),
        PointerHoldGoalKind::Resize if latest_action.action == "mouse_down" => Some(
            "A browser resize gesture is already in progress. Move the pointer toward the requested size change with `browser__move_mouse` or `browser__hover`, then finish with `browser__mouse_up`. Do not submit yet.".to_string(),
        ),
        PointerHoldGoalKind::Slider if latest_action.action == "mouse_down" => Some(
            "A browser slider drag is already in progress. Move the pointer along the slider with `browser__move_mouse` or `browser__hover`, then finish with `browser__mouse_up` once the requested value is reached. Do not click submit yet.".to_string(),
        ),
        PointerHoldGoalKind::ColorWheel if latest_action.action == "mouse_down" => Some(
            "A browser color-wheel gesture is already in progress. Move the pointer to the requested color position with `browser__move_mouse` or `browser__hover`, then finish with `browser__mouse_up`. Do not submit yet.".to_string(),
        ),
        _ => None,
    }
}

pub(super) fn target_search_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let target = recent_goal_primary_target(history)?;
    if snapshot_visible_exact_text_target(snapshot, &target).is_some() {
        return None;
    }

    let affordance = snapshot_visible_search_affordance(snapshot)?;
    if recent_successful_selected_control_semantic_id(history).as_deref()
        == Some(affordance.semantic_id.as_str())
    {
        return None;
    }

    if recent_successful_click_has_post_action_observation(
        history,
        &affordance.semantic_id,
        current_snapshot,
    ) {
        return None;
    }

    if matches!(affordance.kind, SnapshotSearchAffordanceKind::Field)
        && recent_typed_text_matches_search_affordance(history, &affordance, &target)
    {
        return None;
    }

    Some(match affordance.kind {
        SnapshotSearchAffordanceKind::Field => format!(
            "Target text `{target}` is not visible yet. Search field `{}` is already on the page. Use `browser__click_element` on `{}` now so you can type `{target}` next; use the page's search control instead of `browser__find_text`, and do not click unrelated list actions first.",
            affordance.semantic_id, affordance.semantic_id
        ),
        SnapshotSearchAffordanceKind::Activator => format!(
            "Target text `{target}` is not visible yet. Search control `{}` is available. Use `browser__click_element` on `{}` now so you can search for `{target}`; use the page's search control instead of `browser__find_text`, and do not click unrelated list actions first.",
            affordance.semantic_id, affordance.semantic_id
        ),
    })
}

fn start_gate_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let start_gate = snapshot_visible_start_gate_target(snapshot)?;

    if recent_successful_click_has_post_action_observation(
        history,
        &start_gate.semantic_id,
        current_snapshot,
    ) {
        return None;
    }

    let semantic_role = start_gate.semantic_role.to_ascii_lowercase();
    if !matches!(
        semantic_role.as_str(),
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
    ) {
        return None;
    }

    Some(format!(
        "A visible start gate `{}` is still covering the task surface. Use `browser__click_element` on `{}` now to begin the page, then continue with the working controls. Do not click underlying canvas, form, or list targets before this gate clears.",
        start_gate.semantic_id, start_gate.semantic_id
    ))
}

pub(super) fn message_recipient_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let recipient = recent_goal_message_recipient_target(history)?;
    let control = snapshot_visible_message_recipient_control(snapshot)?;
    if control.value.as_deref().is_some_and(|value| {
        normalized_exact_target_text(value) == normalized_exact_target_text(&recipient)
    }) || recent_typed_text_matches_message_recipient_control(history, &control, &recipient)
    {
        return None;
    }

    let send_id = snapshot_visible_send_control_id(snapshot);
    Some(match send_id {
        Some(send_id) => format!(
            "This message still needs recipient `{recipient}`. Focus recipient field `{}` with `browser__click_element` now, then type `{recipient}` on the following step. Do not click `{send_id}` yet.",
            control.semantic_id
        ),
        None => format!(
            "This message still needs recipient `{recipient}`. Focus recipient field `{}` with `browser__click_element` now, then type `{recipient}` on the following step before sending.",
            control.semantic_id
        ),
    })
}

pub(super) fn browser_effect_success_signal_for_message(
    history: &[ChatMessage],
    message: &ChatMessage,
    snapshot: Option<&str>,
) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_click_postcondition_success = tool_message_has_postcondition_success(message);
    if compact.contains("\"typed\":{") && compact.contains("\"already_satisfied\":true") {
        let mut signal = "A recent browser typing action found that the targeted field already contained the requested text. Do not type the same text into that field again.".to_string();
        if let Some(snapshot) = snapshot {
            if let Some(clause) = recent_typed_text_follow_up_clause(history, snapshot) {
                signal.push_str(&clause);
            } else {
                signal.push_str(
                    " Continue with the next required control or verify the updated page state if needed.",
                );
            }
        } else {
            signal.push_str(
                " Continue with the next required control or verify the updated page state if needed.",
            );
        }
        return Some(signal);
    }

    if has_click_postcondition_success
        && compact.contains("Clicked element")
        && (compact.contains("\"checked\":true") || compact.contains("\"selected\":true"))
    {
        return Some(
            "A recent browser interaction already selected a form control (`checked=true` or `selected=true`). Do not click the surrounding option group or form container again. Continue with the next required control (for example `Submit`) or verify once if the goal is already satisfied.".to_string(),
        );
    }

    if has_click_postcondition_success && compact.contains("Clicked element") {
        if let Some(signal) =
            geometry_progress_success_signal_for_message(history, message, snapshot)
        {
            return Some(signal);
        }
    }

    if let Some(signal) = click_opened_new_surface_success_signal(history, message, snapshot) {
        return Some(signal);
    }

    if has_click_postcondition_success && compact.contains("Clicked element") {
        if let Some(current_snapshot) = snapshot {
            if select_submit_progress_pending_signal(history, Some(current_snapshot)).is_some()
                || visible_target_click_pending_signal(history, Some(current_snapshot)).is_some()
            {
                return None;
            }
        }
        let clicked_id = clicked_element_semantic_id(message);
        let mut signal = "A recent browser interaction already caused observable state change (`postcondition.met=true`). Do not repeat the same interaction.".to_string();
        if let Some(snapshot) = snapshot {
            let next_controls = next_visible_follow_up_controls(
                snapshot,
                &clicked_id.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            if !next_controls.is_empty() {
                signal.push_str(&format!(
                    " Use a visible control such as `{}`.",
                    next_controls.join("`, `")
                ));
                signal.push_str(
                    " Do not spend the next step on another `browser__snapshot` unless the page changes again.",
                );
            } else {
                signal.push_str(
                    " Verify once if needed, then finish with `agent__complete` when the goal is satisfied.",
                );
            }
        } else {
            signal.push_str(
                " Verify once if needed, then finish with `agent__complete` when the goal is satisfied.",
            );
        }
        return Some(signal);
    }

    if has_click_postcondition_success
        && (compact.contains("\"synthetic_click\":{")
            || compact.starts_with("Synthetic click at ("))
    {
        let signal = if let Some(signal) =
            geometry_progress_success_signal_for_message(history, message, snapshot)
        {
            signal
        } else {
            let mut signal = "A recent browser synthetic click already caused observable state change (`postcondition.met=true`). Do not repeat the same coordinate blindly.".to_string();
            if let Some(current_snapshot) = snapshot {
                let next_controls = next_visible_follow_up_controls(current_snapshot, &[]);
                if !next_controls.is_empty() {
                    signal.push_str(&format!(
                        " Visible controls now include `{}`.",
                        next_controls.join("`, `")
                    ));
                }
                signal.push_str(
                    " Re-check the updated browser observation before deciding whether to use a visible control, take another grounded action, or finish.",
                );
            } else {
                signal.push_str(" Verify the updated state before choosing another action.");
            }
            signal
        };
        return Some(signal);
    }

    if compact.contains("\"selected\":{")
        && (compact.contains("\"label\":") || compact.contains("\"value\":"))
    {
        return Some(
            "A recent browser dropdown selection already succeeded. Do not repeat the same selection. Use the updated browser state to continue with the next required action or finish if the goal is already satisfied.".to_string(),
        );
    }

    if compact.contains("identical action already succeeded on the previous step") {
        let mut signal =
            "The identical action already succeeded on the previous step. Do not repeat it."
                .to_string();
        if let Some(current_snapshot) = snapshot {
            if let Some(clause) = recent_typed_text_follow_up_clause(history, current_snapshot) {
                signal.push_str(&clause);
                signal.push_str(
                    " Do not spend the next step on another `browser__snapshot` unless the page changed.",
                );
            } else {
                let next_controls = next_visible_follow_up_controls(current_snapshot, &[]);
                if !next_controls.is_empty() {
                    signal.push_str(&format!(
                        " Continue with another visible control such as `{}` after re-checking the updated browser observation.",
                        next_controls.join("`, `")
                    ));
                } else {
                    signal.push_str(" Verify the updated state before choosing another action.");
                }
            }
        } else {
            signal.push_str(" Verify the updated state or finish with the gathered evidence.");
        }
        return Some(signal);
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"key\":\"Home\"") || compact.contains("\"key\":\"PageUp\""))
        && compact.contains("\"scroll_top\":0")
        && compact.contains("\"can_scroll_up\":false")
    {
        let mut signal = "A recent browser key already moved the focused scrollable control to its top edge. Do not repeat the same key.".to_string();
        if let Some(snapshot) = snapshot {
            if let Some(submit_id) = snapshot_visible_submit_control_id(snapshot) {
                signal.push_str(&format!(
                    " If the scroll goal is already satisfied, use visible control `{submit_id}` next."
                ));
            } else {
                signal.push_str(
                    " Verify once if needed, then continue with the next required action or finish if the goal is satisfied.",
                );
            }
        } else {
            signal.push_str(
                " Verify once if needed, then continue with the next required action or finish if the goal is satisfied.",
            );
        }
        return Some(signal);
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"key\":\"End\"") || compact.contains("\"key\":\"PageDown\""))
        && compact.contains("\"can_scroll_down\":false")
    {
        let mut signal = "A recent browser key already moved the focused scrollable control to its bottom edge. Do not repeat the same key.".to_string();
        if let Some(snapshot) = snapshot {
            if let Some(submit_id) = snapshot_visible_submit_control_id(snapshot) {
                signal.push_str(&format!(
                    " If the scroll goal is already satisfied, use visible control `{submit_id}` next."
                ));
            } else {
                signal.push_str(
                    " Verify once if needed, then continue with the next required action or finish if the goal is satisfied.",
                );
            }
        } else {
            signal.push_str(
                " Verify once if needed, then continue with the next required action or finish if the goal is satisfied.",
            );
        }
        return Some(signal);
    }

    None
}

pub(super) fn submitted_selection_turnover_success_signal(
    history: &[ChatMessage],
    snapshot: &str,
) -> Option<String> {
    if !recent_goal_mentions_submit(history) {
        return None;
    }

    let submit_id = recent_successful_click_semantic_id(history)
        .filter(|semantic_id| semantic_id_is_submit_like(semantic_id))?;
    if !recent_successful_click_has_post_action_observation(history, &submit_id, Some(snapshot)) {
        return None;
    }

    let selected_control_id = recent_successful_selected_control_semantic_id(history)?;
    if snapshot_contains_semantic_id(snapshot, &selected_control_id) {
        return None;
    }

    let target = recent_goal_primary_target(history)?;
    if contains_ascii_case_insensitive(snapshot, &target) {
        return None;
    }

    Some(format!(
        "`{submit_id}` turned over the page: target `{target}` and `{selected_control_id}` are gone in the current browser observation. Do not use the new page's controls. Call `agent__complete` now."
    ))
}

pub(super) fn recent_browser_success_signal(
    history: &[ChatMessage],
    snapshot: Option<&str>,
) -> Option<String> {
    let snapshot = snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload));

    if let Some(snapshot) = snapshot {
        if let Some(signal) = autocomplete_commit_success_signal(history, snapshot) {
            return Some(signal);
        }
    }

    for message in history.iter().rev() {
        if let Some(signal) = dropdown_success_signal_for_message(message, snapshot) {
            return Some(signal);
        }
        if dropdown_selection_details(message).is_some() {
            continue;
        }
        if let Some(signal) = browser_effect_success_signal_for_message(history, message, snapshot)
        {
            return Some(signal);
        }
    }

    None
}

pub(crate) fn build_browser_observation_context_from_snapshot(snapshot: &str) -> String {
    build_browser_observation_context_from_snapshot_with_history(snapshot, &[])
}

pub(crate) fn build_browser_observation_context_from_snapshot_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> String {
    let mut assistive_hints = extract_assistive_browser_hints(snapshot);
    if let Some(scroll_target_hint) =
        extract_scroll_target_focus_hint_with_history(snapshot, history)
    {
        assistive_hints.push(scroll_target_hint);
    }
    let compact_observation = compact_browser_observation_with_history(snapshot, history);
    if compact_observation.is_empty() {
        return String::new();
    }

    let assistive_context = if assistive_hints.is_empty() {
        String::new()
    } else {
        format!("ASSISTIVE BROWSER HINTS: {}\n", assistive_hints.join(" | "))
    };

    format!(
        "RECENT BROWSER OBSERVATION:\n{}{}\nUse this semantic browser evidence directly when selecting the next browser action.\n",
        assistive_context, compact_observation
    )
}

pub(super) fn browser_effect_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let message = history
        .iter()
        .rev()
        .find(|message| message.role == "tool")?;

    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if compact.contains("\"autocomplete\":{")
        && (compact.contains("\"assistive_hint\":")
            || compact.contains("\"active_descendant_dom_id\":")
            || compact.contains("\"controls_dom_id\":"))
    {
        if current_snapshot.is_some()
            && autocomplete_follow_up_pending_signal(history, current_snapshot).is_none()
        {
            return None;
        }

        if compact.contains("\"key\":{") {
            if compact.contains("\"key\":\"ArrowDown\"") || compact.contains("\"key\":\"ArrowUp\"")
            {
                return Some("A recent browser navigation key updated the active autocomplete candidate, but the widget is still open. If the highlighted candidate is the intended choice, press `Enter` to commit it before submitting. Otherwise continue navigating or use `browser__snapshot` to verify.".to_string());
            }
            return Some("A recent browser key press left autocomplete active, so that key did not resolve the widget. Do not submit or finish. Use `browser__key` with a different navigation key (for example `ArrowDown` or `ArrowUp`) or take `browser__snapshot` to ground the candidate before committing.".to_string());
        }

        return Some("A recent browser action surfaced active autocomplete state. This widget is not resolved yet. Do not submit or finish until you explicitly commit or dismiss the suggestion, usually by checking updated browser state or using `browser__key`.".to_string());
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"tag_name\":\"body\"") || compact.contains("\"tag_name\":\"html\""))
    {
        return Some("A recent browser key landed on the page itself, not on a specific control. If you intended a textarea, listbox, or nested scroll region, target that control directly with `browser__key` `selector` when it is already grounded; otherwise focus it first or continue with the next required visible control. Do not repeat the same key blindly.".to_string());
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"Home\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_up\":true")
    {
        let selector = recent_browser_key_selector_from_compact(&compact);
        let top_edge_jump_call = top_edge_jump_call_for_selector(selector.as_deref());
        if compact.contains("\"modifiers\":[\"Control\"]") {
            return Some(format!(
                "A recent `{}` still left the focused scrollable control above top (`can_scroll_up=true`). Do not call `{}` again. Use `PageUp` next, then stop only at `can_scroll_up=false` or `scroll_top=0`.",
                top_edge_jump_name(),
                top_edge_jump_name(),
            ));
        }

        if let Some(scroll_top) = focused_home_should_jump_to_top_edge(&compact) {
            return Some(format!(
                "`Home` left a focused scrollable control above top (`scroll_top={scroll_top}`, `can_scroll_up=true`). Do not use `Home` again or spend the next step on `PageUp`. Use `{}` next, then stop only at `can_scroll_up=false` or `scroll_top=0`.",
                top_edge_jump_call,
            ));
        }

        return Some(format!(
            "A recent `Home` key still left the focused scrollable control above top (`can_scroll_up=true`). Do not call `Home` again. Use `PageUp` or `{}` next, then stop only at `can_scroll_up=false` or `scroll_top=0`.",
            top_edge_jump_call,
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"PageUp\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_up\":true")
    {
        let selector = recent_browser_key_selector_from_compact(&compact);
        return Some(format!(
            "A recent `PageUp` still left the focused scrollable control above top (`can_scroll_up=true`). Continue upward or use `{}`. Stop at `can_scroll_up=false` or `scroll_top=0`.",
            top_edge_jump_call_for_selector(selector.as_deref()),
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"End\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_down\":true")
    {
        let selector = recent_browser_key_selector_from_compact(&compact);
        let bottom_edge_jump_call = bottom_edge_jump_call_for_selector(selector.as_deref());
        if compact.contains("\"modifiers\":[\"Control\"]") {
            return Some(format!(
                "A recent `{}` still left the focused scrollable control above bottom (`can_scroll_down=true`). Do not call `{}` again. Use `PageDown` next, then stop only at `can_scroll_down=false`.",
                bottom_edge_jump_name(),
                bottom_edge_jump_name(),
            ));
        }

        return Some(format!(
            "A recent `End` key still left the focused scrollable control above bottom (`can_scroll_down=true`). Do not call `End` again. Use `PageDown` or `{}` next, then stop only at `can_scroll_down=false`.",
            bottom_edge_jump_call,
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"PageDown\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_down\":true")
    {
        let selector = recent_browser_key_selector_from_compact(&compact);
        return Some(format!(
            "A recent `PageDown` still left the focused scrollable control above bottom (`can_scroll_down=true`). Continue downward or use `{}`. Stop at `can_scroll_down=false`.",
            bottom_edge_jump_call_for_selector(selector.as_deref()),
        ));
    }

    if compact.contains("\"scroll\":{")
        && compact.contains("\"page_moved\":false")
        && compact.contains("\"target_moved\":false")
    {
        return Some("A recent browser scroll had no grounded effect on the page or the current scrollable control. Do not repeat the same blind scroll. First verify or focus the intended scroll container with `browser__snapshot`, then use a control-local action such as `browser__key` (`Home`, `End`, `PageUp`, or `PageDown`) or a better-targeted scroll.".to_string());
    }

    if compact.contains("\"focused_control\":{")
        && compact.contains("\"focused\":true")
        && (compact.contains("\"can_scroll_up\":true")
            || compact.contains("\"can_scroll_down\":true"))
        && compact.contains("Clicked element")
    {
        return Some("A recent browser click already focused a scrollable control. Do not keep clicking the surrounding wrapper or container. If the goal is control-local scrolling or text selection in that control, continue there with a control-local action such as `browser__key` (preferably with the control's grounded `selector`) or `browser__select_text`; otherwise move to the next required visible control.".to_string());
    }

    None
}

fn tool_message_has_click_dispatch_timeout(message: &ChatMessage) -> bool {
    tool_message_verify_payload(message)
        .and_then(|verify| {
            verify
                .get("dispatch_failures")
                .and_then(Value::as_array)
                .cloned()
        })
        .is_some_and(|failures| {
            failures.iter().any(|failure| {
                failure
                    .get("error")
                    .and_then(Value::as_str)
                    .is_some_and(|error| error.contains("dispatch timed out"))
            })
        })
}

pub(super) fn click_dispatch_timeout_retry_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let message = history
        .iter()
        .rev()
        .find(|message| message.role == "tool")?;
    let compact = compact_ws_for_prompt(&message.content);
    if !compact.contains("ERROR_CLASS=NoEffectAfterAction") {
        return None;
    }

    let clicked_id = click_attempt_target_semantic_id(message)?;
    if semantic_id_is_submit_like(&clicked_id) {
        return None;
    }
    if !tool_message_has_click_dispatch_timeout(message) {
        return None;
    }
    if snapshot_priority_target_summary(snapshot, &clicked_id).is_none() {
        return None;
    }

    Some(format!(
        "A recent `browser__click_element` on `{clicked_id}` timed out before any observed page effect, and `{clicked_id}` is still visible in the current browser observation. If the goal still requires activating `{clicked_id}`, retry `browser__click_element` on `{clicked_id}` now. Do not spend the next step on `browser__snapshot` unless `{clicked_id}` disappears or the page visibly changes."
    ))
}

pub(super) fn repeated_pagewise_scroll_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let mut repeated_page_up = 0usize;
    let mut repeated_page_down = 0usize;
    let mut repeated_page_up_selector: Option<String> = None;
    let mut repeated_page_down_selector: Option<String> = None;

    for message in history.iter().rev() {
        if message.role != "tool" {
            continue;
        }

        let compact = compact_ws_for_prompt(&message.content);
        if compact.contains("\"key\":{")
            && compact.contains("\"focused\":true")
            && compact.contains("\"key\":\"PageUp\"")
            && compact.contains("\"can_scroll_up\":true")
        {
            repeated_page_up += 1;
            repeated_page_down = 0;
            repeated_page_down_selector = None;
            if repeated_page_up_selector.is_none() {
                repeated_page_up_selector = recent_browser_key_selector_from_compact(&compact);
            }
            if repeated_page_up >= 2 {
                return Some(format!(
                    "Repeated `PageUp` still leaves the focused scrollable control above top (`can_scroll_up=true`). Stop repeating `PageUp`. Use `{}` next, then verify `can_scroll_up=false` or `scroll_top=0` before submit.",
                    top_edge_jump_call_for_selector(repeated_page_up_selector.as_deref()),
                ));
            }
            continue;
        }

        if compact.contains("\"key\":{")
            && compact.contains("\"focused\":true")
            && compact.contains("\"key\":\"PageDown\"")
            && compact.contains("\"can_scroll_down\":true")
        {
            repeated_page_down += 1;
            repeated_page_up = 0;
            repeated_page_up_selector = None;
            if repeated_page_down_selector.is_none() {
                repeated_page_down_selector = recent_browser_key_selector_from_compact(&compact);
            }
            if repeated_page_down >= 2 {
                return Some(format!(
                    "Repeated `PageDown` still leaves the focused scrollable control below bottom (`can_scroll_down=true`). Stop repeating `PageDown`. Use `{}` next, then verify `can_scroll_down=false` before submit.",
                    bottom_edge_jump_call_for_selector(repeated_page_down_selector.as_deref()),
                ));
            }
            continue;
        }

        if repeated_page_up > 0 || repeated_page_down > 0 {
            break;
        }
    }

    None
}

pub(super) fn navigation_observation_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let transition = recent_unobserved_navigation_transition(history)?;
    let action = transition
        .semantic_id
        .map(|semantic_id| format!(" on `{semantic_id}`"))
        .unwrap_or_default();

    Some(format!(
        "A recent browser action{action} changed the page URL to `{}` but there is no newer `browser__snapshot` yet. The current browser observation may still describe the previous page. Do not act on stale element ids or finish yet. Take `browser__snapshot` now, then continue from the updated page state.",
        transition.post_url
    ))
}

pub(super) fn auth_form_pending_signal_from_snapshot(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    let snapshot_lower = snapshot.to_ascii_lowercase();
    let has_password_field = snapshot_lower.contains(r#"dom_id="password""#)
        || snapshot_lower.contains(r#"name="password""#);
    let has_username_field = snapshot_lower.contains(r#"dom_id="username""#)
        || snapshot_lower.contains(r#"name="username""#)
        || snapshot_lower.contains(r#"dom_id="email""#)
        || snapshot_lower.contains(r#"name="email""#);
    let has_login_action = [
        r#"dom_id="sign-in""#,
        r#"dom_id="login""#,
        r#"dom_id="log-in""#,
        r#"name="sign in""#,
        r#"name="log in""#,
        r#"name="login""#,
    ]
    .iter()
    .any(|needle| snapshot_lower.contains(needle));

    if !has_password_field || !has_login_action {
        return None;
    }

    let mut typed_username = false;
    let mut typed_password = false;
    for message in history.iter().rev().take(8) {
        if message.role != "tool" {
            continue;
        }
        let compact = compact_ws_for_prompt(&message.content);
        if !compact.contains("\"typed\":{") {
            continue;
        }
        if compact.contains("\"selector\":\"#username\"")
            || compact.contains("\"selector\":\"#email\"")
            || compact.contains("\"dom_id\":\"username\"")
            || compact.contains("\"dom_id\":\"email\"")
        {
            typed_username = true;
        }
        if compact.contains("\"selector\":\"#password\"")
            || compact.contains("\"dom_id\":\"password\"")
        {
            typed_password = true;
        }
    }

    if typed_username && !typed_password {
        return Some("A visible browser auth form still includes a password field, and recent browser state only confirms the username or email entry. Do not click `Sign in` or submit yet. Fill the remaining password credential field first, then continue with the login action.".to_string());
    }

    if typed_password && !typed_username && has_username_field {
        return Some("A visible browser auth form still includes a username or email field, and recent browser state only confirms the password entry. Do not click `Sign in` or submit yet. Fill the remaining username or email field first, then continue with the login action.".to_string());
    }

    if typed_username && typed_password {
        return Some("A visible browser auth form still remains, and recent browser state confirms both credential fields were filled. Do not keep taking snapshots or retyping the same credentials. Use the login action now (for example `browser__click_element` on the visible sign-in button), then verify that the page changes.".to_string());
    }

    None
}

pub(super) fn auth_form_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let snapshot = history.iter().rev().find_map(browser_snapshot_payload)?;
    auth_form_pending_signal_from_snapshot(snapshot, history)
}

pub(super) fn filter_mismatch_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    dropdown_filter_mismatch_pending_signal(snapshot, history)
}

pub(crate) fn build_recent_command_history_context(
    command_history: &VecDeque<CommandExecution>,
) -> String {
    if command_history.is_empty() {
        return String::new();
    }

    let mut section = String::new();
    section.push_str(
        "\n## RECENT COMMAND EXECUTION HISTORY (Redacted/Reasoning-only)\nYou have access to recent sanitized command context for continuity.\n",
    );

    for (idx, entry) in command_history
        .iter()
        .rev()
        .take(MAX_PROMPT_HISTORY)
        .enumerate()
    {
        section.push_str(&format!(
            "{}. [Step {}] {} → exit={} (stdout: {} | stderr: {})\n",
            idx + 1,
            entry.step_index,
            entry.command,
            entry.exit_code,
            safe_truncate(&entry.stdout, 60),
            safe_truncate(&entry.stderr, 60),
        ));
    }

    section.push_str(
        "Use this context to avoid repeating failed commands and to build on successful steps.\n",
    );
    section
}

pub(super) fn is_browser_snapshot_no_effect_message(message: &ChatMessage) -> bool {
    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with(BROWSER_SNAPSHOT_TOOL_PREFIX)
        && compact.contains("ERROR_CLASS=NoEffectAfterAction")
}

pub(super) fn is_browser_observation_refresh_message(message: &ChatMessage) -> bool {
    if browser_snapshot_payload(message).is_some() {
        return true;
    }

    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_success = (compact.contains("\"postcondition\":{") && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");
    has_success && (compact.contains("browser__") || compact.contains("Clicked element"))
}

pub(super) fn is_incident_follow_up_system_message(message: &ChatMessage) -> bool {
    if message.role != "system" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with("System: Remedy")
        || compact.starts_with("System: Incident")
        || compact.starts_with("System: Selected recovery action")
}

pub(super) fn is_browser_context_echo_system_message(message: &ChatMessage) -> bool {
    if message.role != "system" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    compact.starts_with("RECENT PENDING BROWSER STATE:")
        || compact.starts_with("RECENT SUCCESS SIGNAL:")
        || compact.starts_with("RECENT BROWSER OBSERVATION:")
}

pub(super) fn explicit_pending_browser_state_context_message(
    message: &ChatMessage,
) -> Option<String> {
    if message.role != "system" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if !compact.starts_with("RECENT PENDING BROWSER STATE:") {
        return None;
    }

    let content = message.content.trim();
    (!content.is_empty()).then(|| content.to_string())
}

pub(crate) fn latest_recent_pending_browser_state_context(
    history: &[ChatMessage],
) -> Option<String> {
    let idx = history
        .iter()
        .rposition(|message| explicit_pending_browser_state_context_message(message).is_some())?;
    if history[idx + 1..]
        .iter()
        .any(is_browser_observation_refresh_message)
    {
        return None;
    }

    explicit_pending_browser_state_context_message(&history[idx])
}

pub(super) fn filtered_recent_session_events<'a>(
    history: &'a [ChatMessage],
    prefer_browser_semantics: bool,
) -> Vec<&'a ChatMessage> {
    if !prefer_browser_semantics {
        return history.iter().collect();
    }

    let mut suppressed = HashSet::new();

    for (idx, message) in history.iter().enumerate() {
        if !is_browser_snapshot_no_effect_message(message) {
            continue;
        }

        if !history[idx + 1..]
            .iter()
            .any(is_browser_observation_refresh_message)
        {
            continue;
        }

        suppressed.insert(idx);
        let mut follow_up_idx = idx + 1;
        while follow_up_idx < history.len()
            && is_incident_follow_up_system_message(&history[follow_up_idx])
        {
            suppressed.insert(follow_up_idx);
            follow_up_idx += 1;
        }
    }

    history
        .iter()
        .enumerate()
        .filter_map(|(idx, message)| {
            if suppressed.contains(&idx) {
                return None;
            }

            if is_browser_context_echo_system_message(message) {
                return None;
            }

            if recent_unobserved_navigation_transition(history).is_none()
                && browser_snapshot_payload(message).is_some()
            {
                return None;
            }

            Some(message)
        })
        .collect()
}

pub(crate) fn build_recent_session_events_context(
    history: &[ChatMessage],
    prefer_browser_semantics: bool,
) -> String {
    fn compact_recent_session_event_content(
        message: &ChatMessage,
        prefer_browser_semantics: bool,
    ) -> String {
        if !prefer_browser_semantics || message.role != "tool" {
            return message.content.clone();
        }

        let compact = compact_ws_for_prompt(&message.content);
        if compact.is_empty() {
            return String::new();
        }

        if compact.starts_with("Synthetic click at (") {
            return safe_truncate(&compact, 320);
        }

        for marker in [" verify=", " geometry=", " snapshot="] {
            if let Some(prefix) = compact.split_once(marker).map(|(prefix, _)| prefix.trim()) {
                if !prefix.is_empty() {
                    return prefix.to_string();
                }
            }
        }

        safe_truncate(&compact, 220)
    }

    filtered_recent_session_events(history, prefer_browser_semantics)
        .into_iter()
        .map(|message| {
            format!(
                "{}: {}",
                message.role,
                compact_recent_session_event_content(message, prefer_browser_semantics)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn build_recent_browser_observation_context(history: &[ChatMessage]) -> String {
    if recent_unobserved_navigation_transition(history).is_some() {
        return String::new();
    }

    let Some(observation) = history.iter().rev().find_map(browser_snapshot_payload) else {
        return String::new();
    };

    build_browser_observation_context_from_snapshot_with_history(observation, history)
}

pub(crate) fn build_recent_pending_browser_state_context(history: &[ChatMessage]) -> String {
    build_recent_pending_browser_state_context_with_snapshot(history, None)
}

pub(crate) fn build_recent_pending_browser_state_context_with_snapshot(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> String {
    let has_current_snapshot = current_snapshot.is_some();
    let navigation_signal = if has_current_snapshot {
        None
    } else {
        navigation_observation_pending_signal(history)
    };
    let snapshot_pending_signal = current_snapshot
        .or_else(|| history.iter().rev().find_map(browser_snapshot_payload))
        .and_then(|snapshot| browser_snapshot_pending_signal_with_history(snapshot, history));

    let Some(signal) = navigation_signal
        .or_else(|| auth_form_pending_signal(history))
        .or_else(|| visible_error_text_control_pending_signal(history, current_snapshot))
        .or_else(|| autocomplete_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| {
            tree_change_link_reverification_pending_signal_with_current_snapshot(
                history,
                current_snapshot,
            )
        })
        .or_else(|| filter_mismatch_pending_signal(history, current_snapshot))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, current_snapshot))
        .or_else(|| start_gate_pending_signal(history, current_snapshot))
        .or_else(|| stale_queue_reverification_pending_signal(history, current_snapshot))
        .or_else(|| {
            queue_reverification_history_follow_up_pending_signal(history, current_snapshot)
        })
        .or_else(|| alternate_tab_exploration_pending_signal(history, current_snapshot))
        .or_else(|| click_dispatch_timeout_retry_pending_signal(history, current_snapshot))
        .or_else(|| snapshot_pending_signal)
        .or_else(|| repeated_pagewise_scroll_pending_signal(history))
        .or_else(|| browser_effect_pending_signal(history, current_snapshot))
    else {
        return String::new();
    };

    let compact_signal = safe_truncate(&signal, PENDING_BROWSER_STATE_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT PENDING BROWSER STATE:\n{}\n", compact_signal)
}

pub(crate) fn build_recent_pending_browser_state_context_with_current_snapshot(
    history: &[ChatMessage],
    has_current_snapshot: bool,
) -> String {
    let current_snapshot = if has_current_snapshot {
        history.iter().rev().find_map(browser_snapshot_payload)
    } else {
        None
    };
    build_recent_pending_browser_state_context_with_snapshot(history, current_snapshot)
}

pub(crate) fn build_browser_snapshot_pending_state_context(snapshot: &str) -> String {
    build_browser_snapshot_pending_state_context_with_history(snapshot, &[])
}

pub(crate) fn build_browser_snapshot_pending_state_context_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> String {
    let Some(signal) = auth_form_pending_signal_from_snapshot(snapshot, history)
        .or_else(|| visible_error_text_control_pending_signal(history, Some(snapshot)))
        .or_else(|| autocomplete_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| {
            tree_change_link_reverification_pending_signal_with_current_snapshot(
                history,
                Some(snapshot),
            )
        })
        .or_else(|| dropdown_filter_mismatch_pending_signal(snapshot, history))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, Some(snapshot)))
        .or_else(|| start_gate_pending_signal(history, Some(snapshot)))
        .or_else(|| stale_queue_reverification_pending_signal(history, Some(snapshot)))
        .or_else(|| queue_reverification_history_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| alternate_tab_exploration_pending_signal(history, Some(snapshot)))
        .or_else(|| click_dispatch_timeout_retry_pending_signal(history, Some(snapshot)))
        .or_else(|| browser_snapshot_pending_signal_with_history(snapshot, history))
    else {
        return String::new();
    };

    let compact_signal = safe_truncate(&signal, PENDING_BROWSER_STATE_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT PENDING BROWSER STATE:\n{}\n", compact_signal)
}

pub(crate) fn build_recent_success_signal_context(history: &[ChatMessage]) -> String {
    build_recent_success_signal_context_with_snapshot(history, None)
}

fn tool_message_is_synthetic_click_success(message: &ChatMessage) -> bool {
    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_postcondition_success = (compact.contains("\"postcondition\":{")
        && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");

    has_postcondition_success
        && (compact.contains("\"synthetic_click\":{")
            || compact.starts_with("Synthetic click at ("))
}

fn tool_message_is_scroll_edge_success(message: &ChatMessage) -> bool {
    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if !compact.contains("\"key\":{") {
        return false;
    }

    ((compact.contains("\"key\":\"Home\"") || compact.contains("\"key\":\"PageUp\""))
        && compact.contains("\"scroll_top\":0")
        && compact.contains("\"can_scroll_up\":false"))
        || ((compact.contains("\"key\":\"End\"") || compact.contains("\"key\":\"PageDown\""))
            && compact.contains("\"can_scroll_down\":false"))
}

fn recent_success_signal_should_survive_pending_state(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> bool {
    history.iter().rev().any(|message| {
        geometry_progress_target_for_message(history, message, current_snapshot).is_some()
            || tool_message_is_scroll_edge_success(message)
    })
}

pub(crate) fn build_recent_success_signal_context_with_snapshot(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> String {
    let has_current_snapshot = current_snapshot.is_some();
    let navigation_signal = if has_current_snapshot {
        None
    } else {
        navigation_observation_pending_signal(history)
    };
    let snapshot_pending_signal = current_snapshot
        .or_else(|| history.iter().rev().find_map(browser_snapshot_payload))
        .and_then(|snapshot| browser_snapshot_pending_signal_with_history(snapshot, history));

    let pending_state_present = navigation_signal.is_some()
        || auth_form_pending_signal(history).is_some()
        || autocomplete_follow_up_pending_signal(history, current_snapshot).is_some()
        || tree_change_link_reverification_pending_signal_with_current_snapshot(
            history,
            current_snapshot,
        )
        .is_some()
        || filter_mismatch_pending_signal(history, current_snapshot).is_some()
        || instruction_only_find_text_pagination_pending_signal(history, current_snapshot)
            .is_some()
        || alternate_tab_exploration_pending_signal(history, current_snapshot).is_some()
        || stale_queue_reverification_pending_signal(history, current_snapshot).is_some()
        || queue_reverification_history_follow_up_pending_signal(history, current_snapshot)
            .is_some()
        || snapshot_pending_signal.is_some();

    if pending_state_present
        && !recent_success_signal_should_survive_pending_state(history, current_snapshot)
    {
        return String::new();
    }

    let Some(signal) = recent_browser_success_signal(history, current_snapshot) else {
        return String::new();
    };

    let compact_signal = safe_truncate(&signal, SUCCESS_SIGNAL_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT SUCCESS SIGNAL:\n{}\n", compact_signal)
}

pub(crate) fn build_browser_snapshot_success_signal_context(snapshot: &str) -> String {
    let Some(signal) = browser_snapshot_success_signal(snapshot) else {
        return String::new();
    };

    let compact_signal = safe_truncate(signal, SUCCESS_SIGNAL_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT SUCCESS SIGNAL:\n{}\n", compact_signal)
}
