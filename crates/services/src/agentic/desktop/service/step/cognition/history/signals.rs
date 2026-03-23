use super::*;

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

fn autocomplete_commit_success_signal(history: &[ChatMessage], snapshot: &str) -> Option<String> {
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
    if clicked_id
        .as_deref()
        .is_some_and(|semantic_id| snapshot_contains_semantic_id(snapshot, semantic_id))
    {
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
    if let Some(submit_id) =
        snapshot_visible_submit_control_id(snapshot).filter(|id| id != &control.semantic_id)
    {
        push_unique_control(&mut next_controls, &submit_id);
    }
    for semantic_id in next_visible_follow_up_controls(snapshot, &excluded_ids) {
        push_unique_control(&mut next_controls, &semantic_id);
        if next_controls.len() == 3 {
            break;
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

    for summary in &remaining_targets {
        let Some(tag) = priority_target_tag(summary) else {
            continue;
        };
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if matches!(tag, "heading") {
            continue;
        }
        push_unique_control(&mut next_controls, semantic_id);
        if next_controls.len() == 3 {
            return next_controls;
        }
    }

    next_controls
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

pub(super) fn snapshot_has_confirmation_page_marker(snapshot: &str) -> bool {
    for fragment in snapshot.split('<') {
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id_lower = dom_id.to_ascii_lowercase();
        let selector_lower = selector.to_ascii_lowercase();

        if dom_id_lower.contains("assignment-banner")
            || dom_id_lower.contains("status-summary")
            || dom_id_lower.contains("note-summary")
            || dom_id_lower.contains("save-status")
            || selector_lower.contains("assignment-banner")
            || selector_lower.contains("status-summary")
            || selector_lower.contains("note-summary")
            || selector_lower.contains("save-status")
        {
            return true;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let name_lower = name.to_ascii_lowercase();
        if name_lower.contains("assignment confirmation")
            || name_lower.contains("saved status:")
            || name_lower.contains("saved note:")
        {
            return true;
        }
    }

    false
}

pub(super) fn snapshot_confirmation_summary(
    snapshot: &str,
    dom_id_needle: &str,
    name_needle: &str,
) -> Option<String> {
    for fragment in snapshot.split('<') {
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id_lower = dom_id.to_ascii_lowercase();
        let selector_lower = selector.to_ascii_lowercase();

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let name_lower = name.to_ascii_lowercase();
        if dom_id_lower.contains(dom_id_needle)
            || selector_lower.contains(dom_id_needle)
            || name_lower.contains(name_needle)
        {
            return Some(name);
        }
    }

    None
}

pub(super) fn snapshot_confirmation_assignment_summary(snapshot: &str) -> Option<String> {
    snapshot_confirmation_summary(snapshot, "assignment-banner", "routed to")
}

pub(super) fn snapshot_confirmation_status_summary(snapshot: &str) -> Option<String> {
    snapshot_confirmation_summary(snapshot, "status-summary", "saved status:")
}

pub(super) fn snapshot_confirmation_note_summary(snapshot: &str) -> Option<String> {
    snapshot_confirmation_summary(snapshot, "note-summary", "saved note:")
}

pub(super) fn snapshot_ticket_item_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if !fragment.contains(r#"tag_name="h1""#) {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !name.to_ascii_lowercase().contains("ticket") {
            continue;
        }
        if let Some(item_id) = first_item_like_id(&name) {
            return Some(item_id);
        }
    }

    first_item_like_id(snapshot)
}

pub(super) fn confirmation_summary_value(summary: &str) -> &str {
    let summary = summary.trim();
    if let Some((_, value)) = summary.rsplit_once(':') {
        return value.trim();
    }
    if let Some((_, value)) = summary.rsplit_once("routed to") {
        return value.trim().trim_end_matches('.');
    }
    summary
}

pub(super) fn confirmation_summary_mismatch(
    observed_summary: Option<&str>,
    expected_value: Option<&str>,
    label: &str,
) -> Option<String> {
    let expected_value = expected_value?.trim();
    if expected_value.is_empty() {
        return None;
    }

    let expected_lower = expected_value.to_ascii_lowercase();
    match observed_summary {
        Some(summary) if summary.to_ascii_lowercase().contains(&expected_lower) => None,
        Some(summary) => Some(format!(
            "{label} shows `{}`, not `{expected_value}`",
            confirmation_summary_value(&compact_ws_for_prompt(summary))
        )),
        None => Some(format!("{label} is still missing `{expected_value}`")),
    }
}

pub(super) fn confirmation_page_saved_state_mismatch_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if !snapshot_has_confirmation_page_marker(snapshot) {
        return None;
    }

    let expectation = recent_dispatch_update_expectation(history);
    let assignment_summary = snapshot_confirmation_assignment_summary(snapshot);
    let status_summary = snapshot_confirmation_status_summary(snapshot);
    let note_summary = snapshot_confirmation_note_summary(snapshot);

    let mismatch = confirmation_summary_mismatch(
        assignment_summary.as_deref(),
        expectation.assignee.as_deref(),
        "the saved assignee",
    )
    .or_else(|| {
        confirmation_summary_mismatch(
            status_summary.as_deref(),
            expectation.status.as_deref(),
            "the saved status",
        )
    })
    .or_else(|| {
        confirmation_summary_mismatch(
            note_summary.as_deref(),
            expectation.note.as_deref(),
            "the saved note",
        )
    })?;

    let current_item = assignment_summary
        .as_deref()
        .and_then(first_item_like_id)
        .or_else(|| recent_goal_item_ids(history).into_iter().next());
    let item_clause = current_item
        .as_ref()
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();

    let reopen_button_id = snapshot_reopen_button_id(snapshot)?;
    Some(format!(
        "Use `{reopen_button_id}` now: the current confirmation page{item_clause} does not yet reflect the recent saved update because {mismatch}. Do not spend the next step on `browser__snapshot` or queue/history verification."
    ))
}

pub(super) fn dispatch_update_resume_clause(
    expectation: &DispatchUpdateExpectation,
) -> Option<String> {
    let mut values = Vec::new();
    if let Some(value) = expectation.assignee.as_deref() {
        values.push(format!("`{value}`"));
    }
    if let Some(value) = expectation.status.as_deref() {
        values.push(format!("`{value}`"));
    }
    if let Some(value) = expectation.note.as_deref() {
        values.push(format!("`{value}`"));
    }
    if values.is_empty() {
        return None;
    }

    Some(match values.len() {
        1 => format!("Reapply or verify {} on this page", values[0]),
        2 => format!(
            "Reapply or verify {} and {} on this page",
            values[0], values[1]
        ),
        _ => {
            let last = values.pop().unwrap_or_default();
            format!(
                "Reapply or verify {}, and {} on this page",
                values.join(", "),
                last
            )
        }
    })
}

pub(super) fn dispatch_update_review_clause(
    expectation: &DispatchUpdateExpectation,
) -> Option<String> {
    let mut values = Vec::new();
    if let Some(value) = expectation.assignee.as_deref() {
        values.push(format!("`{value}`"));
    }
    if let Some(value) = expectation.status.as_deref() {
        values.push(format!("`{value}`"));
    }
    if let Some(value) = expectation.note.as_deref() {
        values.push(format!("`{value}`"));
    }
    if values.is_empty() {
        return None;
    }

    Some(match values.len() {
        1 => format!("Verify the reviewed draft still shows {}", values[0]),
        2 => format!(
            "Verify the reviewed draft still shows {} and {}",
            values[0], values[1]
        ),
        _ => {
            let last = values.pop().unwrap_or_default();
            format!(
                "Verify the reviewed draft still shows {}, and {}",
                values.join(", "),
                last
            )
        }
    })
}

pub(super) fn reopened_draft_resume_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if !snapshot_contains_semantic_id(snapshot, "btn_review_update") {
        return None;
    }
    if recent_successful_click_semantic_id(history).as_deref() != Some("btn_reopen_ticket") {
        return None;
    }

    let expectation = recent_dispatch_update_expectation(history);
    let resume_clause = dispatch_update_resume_clause(&expectation)
        .unwrap_or_else(|| "Continue correcting the current draft on this page".to_string());
    let item_clause = snapshot_ticket_item_id(snapshot)
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();

    Some(format!(
        "The draft{item_clause} is reopened so the saved state can be corrected. Do not return to queue/history verification yet. {resume_clause}, then use `btn_review_update`."
    ))
}

pub(super) fn reviewed_draft_confirmation_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let confirm_button_id = snapshot_confirm_update_button_id(snapshot)?;
    if recent_successful_click_semantic_id(history).as_deref() != Some("btn_review_update") {
        return None;
    }

    let expectation = recent_dispatch_update_expectation(history);
    let review_clause = dispatch_update_review_clause(&expectation)
        .unwrap_or_else(|| "Verify the reviewed draft matches the intended update".to_string());
    let item_clause = snapshot_ticket_item_id(snapshot)
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();
    let edit_clause = snapshot_edit_draft_button_id(snapshot)
        .map(|edit_button_id| {
            format!(" Use `{edit_button_id}` instead only if the reviewed draft is wrong.")
        })
        .unwrap_or_default();

    Some(format!(
        "The reviewed draft{item_clause} is ready to be saved. {review_clause}, then use `{confirm_button_id}` now.{edit_clause} Do not return to queue/history verification until the draft is confirmed."
    ))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComparativeResultMetric {
    DurationMinutes,
    PriceAmount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComparativePreference {
    Min,
    Max,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ComparativeResultRequest {
    metric: ComparativeResultMetric,
    preference: ComparativePreference,
    adjective: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotComparativeAction {
    semantic_id: String,
    metric_value: u32,
    metric_display: String,
}

fn recent_requested_comparative_result(
    history: &[ChatMessage],
) -> Option<ComparativeResultRequest> {
    for message in history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
    {
        let lower = message.content.to_ascii_lowercase();
        if lower.contains("shortest") {
            return Some(ComparativeResultRequest {
                metric: ComparativeResultMetric::DurationMinutes,
                preference: ComparativePreference::Min,
                adjective: "shortest",
            });
        }
        if lower.contains("longest") {
            return Some(ComparativeResultRequest {
                metric: ComparativeResultMetric::DurationMinutes,
                preference: ComparativePreference::Max,
                adjective: "longest",
            });
        }
        if lower.contains("cheapest")
            || lower.contains("least expensive")
            || lower.contains("lowest price")
        {
            return Some(ComparativeResultRequest {
                metric: ComparativeResultMetric::PriceAmount,
                preference: ComparativePreference::Min,
                adjective: "cheapest",
            });
        }
        if lower.contains("most expensive") || lower.contains("highest price") {
            return Some(ComparativeResultRequest {
                metric: ComparativeResultMetric::PriceAmount,
                preference: ComparativePreference::Max,
                adjective: "most expensive",
            });
        }
    }

    None
}

fn parse_price_amount(text: &str) -> Option<u32> {
    let text = compact_ws_for_prompt(text);
    let chars = text.chars().collect::<Vec<_>>();
    for idx in 0..chars.len() {
        if chars[idx] != '$' {
            continue;
        }
        let digits = chars
            .iter()
            .skip(idx + 1)
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        if let Ok(value) = digits.parse::<u32>() {
            return Some(value);
        }
    }
    None
}

fn parse_duration_minutes(text: &str) -> Option<u32> {
    let tokens = compact_ws_for_prompt(text)
        .to_ascii_lowercase()
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                .to_string()
        })
        .collect::<Vec<_>>();
    for idx in 0..tokens.len() {
        let Some(hours) = tokens[idx]
            .strip_suffix('h')
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let minutes = tokens
            .get(idx + 1)
            .and_then(|token| token.strip_suffix('m'))
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        return Some(hours * 60 + minutes);
    }
    None
}

fn format_duration_minutes(value: u32) -> String {
    let hours = value / 60;
    let minutes = value % 60;
    if minutes == 0 {
        format!("{hours}h")
    } else {
        format!("{hours}h {minutes}m")
    }
}

fn parse_comparative_metric_from_text(
    text: &str,
    metric: ComparativeResultMetric,
) -> Option<(u32, String)> {
    match metric {
        ComparativeResultMetric::DurationMinutes => {
            parse_duration_minutes(text).map(|value| (value, format_duration_minutes(value)))
        }
        ComparativeResultMetric::PriceAmount => {
            parse_price_amount(text).map(|value| (value, format!("${value}")))
        }
    }
}

fn snapshot_local_comparative_metric_context(
    snapshot: &str,
    fragment: &str,
    target_semantic_id: &str,
) -> Option<String> {
    let selector = extract_browser_xml_attr(fragment, "selector")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty())?;
    let mut ancestor_selector = selector;

    while let Some((parent, _)) = ancestor_selector.rsplit_once(" > ") {
        ancestor_selector = parent.to_string();
        let mut row_text = Vec::new();
        let mut saw_non_action_text = false;

        for candidate in snapshot.split('<') {
            if candidate.contains(r#" visible="false""#) {
                continue;
            }

            let candidate_selector = extract_browser_xml_attr(candidate, "selector")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty());
            if candidate_selector
                .as_deref()
                .is_none_or(|value| !value.starts_with(&ancestor_selector))
            {
                continue;
            }

            let Some(text) = extract_browser_xml_attr(candidate, "name")
                .or_else(|| extract_browser_xml_attr(candidate, "text"))
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty())
            else {
                continue;
            };

            let candidate_id = extract_browser_xml_attr(candidate, "id")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
            let candidate_tag = browser_fragment_tag_name(candidate).unwrap_or_default();
            if candidate_id.as_deref() != Some(target_semantic_id)
                && !matches!(candidate_tag, "button" | "link")
            {
                saw_non_action_text = true;
            }
            row_text.push(text);
        }

        if saw_non_action_text && !row_text.is_empty() {
            return Some(row_text.join(" "));
        }
    }

    None
}

fn snapshot_neighbor_comparative_metric_context(
    fragments: &[&str],
    target_idx: usize,
) -> Option<String> {
    let mut texts = Vec::new();

    for idx in (0..target_idx).rev() {
        let fragment = fragments[idx];
        if fragment.contains(r#" visible="false""#) {
            continue;
        }

        let tag_name = browser_fragment_tag_name(fragment).unwrap_or_default();
        if matches!(tag_name, "button" | "link") {
            if !texts.is_empty() {
                break;
            }
            continue;
        }

        let Some(text) = extract_browser_xml_attr(fragment, "name")
            .or_else(|| extract_browser_xml_attr(fragment, "text"))
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        texts.push(text);
        if texts.len() == 8 {
            break;
        }
    }

    texts.reverse();

    for fragment in fragments.iter().skip(target_idx + 1) {
        if fragment.contains(r#" visible="false""#) {
            continue;
        }

        let tag_name = browser_fragment_tag_name(fragment).unwrap_or_default();
        if matches!(tag_name, "button" | "link") {
            break;
        }

        let Some(text) = extract_browser_xml_attr(fragment, "name")
            .or_else(|| extract_browser_xml_attr(fragment, "text"))
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        texts.push(text);
        if texts.len() == 8 {
            break;
        }
    }

    (!texts.is_empty()).then(|| texts.join(" "))
}

fn snapshot_visible_comparative_actions(
    snapshot: &str,
    request: ComparativeResultRequest,
) -> Vec<SnapshotComparativeAction> {
    let mut actions = Vec::new();
    let fragments = snapshot.split('<').collect::<Vec<_>>();

    for (idx, fragment) in fragments.iter().enumerate() {
        if fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(tag_name) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        let actionable =
            matches!(tag_name, "button" | "link") || fragment.contains(r#" dom_clickable="true""#);
        if !actionable {
            continue;
        }
        if fragment.contains(r#" omitted="true""#)
            && !browser_fragment_allows_omitted_action_target(fragment, tag_name)
        {
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
            .unwrap_or_default();
        let context = extract_browser_xml_attr(fragment, "context")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let combined = if context.is_empty() {
            name.clone()
        } else if name.is_empty() {
            context.clone()
        } else {
            format!("{name} {context}")
        };
        let metric = parse_comparative_metric_from_text(&combined, request.metric)
            .or_else(|| {
                snapshot_local_comparative_metric_context(snapshot, fragment, &semantic_id)
                    .and_then(|row_text| {
                        parse_comparative_metric_from_text(&row_text, request.metric)
                    })
            })
            .or_else(|| {
                snapshot_neighbor_comparative_metric_context(&fragments, idx).and_then(|row_text| {
                    parse_comparative_metric_from_text(&row_text, request.metric)
                })
            });
        let Some((metric_value, metric_display)) = metric else {
            continue;
        };

        actions.push(SnapshotComparativeAction {
            semantic_id,
            metric_value,
            metric_display,
        });
    }

    actions.sort_by(|left, right| {
        let metric_order = match request.preference {
            ComparativePreference::Min => left.metric_value.cmp(&right.metric_value),
            ComparativePreference::Max => right.metric_value.cmp(&left.metric_value),
        };
        metric_order.then_with(|| left.semantic_id.cmp(&right.semantic_id))
    });
    actions.dedup_by(|left, right| left.semantic_id == right.semantic_id);
    actions
}

pub(super) fn comparative_result_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let request = recent_requested_comparative_result(history)?;
    let actions = snapshot_visible_comparative_actions(snapshot, request);
    if actions.len() < 2 {
        return None;
    }

    let target = actions.first()?;
    if recent_successful_click_has_post_action_observation(
        history,
        &target.semantic_id,
        current_snapshot,
    ) {
        return None;
    }

    let options = actions
        .iter()
        .take(4)
        .map(|action| format!("`{}` ({})", action.semantic_id, action.metric_display))
        .collect::<Vec<_>>()
        .join(", ");
    let instruction_clause = snapshot_visible_goal_text_target(snapshot, history)
        .filter(|candidate| {
            matches!(
                candidate.semantic_role.as_str(),
                "generic" | "label" | "text" | "heading"
            )
        })
        .map(|candidate| {
            format!(
                " `{}` is just goal text on this page, not the comparative action to click.",
                candidate.semantic_id
            )
        })
        .unwrap_or_default();

    Some(format!(
        "Goal asks for the {} visible option. Metric-bearing actions on this page are: {}. Use `browser__click_element` on `{}` now because it has the {} {}. Do not spend the next step on `browser__snapshot` or a text-only destination token.{}",
        request.adjective,
        options,
        target.semantic_id,
        request.adjective,
        target.metric_display,
        instruction_clause,
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestedCalendarDate {
    month: u8,
    day: u8,
    year: u16,
}

impl RequestedCalendarDate {
    fn display(&self) -> String {
        format!("{:02}/{:02}/{:04}", self.month, self.day, self.year)
    }

    fn month_year_label(&self) -> &'static str {
        const MONTH_NAMES: [&str; 12] = [
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ];

        MONTH_NAMES
            .get(self.month.saturating_sub(1) as usize)
            .copied()
            .unwrap_or("Unknown")
    }

    fn month_year_display(&self) -> String {
        format!("{} {}", self.month_year_label(), self.year)
    }
}

fn parse_requested_calendar_date_token(token: &str) -> Option<RequestedCalendarDate> {
    let trimmed =
        token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '/' && ch != '-');
    let delimiter = if trimmed.contains('/') {
        '/'
    } else if trimmed.contains('-') {
        '-'
    } else {
        return None;
    };
    let mut parts = trimmed.split(delimiter);
    let month = parts.next()?.parse::<u8>().ok()?;
    let day = parts.next()?.parse::<u8>().ok()?;
    let year = parts.next()?.parse::<u16>().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    Some(RequestedCalendarDate { month, day, year })
}

fn recent_goal_requested_calendar_date(history: &[ChatMessage]) -> Option<RequestedCalendarDate> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| {
            message
                .content
                .split_whitespace()
                .find_map(parse_requested_calendar_date_token)
        })
}

fn parse_calendar_month_year(name: &str) -> Option<(u8, u16)> {
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

    let lower = name.to_ascii_lowercase();
    let month = MONTH_NAMES
        .iter()
        .position(|month| lower.contains(month))
        .map(|idx| idx as u8 + 1)?;
    let year = lower.split_whitespace().find_map(|token| {
        let digits = token.trim_matches(|ch: char| !ch.is_ascii_digit());
        (digits.len() == 4)
            .then(|| digits.parse::<u16>().ok())
            .flatten()
    })?;
    Some((month, year))
}

fn snapshot_visible_calendar_month_year(snapshot: &str) -> Option<(String, u8, u16)> {
    for fragment in snapshot.split('<') {
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some((month, year)) = parse_calendar_month_year(&name) else {
            continue;
        };
        return Some((name, month, year));
    }

    None
}

fn snapshot_visible_calendar_navigation_id(snapshot: &str, previous: bool) -> Option<String> {
    let expected = if previous { "prev" } else { "next" };
    for fragment in snapshot.split('<') {
        let Some(id) = extract_browser_xml_attr(fragment, "id") else {
            continue;
        };
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(tag_name) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(tag_name, "link" | "button") {
            continue;
        }
        if name.eq_ignore_ascii_case(expected) {
            return Some(id);
        }
    }

    None
}

fn snapshot_visible_calendar_day_id(snapshot: &str, day: u8) -> Option<String> {
    let expected = day.to_string();
    for fragment in snapshot.split('<') {
        let Some(id) = extract_browser_xml_attr(fragment, "id") else {
            continue;
        };
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(tag_name) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(tag_name, "link" | "button") {
            continue;
        }
        if name == expected {
            return Some(id);
        }
    }

    None
}

const CALENDAR_CLICK_SEQUENCE_DELAY_MS: u64 = 120;
const CALENDAR_CLICK_SEQUENCE_MAX_NAV_STEPS: i32 = 24;

fn format_click_sequence_ids(ids: &[String]) -> String {
    ids.iter()
        .map(|id| format!("`{id}`"))
        .collect::<Vec<_>>()
        .join(", ")
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
struct SnapshotDateEntryControl {
    semantic_id: String,
    dom_id: Option<String>,
    selector: String,
    value: Option<String>,
    readonly: bool,
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

fn text_has_date_field_hint(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("datepicker") || lower.contains("hasdatepicker") {
        return true;
    }

    lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| matches!(token, "date" | "day" | "month" | "year"))
}

fn snapshot_visible_date_entry_control(snapshot: &str) -> Option<SnapshotDateEntryControl> {
    for fragment in snapshot.split('<') {
        let Some(tag_name) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(tag_name, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(selector) = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let class_name = extract_browser_xml_attr(fragment, "class_name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();

        let date_like = [
            semantic_id.as_str(),
            name.as_str(),
            dom_id.as_deref().unwrap_or_default(),
            selector.as_str(),
            class_name.as_str(),
        ]
        .into_iter()
        .any(text_has_date_field_hint);
        if !date_like {
            continue;
        }

        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let readonly = extract_browser_xml_attr(fragment, "readonly")
            .map(|value| decode_browser_xml_text(&value).trim().to_ascii_lowercase())
            .is_some_and(|value| value.is_empty() || value == "true" || value == "readonly")
            || extract_browser_xml_attr(fragment, "aria_readonly")
                .map(|value| decode_browser_xml_text(&value).trim().to_ascii_lowercase())
                .is_some_and(|value| value == "true")
            || extract_browser_xml_attr(fragment, "aria-readonly")
                .map(|value| decode_browser_xml_text(&value).trim().to_ascii_lowercase())
                .is_some_and(|value| value == "true");

        return Some(SnapshotDateEntryControl {
            semantic_id,
            dom_id,
            selector,
            value,
            readonly,
        });
    }

    None
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

fn normalized_date_entry_locator(value: &str) -> String {
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

fn date_entry_locator_matches(
    selector: Option<&str>,
    dom_id: Option<&str>,
    control: &SnapshotDateEntryControl,
) -> bool {
    if dom_id
        .zip(control.dom_id.as_deref())
        .is_some_and(|(left, right)| left == right)
    {
        return true;
    }

    let control_selector = normalized_date_entry_locator(&control.selector);
    selector.is_some_and(|selector| normalized_date_entry_locator(selector) == control_selector)
        || selector
            .zip(control.dom_id.as_deref())
            .is_some_and(|(selector, dom_id)| {
                normalized_date_entry_locator(selector) == normalized_date_entry_locator(dom_id)
            })
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

fn recent_successful_click_semantic_id_index(
    history: &[ChatMessage],
    semantic_id: &str,
) -> Option<usize> {
    history.iter().enumerate().rev().find_map(|(idx, message)| {
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

        (clicked_element_semantic_id(message).as_deref() == Some(semantic_id)).then_some(idx)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestedClickSequence {
    first_target: String,
    second_target: String,
    delay_ms_between_ids: Option<u64>,
}

fn parse_click_sequence_delay_ms(raw: &str) -> Option<u64> {
    let compact = compact_ws_for_prompt(raw);
    let trimmed = compact.trim().trim_matches(|ch: char| {
        matches!(
            ch,
            '.' | ',' | ';' | ':' | '"' | '\'' | '`' | '(' | ')' | '[' | ']'
        )
    });
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let value = parts.next()?.parse::<u64>().ok()?;
    let unit = parts.next().unwrap_or("ms").to_ascii_lowercase();
    match unit.as_str() {
        "ms" | "msec" | "millisecond" | "milliseconds" => Some(value),
        "s" | "sec" | "secs" | "second" | "seconds" => value.checked_mul(1_000),
        _ => None,
    }
}

fn normalize_click_sequence_target(raw: &str) -> Option<String> {
    let mut target = trim_goal_target_value(raw)?;

    loop {
        let trimmed = target.trim();
        let trimmed_lower = trimmed.to_ascii_lowercase();
        let mut stripped: Option<&str> = None;
        for prefix in [
            "the ",
            "a ",
            "an ",
            "button ",
            "buttons ",
            "link ",
            "links ",
            "tab ",
            "tabs ",
            "checkbox ",
            "checkboxes ",
            "radio ",
            "radios ",
            "option ",
            "options ",
            "item ",
            "items ",
            "result ",
            "results ",
        ] {
            if trimmed_lower.starts_with(prefix) {
                stripped = Some(trimmed[prefix.len()..].trim_start());
                break;
            }
        }

        let Some(next) = stripped else {
            return trim_goal_target_value(trimmed);
        };
        target = next.to_string();
    }
}

fn extract_requested_click_sequence(text: &str) -> Option<RequestedClickSequence> {
    let compact = compact_ws_for_prompt(text);
    let lower = compact.to_ascii_lowercase();
    let first_click_idx = lower.find("click ")?;
    let after_first_idx = first_click_idx + "click ".len();
    let after_first = &compact[after_first_idx..];
    let after_first_lower = &lower[after_first_idx..];
    let then_click_relative_idx = after_first_lower.find(" then click ")?;

    let first_segment = after_first[..then_click_relative_idx].trim();
    let second_segment = after_first[then_click_relative_idx + " then click ".len()..].trim();
    let mut first_target_segment = first_segment;
    let mut delay_ms_between_ids = None;

    if let Some(wait_relative_idx) = first_segment.to_ascii_lowercase().rfind(" wait ") {
        first_target_segment = first_segment[..wait_relative_idx]
            .trim_end()
            .trim_end_matches(',')
            .trim_end();
        let delay_segment = first_segment[wait_relative_idx + " wait ".len()..]
            .trim_start_matches(',')
            .trim();
        delay_ms_between_ids = parse_click_sequence_delay_ms(delay_segment);
        if delay_ms_between_ids.is_none() {
            return None;
        }
    }

    let second_end = second_segment
        .find(['.', ',', ';', '\n', '!', '?'])
        .unwrap_or(second_segment.len());
    let first_target = normalize_click_sequence_target(first_target_segment)?;
    let second_target = normalize_click_sequence_target(&second_segment[..second_end])?;
    if normalized_exact_target_text(&first_target) == normalized_exact_target_text(&second_target) {
        return None;
    }

    Some(RequestedClickSequence {
        first_target,
        second_target,
        delay_ms_between_ids,
    })
}

fn recent_typed_text_match_index(
    history: &[ChatMessage],
    control: &SnapshotDateEntryControl,
    target_value: &str,
) -> Option<usize> {
    history.iter().enumerate().rev().find_map(|(idx, message)| {
        if message.role != "tool" {
            return None;
        }

        let payload = parse_json_value_from_message(&message.content)?;
        let typed = payload.get("typed")?;
        let value = typed
            .get("value")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty())?;
        if value != target_value {
            return None;
        }

        let dom_id = typed
            .get("dom_id")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty());
        let selector = typed
            .get("selector")
            .and_then(Value::as_str)
            .map(compact_ws_for_prompt)
            .filter(|value| !value.is_empty());

        date_entry_locator_matches(selector.as_deref(), dom_id.as_deref(), control).then_some(idx)
    })
}

fn recent_typed_text_matches_control(
    history: &[ChatMessage],
    control: &SnapshotDateEntryControl,
    target_value: &str,
) -> bool {
    recent_typed_text_match_index(history, control, target_value).is_some()
}

pub(super) fn direct_date_entry_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let target = recent_goal_requested_calendar_date(history)?;
    let target_value = target.display();
    let control = snapshot_visible_date_entry_control(snapshot)?;
    let submit_id = snapshot_visible_submit_control_id(snapshot);
    let typed_target_index = recent_typed_text_match_index(history, &control, &target_value);
    let typed_target_value = typed_target_index.is_some();
    let submit_clicked_after_grounded = submit_id
        .as_deref()
        .and_then(|submit_id| recent_successful_click_semantic_id_index(history, submit_id))
        .zip(typed_target_index)
        .is_some_and(|(submit_idx, typed_idx)| submit_idx > typed_idx);

    if typed_target_value && submit_clicked_after_grounded {
        return None;
    }

    if control.value.as_deref() == Some(target_value.as_str()) || typed_target_value {
        let submit_id = submit_id?;
        return Some(format!(
            "The date field `{}` is already grounded to `{}`. Use `browser__click_element` on `{}` now. Do not spend the next step on calendar navigation, another `browser__type`, or another `browser__snapshot`.",
            control.semantic_id,
            target_value,
            submit_id,
        ));
    }

    if control.readonly {
        if snapshot_visible_calendar_month_year(snapshot).is_some() {
            return None;
        }
        if let Some(submit_id) = submit_id {
            return Some(format!(
                "Goal date is explicit (`{}`). The visible date field `{}` is readonly and calendar-backed. Use `browser__click_element` on `{}` now to open the calendar, then choose the date before clicking `{}`. Do not use `browser__type` on `{}` or submit yet.",
                target_value,
                control.semantic_id,
                control.semantic_id,
                submit_id,
                control.semantic_id,
            ));
        }
        return Some(format!(
            "Goal date is explicit (`{}`). The visible date field `{}` is readonly and calendar-backed. Use `browser__click_element` on `{}` now to open the calendar. Do not use `browser__type` on `{}`.",
            target_value,
            control.semantic_id,
            control.semantic_id,
            control.semantic_id,
        ));
    }

    if let Some(submit_id) = submit_id {
        return Some(format!(
            "Goal date is explicit (`{}`). The visible date field `{}` supports direct entry via selector `{}`. Use `browser__type` with selector `{}` and text `{}` now, then click `{}`. Do not spend more steps on calendar navigation or another `browser__snapshot`.",
            target_value,
            control.semantic_id,
            control.selector,
            control.selector,
            target_value,
            submit_id,
        ));
    }

    Some(format!(
        "Goal date is explicit (`{}`). The visible date field `{}` supports direct entry via selector `{}`. Use `browser__type` with selector `{}` and text `{}` now. Do not spend more steps on calendar navigation or another `browser__snapshot`.",
        target_value,
        control.semantic_id,
        control.selector,
        control.selector,
        target_value,
    ))
}

pub(super) fn calendar_date_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let target = recent_goal_requested_calendar_date(history)?;
    let target_value = target.display();
    let submit_id = snapshot_visible_submit_control_id(snapshot);

    if let Some(control) = snapshot_visible_date_entry_control(snapshot) {
        let grounded = control.value.as_deref() == Some(target_value.as_str())
            || recent_typed_text_matches_control(history, &control, &target_value);
        if grounded {
            let submit_clicked_after_grounded = submit_id
                .as_deref()
                .and_then(|submit_id| recent_successful_click_semantic_id_index(history, submit_id))
                .zip(recent_typed_text_match_index(
                    history,
                    &control,
                    &target_value,
                ))
                .is_some_and(|(submit_idx, typed_idx)| submit_idx > typed_idx);
            if submit_clicked_after_grounded {
                return None;
            }

            if let Some(submit_id) = submit_id {
                return Some(format!(
                    "The date field `{}` is already grounded to `{}`. Use `browser__click_element` on `{}` now. Do not spend the next step on calendar navigation, another `browser__type`, or another `browser__snapshot`.",
                    control.semantic_id,
                    target_value,
                    submit_id,
                ));
            }

            return None;
        }
    }

    let (visible_label, visible_month, visible_year) =
        snapshot_visible_calendar_month_year(snapshot)?;
    let visible_ordinal = i32::from(visible_year) * 12 + i32::from(visible_month);
    let target_ordinal = i32::from(target.year) * 12 + i32::from(target.month);

    if visible_ordinal != target_ordinal {
        let use_previous = visible_ordinal > target_ordinal;
        let nav_id = snapshot_visible_calendar_navigation_id(snapshot, use_previous)?;
        let nav_steps = (visible_ordinal - target_ordinal).abs();
        if nav_steps <= CALENDAR_CLICK_SEQUENCE_MAX_NAV_STEPS {
            if let Some(day_id) = snapshot_visible_calendar_day_id(snapshot, target.day) {
                let mut ids = vec![nav_id.clone(); nav_steps as usize];
                ids.push(day_id.clone());
                if let Some(submit_id) = submit_id.clone() {
                    let submit_target = submit_id.clone();
                    ids.push(submit_id);
                    let ids_display = format_click_sequence_ids(&ids);
                    return Some(format!(
                        "Goal date is `{}`, but the visible calendar still shows `{}`. The month navigation and requested day are already grounded as `{}` repeated {} time(s) followed by `{}` and `{}`. Use `browser__click_element` with `ids` [{ids_display}] and `delay_ms_between_ids` {} now so month navigation, day selection, and submit stay inside one execution boundary. Do not reopen the date field or spend the next step on another `browser__snapshot`.",
                        target.display(),
                        visible_label,
                        nav_id,
                        nav_steps,
                        day_id,
                        submit_target,
                        CALENDAR_CLICK_SEQUENCE_DELAY_MS,
                    ));
                }

                let ids_display = format_click_sequence_ids(&ids);
                return Some(format!(
                    "Goal date is `{}`, but the visible calendar still shows `{}`. The month navigation and requested day are already grounded as `{}` repeated {} time(s) followed by `{}`. Use `browser__click_element` with `ids` [{ids_display}] and `delay_ms_between_ids` {} now so month navigation and day selection stay inside one execution boundary. Do not reopen the date field or spend the next step on another `browser__snapshot`.",
                    target.display(),
                    visible_label,
                    nav_id,
                    nav_steps,
                    day_id,
                    CALENDAR_CLICK_SEQUENCE_DELAY_MS,
                ));
            }
        }

        return Some(format!(
            "Goal date is `{}`, but the visible calendar still shows `{}`. Use `browser__click_element` on `{}`{} to reach `{}`. Do not reopen the date field{}, and do not spend the next step on another `browser__snapshot`.",
            target.display(),
            visible_label,
            nav_id,
            (recent_successful_click_semantic_id(history).as_deref() == Some(nav_id.as_str()))
                .then_some(" again")
                .unwrap_or(""),
            target.month_year_display(),
            submit_id
                .as_deref()
                .map(|id| format!(", do not click `{id}` yet"))
                .unwrap_or_default(),
        ));
    }

    let day_id = snapshot_visible_calendar_day_id(snapshot, target.day)?;
    if recent_successful_click_semantic_id(history).as_deref() == Some(day_id.as_str()) {
        if let Some(submit_id) = submit_id {
            return Some(format!(
                "The requested date `{}` is already selected. Use `browser__click_element` on `{}` now. Do not spend the next step on another `browser__snapshot`.",
                target.display(),
                submit_id,
            ));
        }
        return None;
    }

    if let Some(submit_id) = submit_id {
        let ids = vec![day_id.clone(), submit_id.clone()];
        let ids_display = format_click_sequence_ids(&ids);
        return Some(format!(
            "The visible calendar already shows `{}`, and requested day `{}` is available as `{}`. Use `browser__click_element` with `ids` [{ids_display}] and `delay_ms_between_ids` {} now so the date selection and submit stay inside one execution boundary. Do not spend the next step on another `browser__snapshot`.",
            target.month_year_display(),
            target.day,
            day_id,
            CALENDAR_CLICK_SEQUENCE_DELAY_MS,
        ));
    }

    Some(format!(
        "The visible calendar already shows `{}`, and requested day `{}` is available as `{}`. Use `browser__click_element` on `{}` now. Do not spend the next step on another `browser__snapshot`.",
        target.month_year_display(),
        target.day,
        day_id,
        day_id,
    ))
}

pub(super) fn ordered_click_sequence_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    if recent_successful_click_semantic_id(history).is_some() {
        return None;
    }

    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let sequence = history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| extract_requested_click_sequence(&message.content))?;
    let first = snapshot_visible_exact_text_target(snapshot, &sequence.first_target)?;
    let second = snapshot_visible_exact_text_target(snapshot, &sequence.second_target)?;
    if first.semantic_id == second.semantic_id {
        return None;
    }

    let ids = format!("`{}`", first.semantic_id) + ", " + &format!("`{}`", second.semantic_id);
    if let Some(delay_ms_between_ids) = sequence.delay_ms_between_ids {
        return Some(format!(
            "The requested click sequence is already grounded: `{}` -> `{}` are visible as `{}` and `{}`. Use `browser__click_element` with `ids` [{ids}] and `delay_ms_between_ids` {} now so the timed sequence executes without another inference turn. Do not spend the next step on only the first click or another `browser__snapshot`.",
            sequence.first_target,
            sequence.second_target,
            first.semantic_id,
            second.semantic_id,
            delay_ms_between_ids,
        ));
    }

    Some(format!(
        "The requested click sequence is already grounded: `{}` -> `{}` are visible as `{}` and `{}`. Use `browser__click_element` with `ids` [{ids}] now instead of spending separate steps on the individual clicks or another `browser__snapshot`.",
        sequence.first_target,
        sequence.second_target,
        first.semantic_id,
        second.semantic_id,
    ))
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
            } else if lower.contains("draw")
                || lower.contains("trace")
                || lower.contains("create a line")
                || lower.contains("draw a line")
                || lower.contains("line that bisect")
                || lower.contains("bisect the angle")
            {
                Some(PointerHoldGoalKind::Draw)
            } else if lower.contains("resize") {
                Some(PointerHoldGoalKind::Resize)
            } else if lower.contains("slider") {
                Some(PointerHoldGoalKind::Slider)
            } else if lower.contains("color wheel") || lower.contains("colorwheel") {
                Some(PointerHoldGoalKind::ColorWheel)
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

pub(super) fn pointer_submit_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let goal_kind = recent_pointer_hold_goal_kind(history)?;
    if recent_goal_likely_needs_multiple_pointer_commits(history) {
        return None;
    }

    let latest_action = recent_pointer_action_state(history)?;
    if latest_action.action != "mouse_up" {
        return None;
    }

    if goal_kind == PointerHoldGoalKind::Draw {
        if let Some(signal) = pointer_trace_geometry_follow_up_signal(history, snapshot) {
            return Some(signal);
        }
    }

    if recent_pointer_gesture_released_without_motion(history) {
        let retry_instruction = match goal_kind {
            PointerHoldGoalKind::Drag => {
                "The drag gesture was released without any movement after press. Start it again with `browser__mouse_down`, move to the intended drop target with `browser__move_mouse` or `browser__hover`, then finish with `browser__mouse_up`. Do not click submit yet."
            }
            PointerHoldGoalKind::Draw => {
                "The pointer trace was released without any movement after press. Start it again with `browser__mouse_down`, extend it with `browser__move_mouse` or `browser__hover`, then finish with `browser__mouse_up`. Do not click submit yet."
            }
            PointerHoldGoalKind::Resize => {
                "The resize gesture was released without any movement after press. Start it again with `browser__mouse_down`, move with `browser__move_mouse` or `browser__hover` until the requested size is reached, then finish with `browser__mouse_up`. Do not click submit yet."
            }
            PointerHoldGoalKind::Slider => {
                "The slider gesture was released without any movement after press. Start it again with `browser__mouse_down`, move with `browser__move_mouse` or `browser__hover` until the requested value is reached, then finish with `browser__mouse_up`. Do not click submit yet."
            }
            PointerHoldGoalKind::ColorWheel => {
                "The color-wheel gesture was released without any movement after press. Start it again with `browser__mouse_down`, move with `browser__move_mouse` or `browser__hover` to the requested color position, then finish with `browser__mouse_up`. Do not click submit yet."
            }
        };
        return Some(retry_instruction.to_string());
    }

    let submit_id = snapshot_visible_submit_control_id(snapshot)?;
    if recent_successful_click_has_post_action_observation(history, &submit_id, current_snapshot) {
        return None;
    }

    Some(format!(
        "The pointer gesture is finished, but this task page still has submit control `{submit_id}`. If the gesture already matches the goal, use `browser__click_element` on `{submit_id}` now to commit it. Do not call `agent__complete` while the page is still waiting for submission."
    ))
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
    let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
        && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");
    if compact.contains("\"typed\":{") && compact.contains("\"already_satisfied\":true") {
        return Some(
            "A recent browser typing action found that the targeted field already contained the requested text. Do not type the same text into that field again. Continue with the next required control or verify the updated page state if needed.".to_string(),
        );
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
        let mut signal = "A recent browser synthetic click already caused observable state change (`postcondition.met=true`). Do not keep clicking nearby drawing anchors unless the current geometry is clearly wrong.".to_string();
        if let Some(snapshot) = snapshot {
            let next_controls = next_visible_follow_up_controls(snapshot, &[]);
            if !next_controls.is_empty() {
                signal.push_str(&format!(
                    " Continue with a visible control such as `{}`.",
                    next_controls.join("`, `")
                ));
            } else {
                signal.push_str(
                    " Verify once if needed, then continue with the next required visible control.",
                );
            }
        } else {
            signal.push_str(
                " Verify once if needed, then continue with the next required visible control.",
            );
        }
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
        return Some(
            "The identical action already succeeded on the previous step. Do not repeat it. Verify the updated state or finish with the gathered evidence.".to_string(),
        );
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"key\":\"Home\"") || compact.contains("\"key\":\"PageUp\""))
        && compact.contains("\"scroll_top\":0")
        && compact.contains("\"can_scroll_up\":false")
    {
        return Some(
            "A recent browser key already moved the focused scrollable control to its top edge. Do not repeat the same key. Verify once if needed, then continue with the next required action or finish if the goal is satisfied.".to_string(),
        );
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"key\":\"End\"") || compact.contains("\"key\":\"PageDown\""))
        && compact.contains("\"can_scroll_down\":false")
    {
        return Some(
            "A recent browser key already moved the focused scrollable control to its bottom edge. Do not repeat the same key. Verify once if needed, then continue with the next required action or finish if the goal is satisfied.".to_string(),
        );
    }

    None
}

fn recent_synthetic_click_point(message: &ChatMessage) -> Option<(f64, f64)> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if compact.contains("\"synthetic_click\":{") {
        let x =
            extract_scoped_compact_jsonish_number_field(&compact, "\"synthetic_click\":{", "x")?;
        let y =
            extract_scoped_compact_jsonish_number_field(&compact, "\"synthetic_click\":{", "y")?;
        return Some((x, y));
    }

    let start = compact.find("Synthetic click at (")? + "Synthetic click at (".len();
    let remainder = &compact[start..];
    let end = remainder.find(')')?;
    let (x, y) = remainder[..end].split_once(',')?;
    Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
}

fn recent_synthetic_click_message(history: &[ChatMessage]) -> Option<&ChatMessage> {
    history
        .iter()
        .rev()
        .find(|message| recent_synthetic_click_point(message).is_some())
}

fn parse_geometry_point(text: &str) -> Option<(f64, f64)> {
    let (x, y) = text.split_once(',')?;
    Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
}

fn parse_geometry_point_list_attr(
    fragment: &str,
    precise_attr: &str,
    fallback_attr: &str,
) -> Vec<(f64, f64)> {
    extract_browser_xml_attr(fragment, precise_attr)
        .or_else(|| extract_browser_xml_attr(fragment, fallback_attr))
        .map(|value| {
            value
                .split('|')
                .filter_map(parse_geometry_point)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_geometry_angle_list_attr(
    fragment: &str,
    precise_attr: &str,
    fallback_attr: &str,
) -> Vec<f64> {
    extract_browser_xml_attr(fragment, precise_attr)
        .or_else(|| extract_browser_xml_attr(fragment, fallback_attr))
        .map(|value| {
            value
                .split('|')
                .filter_map(|part| part.parse::<f64>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn round_geometry_display_value(value: f64) -> f64 {
    ((value * 10.0).round()) / 10.0
}

fn round_geometry_tool_call_value(value: f64) -> f64 {
    ((value * 1_000_000.0).round()) / 1_000_000.0
}

const GEOMETRY_SUBMIT_MAX_ERROR_DEG: f64 = 0.25;

fn fragment_geometry_center_point(fragment: &str) -> Option<(f64, f64)> {
    let center_x = extract_browser_xml_attr(fragment, "center_x_precise")
        .or_else(|| extract_browser_xml_attr(fragment, "center_x"))?
        .parse::<f64>()
        .ok()?;
    let center_y = extract_browser_xml_attr(fragment, "center_y_precise")
        .or_else(|| extract_browser_xml_attr(fragment, "center_y"))?
        .parse::<f64>()
        .ok()?;
    Some((center_x, center_y))
}

fn fragment_is_endpoint_circle(fragment: &str) -> bool {
    if extract_browser_xml_attr(fragment, "geometry_role").as_deref() != Some("endpoint") {
        return false;
    }

    matches!(
        extract_browser_xml_attr(fragment, "shape_kind").as_deref(),
        Some("circle") | Some("ellipse")
    )
}

fn format_geometry_angle_sequence(angles: &[f64]) -> String {
    angles
        .iter()
        .map(|angle| format_prompt_number(round_geometry_display_value(*angle)))
        .collect::<Vec<_>>()
        .join("|")
}

#[derive(Clone, Copy)]
struct SnapshotBisectorObservedEndpoint {
    point: (f64, f64),
    angle_deg: f64,
}

fn snapshot_explicit_bisector_endpoints(
    snapshot: &str,
    vertex_semantic_id: &str,
    vertex_center: (f64, f64),
) -> Vec<SnapshotBisectorObservedEndpoint> {
    snapshot
        .split('<')
        .filter(|fragment| {
            extract_browser_xml_attr(fragment, "id")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .as_deref()
                != Some(vertex_semantic_id)
        })
        .filter(|fragment| fragment_is_endpoint_circle(fragment))
        .filter_map(|fragment| {
            let point = fragment_geometry_center_point(fragment)?;
            let angle_deg = (point.1 - vertex_center.1)
                .atan2(point.0 - vertex_center.0)
                .to_degrees();
            if !angle_deg.is_finite() {
                return None;
            }

            Some(SnapshotBisectorObservedEndpoint { point, angle_deg })
        })
        .collect()
}

struct SnapshotBisectorGeometryCandidate {
    semantic_id: String,
    connected_line_angles_deg: String,
    connected_points: Vec<(f64, f64)>,
    candidate_index: usize,
    target_mid_deg: f64,
    candidate_error_deg: f64,
}

fn snapshot_bisector_candidate_from_geometry(
    semantic_id: String,
    connected_line_angles_deg: String,
    angles: Vec<f64>,
    connected_points: Vec<(f64, f64)>,
) -> Option<SnapshotBisectorGeometryCandidate> {
    if angles.len() < 3 || (!connected_points.is_empty() && connected_points.len() != angles.len())
    {
        return None;
    }

    let min_angle = angles.iter().copied().fold(f64::INFINITY, f64::min);
    let max_angle = angles.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if !min_angle.is_finite() || !max_angle.is_finite() || max_angle <= min_angle {
        return None;
    }

    let target_mid_deg = (min_angle + max_angle) / 2.0;
    let candidate_index = angles
        .iter()
        .enumerate()
        .filter(|(_, angle)| (**angle - min_angle).abs() > f64::EPSILON)
        .filter(|(_, angle)| (**angle - max_angle).abs() > f64::EPSILON)
        .min_by(|(_, left), (_, right)| {
            (*left - target_mid_deg)
                .abs()
                .partial_cmp(&(*right - target_mid_deg).abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(index, _)| index)
        .unwrap_or_else(|| {
            angles
                .iter()
                .enumerate()
                .min_by(|(_, left), (_, right)| {
                    (*left - target_mid_deg)
                        .abs()
                        .partial_cmp(&(*right - target_mid_deg).abs())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(index, _)| index)
                .unwrap_or(0)
        });
    let candidate_angle = angles
        .get(candidate_index)
        .copied()
        .unwrap_or(target_mid_deg);
    let candidate_error_deg = (candidate_angle - target_mid_deg).abs();

    Some(SnapshotBisectorGeometryCandidate {
        semantic_id,
        connected_line_angles_deg,
        connected_points,
        candidate_index,
        target_mid_deg,
        candidate_error_deg,
    })
}

fn snapshot_bisector_geometry_candidate(
    snapshot: &str,
) -> Option<SnapshotBisectorGeometryCandidate> {
    snapshot
        .split('<')
        .filter_map(|fragment| {
            if !fragment.contains(r#" geometry_role="vertex""#) {
                return None;
            }

            let connected_lines = extract_browser_xml_attr(fragment, "connected_lines")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if connected_lines < 3 {
                return None;
            }

            let semantic_id = extract_browser_xml_attr(fragment, "id")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "grounded vertex".to_string());

            if let Some(vertex_center) = fragment_geometry_center_point(fragment) {
                let explicit_endpoints =
                    snapshot_explicit_bisector_endpoints(snapshot, &semantic_id, vertex_center);
                if explicit_endpoints.len() >= 3 {
                    let angles = explicit_endpoints
                        .iter()
                        .map(|endpoint| endpoint.angle_deg)
                        .collect::<Vec<_>>();
                    let connected_points = explicit_endpoints
                        .iter()
                        .map(|endpoint| endpoint.point)
                        .collect::<Vec<_>>();
                    let connected_line_angles_deg = format_geometry_angle_sequence(&angles);

                    if let Some(candidate) = snapshot_bisector_candidate_from_geometry(
                        semantic_id.clone(),
                        connected_line_angles_deg,
                        angles,
                        connected_points,
                    ) {
                        return Some(candidate);
                    }
                }
            }

            let connected_line_angles_deg =
                extract_browser_xml_attr(fragment, "connected_line_angles_deg").unwrap_or_default();
            let angles = parse_geometry_angle_list_attr(
                fragment,
                "connected_line_angles_deg_precise",
                "connected_line_angles_deg",
            );
            let connected_points = parse_geometry_point_list_attr(
                fragment,
                "connected_points_precise",
                "connected_points",
            );

            snapshot_bisector_candidate_from_geometry(
                semantic_id,
                connected_line_angles_deg,
                angles,
                connected_points,
            )
        })
        .min_by(|left, right| {
            left.candidate_error_deg
                .partial_cmp(&right.candidate_error_deg)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

fn snapshot_fragment_for_semantic_id<'a>(snapshot: &'a str, semantic_id: &str) -> Option<&'a str> {
    snapshot.split('<').find(|fragment| {
        extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .as_deref()
            == Some(semantic_id)
    })
}

fn pointer_trace_geometry_follow_up_signal(
    history: &[ChatMessage],
    snapshot: &str,
) -> Option<String> {
    let candidate = snapshot_bisector_geometry_candidate(snapshot)?;
    let rounded_mid = ((candidate.target_mid_deg * 10.0).round()) / 10.0;
    let rounded_error = ((candidate.candidate_error_deg * 10.0).round()) / 10.0;

    let correction_signal = recent_pointer_release_point(history)
        .zip(candidate.connected_points.get(candidate.candidate_index).copied())
        .and_then(|((release_x, release_y), (observed_x, observed_y))| {
            if candidate.candidate_error_deg <= GEOMETRY_SUBMIT_MAX_ERROR_DEG {
                return None;
            }

            let fragment = snapshot_fragment_for_semantic_id(snapshot, &candidate.semantic_id)?;
            let (center_x, center_y) = fragment_geometry_center_point(fragment)?;
            let release_offset_x = observed_x - release_x;
            let release_offset_y = observed_y - release_y;
            let release_offset_magnitude =
                (release_offset_x * release_offset_x + release_offset_y * release_offset_y).sqrt();
            if !release_offset_magnitude.is_finite() || release_offset_magnitude < 0.75 {
                return None;
            }

            let candidate_radius =
                ((observed_x - center_x).powi(2) + (observed_y - center_y).powi(2)).sqrt();
            if !candidate_radius.is_finite() || candidate_radius <= 0.01 {
                return None;
            }

            let target_mid_radians = candidate.target_mid_deg.to_radians();
            let desired_x = center_x + candidate_radius * target_mid_radians.cos();
            let desired_y = center_y + candidate_radius * target_mid_radians.sin();
            let corrected_click_x = desired_x - release_offset_x;
            let corrected_click_y = desired_y - release_offset_y;
            let rounded_observed_x = round_geometry_display_value(observed_x);
            let rounded_observed_y = round_geometry_display_value(observed_y);
            let rounded_release_x = round_geometry_display_value(release_x);
            let rounded_release_y = round_geometry_display_value(release_y);
            let rounded_offset_x = round_geometry_display_value(release_offset_x);
            let rounded_offset_y = round_geometry_display_value(release_offset_y);
            let rounded_corrected_click_x = round_geometry_tool_call_value(corrected_click_x);
            let rounded_corrected_click_y = round_geometry_tool_call_value(corrected_click_y);
            let corrected_call = format!(
                r#"browser__synthetic_click {{"x":{},"y":{}}}"#,
                format_prompt_number(rounded_corrected_click_x),
                format_prompt_number(rounded_corrected_click_y),
            );

            Some(format!(
                "The next action must be `{corrected_call}`. Copy the numeric x/y exactly as written; do not round or simplify them. Do not click any visible element before that. A recent pointer trace changed geometry at `{}`: outer_angle_mid={}deg, candidate_error={}deg, connected_line_angles={}deg, endpoint {},{} after release {},{}, surface offset {},{}.",
                candidate.semantic_id,
                format_prompt_number(rounded_mid),
                format_prompt_number(rounded_error),
                candidate.connected_line_angles_deg,
                format_prompt_number(rounded_observed_x),
                format_prompt_number(rounded_observed_y),
                format_prompt_number(rounded_release_x),
                format_prompt_number(rounded_release_y),
                format_prompt_number(rounded_offset_x),
                format_prompt_number(rounded_offset_y),
            ))
        });
    if correction_signal.is_some() {
        return correction_signal;
    }

    if candidate.candidate_error_deg > GEOMETRY_SUBMIT_MAX_ERROR_DEG {
        return Some(format!(
            "A recent pointer trace changed geometry at `{}`, but connected_line_angles={}deg still imply outer_angle_mid={}deg and candidate_error={}deg. Correct the geometry with another coordinate action before any visible control.",
            candidate.semantic_id,
            candidate.connected_line_angles_deg,
            format_prompt_number(rounded_mid),
            format_prompt_number(rounded_error),
        ));
    }

    let submit_id = snapshot_visible_submit_control_id(snapshot)?;
    Some(format!(
        "A recent pointer trace changed geometry at `{}` and connected_line_angles={}deg now imply outer_angle_mid={}deg with candidate_error={}deg. Use `browser__click_element` on `{}` now to commit it. Do not restart the trace or call `agent__complete` before the page is submitted.",
        candidate.semantic_id,
        candidate.connected_line_angles_deg,
        format_prompt_number(rounded_mid),
        format_prompt_number(rounded_error),
        submit_id,
    ))
}

fn synthetic_click_geometry_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let message = recent_synthetic_click_message(history)?;

    if let Some(signal) = synthetic_click_geometry_reverification_signal(history, message, snapshot)
    {
        return Some(signal);
    }

    let candidate = snapshot_bisector_geometry_candidate(snapshot)?;
    if candidate.candidate_error_deg > GEOMETRY_SUBMIT_MAX_ERROR_DEG
        || !recent_goal_mentions_submit(history)
    {
        return None;
    }

    let submit_id = snapshot_visible_submit_control_id(snapshot)?;
    let rounded_mid = ((candidate.target_mid_deg * 10.0).round()) / 10.0;
    let rounded_error = ((candidate.candidate_error_deg * 10.0).round()) / 10.0;
    Some(format!(
        "A recent browser synthetic click changed geometry at `{}` and connected_line_angles={}deg now imply outer_angle_mid={}deg with candidate_error={}deg. Use `browser__click_element` on `{}` now to commit it. Do not click other drawing anchors first.",
        candidate.semantic_id,
        candidate.connected_line_angles_deg,
        format_prompt_number(rounded_mid),
        format_prompt_number(rounded_error),
        submit_id,
    ))
}

fn synthetic_click_geometry_reverification_signal(
    history: &[ChatMessage],
    message: &ChatMessage,
    snapshot: &str,
) -> Option<String> {
    let click_point = recent_synthetic_click_point(message);

    if let Some(candidate) = snapshot_bisector_geometry_candidate(snapshot) {
        let rounded_mid = round_geometry_display_value(candidate.target_mid_deg);
        let rounded_error = round_geometry_display_value(candidate.candidate_error_deg);
        let correction_signal = click_point
            .zip(candidate.connected_points.get(candidate.candidate_index).copied())
            .and_then(|((click_x, click_y), (observed_x, observed_y))| {
                if candidate.candidate_error_deg <= GEOMETRY_SUBMIT_MAX_ERROR_DEG {
                    return None;
                }

                let fragment =
                    snapshot_fragment_for_semantic_id(snapshot, &candidate.semantic_id)?;
                let (center_x, center_y) = fragment_geometry_center_point(fragment)?;
                let click_offset_x = observed_x - click_x;
                let click_offset_y = observed_y - click_y;
                let click_offset_magnitude =
                    (click_offset_x * click_offset_x + click_offset_y * click_offset_y).sqrt();
                if !click_offset_magnitude.is_finite() || click_offset_magnitude < 0.75 {
                    return None;
                }

                let candidate_radius = ((observed_x - center_x).powi(2)
                    + (observed_y - center_y).powi(2))
                .sqrt();
                if !candidate_radius.is_finite() || candidate_radius <= 0.01 {
                    return None;
                }

                let target_mid_radians = candidate.target_mid_deg.to_radians();
                let desired_x = center_x + candidate_radius * target_mid_radians.cos();
                let desired_y = center_y + candidate_radius * target_mid_radians.sin();
                let corrected_click_x = desired_x - click_offset_x;
                let corrected_click_y = desired_y - click_offset_y;
                let rounded_observed_x = round_geometry_display_value(observed_x);
                let rounded_observed_y = round_geometry_display_value(observed_y);
                let rounded_click_x = round_geometry_display_value(click_x);
                let rounded_click_y = round_geometry_display_value(click_y);
                let rounded_offset_x = round_geometry_display_value(click_offset_x);
                let rounded_offset_y = round_geometry_display_value(click_offset_y);
                let rounded_corrected_click_x = round_geometry_tool_call_value(corrected_click_x);
                let rounded_corrected_click_y = round_geometry_tool_call_value(corrected_click_y);
                let corrected_call = format!(
                    r#"browser__synthetic_click {{"x":{},"y":{}}}"#,
                    format_prompt_number(rounded_corrected_click_x),
                    format_prompt_number(rounded_corrected_click_y),
                );

                Some(format!(
                    "The next action must be `{corrected_call}`. Copy the numeric x/y exactly as written; do not round or simplify them. Do not click any visible element before that. A recent browser synthetic click changed geometry at `{}`: outer_angle_mid={}deg, candidate_error={}deg, connected_line_angles={}deg, endpoint {},{} after click {},{}, surface offset {},{}.",
                    candidate.semantic_id,
                    format_prompt_number(rounded_mid),
                    format_prompt_number(rounded_error),
                    candidate.connected_line_angles_deg,
                    format_prompt_number(rounded_observed_x),
                    format_prompt_number(rounded_observed_y),
                    format_prompt_number(rounded_click_x),
                    format_prompt_number(rounded_click_y),
                    format_prompt_number(rounded_offset_x),
                    format_prompt_number(rounded_offset_y),
                ))
            });
        if correction_signal.is_some() {
            return correction_signal;
        }
        if candidate.candidate_error_deg > GEOMETRY_SUBMIT_MAX_ERROR_DEG {
            return Some(format!(
                "A recent browser synthetic click changed geometry at `{}`, but connected_line_angles={}deg still imply outer_angle_mid={}deg and candidate_error={}deg. Correct the geometry with another coordinate action before any visible control.",
                candidate.semantic_id,
                candidate.connected_line_angles_deg,
                format_prompt_number(rounded_mid),
                format_prompt_number(rounded_error),
            ));
        }
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
        if let Some(signal) = submitted_selection_turnover_success_signal(history, snapshot) {
            return Some(signal);
        }
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
        return Some("A recent browser key landed on the page itself, not on a specific control. If you intended a textarea, listbox, or nested scroll region, focus that control first with `browser__click_element` or `browser__click`; otherwise continue with the next required visible control. Do not repeat the same key blindly.".to_string());
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"Home\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_up\":true")
    {
        if compact.contains("\"modifiers\":[\"Control\"]") {
            return Some(format!(
                "A recent `{}` still left the focused scrollable control with `can_scroll_up=true`. Do not call `{}` again, and do not submit or finish yet. Use `PageUp` next, and stop only when grounded state shows `can_scroll_up=false` or `scroll_top=0`.",
                top_edge_jump_name(),
                top_edge_jump_name(),
            ));
        }

        if let Some(scroll_top) = focused_home_should_jump_to_top_edge(&compact) {
            return Some(format!(
                "`Home` left a focused scrollable control far from top (`scroll_top={scroll_top}`, `can_scroll_up=true`). Do not use `Home` again or spend the next step on `PageUp`. Do not submit yet. Use `{}` next. Stop only at top (`can_scroll_up=false` or `scroll_top=0`).",
                top_edge_jump_call(),
            ));
        }

        return Some(format!(
            "A recent `Home` key still left the focused scrollable control with `can_scroll_up=true`. Do not call `Home` again, and do not submit or finish yet. Use `PageUp` or `{}` next. Stop only when grounded state shows `can_scroll_up=false` or `scroll_top=0`.",
            top_edge_jump_call(),
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"PageUp\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_up\":true")
    {
        return Some(format!(
            "A recent `PageUp` still left the focused scrollable control with `can_scroll_up=true`. Do not submit yet. Continue upward or use `{}`. Stop only when grounded state shows `can_scroll_up=false` or `scroll_top=0`.",
            top_edge_jump_call(),
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"End\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_down\":true")
    {
        if compact.contains("\"modifiers\":[\"Control\"]") {
            return Some(format!(
                "A recent `{}` still left the focused scrollable control with `can_scroll_down=true`. Do not call `{}` again, and do not submit or finish yet. Use `PageDown` next, and stop only when grounded state shows `can_scroll_down=false`.",
                bottom_edge_jump_name(),
                bottom_edge_jump_name(),
            ));
        }

        return Some(format!(
            "A recent `End` key still left the focused scrollable control with `can_scroll_down=true`. Do not call `End` again, and do not submit or finish yet. Use `PageDown` or `{}` next. Stop only when grounded state shows `can_scroll_down=false`.",
            bottom_edge_jump_call(),
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"PageDown\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_down\":true")
    {
        return Some(format!(
            "A recent `PageDown` still left the focused scrollable control with `can_scroll_down=true`. Do not submit yet. Continue downward or use `{}`. Stop only when grounded state shows `can_scroll_down=false`.",
            bottom_edge_jump_call(),
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
        return Some("A recent browser click already focused a scrollable control. Do not keep clicking the surrounding wrapper or container. If the goal is control-local scrolling or text selection in that control, continue there with a control-local action such as `browser__key` or `browser__select_text`; otherwise move to the next required visible control.".to_string());
    }

    None
}

pub(super) fn repeated_pagewise_scroll_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let mut repeated_page_up = 0usize;
    let mut repeated_page_down = 0usize;

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
            if repeated_page_up >= 2 {
                return Some(format!(
                    "Several recent `PageUp` steps still left the focused scrollable control with `can_scroll_up=true`. If the goal is the top edge, stop spending steps on repeated `PageUp`. Use `{}` next, then verify grounded state shows `can_scroll_up=false` or `scroll_top=0` before submitting or finishing.",
                    top_edge_jump_call(),
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
            if repeated_page_down >= 2 {
                return Some(format!(
                    "Several recent `PageDown` steps still left the focused scrollable control with `can_scroll_down=true`. If the goal is the bottom edge, stop spending steps on repeated `PageDown`. Use `{}` next, then verify grounded state shows `can_scroll_down=false` before submitting or finishing.",
                    bottom_edge_jump_call(),
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
        .or_else(|| autocomplete_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| {
            tree_change_link_reverification_pending_signal_with_current_snapshot(
                history,
                current_snapshot,
            )
        })
        .or_else(|| filter_mismatch_pending_signal(history, current_snapshot))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, current_snapshot))
        .or_else(|| direct_date_entry_pending_signal(history, current_snapshot))
        .or_else(|| start_gate_pending_signal(history, current_snapshot))
        .or_else(|| stale_queue_reverification_pending_signal(history, current_snapshot))
        .or_else(|| {
            queue_reverification_history_follow_up_pending_signal(history, current_snapshot)
        })
        .or_else(|| {
            confirmation_page_saved_state_mismatch_pending_signal(history, current_snapshot)
        })
        .or_else(|| reviewed_draft_confirmation_pending_signal(history, current_snapshot))
        .or_else(|| reopened_draft_resume_pending_signal(history, current_snapshot))
        .or_else(|| history_page_verification_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| history_page_verification_mismatch_pending_signal(history, current_snapshot))
        .or_else(|| history_verification_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| target_search_pending_signal(history, current_snapshot))
        .or_else(|| visible_error_text_control_pending_signal(history, current_snapshot))
        .or_else(|| active_target_submit_pending_signal(history, current_snapshot))
        .or_else(|| visible_target_click_pending_signal(history, current_snapshot))
        .or_else(|| alternate_tab_exploration_pending_signal(history, current_snapshot))
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
        .or_else(|| autocomplete_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| {
            tree_change_link_reverification_pending_signal_with_current_snapshot(
                history,
                Some(snapshot),
            )
        })
        .or_else(|| dropdown_filter_mismatch_pending_signal(snapshot, history))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, Some(snapshot)))
        .or_else(|| direct_date_entry_pending_signal(history, Some(snapshot)))
        .or_else(|| start_gate_pending_signal(history, Some(snapshot)))
        .or_else(|| stale_queue_reverification_pending_signal(history, Some(snapshot)))
        .or_else(|| queue_reverification_history_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| confirmation_page_saved_state_mismatch_pending_signal(history, Some(snapshot)))
        .or_else(|| reviewed_draft_confirmation_pending_signal(history, Some(snapshot)))
        .or_else(|| reopened_draft_resume_pending_signal(history, Some(snapshot)))
        .or_else(|| history_page_verification_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| history_page_verification_mismatch_pending_signal(history, Some(snapshot)))
        .or_else(|| history_verification_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| target_search_pending_signal(history, Some(snapshot)))
        .or_else(|| visible_error_text_control_pending_signal(history, Some(snapshot)))
        .or_else(|| active_target_submit_pending_signal(history, Some(snapshot)))
        .or_else(|| select_submit_progress_pending_signal(history, Some(snapshot)))
        .or_else(|| visible_target_click_pending_signal(history, Some(snapshot)))
        .or_else(|| alternate_tab_exploration_pending_signal(history, Some(snapshot)))
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
        .and_then(browser_snapshot_pending_signal);

    if navigation_signal.is_some()
        || auth_form_pending_signal(history).is_some()
        || autocomplete_follow_up_pending_signal(history, current_snapshot).is_some()
        || tree_change_link_reverification_pending_signal_with_current_snapshot(
            history,
            current_snapshot,
        )
        .is_some()
        || filter_mismatch_pending_signal(history, current_snapshot).is_some()
        || instruction_only_find_text_pagination_pending_signal(history, current_snapshot).is_some()
        || direct_date_entry_pending_signal(history, current_snapshot).is_some()
        || active_target_submit_pending_signal(history, current_snapshot).is_some()
        || select_submit_progress_pending_signal(history, current_snapshot).is_some()
        || visible_target_click_pending_signal(history, current_snapshot).is_some()
        || alternate_tab_exploration_pending_signal(history, current_snapshot).is_some()
        || stale_queue_reverification_pending_signal(history, current_snapshot).is_some()
        || queue_reverification_history_follow_up_pending_signal(history, current_snapshot)
            .is_some()
        || confirmation_page_saved_state_mismatch_pending_signal(history, current_snapshot)
            .is_some()
        || reviewed_draft_confirmation_pending_signal(history, current_snapshot).is_some()
        || reopened_draft_resume_pending_signal(history, current_snapshot).is_some()
        || history_page_verification_follow_up_pending_signal(history, current_snapshot).is_some()
        || history_page_verification_mismatch_pending_signal(history, current_snapshot).is_some()
        || history_verification_follow_up_pending_signal(history, current_snapshot).is_some()
        || snapshot_pending_signal.is_some()
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
