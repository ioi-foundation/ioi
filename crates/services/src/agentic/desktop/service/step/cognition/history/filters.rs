use super::*;

pub(super) fn dropdown_selection_details(message: &ChatMessage) -> Option<(String, String)> {
    if message.role != "tool" {
        return None;
    }

    let payload = parse_json_value_from_message(&message.content)?;
    let selected = payload.get("selected")?;
    let selected_label = selected
        .get("label")
        .and_then(Value::as_str)
        .or_else(|| selected.get("value").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())?;
    let dropdown_id = payload
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| payload.get("selector").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())?;

    Some((dropdown_id, selected_label))
}

pub(super) fn typed_field_details(message: &ChatMessage) -> Option<(String, String)> {
    if message.role != "tool" {
        return None;
    }

    let payload = parse_json_value_from_message(&message.content)?;
    let typed = payload.get("typed")?;
    let text = typed
        .get("value")
        .and_then(Value::as_str)
        .or_else(|| typed.get("text").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())?;
    let locator = typed
        .get("dom_id")
        .and_then(Value::as_str)
        .or_else(|| typed.get("selector").and_then(Value::as_str))
        .or_else(|| typed.get("requested_selector").and_then(Value::as_str))
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty())?;

    Some((locator, text))
}

#[derive(Default)]
pub(super) struct DispatchUpdateExpectation {
    pub(super) assignee: Option<String>,
    pub(super) status: Option<String>,
    pub(super) note: Option<String>,
}

pub(super) fn recent_dispatch_update_expectation(
    history: &[ChatMessage],
) -> DispatchUpdateExpectation {
    let mut expectation = DispatchUpdateExpectation::default();

    for message in history.iter().rev() {
        if expectation.assignee.is_none() || expectation.status.is_none() {
            if let Some((dropdown_id, selected_label)) = dropdown_selection_details(message) {
                let dropdown_lower = dropdown_id.to_ascii_lowercase();
                if expectation.assignee.is_none()
                    && (dropdown_lower.contains("assign")
                        || dropdown_lower.contains("assignee")
                        || dropdown_lower.contains("team"))
                {
                    expectation.assignee = Some(selected_label.clone());
                }
                if expectation.status.is_none() && dropdown_lower.contains("status") {
                    expectation.status = Some(selected_label);
                }
            }
        }

        if expectation.note.is_none() {
            if let Some((locator, text)) = typed_field_details(message) {
                let locator_lower = locator.to_ascii_lowercase();
                if locator_lower.contains("note") {
                    expectation.note = Some(text);
                }
            }
        }

        if expectation.assignee.is_some()
            && expectation.status.is_some()
            && expectation.note.is_some()
        {
            break;
        }
    }

    expectation
}

pub(super) fn snapshot_mentions_dropdown_locator(snapshot: &str, locator: &str) -> bool {
    let semantic_id_marker = format!(r#"id="{}""#, locator);
    let selector_marker = format!(r#"selector="{}""#, locator);
    let compact_summary_marker = format!("#{locator}");
    let compact_summary_raw = format!("{locator} tag=");
    let compact_summary_attr = format!("id={locator}");

    snapshot.contains(&semantic_id_marker)
        || snapshot.contains(&selector_marker)
        || snapshot.contains(&compact_summary_marker)
        || snapshot.contains(&compact_summary_raw)
        || snapshot.contains(&compact_summary_attr)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotDropdownState {
    pub(super) semantic_id: String,
    pub(super) name: Option<String>,
    pub(super) value: Option<String>,
    pub(super) dom_id: Option<String>,
    pub(super) selector: Option<String>,
}

pub(super) fn snapshot_dropdown_states(snapshot: &str) -> Vec<SnapshotDropdownState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("combobox ") || fragment.contains(" omitted=\"true\"")
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
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotDropdownState {
            semantic_id,
            name,
            value,
            dom_id,
            selector,
        });
    }

    states
}

pub(super) fn snapshot_sort_dropdown_state(snapshot: &str) -> Option<SnapshotDropdownState> {
    snapshot_dropdown_states(snapshot)
        .into_iter()
        .find(|dropdown| {
            dropdown_descriptor_text(dropdown)
                .to_ascii_lowercase()
                .contains("sort")
        })
}

pub(super) fn snapshot_apply_filters_button_id(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("button ") {
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
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();

        let lower_name = name.to_ascii_lowercase();
        let lower_dom_id = dom_id.to_ascii_lowercase();
        let lower_selector = selector.to_ascii_lowercase();
        let lower_semantic_id = semantic_id.to_ascii_lowercase();
        if lower_name.contains("apply")
            || lower_name.contains("refresh")
            || lower_dom_id.contains("apply")
            || lower_dom_id.contains("refresh")
            || lower_selector.contains("apply")
            || lower_selector.contains("refresh")
            || lower_semantic_id.contains("apply")
            || lower_semantic_id.contains("refresh")
        {
            return Some(semantic_id);
        }
    }

    None
}

pub(super) fn dropdown_descriptor_text(dropdown: &SnapshotDropdownState) -> String {
    [
        Some(dropdown.semantic_id.as_str()),
        dropdown.name.as_deref(),
        dropdown.dom_id.as_deref(),
        dropdown.selector.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
}

pub(super) fn semantic_hint_tokens(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let lowered = token.trim_matches(|ch: char| ch.is_ascii_digit());
            if lowered.len() < 3 {
                return None;
            }

            let lowered = lowered.to_ascii_lowercase();
            if matches!(
                lowered.as_str(),
                "inp"
                    | "btn"
                    | "lnk"
                    | "grp"
                    | "dom"
                    | "id"
                    | "selector"
                    | "field"
                    | "form"
                    | "control"
                    | "dropdown"
                    | "select"
                    | "combobox"
                    | "button"
                    | "link"
                    | "queue"
                    | "ticket"
                    | "view"
                    | "list"
                    | "current"
                    | "saved"
            ) {
                return None;
            }

            Some(lowered)
        })
        .collect()
}

pub(super) fn is_filter_like_dropdown(dropdown: &SnapshotDropdownState) -> bool {
    let descriptor = dropdown_descriptor_text(dropdown).to_ascii_lowercase();
    descriptor.contains("filter") || descriptor.contains("sort")
}

pub(super) fn dropdown_filter_overlap_count(
    dropdown_id: &str,
    filter_dropdown: &SnapshotDropdownState,
) -> usize {
    let selection_tokens = semantic_hint_tokens(dropdown_id);
    if selection_tokens.is_empty() {
        return 0;
    }

    let filter_tokens = semantic_hint_tokens(&dropdown_descriptor_text(filter_dropdown));
    selection_tokens.intersection(&filter_tokens).count()
}

pub(super) fn dropdown_filter_mismatch_pending_signal(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    let filter_dropdowns = snapshot_dropdown_states(snapshot)
        .into_iter()
        .filter(is_filter_like_dropdown)
        .collect::<Vec<_>>();
    if filter_dropdowns.is_empty() {
        return None;
    }

    for message in history.iter().rev() {
        let Some((dropdown_id, selected_label)) = dropdown_selection_details(message) else {
            continue;
        };

        let best_match = filter_dropdowns
            .iter()
            .filter_map(|filter_dropdown| {
                if filter_dropdown.semantic_id == dropdown_id {
                    return None;
                }

                let current_value = filter_dropdown.value.as_deref()?;
                if current_value.eq_ignore_ascii_case(&selected_label) {
                    return None;
                }

                let overlap = dropdown_filter_overlap_count(&dropdown_id, filter_dropdown);
                (overlap > 0).then_some((filter_dropdown, current_value, overlap))
            })
            .max_by_key(|(_, _, overlap)| *overlap);

        let Some((filter_dropdown, current_value, _)) = best_match else {
            continue;
        };

        let filter_name = filter_dropdown
            .name
            .as_deref()
            .unwrap_or(filter_dropdown.semantic_id.as_str());
        return Some(format!(
            "A recent dropdown changed `{}` to `{}`, but filter `{}` (`{}`) still shows `{}` and may hide the updated item. Do not call `browser__snapshot` again yet. Use `browser__select_dropdown` on `{}` now: first try `{}`; if unavailable, clear it to an all-items option. Then verify the updated item in the list.",
            dropdown_id,
            selected_label,
            filter_dropdown.semantic_id,
            filter_name,
            current_value,
            filter_dropdown.semantic_id,
            selected_label
        ));
    }

    None
}

pub(super) fn snapshot_has_stale_queue_reverification_marker(snapshot: &str) -> bool {
    let lower = snapshot_lower_text(snapshot);
    let mentions_queue = lower.contains("queue");
    let mentions_stale = lower.contains("stale");
    let mentions_refresh = lower.contains("refresh") || lower.contains("reapply");
    let mentions_row_evidence = lower.contains("row order")
        || lower.contains("row state")
        || lower.contains("trusting any row state")
        || lower.contains("using row order as evidence");

    mentions_queue && mentions_stale && mentions_refresh && mentions_row_evidence
}

pub(super) fn snapshot_has_queue_reverification_controls(snapshot: &str) -> bool {
    snapshot_sort_dropdown_state(snapshot).is_some()
        && (snapshot_apply_filters_button_id(snapshot).is_some()
            || snapshot_lower_text(snapshot).contains("queue search")
            || snapshot_lower_text(snapshot).contains("queue status filter"))
}

pub(super) fn recent_goal_requires_queue_reverification(history: &[ChatMessage]) -> bool {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .any(|message| {
            let lower = message.content.to_ascii_lowercase();
            lower.contains("refresh the queue")
                || lower.contains("refresh the list")
                || lower.contains("queue view is stale")
                || lower.contains("row order")
                || lower.contains("row state")
        })
}

pub(super) fn stale_queue_reverification_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let apply_control_id = snapshot_apply_filters_button_id(snapshot);
    let refresh_already_observed = apply_control_id.as_deref().is_some_and(|semantic_id| {
        recent_successful_click_semantic_id(history).as_deref() == Some(semantic_id)
            && (current_snapshot.is_some()
                || recent_successful_click_is_observed_in_later_snapshot(history, semantic_id))
    });
    if refresh_already_observed {
        return None;
    }

    let goal_requires_queue_reverification = recent_goal_requires_queue_reverification(history);
    let inferred_post_confirm_queue_reverification = goal_requires_queue_reverification
        && recent_confirmation_queue_return(history)
        && snapshot_has_queue_reverification_controls(snapshot);
    if !snapshot_has_stale_queue_reverification_marker(snapshot)
        && !inferred_post_confirm_queue_reverification
    {
        return None;
    }

    let sort_dropdown = snapshot_sort_dropdown_state(snapshot)?;
    let apply_control = apply_control_id
        .map(|id| format!("`{id}`"))
        .unwrap_or_else(|| "the visible refresh/apply control".to_string());
    let requested_sort = recent_requested_sort_label(history);
    let current_value = sort_dropdown
        .value
        .as_deref()
        .map(compact_ws_for_prompt)
        .filter(|value| !value.is_empty());

    if let Some(requested_sort) = requested_sort {
        if current_value
            .as_deref()
            .is_some_and(|current| current.eq_ignore_ascii_case(&requested_sort))
        {
            return Some(format!(
                "Stale queue/list view: row order is not evidence yet. `{}` already shows `{}`, but the list still needs refresh. Do not open ticket/history links or call `browser__snapshot` again. Use {} now, then verify row order on the updated queue.",
                sort_dropdown.semantic_id, requested_sort, apply_control
            ));
        }

        if let Some(current_value) = current_value {
            return Some(format!(
                "Stale queue/list view: row order is not evidence yet. `{}` still shows `{}`. Do not open ticket/history links or call `browser__snapshot` again. Use `browser__select_dropdown` on `{}` to choose `{}`, then use {} to refresh before verifying row order.",
                sort_dropdown.semantic_id,
                current_value,
                sort_dropdown.semantic_id,
                requested_sort,
                apply_control
            ));
        }

        return Some(format!(
            "Stale queue/list view: row order is not evidence yet. Do not open ticket/history links or call `browser__snapshot` again. Use `browser__select_dropdown` on `{}` to choose `{}`, then use {} to refresh before verifying row order.",
            sort_dropdown.semantic_id, requested_sort, apply_control
        ));
    }

    Some(format!(
        "Stale queue/list view: row order is not evidence yet. Do not open ticket/history links or call `browser__snapshot` again. Reapply the visible queue controls, then use {} to refresh before verifying row order.",
        apply_control
    ))
}

pub(super) fn queue_reverification_history_follow_up_pending_signal_for_snapshot(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    if !recent_history_viewed_item_ids(history).is_empty() {
        return None;
    }
    if !recent_confirmation_queue_return(history) {
        return None;
    }

    let sort_dropdown = snapshot_sort_dropdown_state(snapshot)?;
    let requested_sort = recent_requested_sort_label(history)?;
    let current_sort = sort_dropdown.value.as_deref()?;
    if !current_sort.eq_ignore_ascii_case(&requested_sort) {
        return None;
    }

    let apply_button_id = snapshot_apply_filters_button_id(snapshot)?;
    if recent_successful_click_semantic_id(history).as_deref() != Some(apply_button_id.as_str()) {
        return None;
    }

    let goal_items = recent_goal_item_sequence(history);
    if goal_items.len() < 2 {
        return None;
    }
    let target_item = &goal_items[0];
    let distractor_item = &goal_items[1];

    let visible_order = snapshot_visible_item_order(snapshot);
    let target_idx = visible_order
        .iter()
        .position(|item_id| item_id.eq_ignore_ascii_case(target_item))?;
    let distractor_idx = visible_order
        .iter()
        .position(|item_id| item_id.eq_ignore_ascii_case(distractor_item))?;
    if target_idx >= distractor_idx {
        return None;
    }

    let expectation = recent_dispatch_update_expectation(history);
    if expectation.assignee.is_none() && expectation.status.is_none() {
        return None;
    }

    let target_ticket_link = snapshot_ticket_link_for_item(snapshot, target_item)?;
    let target_context = target_ticket_link.context.as_deref()?;
    if let Some(expected_assignee) = expectation.assignee.as_deref() {
        if !contains_ascii_case_insensitive(target_context, expected_assignee) {
            return None;
        }
    }
    if let Some(expected_status) = expectation.status.as_deref() {
        if !contains_ascii_case_insensitive(target_context, expected_status) {
            return None;
        }
    }

    let distractor_history_link = snapshot_history_link_for_item(snapshot, distractor_item)?;
    let mut matched_fields = Vec::new();
    if let Some(expected_assignee) = expectation.assignee.as_deref() {
        matched_fields.push(format!("assignee `{expected_assignee}`"));
    }
    if let Some(expected_status) = expectation.status.as_deref() {
        matched_fields.push(format!("status `{expected_status}`"));
    }
    let matched_clause = if matched_fields.is_empty() {
        String::new()
    } else {
        format!(" with {}", matched_fields.join(" and "))
    };

    Some(format!(
        "The refreshed queue already shows `{target_item}` ahead of `{distractor_item}` under `{requested_sort}`{matched_clause}. Do not reopen `{target_item}` or spend the next step on another `browser__snapshot`. Continue the remaining verification on `{distractor_item}` by using `{}` now.",
        distractor_history_link.semantic_id
    ))
}

pub(super) fn queue_reverification_history_follow_up_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    current_snapshot
        .and_then(|snapshot| {
            queue_reverification_history_follow_up_pending_signal_for_snapshot(snapshot, history)
        })
        .or_else(|| {
            history
                .iter()
                .rev()
                .find_map(browser_snapshot_payload)
                .and_then(|snapshot| {
                    queue_reverification_history_follow_up_pending_signal_for_snapshot(
                        snapshot, history,
                    )
                })
        })
}
