use super::*;

pub(super) fn history_page_instruction_text(snapshot: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        let is_history_status = dom_id.to_ascii_lowercase().contains("history-status")
            || selector.to_ascii_lowercase().contains("history-status");
        let mentions_verify = name
            .as_deref()
            .is_some_and(|text| text.to_ascii_lowercase().contains("verify"));
        if is_history_status || mentions_verify {
            return name;
        }
    }

    None
}

pub(super) fn history_page_row_summaries(snapshot: &str) -> Vec<String> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();

    for fragment in snapshot.split('<') {
        if !fragment.contains(r#"tag_name="tr""#) || fragment.contains(r#" omitted="true""#) {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !seen.insert(name.clone()) {
            continue;
        }
        rows.push(name);
    }

    rows
}

pub(super) fn history_page_has_matching_verification_row(snapshot: &str) -> Option<bool> {
    if !snapshot_has_history_page_marker(snapshot) {
        return None;
    }

    let instruction = history_page_instruction_text(snapshot)?;
    let instruction_tokens = history_verification_tokens(&instruction);
    if instruction_tokens.len() < 2 {
        return None;
    }

    let row_summaries = history_page_row_summaries(snapshot);
    if row_summaries.is_empty() {
        return None;
    }

    Some(row_summaries.into_iter().any(|row| {
        let row_tokens = history_verification_tokens(&row);
        instruction_tokens.intersection(&row_tokens).count() >= 2
    }))
}

pub(super) fn snapshot_has_history_page_marker(snapshot: &str) -> bool {
    for fragment in snapshot.split('<') {
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .unwrap_or_default();

        if dom_id.to_ascii_lowercase().contains("history-status")
            || selector.to_ascii_lowercase().contains("history-status")
        {
            return true;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        if !(fragment.contains(r#"tag_name="h1""#) || fragment.contains(r#"tag_name="h2""#)) {
            continue;
        }

        if name.to_ascii_lowercase().contains("history") {
            return true;
        }
    }

    false
}

pub(super) fn snapshot_history_item_id(snapshot: &str) -> Option<String> {
    if !snapshot_has_history_page_marker(snapshot) {
        return None;
    }

    for fragment in snapshot.split('<') {
        if !fragment.contains(r#"tag_name="h1""#) && !fragment.contains(r#"tag_name="h2""#) {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !name.to_ascii_lowercase().contains("history") {
            continue;
        }
        if let Some(item_id) = first_item_like_id(&name) {
            return Some(item_id);
        }
    }

    first_item_like_id(snapshot)
}

pub(super) fn snapshot_queue_link_id(snapshot: &str) -> Option<String> {
    snapshot_link_states(snapshot).into_iter().find_map(|link| {
        let is_queue_link = link
            .name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("queue"))
            || link
                .dom_id
                .as_deref()
                .is_some_and(|dom_id| dom_id.to_ascii_lowercase().contains("queue-link"))
            || link.semantic_id.eq("lnk_queue");
        is_queue_link.then_some(link.semantic_id)
    })
}

pub(super) fn history_page_verification_follow_up_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if !snapshot_has_history_page_marker(snapshot) {
        return None;
    }
    if !history_page_has_matching_verification_row(snapshot)? {
        return None;
    }

    let current_item = snapshot_history_item_id(snapshot)
        .or_else(|| recent_history_viewed_item_ids(history).into_iter().next());
    let mut remaining_goal_items = recent_goal_item_ids(history);
    if let Some(current_item) = current_item.as_ref() {
        remaining_goal_items.remove(current_item);
    }

    let item_clause = current_item
        .as_ref()
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();

    if let Some(queue_link_id) = snapshot_queue_link_id(snapshot) {
        let next_item_clause = remaining_goal_items
            .iter()
            .next()
            .map(|item_id| {
                format!(
                    " then continue the remaining verification for another required item such as `{item_id}`."
                )
            })
            .unwrap_or_else(|| {
                " then continue with the next required action or finish if every required verification is complete."
                    .to_string()
            });

        return Some(format!(
            "The current history view{item_clause} already shows a row matching the page-visible verification prompt. Use `{queue_link_id}` to return to the queue,{next_item_clause} Do not call `browser__snapshot` again. Do not reopen or mutate the item just to re-read the same history view.",
        ));
    }

    let next_controls = next_visible_follow_up_controls(snapshot, &[]);
    if next_controls.is_empty() {
        return None;
    }

    Some(format!(
        "The current history view{item_clause} already shows a row matching the page-visible verification prompt. Do not call `browser__snapshot` again. Continue with another grounded control such as `{}`.",
        next_controls.join("`, `")
    ))
}

pub(super) fn snapshot_confirmation_link_id(snapshot: &str) -> Option<String> {
    snapshot_link_states(snapshot).into_iter().find_map(|link| {
        let is_confirmation_link =
            link.name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case("confirmation"))
                || link.dom_id.as_deref().is_some_and(|dom_id| {
                    dom_id.to_ascii_lowercase().contains("confirmation-link")
                })
                || link.semantic_id.eq("lnk_confirmation");
        is_confirmation_link.then_some(link.semantic_id)
    })
}

pub(super) fn snapshot_reopen_button_id(snapshot: &str) -> Option<String> {
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

        if lower_name.contains("reopen")
            || lower_dom_id.contains("reopen-ticket")
            || lower_selector.contains("reopen-ticket")
            || semantic_id.to_ascii_lowercase().contains("reopen")
        {
            return Some(semantic_id);
        }
    }

    None
}

pub(super) fn snapshot_confirm_update_button_id(snapshot: &str) -> Option<String> {
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

        if lower_name.contains("confirm update")
            || lower_dom_id.contains("confirm-update")
            || lower_selector.contains("confirm-update")
            || lower_semantic_id.contains("confirm_update")
        {
            return Some(semantic_id);
        }
    }

    None
}

pub(super) fn snapshot_edit_draft_button_id(snapshot: &str) -> Option<String> {
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

        if lower_name.contains("edit draft")
            || lower_dom_id.contains("edit-update")
            || lower_selector.contains("edit-update")
            || lower_semantic_id.contains("edit_draft")
        {
            return Some(semantic_id);
        }
    }

    None
}

pub(super) fn history_page_verification_mismatch_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    if !snapshot_has_history_page_marker(snapshot) {
        return None;
    }
    if history_page_has_matching_verification_row(snapshot)? {
        return None;
    }

    let current_item = snapshot_history_item_id(snapshot)
        .or_else(|| recent_history_viewed_item_ids(history).into_iter().next());
    let item_clause = current_item
        .as_ref()
        .map(|item_id| format!(" for `{item_id}`"))
        .unwrap_or_default();

    let confirmation_link_id = snapshot_confirmation_link_id(snapshot);
    let reopen_button_id = snapshot_reopen_button_id(snapshot);
    let queue_link_id = snapshot_queue_link_id(snapshot);

    match (
        confirmation_link_id.as_deref(),
        reopen_button_id.as_deref(),
        queue_link_id.as_deref(),
    ) {
        (Some(confirmation_link_id), Some(reopen_button_id), Some(queue_link_id)) => Some(
            format!(
                "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{confirmation_link_id}` to inspect the saved dispatch details or `{reopen_button_id}` to correct them, then return through `{queue_link_id}` only after the history row matches."
            ),
        ),
        (Some(confirmation_link_id), Some(reopen_button_id), None) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{confirmation_link_id}` to inspect the saved dispatch details or `{reopen_button_id}` to correct them before checking history again."
        )),
        (Some(confirmation_link_id), None, Some(queue_link_id)) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{confirmation_link_id}` to inspect the saved dispatch details, then return through `{queue_link_id}` only after the history row matches."
        )),
        (None, Some(reopen_button_id), Some(queue_link_id)) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{reopen_button_id}` to correct the saved state, then return through `{queue_link_id}` only after the history row matches."
        )),
        (Some(confirmation_link_id), None, None) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{confirmation_link_id}` to inspect the saved dispatch details before checking history again."
        )),
        (None, Some(reopen_button_id), None) => Some(format!(
            "The current history view{item_clause} does not yet show a row matching the page-visible verification prompt. Do not spend the next step on another `browser__snapshot`, and do not treat this audit-history check as complete. Use `{reopen_button_id}` to correct the saved state before checking history again."
        )),
        _ => None,
    }
}

pub(super) fn recent_verified_history_item_id(history: &[ChatMessage]) -> Option<String> {
    history.iter().rev().take(20).find_map(|message| {
        let snapshot = browser_snapshot_payload(message)?;
        if !history_page_has_matching_verification_row(snapshot).unwrap_or(false) {
            return None;
        }
        snapshot_history_item_id(snapshot)
    })
}

pub(super) fn history_verification_follow_up_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let returned_item = recent_history_return_item_id(history)?;
    let verified_item = recent_verified_history_item_id(history)
        .or_else(|| recent_history_viewed_item_ids(history).into_iter().next())?;
    if verified_item != returned_item {
        return None;
    }

    let goal_item_ids = recent_goal_item_ids(history);
    let mut alternate_history_links = snapshot_link_states(snapshot)
        .into_iter()
        .filter(is_history_like_link)
        .filter_map(|link| {
            let item_id = snapshot_link_item_id(&link)?;
            (item_id != returned_item).then_some((link, item_id))
        })
        .collect::<Vec<_>>();
    if alternate_history_links.is_empty() {
        return None;
    }

    alternate_history_links.sort_by(|(left_link, left_item_id), (right_link, right_item_id)| {
        let left_goal_match = goal_item_ids.contains(left_item_id);
        let right_goal_match = goal_item_ids.contains(right_item_id);

        right_goal_match
            .cmp(&left_goal_match)
            .then(left_item_id.cmp(right_item_id))
            .then(left_link.semantic_id.cmp(&right_link.semantic_id))
    });

    let examples = alternate_history_links
        .into_iter()
        .take(3)
        .map(|(link, item_id)| format!("`{}` for `{}`", link.semantic_id, item_id))
        .collect::<Vec<_>>();
    if examples.is_empty() {
        return None;
    }

    Some(format!(
        "A recent browser action already returned from history for `{}` to the list view. Do not reopen `{}` right away. Continue the remaining cross-item verification on another visible history link instead, such as {}.",
        returned_item,
        returned_item,
        examples.join(" or ")
    ))
}

