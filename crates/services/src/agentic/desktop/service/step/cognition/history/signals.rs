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

pub(super) fn next_visible_follow_up_controls(snapshot: &str, excluded_ids: &[&str]) -> Vec<String> {
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
        let Some(tag) = priority_target_tag(summary) else {
            continue;
        };
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if !matches!(tag, "link" | "heading") {
            push_unique_control(&mut next_controls, semantic_id);
            if next_controls.len() == 3 {
                return next_controls;
            }
        }
    }

    for summary in &remaining_targets {
        let Some(tag) = priority_target_tag(summary) else {
            continue;
        };
        let Some(semantic_id) = priority_target_semantic_id(summary) else {
            continue;
        };
        if matches!(tag, "heading") || summary.contains("name=History") {
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

pub(super) fn dispatch_update_resume_clause(expectation: &DispatchUpdateExpectation) -> Option<String> {
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

pub(super) fn dispatch_update_review_clause(expectation: &DispatchUpdateExpectation) -> Option<String> {
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

pub(super) fn visible_target_click_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let target = recent_goal_primary_target(history)?;
    let candidate = snapshot_visible_exact_text_target(snapshot, &target)?;

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

pub(super) fn browser_effect_success_signal_for_message(
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
        let mut signal = "A recent browser interaction already reported observable state change (`postcondition.met=true`). Do not repeat the same interaction.".to_string();
        if let Some(snapshot) = snapshot {
            let next_controls = next_visible_follow_up_controls(
                snapshot,
                &clicked_id.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            if !next_controls.is_empty() {
                signal.push_str(&format!(
                    " Continue with another visible control such as `{}`.",
                    next_controls.join("`, `")
                ));
                signal.push_str(
                    " Do not spend the next step on another `browser__snapshot` unless those controls disappear or the page changes again.",
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
    }

    for message in history.iter().rev() {
        if let Some(signal) = dropdown_success_signal_for_message(message, snapshot) {
            return Some(signal);
        }
        if dropdown_selection_details(message).is_some() {
            continue;
        }
        if let Some(signal) = browser_effect_success_signal_for_message(message, snapshot) {
            return Some(signal);
        }
    }

    None
}

pub(crate) fn build_browser_observation_context_from_snapshot(snapshot: &str) -> String {
    let mut assistive_hints = extract_assistive_browser_hints(snapshot);
    if let Some(scroll_target_hint) = extract_scroll_target_focus_hint(snapshot) {
        assistive_hints.push(scroll_target_hint);
    }
    let compact_observation = compact_browser_observation(snapshot);
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

pub(super) fn browser_effect_pending_signal(message: &ChatMessage) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if compact.contains("\"autocomplete\":{")
        && (compact.contains("\"assistive_hint\":")
            || compact.contains("\"active_descendant_dom_id\":")
            || compact.contains("\"controls_dom_id\":"))
    {
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
        return Some("A recent browser key landed on the page itself, not on a specific control. Do not repeat the same key blindly. If you intended a textarea, listbox, or nested scroll region, focus that control first with `browser__click_element` or `browser__click`, then send the key again.".to_string());
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

pub(super) fn explicit_pending_browser_state_context_message(message: &ChatMessage) -> Option<String> {
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
    filtered_recent_session_events(history, prefer_browser_semantics)
        .into_iter()
        .map(|message| format!("{}: {}", message.role, message.content))
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

    build_browser_observation_context_from_snapshot(observation)
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

    let Some(signal) = navigation_signal
        .or_else(|| auth_form_pending_signal(history))
        .or_else(|| autocomplete_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| tree_change_link_reverification_pending_signal(history))
        .or_else(|| filter_mismatch_pending_signal(history, current_snapshot))
        .or_else(|| ranked_result_pending_signal(history, current_snapshot))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, current_snapshot))
        .or_else(|| visible_target_click_pending_signal(history, current_snapshot))
        .or_else(|| alternate_tab_exploration_pending_signal(history, current_snapshot))
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
        .or_else(|| repeated_pagewise_scroll_pending_signal(history))
        .or_else(|| history.iter().rev().find_map(browser_effect_pending_signal))
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
        .or_else(|| tree_change_link_reverification_pending_signal(history))
        .or_else(|| dropdown_filter_mismatch_pending_signal(snapshot, history))
        .or_else(|| ranked_result_pending_signal(history, Some(snapshot)))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, Some(snapshot)))
        .or_else(|| visible_target_click_pending_signal(history, Some(snapshot)))
        .or_else(|| alternate_tab_exploration_pending_signal(history, Some(snapshot)))
        .or_else(|| stale_queue_reverification_pending_signal(history, Some(snapshot)))
        .or_else(|| queue_reverification_history_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| confirmation_page_saved_state_mismatch_pending_signal(history, Some(snapshot)))
        .or_else(|| reviewed_draft_confirmation_pending_signal(history, Some(snapshot)))
        .or_else(|| reopened_draft_resume_pending_signal(history, Some(snapshot)))
        .or_else(|| history_page_verification_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| history_page_verification_mismatch_pending_signal(history, Some(snapshot)))
        .or_else(|| history_verification_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| browser_snapshot_pending_signal(snapshot))
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

    if navigation_signal.is_some()
        || auth_form_pending_signal(history).is_some()
        || autocomplete_follow_up_pending_signal(history, current_snapshot).is_some()
        || tree_change_link_reverification_pending_signal(history).is_some()
        || filter_mismatch_pending_signal(history, current_snapshot).is_some()
        || ranked_result_pending_signal(history, current_snapshot).is_some()
        || instruction_only_find_text_pagination_pending_signal(history, current_snapshot).is_some()
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

