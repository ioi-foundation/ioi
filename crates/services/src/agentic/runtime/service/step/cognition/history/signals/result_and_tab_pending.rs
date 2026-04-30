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
                    "Use `browser__click` on `{}` now to reach result {}.",
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
            "{} `{}` is the instruction token for `{}`, not a search result. Only {} actual result links are visible here (ranks {}-{}), so result {} is still off-screen. Do not click `{}`, do not use `browser__scroll`, and do not spend the next step on `browser__inspect`.{}{}",
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
        "Use `browser__click` on `{}` now. Result {} on this page is visible result link `{}` (`{}`). `{}` is the visible instruction token for `{}`, not the result to click. Do not use `browser__scroll`, do not spend the next step on `browser__inspect`, and do not click `{}` or finish.{}{}",
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
            "`{}` is not on the current record `{}`. Do not click this record's links. The only valid next `browser__click` id here is `{}`. Use it now. Do not invent ids or repeat `browser__find_text`.",
            recent_find.query,
            heading.name,
            page_control.semantic_id,
        ),
        None => format!(
            "Recent `browser__find_text` for `{}` matched instruction token `{}`, not the current record. The only valid next `browser__click` id here is `{}`. Use it now. Do not invent ids, repeat `browser__find_text`, or spend the next step on `browser__inspect`.",
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
        "The currently expanded section `{focused_label}` does not show the target text `{target}`. Do not click `{}` again, and do not spend the next step on another `browser__inspect`. Use another visible section tab such as {candidate_clause} now. When `{target}` becomes visible, click that target directly.",
        focused_tab.semantic_id,
    ))
}
