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

pub(super) fn snapshot_visible_autocomplete_suggestion_target(
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
    if autocomplete_value_looks_committed(history, &control) {
        if let Some(signal) = autocomplete_commit_success_signal(history, snapshot) {
            return Some(signal);
        }
    }
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
                "A recent `{submit_id}` click left autocomplete unresolved on `{}`{value_clause}. That submit does not finish the task. The visible suggestion `{}` already matches the field. Use `browser__click` on `{}` now to commit it in one step before submitting again.",
                control.semantic_id,
                suggestion.name,
                suggestion.semantic_id,
            ));
        }

        if highlighted_candidate {
            return Some(format!(
                "A recent `{submit_id}` click left autocomplete unresolved on `{}`{value_clause}. That submit does not finish the task. Use `browser__press_key` `Enter` now to commit the highlighted suggestion, then verify the widget is gone before submitting again.",
                control.semantic_id
            ));
        }

        if recent_enter_failed || guided_arrowdown_then_enter {
            return Some(format!(
                "A recent `{submit_id}` click left autocomplete unresolved on `{}`{value_clause}. That submit does not finish the task. Use `browser__press_key` `ArrowDown` now to highlight the suggestion, then `browser__press_key` `Enter` to commit it before submitting again.",
                control.semantic_id
            ));
        }

        return Some(format!(
            "A recent `{submit_id}` click left autocomplete unresolved on `{}`. That submit does not finish the task. Use `browser__press_key` with `ArrowDown` or `ArrowUp` to ground the intended suggestion, then `browser__press_key` `Enter` to commit it before submitting again.",
            control.semantic_id
        ));
    }

    if let Some(suggestion) = visible_suggestion.as_ref() {
        if recent_enter_failed {
            return Some(format!(
                "A recent `Enter` key left autocomplete unresolved on `{}`{value_clause}. That key did not commit the suggestion. The visible suggestion `{}` already matches the field. Use `browser__click` on `{}` now to commit it in one step.",
                control.semantic_id,
                suggestion.name,
                suggestion.semantic_id,
            ));
        }

        return Some(format!(
            "Autocomplete is still open on `{}`{value_clause}. The visible suggestion `{}` already matches it. Use `browser__click` on `{}` now to commit it in one step. Do not spend the next step on `ArrowDown`, `Enter`, or another `browser__inspect`.",
            control.semantic_id,
            suggestion.name,
            suggestion.semantic_id,
        ));
    }

    if recent_enter_failed {
        return Some(format!(
            "A recent `Enter` key left autocomplete unresolved on `{}`{value_clause}. That key did not commit the suggestion. Do not submit or finish yet. Use `browser__press_key` `ArrowDown` now to highlight it, then `browser__press_key` `Enter` to commit it before submitting.",
            control.semantic_id
        ));
    }

    if highlighted_candidate {
        return Some(format!(
            "Autocomplete is still open on `{}`{value_clause}. Do not submit or finish yet. Use `browser__press_key` `Enter` now to commit the highlighted suggestion, then verify the widget is gone before submitting.",
            control.semantic_id
        ));
    }

    if guided_arrowdown_then_enter {
        return Some(format!(
            "Autocomplete is still open on `{}`{value_clause}. The suggestion is not committed yet. Do not submit or finish. Use `browser__press_key` `ArrowDown` now to highlight it, then `browser__press_key` `Enter` to commit it before submitting.",
            control.semantic_id
        ));
    }

    Some(format!(
        "Autocomplete is still open on `{}`. Do not submit or finish yet. Use `browser__press_key` with `ArrowDown` or `ArrowUp` to ground the intended suggestion, then `browser__press_key` `Enter` to commit it.",
        control.semantic_id
    ))
}
