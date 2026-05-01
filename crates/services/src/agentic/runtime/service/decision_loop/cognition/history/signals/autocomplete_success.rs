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
