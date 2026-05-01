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
        if let Some(snapshot) = snapshot {
            if let Some(signal) = snapshot_select_submit_progress_success_signal(snapshot) {
                return Some(signal);
            }
        }

        return Some(
            "A recent browser interaction already selected a form control (`checked=true` or `selected=true`). Do not click the surrounding option group or form container again. Continue with the next required control (for example `Submit`) or verify once if the goal is already satisfied.".to_string(),
        );
    }

    if has_click_postcondition_success && compact.contains("Clicked element") {
        if let Some(snapshot) = snapshot {
            if let Some(clicked_id) = clicked_element_semantic_id(message) {
                let clicked_control_selected = snapshot_visible_selectable_control_states(snapshot)
                    .into_iter()
                    .any(|control| control.selected && control.semantic_id == clicked_id);
                if clicked_control_selected {
                    if let Some(signal) = snapshot_select_submit_progress_success_signal(snapshot) {
                        return Some(signal);
                    }
                }
            }
        }

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
                    " Do not spend the next step on another `browser__inspect` unless the page changes again.",
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
                    " Do not spend the next step on another `browser__inspect` unless the page changed.",
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
