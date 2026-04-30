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
        "The target text `{target}` is already visible as `{}`. Use `browser__click` on `{}` now. Do not click a surrounding container or panel, do not use `browser__find_text`, and do not spend the next step on another `browser__inspect`.",
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
        "Target text `{target}` is already active as `{}`. Use `browser__click` on `{submit_id}` now to commit the current page state. Do not click `{}` again, and do not call `agent__complete` before submission.",
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
        "Recent submit `{submit_id}` left visible field `{}` marked invalid.{value_clause} Use `browser__click` on `{}` now so you can repair it before submitting again. Do not click `{submit_id}` again yet.",
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
