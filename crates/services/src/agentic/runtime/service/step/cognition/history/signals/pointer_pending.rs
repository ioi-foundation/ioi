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
            "The pointer is already positioned{target_clause} for the requested pointer task. Use `browser__pointer_down` now to {action_clause}.{repeat_clause}"
        ));
    }

    match goal_kind {
        PointerHoldGoalKind::Drag if latest_action.action == "hover" => {
            let target = pointer_action_target_label(&latest_action, current_snapshot)?;
            Some(format!(
                "A browser drag is already in progress and the pointer is grounded on `{target}`. Use `browser__pointer_up` now to release there. Do not repeat `browser__hover` on `{target}` or click submit yet."
            ))
        }
        PointerHoldGoalKind::Drag if latest_action.action == "mouse_down" => Some(
            "A browser drag is already in progress. Move to the intended drop target with `browser__hover` when a grounded target is visible, or use `browser__move_pointer` if you only have coordinates, then finish with `browser__pointer_up`. Do not click submit yet.".to_string(),
        ),
        PointerHoldGoalKind::Draw if latest_action.action == "mouse_down" => Some(
            "A browser pointer trace is already in progress. The next action must be `browser__move_pointer` or `browser__hover` to extend the stroke; do not use `browser__pointer_up` yet. Finish with `browser__pointer_up` only after the pointer has moved. Do not submit yet.".to_string(),
        ),
        PointerHoldGoalKind::Resize if latest_action.action == "mouse_down" => Some(
            "A browser resize gesture is already in progress. Move the pointer toward the requested size change with `browser__move_pointer` or `browser__hover`, then finish with `browser__pointer_up`. Do not submit yet.".to_string(),
        ),
        PointerHoldGoalKind::Slider if latest_action.action == "mouse_down" => Some(
            "A browser slider drag is already in progress. Move the pointer along the slider with `browser__move_pointer` or `browser__hover`, then finish with `browser__pointer_up` once the requested value is reached. Do not click submit yet.".to_string(),
        ),
        PointerHoldGoalKind::ColorWheel if latest_action.action == "mouse_down" => Some(
            "A browser color-wheel gesture is already in progress. Move the pointer to the requested color position with `browser__move_pointer` or `browser__hover`, then finish with `browser__pointer_up`. Do not submit yet.".to_string(),
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
            "Target text `{target}` is not visible yet. Search field `{}` is already on the page. Use `browser__click` on `{}` now so you can type `{target}` next; use the page's search control instead of `browser__find_text`, and do not click unrelated list actions first.",
            affordance.semantic_id, affordance.semantic_id
        ),
        SnapshotSearchAffordanceKind::Activator => format!(
            "Target text `{target}` is not visible yet. Search control `{}` is available. Use `browser__click` on `{}` now so you can search for `{target}`; use the page's search control instead of `browser__find_text`, and do not click unrelated list actions first.",
            affordance.semantic_id, affordance.semantic_id
        ),
    })
}
