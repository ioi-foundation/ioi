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
        "A visible start gate `{}` is still covering the task surface. Use `browser__click` on `{}` now to begin the page, then continue with the working controls. Do not click underlying canvas, form, or list targets before this gate clears.",
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
            "This message still needs recipient `{recipient}`. Focus recipient field `{}` with `browser__click` now, then type `{recipient}` on the following step. Do not click `{send_id}` yet.",
            control.semantic_id
        ),
        None => format!(
            "This message still needs recipient `{recipient}`. Focus recipient field `{}` with `browser__click` now, then type `{recipient}` on the following step before sending.",
            control.semantic_id
        ),
    })
}
