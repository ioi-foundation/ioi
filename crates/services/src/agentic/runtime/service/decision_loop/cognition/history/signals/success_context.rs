pub(crate) fn build_recent_success_signal_context(history: &[ChatMessage]) -> String {
    build_recent_success_signal_context_with_snapshot(history, None)
}

fn tool_message_is_synthetic_click_success(message: &ChatMessage) -> bool {
    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_postcondition_success = (compact.contains("\"postcondition\":{")
        && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");

    has_postcondition_success
        && (compact.contains("\"synthetic_click\":{")
            || compact.starts_with("Synthetic click at ("))
}

fn tool_message_is_scroll_edge_success(message: &ChatMessage) -> bool {
    if message.role != "tool" {
        return false;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if !compact.contains("\"key\":{") {
        return false;
    }

    ((compact.contains("\"key\":\"Home\"") || compact.contains("\"key\":\"PageUp\""))
        && compact.contains("\"scroll_top\":0")
        && compact.contains("\"can_scroll_up\":false"))
        || ((compact.contains("\"key\":\"End\"") || compact.contains("\"key\":\"PageDown\""))
            && compact.contains("\"can_scroll_down\":false"))
}

fn recent_success_signal_should_survive_pending_state(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> bool {
    history.iter().rev().any(|message| {
        geometry_progress_target_for_message(history, message, current_snapshot).is_some()
            || tool_message_is_scroll_edge_success(message)
    })
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
    let snapshot_pending_signal = current_snapshot
        .or_else(|| history.iter().rev().find_map(browser_snapshot_payload))
        .and_then(|snapshot| browser_snapshot_pending_signal_with_history(snapshot, history));

    let pending_state_present = navigation_signal.is_some()
        || auth_form_pending_signal(history).is_some()
        || autocomplete_follow_up_pending_signal(history, current_snapshot).is_some()
        || tree_change_link_reverification_pending_signal_with_current_snapshot(
            history,
            current_snapshot,
        )
        .is_some()
        || filter_mismatch_pending_signal(history, current_snapshot).is_some()
        || instruction_only_find_text_pagination_pending_signal(history, current_snapshot)
            .is_some()
        || alternate_tab_exploration_pending_signal(history, current_snapshot).is_some()
        || stale_queue_reverification_pending_signal(history, current_snapshot).is_some()
        || queue_reverification_history_follow_up_pending_signal(history, current_snapshot)
            .is_some()
        || snapshot_pending_signal.is_some();

    if pending_state_present
        && !recent_success_signal_should_survive_pending_state(history, current_snapshot)
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
