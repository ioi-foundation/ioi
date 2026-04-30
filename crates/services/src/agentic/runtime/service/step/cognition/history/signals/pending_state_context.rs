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
    let snapshot_pending_signal = current_snapshot
        .or_else(|| history.iter().rev().find_map(browser_snapshot_payload))
        .and_then(|snapshot| browser_snapshot_pending_signal_with_history(snapshot, history));

    let Some(signal) = navigation_signal
        .or_else(|| auth_form_pending_signal(history))
        .or_else(|| visible_error_text_control_pending_signal(history, current_snapshot))
        .or_else(|| autocomplete_follow_up_pending_signal(history, current_snapshot))
        .or_else(|| {
            tree_change_link_reverification_pending_signal_with_current_snapshot(
                history,
                current_snapshot,
            )
        })
        .or_else(|| filter_mismatch_pending_signal(history, current_snapshot))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, current_snapshot))
        .or_else(|| start_gate_pending_signal(history, current_snapshot))
        .or_else(|| stale_queue_reverification_pending_signal(history, current_snapshot))
        .or_else(|| {
            queue_reverification_history_follow_up_pending_signal(history, current_snapshot)
        })
        .or_else(|| alternate_tab_exploration_pending_signal(history, current_snapshot))
        .or_else(|| click_dispatch_timeout_retry_pending_signal(history, current_snapshot))
        .or_else(|| snapshot_pending_signal)
        .or_else(|| repeated_pagewise_scroll_pending_signal(history))
        .or_else(|| browser_effect_pending_signal(history, current_snapshot))
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
        .or_else(|| visible_error_text_control_pending_signal(history, Some(snapshot)))
        .or_else(|| autocomplete_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| {
            tree_change_link_reverification_pending_signal_with_current_snapshot(
                history,
                Some(snapshot),
            )
        })
        .or_else(|| dropdown_filter_mismatch_pending_signal(snapshot, history))
        .or_else(|| instruction_only_find_text_pagination_pending_signal(history, Some(snapshot)))
        .or_else(|| start_gate_pending_signal(history, Some(snapshot)))
        .or_else(|| stale_queue_reverification_pending_signal(history, Some(snapshot)))
        .or_else(|| queue_reverification_history_follow_up_pending_signal(history, Some(snapshot)))
        .or_else(|| alternate_tab_exploration_pending_signal(history, Some(snapshot)))
        .or_else(|| click_dispatch_timeout_retry_pending_signal(history, Some(snapshot)))
        .or_else(|| browser_snapshot_pending_signal_with_history(snapshot, history))
    else {
        return String::new();
    };

    let compact_signal = safe_truncate(&signal, PENDING_BROWSER_STATE_MAX_CHARS);
    if compact_signal.is_empty() {
        return String::new();
    }

    format!("RECENT PENDING BROWSER STATE:\n{}\n", compact_signal)
}
