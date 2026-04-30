pub(crate) fn build_browser_observation_context_from_snapshot(snapshot: &str) -> String {
    build_browser_observation_context_from_snapshot_with_history(snapshot, &[])
}

pub(crate) fn build_browser_observation_context_from_snapshot_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> String {
    let mut assistive_hints = extract_assistive_browser_hints(snapshot);
    if let Some(scroll_target_hint) =
        extract_scroll_target_focus_hint_with_history(snapshot, history)
    {
        assistive_hints.push(scroll_target_hint);
    }
    let compact_observation = compact_browser_observation_with_history(snapshot, history);
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

pub(super) fn browser_effect_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let message = history
        .iter()
        .rev()
        .find(|message| message.role == "tool")?;

    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    if compact.contains("\"autocomplete\":{")
        && (compact.contains("\"assistive_hint\":")
            || compact.contains("\"active_descendant_dom_id\":")
            || compact.contains("\"controls_dom_id\":"))
    {
        if current_snapshot.is_some()
            && autocomplete_follow_up_pending_signal(history, current_snapshot).is_none()
        {
            return None;
        }

        if compact.contains("\"key\":{") {
            if compact.contains("\"key\":\"ArrowDown\"") || compact.contains("\"key\":\"ArrowUp\"")
            {
                return Some("A recent browser navigation key updated the active autocomplete candidate, but the widget is still open. If the highlighted candidate is the intended choice, press `Enter` to commit it before submitting. Otherwise continue navigating or use `browser__inspect` to verify.".to_string());
            }
            return Some("A recent browser key press left autocomplete active, so that key did not resolve the widget. Do not submit or finish. Use `browser__press_key` with a different navigation key (for example `ArrowDown` or `ArrowUp`) or take `browser__inspect` to ground the candidate before committing.".to_string());
        }

        return Some("A recent browser action surfaced active autocomplete state. This widget is not resolved yet. Do not submit or finish until you explicitly commit or dismiss the suggestion, usually by checking updated browser state or using `browser__press_key`.".to_string());
    }

    if compact.contains("\"key\":{")
        && (compact.contains("\"tag_name\":\"body\"") || compact.contains("\"tag_name\":\"html\""))
    {
        return Some("A recent browser key landed on the page itself, not on a specific control. If you intended a textarea, listbox, or nested scroll region, target that control directly with `browser__press_key` `selector` when it is already grounded; otherwise focus it first or continue with the next required visible control. Do not repeat the same key blindly.".to_string());
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"Home\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_up\":true")
    {
        let selector = recent_browser_key_selector_from_compact(&compact);
        let top_edge_jump_call = top_edge_jump_call_for_selector(selector.as_deref());
        if compact.contains("\"modifiers\":[\"Control\"]") {
            return Some(format!(
                "A recent `{}` still left the focused scrollable control above top (`can_scroll_up=true`). Do not call `{}` again. Use `PageUp` next, then stop only at `can_scroll_up=false` or `scroll_top=0`.",
                top_edge_jump_name(),
                top_edge_jump_name(),
            ));
        }

        if let Some(scroll_top) = focused_home_should_jump_to_top_edge(&compact) {
            return Some(format!(
                "`Home` left a focused scrollable control above top (`scroll_top={scroll_top}`, `can_scroll_up=true`). Do not use `Home` again or spend the next step on `PageUp`. Use `{}` next, then stop only at `can_scroll_up=false` or `scroll_top=0`.",
                top_edge_jump_call,
            ));
        }

        return Some(format!(
            "A recent `Home` key still left the focused scrollable control above top (`can_scroll_up=true`). Do not call `Home` again. Use `PageUp` or `{}` next, then stop only at `can_scroll_up=false` or `scroll_top=0`.",
            top_edge_jump_call,
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"PageUp\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_up\":true")
    {
        let selector = recent_browser_key_selector_from_compact(&compact);
        return Some(format!(
            "A recent `PageUp` still left the focused scrollable control above top (`can_scroll_up=true`). Continue upward or use `{}`. Stop at `can_scroll_up=false` or `scroll_top=0`.",
            top_edge_jump_call_for_selector(selector.as_deref()),
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"End\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_down\":true")
    {
        let selector = recent_browser_key_selector_from_compact(&compact);
        let bottom_edge_jump_call = bottom_edge_jump_call_for_selector(selector.as_deref());
        if compact.contains("\"modifiers\":[\"Control\"]") {
            return Some(format!(
                "A recent `{}` still left the focused scrollable control above bottom (`can_scroll_down=true`). Do not call `{}` again. Use `PageDown` next, then stop only at `can_scroll_down=false`.",
                bottom_edge_jump_name(),
                bottom_edge_jump_name(),
            ));
        }

        return Some(format!(
            "A recent `End` key still left the focused scrollable control above bottom (`can_scroll_down=true`). Do not call `End` again. Use `PageDown` or `{}` next, then stop only at `can_scroll_down=false`.",
            bottom_edge_jump_call,
        ));
    }

    if compact.contains("\"key\":{")
        && compact.contains("\"key\":\"PageDown\"")
        && compact.contains("\"focused\":true")
        && compact.contains("\"can_scroll_down\":true")
    {
        let selector = recent_browser_key_selector_from_compact(&compact);
        return Some(format!(
            "A recent `PageDown` still left the focused scrollable control above bottom (`can_scroll_down=true`). Continue downward or use `{}`. Stop at `can_scroll_down=false`.",
            bottom_edge_jump_call_for_selector(selector.as_deref()),
        ));
    }

    if compact.contains("\"scroll\":{")
        && compact.contains("\"page_moved\":false")
        && compact.contains("\"target_moved\":false")
    {
        return Some("A recent browser scroll had no grounded effect on the page or the current scrollable control. Do not repeat the same blind scroll. First verify or focus the intended scroll container with `browser__inspect`, then use a control-local action such as `browser__press_key` (`Home`, `End`, `PageUp`, or `PageDown`) or a better-targeted scroll.".to_string());
    }

    if compact.contains("\"focused_control\":{")
        && compact.contains("\"focused\":true")
        && (compact.contains("\"can_scroll_up\":true")
            || compact.contains("\"can_scroll_down\":true"))
        && compact.contains("Clicked element")
    {
        return Some("A recent browser click already focused a scrollable control. Do not keep clicking the surrounding wrapper or container. If the goal is control-local scrolling or text selection in that control, continue there with a control-local action such as `browser__press_key` (preferably with the control's grounded `selector`) or `browser__select`; otherwise move to the next required visible control.".to_string());
    }

    None
}

fn tool_message_has_click_dispatch_timeout(message: &ChatMessage) -> bool {
    tool_message_verify_payload(message)
        .and_then(|verify| {
            verify
                .get("dispatch_failures")
                .and_then(Value::as_array)
                .cloned()
        })
        .is_some_and(|failures| {
            failures.iter().any(|failure| {
                failure
                    .get("error")
                    .and_then(Value::as_str)
                    .is_some_and(|error| error.contains("dispatch timed out"))
            })
        })
}

pub(super) fn click_dispatch_timeout_retry_pending_signal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let snapshot =
        current_snapshot.or_else(|| history.iter().rev().find_map(browser_snapshot_payload))?;
    let message = history
        .iter()
        .rev()
        .find(|message| message.role == "tool")?;
    let compact = compact_ws_for_prompt(&message.content);
    if !compact.contains("ERROR_CLASS=NoEffectAfterAction") {
        return None;
    }

    let clicked_id = click_attempt_target_semantic_id(message)?;
    if semantic_id_is_submit_like(&clicked_id) {
        return None;
    }
    if !tool_message_has_click_dispatch_timeout(message) {
        return None;
    }
    if snapshot_priority_target_summary(snapshot, &clicked_id).is_none() {
        return None;
    }

    Some(format!(
        "A recent `browser__click` on `{clicked_id}` timed out before any observed page effect, and `{clicked_id}` is still visible in the current browser observation. If the goal still requires activating `{clicked_id}`, retry `browser__click` on `{clicked_id}` now. Do not spend the next step on `browser__inspect` unless `{clicked_id}` disappears or the page visibly changes."
    ))
}

pub(super) fn repeated_pagewise_scroll_pending_signal(history: &[ChatMessage]) -> Option<String> {
    let mut repeated_page_up = 0usize;
    let mut repeated_page_down = 0usize;
    let mut repeated_page_up_selector: Option<String> = None;
    let mut repeated_page_down_selector: Option<String> = None;

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
            repeated_page_down_selector = None;
            if repeated_page_up_selector.is_none() {
                repeated_page_up_selector = recent_browser_key_selector_from_compact(&compact);
            }
            if repeated_page_up >= 2 {
                return Some(format!(
                    "Repeated `PageUp` still leaves the focused scrollable control above top (`can_scroll_up=true`). Stop repeating `PageUp`. Use `{}` next, then verify `can_scroll_up=false` or `scroll_top=0` before submit.",
                    top_edge_jump_call_for_selector(repeated_page_up_selector.as_deref()),
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
            repeated_page_up_selector = None;
            if repeated_page_down_selector.is_none() {
                repeated_page_down_selector = recent_browser_key_selector_from_compact(&compact);
            }
            if repeated_page_down >= 2 {
                return Some(format!(
                    "Repeated `PageDown` still leaves the focused scrollable control below bottom (`can_scroll_down=true`). Stop repeating `PageDown`. Use `{}` next, then verify `can_scroll_down=false` before submit.",
                    bottom_edge_jump_call_for_selector(repeated_page_down_selector.as_deref()),
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
        "A recent browser action{action} changed the page URL to `{}` but there is no newer `browser__inspect` yet. The current browser observation may still describe the previous page. Do not act on stale element ids or finish yet. Take `browser__inspect` now, then continue from the updated page state.",
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
        return Some("A visible browser auth form still remains, and recent browser state confirms both credential fields were filled. Do not keep taking snapshots or retyping the same credentials. Use the login action now (for example `browser__click` on the visible sign-in button), then verify that the page changes.".to_string());
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
