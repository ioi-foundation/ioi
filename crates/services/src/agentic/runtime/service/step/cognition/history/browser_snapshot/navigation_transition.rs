#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BrowserNavigationTransition {
    pub(super) semantic_id: Option<String>,
    pub(super) pre_url: Option<String>,
    pub(super) post_url: String,
}

fn clicked_element_semantic_id_from_text(text: &str) -> Option<String> {
    let rest = text.trim().strip_prefix("Clicked element '")?;
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn click_effect_text_from_message(message: &ChatMessage) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    parse_json_value_from_message(&message.content).and_then(|payload| {
        payload
            .get("click")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn text_has_click_postcondition_success(text: &str) -> bool {
    let compact = compact_ws_for_prompt(text);
    (compact.contains("\"postcondition\":{") && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true")
}

fn message_has_click_postcondition_success(message: &ChatMessage) -> bool {
    text_has_click_postcondition_success(&message.content)
        || click_effect_text_from_message(message)
            .as_deref()
            .is_some_and(text_has_click_postcondition_success)
}

pub(super) fn clicked_element_semantic_id(message: &ChatMessage) -> Option<String> {
    if message.role != "tool" {
        return None;
    }

    clicked_element_semantic_id_from_text(&message.content).or_else(|| {
        click_effect_text_from_message(message)
            .and_then(|click| clicked_element_semantic_id_from_text(&click))
    })
}

pub(super) fn recent_successful_click_semantic_id(history: &[ChatMessage]) -> Option<String> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        if !message_has_click_postcondition_success(message)
            || clicked_element_semantic_id(message).is_none()
        {
            return None;
        }

        clicked_element_semantic_id(message)
    })
}

pub(super) fn recent_successful_selected_control_semantic_id(
    history: &[ChatMessage],
) -> Option<String> {
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let click_text = click_effect_text_from_message(message).unwrap_or_default();
        let selected_control = compact.contains("\"checked\":true")
            || compact.contains("\"selected\":true")
            || click_text.contains("\"checked\":true")
            || click_text.contains("\"selected\":true");
        if !message_has_click_postcondition_success(message)
            || clicked_element_semantic_id(message).is_none()
            || !selected_control
        {
            return None;
        }

        clicked_element_semantic_id(message)
    })
}

pub(super) fn recent_successful_click_is_observed_in_later_snapshot(
    history: &[ChatMessage],
    semantic_id: &str,
) -> bool {
    let mut saw_later_snapshot = false;

    for message in history.iter().rev() {
        if browser_snapshot_payload(message).is_some() {
            saw_later_snapshot = true;
            continue;
        }
        if message.role != "tool" {
            continue;
        }

        if !message_has_click_postcondition_success(message)
            || clicked_element_semantic_id(message).is_none()
        {
            continue;
        }
        if clicked_element_semantic_id(message).as_deref() == Some(semantic_id) {
            return saw_later_snapshot;
        }
    }

    false
}

pub(super) fn recent_successful_click_has_post_action_observation(
    history: &[ChatMessage],
    semantic_id: &str,
    current_snapshot: Option<&str>,
) -> bool {
    if recent_successful_click_is_observed_in_later_snapshot(history, semantic_id) {
        return true;
    }

    current_snapshot.is_some()
        && recent_successful_click_semantic_id(history).as_deref() == Some(semantic_id)
}

fn snapshot_semantic_id_name(snapshot: &str, semantic_id: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if extract_browser_xml_attr(fragment, "id").as_deref() != Some(semantic_id) {
            continue;
        }

        return extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
    }

    None
}

pub(super) fn snapshot_semantic_id_has_selected_state(snapshot: &str, semantic_id: &str) -> bool {
    let semantic_id_attr = format!(r#"id="{}""#, semantic_id);

    snapshot.split('<').any(|fragment| {
        fragment.contains(&semantic_id_attr)
            && (fragment.contains(r#" checked="true""#) || fragment.contains(r#" selected="true""#))
    })
}

fn snapshot_semantic_id_is_reusable_navigation_control(snapshot: &str, semantic_id: &str) -> bool {
    snapshot_semantic_id_name(snapshot, semantic_id)
        .map(|name| browser_name_looks_like_reusable_navigation_control(&name.to_ascii_lowercase()))
        .unwrap_or_else(|| {
            let lower = semantic_id.to_ascii_lowercase();
            lower.contains("prev") || lower.contains("next")
        })
}

pub(super) fn tree_change_link_reverification_pending_signal(
    history: &[ChatMessage],
) -> Option<String> {
    let latest_snapshot_idx = history
        .iter()
        .rposition(|message| browser_snapshot_payload(message).is_some());
    let search_start = latest_snapshot_idx.map_or(0, |idx| idx + 1);
    let prior_snapshot =
        latest_snapshot_idx.and_then(|idx| browser_snapshot_payload(&history[idx]));

    let clicked_id = history[search_start..].iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success
            || !compact.contains("Clicked element")
            || !compact.contains("\"tree_changed\":true")
            || compact.contains("\"url_changed\":true")
        {
            return None;
        }

        let clicked_id = clicked_element_semantic_id(message)?;
        let link_like = clicked_id.to_ascii_lowercase().starts_with("lnk_")
            || compact.contains(r#""tag_name":"a""#);
        link_like.then_some(clicked_id)
    })?;

    if prior_snapshot.is_some_and(|snapshot| {
        snapshot_semantic_id_is_reusable_navigation_control(snapshot, &clicked_id)
    }) {
        return Some(format!(
            "A recent click on navigation control `{clicked_id}` already changed the page state (`tree_changed=true`). The previous browser observation is stale for non-navigation targets, but `{clicked_id}` remains reusable. If the goal still requires more movement in that same direction, you may click `{clicked_id}` again now; otherwise use `browser__inspect` before choosing newly visible content from the updated page."
        ));
    }

    Some(format!(
        "A recent click on `{clicked_id}` already changed the page state (`tree_changed=true`). Do not click `{clicked_id}` again or act on stale controls from the previous browser observation. Use `browser__inspect` once now to ground the updated page before taking the next action."
    ))
}

pub(super) fn tree_change_link_reverification_pending_signal_with_current_snapshot(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    let latest_snapshot = history.iter().rev().find_map(browser_snapshot_payload);
    if current_snapshot.is_some_and(|snapshot| latest_snapshot != Some(snapshot)) {
        return None;
    }

    tree_change_link_reverification_pending_signal(history)
}

pub(super) fn semantic_id_is_submit_like(semantic_id: &str) -> bool {
    let lower = semantic_id.to_ascii_lowercase();
    lower.contains("submit") || lower.contains("subbtn") || lower.contains("search")
}

pub(super) fn snapshot_contains_semantic_id(snapshot: &str, semantic_id: &str) -> bool {
    let semantic_id_attr = format!(r#"id="{}""#, semantic_id);
    let compact_summary = format!("#{semantic_id}");
    let compact_summary_raw = format!("{semantic_id} tag=");
    let compact_summary_attr = format!("id={semantic_id}");
    snapshot.contains(&semantic_id_attr)
        || snapshot.contains(&compact_summary)
        || snapshot.contains(&compact_summary_raw)
        || snapshot.contains(&compact_summary_attr)
}

pub(super) fn recent_confirmation_queue_return(history: &[ChatMessage]) -> bool {
    history.iter().rev().take(10).any(|message| {
        let Some(transition) = browser_navigation_transition(message) else {
            return false;
        };
        let Some(pre_url) = transition.pre_url else {
            return false;
        };

        pre_url.to_ascii_lowercase().contains("/confirmation")
            && transition.post_url.to_ascii_lowercase().contains("/queue")
    })
}

pub(super) fn browser_navigation_transition(
    message: &ChatMessage,
) -> Option<BrowserNavigationTransition> {
    if message.role != "tool" {
        return None;
    }

    let compact = compact_ws_for_prompt(&message.content);
    let has_success = (compact.contains("\"postcondition\":{") && compact.contains("\"met\":true"))
        || compact.contains("\"postcondition_met\":true");
    if !has_success {
        return None;
    }

    let pre_url = extract_compact_jsonish_string_field(&compact, "pre_url")
        .or_else(|| extract_scoped_compact_jsonish_string_field(&compact, "\"pre\":{", "url"));
    let post_url = extract_compact_jsonish_string_field(&compact, "post_url")
        .or_else(|| extract_scoped_compact_jsonish_string_field(&compact, "\"post\":{", "url"));
    let has_url_change = compact.contains("\"url_changed\":true")
        || pre_url
            .as_ref()
            .zip(post_url.as_ref())
            .is_some_and(|(pre, post)| pre != post);
    if !has_url_change {
        return None;
    }

    Some(BrowserNavigationTransition {
        semantic_id: clicked_element_semantic_id(message),
        pre_url,
        post_url: post_url.unwrap_or_else(|| "the new page".to_string()),
    })
}

pub(super) fn recent_unobserved_navigation_transition(
    history: &[ChatMessage],
) -> Option<BrowserNavigationTransition> {
    let latest_snapshot_idx = history
        .iter()
        .rposition(|message| browser_snapshot_payload(message).is_some());
    let search_start = latest_snapshot_idx.map_or(0, |idx| idx + 1);
    history[search_start..]
        .iter()
        .rev()
        .find_map(browser_navigation_transition)
}
