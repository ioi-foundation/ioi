use super::*;

pub(super) fn is_history_like_link(link: &SnapshotLinkState) -> bool {
    link.name
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case("history"))
        || link
            .dom_id
            .as_deref()
            .is_some_and(|dom_id| dom_id.to_ascii_lowercase().contains("history"))
        || link
            .selector
            .as_deref()
            .is_some_and(|selector| selector.to_ascii_lowercase().contains("history"))
}

pub(super) fn snapshot_link_item_id(link: &SnapshotLinkState) -> Option<String> {
    [
        Some(link.semantic_id.as_str()),
        link.name.as_deref(),
        link.dom_id.as_deref(),
        link.selector.as_deref(),
        link.context.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find_map(first_item_like_id)
}

pub(super) fn recent_goal_item_ids(history: &[ChatMessage]) -> HashSet<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .flat_map(|message| extract_item_like_ids(&message.content))
        .collect()
}

pub(super) fn recent_goal_item_sequence(history: &[ChatMessage]) -> Vec<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .find_map(|message| {
            let ids = extract_item_like_ids(&message.content);
            (!ids.is_empty()).then_some(ids)
        })
        .unwrap_or_default()
}

pub(super) fn recent_successful_tab_click_ids(
    history: &[ChatMessage],
    snapshot: &str,
) -> Vec<String> {
    let valid_ids = snapshot_tab_states(snapshot)
        .into_iter()
        .map(|tab| tab.semantic_id)
        .collect::<HashSet<_>>();
    let mut tab_ids = Vec::new();
    let mut seen = HashSet::new();

    for message in history.iter().rev() {
        let Some(clicked_id) = clicked_element_semantic_id(message) else {
            continue;
        };
        if !valid_ids.contains(&clicked_id) || !seen.insert(clicked_id.clone()) {
            continue;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let has_click_postcondition_success = (compact.contains("\"postcondition\":{")
            && compact.contains("\"met\":true"))
            || compact.contains("\"postcondition_met\":true");
        if !has_click_postcondition_success {
            continue;
        }

        tab_ids.push(clicked_id);
        if tab_ids.len() >= 3 {
            break;
        }
    }

    tab_ids
}

pub(super) fn snapshot_ticket_link_for_item(
    snapshot: &str,
    item_id: &str,
) -> Option<SnapshotLinkState> {
    snapshot_link_states(snapshot).into_iter().find(|link| {
        !is_history_like_link(link)
            && snapshot_link_item_id(link)
                .as_deref()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(item_id))
    })
}

pub(super) fn snapshot_history_link_for_item(
    snapshot: &str,
    item_id: &str,
) -> Option<SnapshotLinkState> {
    snapshot_link_states(snapshot).into_iter().find(|link| {
        is_history_like_link(link)
            && snapshot_link_item_id(link)
                .as_deref()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(item_id))
    })
}

pub(super) fn snapshot_visible_item_order(snapshot: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();

    for link in snapshot_link_states(snapshot) {
        if is_history_like_link(&link) {
            continue;
        }

        let Some(item_id) = snapshot_link_item_id(&link) else {
            continue;
        };
        if seen.insert(item_id.clone()) {
            ids.push(item_id);
        }
    }

    ids
}

pub(super) fn link_name_is_pagination_like(name: &str) -> bool {
    let raw = compact_ws_for_prompt(name);
    let raw_trimmed = raw.trim();
    if matches!(
        raw_trimmed,
        "<" | ">" | "<<" | ">>" | "&lt;" | "&gt;" | "&lt;&lt;" | "&gt;&gt;"
    ) {
        return true;
    }

    let normalized = normalized_exact_target_text(name);
    !normalized.is_empty()
        && (normalized.chars().all(|ch| ch.is_ascii_digit())
            || matches!(
                normalized.as_str(),
                "first" | "last" | "next" | "previous" | "prev"
            )
            || matches!(name.trim(), "<" | ">" | "<<" | ">>"))
}

pub(super) fn parse_zero_based_result_rank_marker(raw: &str) -> Option<usize> {
    let normalized = raw.trim().to_ascii_lowercase();
    let suffix = normalized
        .strip_prefix("result-")
        .or_else(|| normalized.strip_prefix("result_"))?;
    suffix.parse::<usize>().ok().map(|rank| rank + 1)
}

pub(super) fn snapshot_link_result_rank(link: &SnapshotLinkState) -> Option<usize> {
    link.dom_id
        .as_deref()
        .and_then(parse_zero_based_result_rank_marker)
        .or_else(|| {
            link.selector
                .as_deref()
                .and_then(parse_zero_based_result_rank_marker)
        })
        .or_else(|| {
            link.context
                .as_deref()
                .and_then(parse_zero_based_result_rank_marker)
        })
        .or_else(|| {
            link.semantic_id
                .to_ascii_lowercase()
                .contains("result")
                .then(|| semantic_id_numeric_suffix(&link.semantic_id))
                .flatten()
        })
}

pub(super) fn snapshot_visible_result_links(snapshot: &str) -> Vec<SnapshotLinkState> {
    let visible_links = snapshot_link_states(snapshot)
        .into_iter()
        .filter(|link| link.visible)
        .collect::<Vec<_>>();
    let mut explicit_ranked_links = visible_links
        .iter()
        .filter_map(|link| snapshot_link_result_rank(link).map(|rank| (rank, link.clone())))
        .collect::<Vec<_>>();
    explicit_ranked_links.sort_by(|(left_rank, left_link), (right_rank, right_link)| {
        left_rank
            .cmp(right_rank)
            .then_with(|| left_link.semantic_id.cmp(&right_link.semantic_id))
    });
    explicit_ranked_links.dedup_by(|(left_rank, _), (right_rank, _)| left_rank == right_rank);
    if !explicit_ranked_links.is_empty() {
        return explicit_ranked_links
            .into_iter()
            .map(|(_, link)| link)
            .collect();
    }

    visible_links
        .into_iter()
        .filter(|link| {
            link.name
                .as_deref()
                .is_some_and(|name| !link_name_is_pagination_like(name))
        })
        .collect()
}

pub(super) fn snapshot_visible_pagination_links(snapshot: &str) -> Vec<SnapshotLinkState> {
    snapshot_link_states(snapshot)
        .into_iter()
        .filter(|link| link.visible)
        .filter(|link| {
            link.name
                .as_deref()
                .is_some_and(link_name_is_pagination_like)
        })
        .collect()
}

pub(super) fn snapshot_pagination_link_for_page(
    snapshot: &str,
    page: usize,
) -> Option<SnapshotLinkState> {
    let page_label = page.to_string();
    snapshot_visible_pagination_links(snapshot)
        .into_iter()
        .find(|link| {
            link.name
                .as_deref()
                .is_some_and(|name| normalized_exact_target_text(name) == page_label)
        })
}

pub(super) fn pagination_name_is_previous_like(name: &str) -> bool {
    matches!(
        compact_ws_for_prompt(name).trim(),
        "<" | "<<" | "&lt;" | "&lt;&lt;"
    ) || matches!(
        normalized_exact_target_text(name).as_str(),
        "previous" | "prev"
    )
}

pub(super) fn pagination_name_is_next_like(name: &str) -> bool {
    matches!(
        compact_ws_for_prompt(name).trim(),
        ">" | ">>" | "&gt;" | "&gt;&gt;"
    ) || matches!(normalized_exact_target_text(name).as_str(), "next")
}

pub(super) fn snapshot_current_pagination_page(snapshot: &str) -> Option<usize> {
    let pagination_links = snapshot_visible_pagination_links(snapshot);
    if pagination_links.is_empty() {
        return None;
    }

    let has_previous = pagination_links
        .iter()
        .filter_map(|link| link.name.as_deref())
        .any(pagination_name_is_previous_like);
    let has_next = pagination_links
        .iter()
        .filter_map(|link| link.name.as_deref())
        .any(pagination_name_is_next_like);
    let numeric_pages = pagination_links
        .iter()
        .filter_map(|link| link.name.as_deref())
        .filter_map(|name| normalized_exact_target_text(name).parse::<usize>().ok())
        .collect::<Vec<_>>();
    if numeric_pages.is_empty() {
        return None;
    }

    if !has_previous && numeric_pages.contains(&1) {
        return Some(1);
    }

    if !has_next {
        return numeric_pages.iter().max().copied();
    }

    None
}

pub(super) fn snapshot_next_pagination_link(snapshot: &str) -> Option<SnapshotLinkState> {
    snapshot_visible_pagination_links(snapshot)
        .into_iter()
        .find(|link| {
            link.name
                .as_deref()
                .is_some_and(pagination_name_is_next_like)
        })
}

pub(super) fn snapshot_forward_pagination_link(snapshot: &str) -> Option<SnapshotLinkState> {
    snapshot_next_pagination_link(snapshot).or_else(|| {
        let current_page = snapshot_current_pagination_page(snapshot).unwrap_or(0);
        let mut numeric_links = snapshot_visible_pagination_links(snapshot)
            .into_iter()
            .filter_map(|link| {
                let page = link
                    .name
                    .as_deref()
                    .and_then(|name| normalized_exact_target_text(name).parse::<usize>().ok())?;
                Some((page, link))
            })
            .collect::<Vec<_>>();
        numeric_links.sort_by(|(left_page, left_link), (right_page, right_link)| {
            left_page
                .cmp(right_page)
                .then_with(|| left_link.semantic_id.cmp(&right_link.semantic_id))
        });
        numeric_links
            .into_iter()
            .find(|(page, _)| *page > current_page)
            .map(|(_, link)| link)
    })
}

pub(super) fn semantic_id_numeric_suffix(semantic_id: &str) -> Option<usize> {
    let digits = semantic_id
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    (!digits.is_empty())
        .then(|| digits.parse::<usize>().ok())
        .flatten()
}

pub(super) fn tool_output_click_semantic_id(message: &ChatMessage) -> Option<String> {
    clicked_element_semantic_id(message).or_else(|| {
        (message.role == "tool")
            .then(|| {
                extract_compact_jsonish_string_field(&compact_ws_for_prompt(&message.content), "id")
            })
            .flatten()
    })
}

pub(super) fn recent_clicked_pagination_page_number(
    history: &[ChatMessage],
    snapshot: &str,
) -> Option<usize> {
    if let Some(current_page) = snapshot_current_pagination_page(snapshot) {
        return Some(current_page);
    }

    let pagination_links = snapshot_visible_pagination_links(snapshot);
    history.iter().rev().find_map(|message| {
        if message.role != "tool" {
            return None;
        }

        let compact = compact_ws_for_prompt(&message.content);
        let semantic_id = tool_output_click_semantic_id(message)?;
        let mapped = pagination_links
            .iter()
            .find(|link| link.semantic_id == semantic_id)
            .and_then(|link| link.name.as_deref())
            .and_then(|name| normalized_exact_target_text(name).parse::<usize>().ok());
        let effective_transition = compact.contains("\"postcondition\":{")
            && (compact.contains("\"met\":true")
                || compact.contains("\"tree_changed\":true")
                || compact.contains("\"url_changed\":true"));
        if !effective_transition {
            return None;
        }

        mapped.or_else(|| semantic_id_numeric_suffix(&semantic_id))
    })
}

pub(super) fn contains_ascii_case_insensitive(text: &str, needle: &str) -> bool {
    text.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

pub(super) fn instruction_like_attr_matches(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("query") || lowered.contains("instruction") || lowered.contains("prompt")
}

pub(super) fn snapshot_visible_instruction_query_target(
    snapshot: &str,
    query: &str,
) -> Option<SnapshotVisibleTargetState> {
    if query.trim().is_empty() {
        return None;
    }

    let mut best_match: Option<(u8, usize, SnapshotVisibleTargetState)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
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
        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !contains_ascii_case_insensitive(&name, query) {
            continue;
        }

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
        if !instruction_like_attr_matches(&semantic_id)
            && !dom_id.as_deref().is_some_and(instruction_like_attr_matches)
            && !selector
                .as_deref()
                .is_some_and(instruction_like_attr_matches)
        {
            continue;
        }

        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: name.clone(),
            semantic_role: semantic_role.clone(),
            already_active: false,
        };
        let candidate_score = visible_target_role_priority(&semantic_role);
        let candidate_name_len = name.chars().count();

        match best_match.as_ref() {
            Some((best_score, best_len, best_candidate))
                if *best_score > candidate_score
                    || (*best_score == candidate_score
                        && (*best_len < candidate_name_len
                            || (*best_len == candidate_name_len
                                && best_candidate.semantic_id <= candidate.semantic_id))) => {}
            _ => best_match = Some((candidate_score, candidate_name_len, candidate)),
        }
    }

    best_match.map(|(_, _, candidate)| candidate)
}

pub(super) fn snapshot_primary_visible_heading(
    snapshot: &str,
) -> Option<SnapshotVisibleTargetState> {
    snapshot.split('<').find_map(|fragment| {
        if !fragment.trim_start().starts_with("heading ")
            || fragment.contains(r#" omitted="true""#)
            || fragment.contains(r#" visible="false""#)
        {
            return None;
        }

        let semantic_id = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())?;
        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())?;

        Some(SnapshotVisibleTargetState {
            semantic_id,
            name,
            semantic_role: "heading".to_string(),
            already_active: false,
        })
    })
}

pub(super) fn recent_history_viewed_item_ids(history: &[ChatMessage]) -> Vec<String> {
    let mut item_ids = Vec::new();
    let mut seen = HashSet::new();

    for message in history.iter().rev().take(20) {
        if let Some(transition) = browser_navigation_transition(message) {
            for url in [
                transition.pre_url.as_deref(),
                Some(transition.post_url.as_str()),
            ]
            .into_iter()
            .flatten()
            {
                if !url.to_ascii_lowercase().contains("/history") {
                    continue;
                }
                if let Some(item_id) = history_item_like_id_from_url(url) {
                    if seen.insert(item_id.clone()) {
                        item_ids.push(item_id);
                    }
                }
            }
        }

        if item_ids.len() >= 3 {
            break;
        }
    }

    item_ids
}

pub(super) fn recent_history_return_item_id(history: &[ChatMessage]) -> Option<String> {
    history.iter().rev().find_map(|message| {
        let transition = browser_navigation_transition(message)?;
        let pre_url = transition.pre_url?;
        if !pre_url.to_ascii_lowercase().contains("/history") {
            return None;
        }
        if transition
            .post_url
            .to_ascii_lowercase()
            .contains("/history")
        {
            return None;
        }
        history_item_like_id_from_url(&pre_url)
    })
}

pub(super) fn history_verification_tokens(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let lowered = token.trim();
            if lowered.len() < 4 {
                return None;
            }

            let lowered = lowered.to_ascii_lowercase();
            if matches!(
                lowered.as_str(),
                "verify"
                    | "that"
                    | "this"
                    | "with"
                    | "from"
                    | "before"
                    | "after"
                    | "return"
                    | "queue"
                    | "audit"
                    | "history"
                    | "ticket"
                    | "actor"
                    | "action"
                    | "requested"
                    | "matches"
                    | "match"
                    | "there"
                    | "their"
                    | "visible"
                    | "already"
                    | "current"
            ) {
                return None;
            }

            Some(lowered)
        })
        .collect()
}
