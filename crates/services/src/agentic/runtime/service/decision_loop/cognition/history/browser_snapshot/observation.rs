pub(super) fn compact_browser_observation(snapshot: &str) -> String {
    compact_browser_observation_with_history(snapshot, &[])
}

fn snapshot_priority_summary_for_semantic_id(snapshot: &str, semantic_id: &str) -> Option<String> {
    for fragment in snapshot.split('<') {
        if extract_browser_xml_attr(fragment, "id").as_deref() != Some(semantic_id) {
            continue;
        }

        return browser_fragment_summary(snapshot, fragment).map(|(_, summary)| summary);
    }

    None
}

fn pending_state_priority_target_ids(snapshot: &str, history: &[ChatMessage]) -> HashSet<String> {
    if history.is_empty() {
        return HashSet::new();
    }

    let pending_context =
        build_recent_pending_browser_state_context_with_snapshot(history, Some(snapshot));
    if pending_context.is_empty() {
        return HashSet::new();
    }

    let mut ids = HashSet::new();
    let mut remainder = pending_context.as_str();
    while let Some((prefix, tail)) = remainder.split_once('`') {
        let Some((candidate, rest)) = tail.split_once('`') else {
            break;
        };
        let blocked_target = prefix
            .trim_end()
            .to_ascii_lowercase()
            .ends_with("do not click");
        if !blocked_target
            && !candidate.is_empty()
            && snapshot_priority_summary_for_semantic_id(snapshot, candidate).is_some()
        {
            ids.insert(candidate.to_string());
        }
        remainder = rest;
    }

    ids
}

pub(super) fn compact_browser_observation_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> String {
    let compact = compact_ws_for_prompt(snapshot.trim());
    let pending_target_ids = pending_state_priority_target_ids(snapshot, history);
    if let Some((_, summary)) = snapshot_visible_start_gate_priority_summary(snapshot) {
        let root_summary =
            browser_snapshot_root_summary(snapshot).unwrap_or_else(|| safe_truncate(&compact, 96));
        let suffix_prefix = " IMPORTANT TARGETS: ";
        let closing = " </root>";
        let suffix_budget = BROWSER_OBSERVATION_CONTEXT_MAX_CHARS
            .saturating_sub(
                root_summary.chars().count()
                    + suffix_prefix.chars().count()
                    + closing.chars().count(),
            )
            .max(64);
        let suffix = safe_truncate(&summary, suffix_budget);
        if !suffix.is_empty() {
            return format!("{root_summary}{suffix_prefix}{suffix}{closing}");
        }
    }

    if compact.chars().count() <= BROWSER_OBSERVATION_CONTEXT_MAX_CHARS
        && !snapshot_has_specific_grounded_geometry(snapshot)
        && pending_target_ids.is_empty()
    {
        return compact;
    }

    let mut priority_targets = prioritized_browser_target_entries(snapshot)
        .into_iter()
        .filter(|(_, _, summary)| {
            !snapshot_has_specific_grounded_geometry(snapshot)
                || !priority_target_looks_like_surface_wrapper(summary)
        })
        .filter(|(score, _, _)| *score >= 4)
        .collect::<Vec<_>>();
    if !pending_target_ids.is_empty() {
        priority_targets.sort_by(|left, right| {
            let left_pending = priority_target_semantic_id(&left.2)
                .is_some_and(|semantic_id| pending_target_ids.contains(semantic_id));
            let right_pending = priority_target_semantic_id(&right.2)
                .is_some_and(|semantic_id| pending_target_ids.contains(semantic_id));
            right_pending
                .cmp(&left_pending)
                .then(right.0.cmp(&left.0))
                .then(left.1.cmp(&right.1))
        });
    }
    let priority_targets = priority_targets
        .into_iter()
        .map(|(_, _, summary)| summary)
        .collect::<Vec<_>>();
    if priority_targets.is_empty() {
        return safe_truncate(&compact, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS);
    }

    let root_summary =
        browser_snapshot_root_summary(snapshot).unwrap_or_else(|| safe_truncate(&compact, 96));
    let suffix_prefix = " IMPORTANT TARGETS: ";
    let closing = " </root>";
    let suffix_budget = BROWSER_OBSERVATION_CONTEXT_MAX_CHARS
        .saturating_sub(
            root_summary.chars().count() + suffix_prefix.chars().count() + closing.chars().count(),
        )
        .max(64);
    let suffix = join_priority_targets_within_budget(priority_targets, suffix_budget);
    if suffix.is_empty() {
        return safe_truncate(&compact, BROWSER_OBSERVATION_CONTEXT_MAX_CHARS);
    }

    format!("{root_summary}{suffix_prefix}{suffix}{closing}")
}

pub(super) fn snapshot_lower_text(snapshot: &str) -> String {
    compact_ws_for_prompt(&decode_browser_xml_text(snapshot)).to_ascii_lowercase()
}
