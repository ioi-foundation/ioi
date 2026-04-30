pub(super) fn snapshot_has_negative_selection_instruction(snapshot: &str) -> bool {
    let lower = snapshot_lower_text(snapshot);
    [
        "select nothing",
        "select none",
        "choose nothing",
        "choose none",
        "check nothing",
        "check none",
        "leave unchecked",
        "leave unselected",
        "keep unchecked",
        "keep unselected",
        "select no items",
        "select no options",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
}

pub(super) fn snapshot_has_selectable_controls(snapshot: &str) -> bool {
    let lower = snapshot.to_ascii_lowercase();
    lower.contains("<checkbox ") || lower.contains("<radio ") || lower.contains("<option ")
}

pub(super) fn snapshot_has_selected_controls(snapshot: &str) -> bool {
    let lower = snapshot.to_ascii_lowercase();
    lower.contains("checked=\"true\"") || lower.contains("selected=\"true\"")
}

fn snapshot_visible_submit_control_id_local(snapshot: &str) -> Option<String> {
    let mut best_match: Option<((u8, u8, u8, u8, u8), String)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        let omitted = fragment.contains(r#" omitted="true""#);
        if omitted && !browser_fragment_allows_omitted_action_target(fragment, semantic_role) {
            continue;
        }
        let normalized_name = extract_browser_xml_attr(fragment, "name")
            .map(|value| normalized_exact_target_text(&decode_browser_xml_text(&value)))
            .unwrap_or_default();
        let semantic_id_submit_like = semantic_id_is_submit_like(&semantic_id);
        let submit_like_name = normalized_name
            .split_whitespace()
            .any(|token| token == "submit");
        if !(semantic_id_submit_like || submit_like_name) {
            continue;
        }

        let actionable = u8::from(browser_fragment_is_actionable_goal_target(
            fragment,
            semantic_role,
        ));
        let selector_present = u8::from(fragment.contains(r#" selector=""#));
        let focused = u8::from(fragment.contains(r#" focused="true""#));
        let candidate_rank = (
            actionable,
            u8::from(semantic_id_submit_like),
            u8::from(!omitted),
            selector_present,
            focused,
        );

        match best_match.as_ref() {
            Some((best_rank, best_id))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank && best_id <= &semantic_id) => {}
            _ => best_match = Some((candidate_rank, semantic_id)),
        }
    }

    best_match.map(|(_, semantic_id)| semantic_id)
}

pub(super) fn snapshot_visible_selectable_control_states(
    snapshot: &str,
) -> Vec<SnapshotSelectableControlState> {
    let mut seen_ids = HashSet::new();
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "checkbox" | "radio" | "option") {
            continue;
        }
        if fragment.contains(r#" omitted="true""#)
            && !browser_fragment_allows_omitted_action_target(fragment, semantic_role)
        {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if !seen_ids.insert(semantic_id.clone()) {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        states.push(SnapshotSelectableControlState {
            semantic_id,
            name,
            selected: fragment.contains(r#" checked="true""#)
                || fragment.contains(r#" selected="true""#),
        });
    }

    states
}

pub(super) fn snapshot_select_submit_progress_pending_signal_for_requested_targets(
    snapshot: &str,
    requested_targets: &str,
) -> Option<String> {
    let selectable_controls = snapshot_visible_selectable_control_states(snapshot);
    if selectable_controls.is_empty() {
        return None;
    }

    let requested_controls = selectable_controls
        .iter()
        .filter(|control| normalized_text_contains_exact_phrase(&requested_targets, &control.name))
        .collect::<Vec<_>>();
    if requested_controls.is_empty() {
        return None;
    }

    let missing_controls = requested_controls
        .iter()
        .filter(|control| !control.selected)
        .collect::<Vec<_>>();
    if !missing_controls.is_empty() {
        let remaining = missing_controls
            .iter()
            .take(4)
            .map(|control| format!("`{}` (`{}`)", control.semantic_id, control.name))
            .collect::<Vec<_>>()
            .join(", ");
        let plural = if missing_controls.len() == 1 {
            "target"
        } else {
            "targets"
        };
        if missing_controls.len() > 1 {
            let batch_ids = missing_controls
                .iter()
                .map(|control| format!("`{}`", control.semantic_id))
                .collect::<Vec<_>>()
                .join(", ");
            return Some(format!(
                "Requested selectable {plural} still missing from current browser state: {remaining}. Use `browser__click` with `ids` [{batch_ids}] now to click the remaining visible targets in order. Do not re-click already selected controls or `Submit` yet."
            ));
        }
        return Some(format!(
            "Requested selectable {plural} still missing from current browser state: {remaining}. Click one missing visible target now. Do not re-click already selected controls or `Submit` yet."
        ));
    }

    let submit_id = snapshot_visible_submit_control_id_local(snapshot)?;
    Some(format!(
        "All requested selectable targets already appear checked or selected. Use `browser__click` on `{submit_id}` now. Do not spend another step re-clicking the same selections."
    ))
}

pub(super) fn snapshot_select_submit_progress_pending_signal(snapshot: &str) -> Option<String> {
    let decoded_snapshot = decode_browser_xml_text(snapshot);
    let requested_targets = extract_select_submit_target(&decoded_snapshot)?;
    snapshot_select_submit_progress_pending_signal_for_requested_targets(
        snapshot,
        &requested_targets,
    )
}

pub(super) fn browser_snapshot_pending_signal(snapshot: &str) -> Option<String> {
    browser_snapshot_pending_signal_with_history(snapshot, &[])
}

pub(super) fn browser_snapshot_pending_signal_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    if snapshot_has_negative_selection_instruction(snapshot)
        && snapshot_has_selectable_controls(snapshot)
        && snapshot_has_selected_controls(snapshot)
    {
        return Some("The page-visible instruction requires no selections, but current browser state already shows checked or selected controls. Do not submit yet. Clear those selections so the relevant controls return to unchecked or unselected, then continue with the next required control.".to_string());
    }

    if history_requests_scroll_surface(history) {
        if let Some((scroll_target_id, summary, selector)) =
            unique_visible_scroll_target_details(snapshot)
        {
            if let Some(scroll_top) =
                recent_focused_scroll_remaining_within_final_page_up_window(history, &selector)
            {
                let next_controls =
                    next_visible_follow_up_controls(snapshot, &[scroll_target_id.as_str()]);
                if next_controls.len() == 1 {
                    let follow_up_id = &next_controls[0];
                    return Some(format!(
                        "Visible scroll target `{summary}` is already on the page. Recent grounded scroll state shows `scroll_top={scroll_top}`: one `PageUp` plus a grounded top-edge jump can finish it. Use `{}` now so the same grounded key chain can continue with visible control `{follow_up_id}`. Stop only when updated state shows `can_scroll_up=false` or `scroll_top=0`.",
                        page_up_then_top_edge_jump_call_for_selector_with_follow_up(
                            Some(&selector),
                            Some(follow_up_id),
                        )
                    ));
                }
            }

            if let Some(scroll_top) = recent_focused_scroll_remaining_near_top(history, &selector) {
                let next_controls =
                    next_visible_follow_up_controls(snapshot, &[scroll_target_id.as_str()]);
                if next_controls.len() == 1 {
                    let follow_up_id = &next_controls[0];
                    return Some(format!(
                        "Visible scroll target `{summary}` is already on the page. Recent grounded scroll state shows only `scroll_top={scroll_top}` remaining. Use `{}` now so the same grounded top-edge jump can continue with visible control `{follow_up_id}`. Stop only when updated state shows `can_scroll_up=false` or `scroll_top=0`.",
                        top_edge_jump_call_for_selector_with_follow_up(
                            Some(&selector),
                            Some(follow_up_id),
                        )
                ));
                }
            }

            if let Some(scroll_top) = recent_top_edge_jump_left_scroll_remaining(history, &selector)
            {
                return Some(format!(
                    "Visible scroll target `{summary}` is already on the page. Recent grounded top-edge jump still left `scroll_top={scroll_top}` above zero. Use `{}` next; stop only when updated state shows `can_scroll_up=false` or `scroll_top=0`.",
                    page_up_call_for_selector(Some(&selector))
                ));
            }

            if history_requests_top_scroll_edge(history) {
                return Some(format!(
                    "Visible scroll target `{summary}` is already on the page. Use `{}` now to move that control toward the top edge; otherwise continue with the next required visible control.",
                    top_edge_jump_call_for_selector(Some(&selector))
                ));
            }

            if history_requests_bottom_scroll_edge(history) {
                return Some(format!(
                    "Visible scroll target `{summary}` is already on the page. Use `{}` now to move that control toward the bottom edge; otherwise continue with the next required visible control.",
                    bottom_edge_jump_call_for_selector(Some(&selector))
                ));
            }

            return Some(format!(
                "Visible scroll target `{summary}` is already on the page. Use `browser__press_key` with that control's grounded `selector` for `Home` or `End`; otherwise continue with the next required visible control."
            ));
        }
    }

    None
}

pub(super) fn browser_snapshot_success_signal(snapshot: &str) -> Option<&'static str> {
    if snapshot_has_negative_selection_instruction(snapshot)
        && snapshot_has_selectable_controls(snapshot)
        && !snapshot_has_selected_controls(snapshot)
    {
        return Some(
            "The page-visible instruction already requires no selections, and current browser state shows no checked or selected controls. Do not click any checkbox, radio, or option. Continue with the next required control (for example `Submit`) or verify once if the goal is already satisfied.",
        );
    }

    None
}
