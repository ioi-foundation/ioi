pub(super) fn extract_assistive_browser_hints(snapshot: &str) -> Vec<String> {
    let mut hints = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.contains("assistive_hint=\"true\"") {
            continue;
        }

        let Some(name) = extract_browser_xml_attr(fragment, "name") else {
            continue;
        };
        let name = compact_ws_for_prompt(&decode_browser_xml_text(&name));
        if name.is_empty() || hints.iter().any(|existing| existing == &name) {
            continue;
        }
        hints.push(name);
        if hints.len() >= 3 {
            break;
        }
    }

    hints
}

pub(super) fn browser_fragment_scroll_target_summary(fragment: &str) -> Option<String> {
    if !fragment.contains(" scroll_top=\"") || !fragment.contains(" client_height=\"") {
        return None;
    }

    if !(fragment.contains(" can_scroll_up=\"true\"")
        || fragment.contains(" can_scroll_down=\"true\""))
    {
        return None;
    }

    let tag_name = browser_fragment_tag_name(fragment)?;
    let semantic_id = extract_browser_xml_attr(fragment, "id")?;
    let dom_id = extract_browser_xml_attr(fragment, "dom_id")
        .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
        .filter(|value| !value.is_empty());

    let mut summary = format!("{semantic_id} tag={tag_name}");
    if let Some(dom_id) = dom_id {
        summary.push_str(&format!(" dom_id={dom_id}"));
    }

    Some(summary)
}

pub(super) fn unique_visible_scroll_target_summary(snapshot: &str) -> Option<String> {
    let mut candidate = None;

    for fragment in snapshot.split('<') {
        let Some(summary) = browser_fragment_scroll_target_summary(fragment) else {
            continue;
        };

        if fragment.contains(" focused=\"true\"") {
            return None;
        }

        if candidate.replace(summary).is_some() {
            return None;
        }
    }

    candidate
}

fn unique_visible_scroll_target_details(snapshot: &str) -> Option<(String, String, String)> {
    let mut candidate = None;

    for fragment in snapshot.split('<') {
        let Some(summary) = browser_fragment_scroll_target_summary(fragment) else {
            continue;
        };
        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some(selector) = extract_browser_xml_attr(fragment, "selector")
            .map(|value| decode_browser_xml_text(&value))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        if candidate
            .replace((semantic_id, summary, selector))
            .is_some()
        {
            return None;
        }
    }

    candidate
}

fn history_requests_scroll_surface(history: &[ChatMessage]) -> bool {
    if history.is_empty() {
        return true;
    }

    history.iter().rev().take(6).any(|message| {
        let compact = compact_ws_for_prompt(&message.content).to_ascii_lowercase();
        compact.contains("scroll")
            || compact.contains("pageup")
            || compact.contains("page up")
            || compact.contains("pagedown")
            || compact.contains("page down")
            || compact.contains("control+home")
            || compact.contains("control+end")
            || compact.contains("meta+arrowup")
            || compact.contains("meta+arrowdown")
            || compact.contains(" top of ")
            || compact.contains(" bottom of ")
    })
}

fn history_requests_top_scroll_edge(history: &[ChatMessage]) -> bool {
    history.iter().rev().take(6).any(|message| {
        let compact = compact_ws_for_prompt(&message.content).to_ascii_lowercase();
        compact.contains(" top of ")
            || compact.contains("scroll to the top")
            || compact.contains("control+home")
            || compact.contains("meta+arrowup")
    })
}

fn history_requests_bottom_scroll_edge(history: &[ChatMessage]) -> bool {
    history.iter().rev().take(6).any(|message| {
        let compact = compact_ws_for_prompt(&message.content).to_ascii_lowercase();
        compact.contains(" bottom of ")
            || compact.contains("scroll to the bottom")
            || compact.contains("control+end")
            || compact.contains("meta+arrowdown")
    })
}

pub(super) fn extract_scroll_target_focus_hint(snapshot: &str) -> Option<String> {
    let summary = unique_visible_scroll_target_summary(snapshot)?;
    Some(format!(
        "Visible scroll target `{summary}` is already on the page. If the goal requires interacting with that control, use control-local actions there. For scroll-specific keys like `Home` or `End`, prefer `browser__press_key` with that control's grounded `selector` instead of sending page-level edge keys."
    ))
}

pub(super) fn extract_scroll_target_focus_hint_with_history(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<String> {
    if !history_requests_scroll_surface(history) {
        return None;
    }
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
                    "Visible scroll target `{summary}` is already on the page. Recent grounded scroll state shows `scroll_top={scroll_top}`: one `PageUp` plus a grounded top-edge jump can finish it. Use `{}` now so the same grounded key chain can continue with visible control `{follow_up_id}`.",
                    page_up_then_top_edge_jump_call_for_selector_with_follow_up(
                        Some(&selector),
                        Some(follow_up_id),
                    )
                ));
            }
        }

        if let Some(scroll_top) = recent_top_edge_jump_left_scroll_remaining(history, &selector) {
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
    }

    extract_scroll_target_focus_hint(snapshot)
}
