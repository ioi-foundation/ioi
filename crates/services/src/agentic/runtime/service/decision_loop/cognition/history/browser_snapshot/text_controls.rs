pub(super) fn snapshot_visible_goal_text_target(
    snapshot: &str,
    history: &[ChatMessage],
) -> Option<SnapshotVisibleTargetState> {
    let recent_goal_texts = history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .take(3)
        .map(|message| normalized_exact_target_text(&message.content))
        .filter(|message| !message.is_empty())
        .collect::<Vec<_>>();
    if recent_goal_texts.is_empty() {
        return None;
    }

    let mut best_match: Option<(
        (u8, u8, u8, u8, u8, u8, u8, usize),
        SnapshotVisibleTargetState,
    )> = None;

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

        let normalized_name = normalized_exact_target_text(&name);
        if normalized_name.is_empty() || normalized_goal_text_target_is_noise(&normalized_name) {
            continue;
        }
        let matching_goals = recent_goal_texts
            .iter()
            .filter(|goal| normalized_text_contains_exact_phrase(goal, &normalized_name))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if matching_goals.is_empty()
            || snapshot_goal_text_match_is_premature_submit_fallback(
                &semantic_id,
                &normalized_name,
                &matching_goals,
            )
        {
            continue;
        }

        let instruction_context =
            browser_fragment_looks_like_instruction_context(fragment, &semantic_role);
        let actionable_target =
            browser_fragment_is_actionable_goal_target(fragment, &semantic_role);
        if instruction_context && !actionable_target {
            continue;
        }
        let stateful_class_hint = u8::from(browser_fragment_stateful_match_hint(fragment));
        let area_bucket = browser_fragment_visual_area_bucket(fragment);
        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: name.clone(),
            semantic_role: semantic_role.clone(),
            already_active: stateful_class_hint > 0,
        };
        let candidate_rank = (
            u8::from(actionable_target),
            u8::from(!instruction_context),
            stateful_class_hint,
            u8::from(!matches!(
                semantic_role.as_str(),
                "generic" | "text" | "heading" | "label"
            )),
            area_bucket,
            u8::from(fragment.contains(r#" dom_clickable="true""#)),
            u8::from(fragment.contains(r#" selector=""#) || fragment.contains(r#" dom_id=""#)),
            name.chars().count(),
        );

        match best_match.as_ref() {
            Some((best_rank, best_candidate))
                if *best_rank > candidate_rank
                    || (*best_rank == candidate_rank
                        && best_candidate.semantic_id <= candidate.semantic_id) => {}
            _ => best_match = Some((candidate_rank, candidate)),
        }
    }

    best_match.map(|(_, candidate)| candidate)
}

fn normalized_goal_text_target_is_noise(normalized_name: &str) -> bool {
    let mut tokens = normalized_name.split_whitespace();
    let Some(first_token) = tokens.next() else {
        return true;
    };
    if tokens.next().is_some() {
        return false;
    }

    matches!(
        first_token,
        "a" | "an"
            | "and"
            | "at"
            | "by"
            | "for"
            | "from"
            | "in"
            | "into"
            | "of"
            | "on"
            | "or"
            | "the"
            | "to"
            | "with"
    )
}

fn browser_fragment_is_actionable_goal_target(fragment: &str, semantic_role: &str) -> bool {
    fragment.contains(r#" dom_clickable="true""#)
        || matches!(
            semantic_role,
            "button"
                | "link"
                | "textbox"
                | "searchbox"
                | "combobox"
                | "checkbox"
                | "radio"
                | "menuitem"
                | "option"
                | "tab"
        )
}

fn browser_fragment_has_action_locator(fragment: &str) -> bool {
    fragment.contains(r#" selector=""#) || fragment.contains(r#" dom_id=""#)
}

pub(super) fn browser_fragment_allows_omitted_action_target(
    fragment: &str,
    semantic_role: &str,
) -> bool {
    browser_fragment_is_actionable_goal_target(fragment, semantic_role)
        && (browser_fragment_has_action_locator(fragment)
            || fragment.contains(r#" dom_clickable="true""#))
}

pub(super) fn snapshot_focused_text_control_states(
    snapshot: &str,
) -> Vec<SnapshotAutocompleteControlState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || !fragment.contains(r#" focused="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotAutocompleteControlState {
            semantic_id,
            dom_id,
            selector,
            controls_dom_id,
            value,
            has_active_candidate: false,
        });
    }

    states
}

pub(super) fn snapshot_visible_text_control_states(
    snapshot: &str,
) -> Vec<SnapshotAutocompleteControlState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let active_descendant_dom_id =
            extract_browser_xml_attr(fragment, "active_descendant_dom_id")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotAutocompleteControlState {
            semantic_id,
            dom_id,
            selector,
            controls_dom_id,
            value,
            has_active_candidate: active_descendant_dom_id.is_some(),
        });
    }

    states
}

pub(super) fn snapshot_focused_autocomplete_control_state(
    snapshot: &str,
) -> Option<SnapshotAutocompleteControlState> {
    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || !fragment.contains(r#" focused="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment) else {
            continue;
        };
        if !matches!(semantic_role, "textbox" | "searchbox" | "combobox") {
            continue;
        }

        let autocomplete = extract_browser_xml_attr(fragment, "autocomplete")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let active_descendant_dom_id =
            extract_browser_xml_attr(fragment, "active_descendant_dom_id")
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty());
        if autocomplete.is_none() && controls_dom_id.is_none() && active_descendant_dom_id.is_none()
        {
            continue;
        }

        let semantic_id = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())?;
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        return Some(SnapshotAutocompleteControlState {
            semantic_id,
            dom_id,
            selector,
            controls_dom_id,
            value,
            has_active_candidate: active_descendant_dom_id.is_some(),
        });
    }

    None
}

fn selector_references_dom_id(selector: &str, dom_id: &str) -> bool {
    selector.contains(&format!("#{dom_id}"))
        || selector.contains(&format!(r#"[id="{dom_id}"]"#))
        || selector.contains(&format!(r#"[id='{dom_id}']"#))
}

fn normalized_control_locator(value: &str) -> String {
    let trimmed = compact_ws_for_prompt(value).trim().to_string();
    if let Some(token) = trimmed.strip_prefix('#') {
        return token.to_string();
    }
    if let Some(token) = trimmed
        .strip_prefix("[id=\"")
        .and_then(|value| value.strip_suffix("\"]"))
    {
        return token.to_string();
    }
    if let Some(token) = trimmed
        .strip_prefix("[id='")
        .and_then(|value| value.strip_suffix("']"))
    {
        return token.to_string();
    }
    trimmed
}

pub(super) fn autocomplete_control_locator_matches(
    selector: Option<&str>,
    dom_id: Option<&str>,
    control: &SnapshotAutocompleteControlState,
) -> bool {
    if dom_id
        .zip(control.dom_id.as_deref())
        .is_some_and(|(left, right)| left == right)
    {
        return true;
    }

    let control_selector = control
        .selector
        .as_deref()
        .map(normalized_control_locator)
        .unwrap_or_default();
    selector.is_some_and(|selector| normalized_control_locator(selector) == control_selector)
        || selector
            .zip(control.dom_id.as_deref())
            .is_some_and(|(selector, dom_id)| {
                normalized_control_locator(selector) == normalized_control_locator(dom_id)
            })
}

fn snapshot_visible_autocomplete_popup(
    snapshot: &str,
    control: &SnapshotAutocompleteControlState,
) -> bool {
    let Some(controls_dom_id) = control.controls_dom_id.as_deref() else {
        return false;
    };

    snapshot.split('<').any(|fragment| {
        if fragment.contains(r#" visible="false""#) || fragment.contains(r#" omitted="true""#) {
            return false;
        }

        let semantic_id = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
        if semantic_id.as_deref() == Some(control.semantic_id.as_str()) {
            return false;
        }

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)));
        if dom_id.as_deref() == Some(controls_dom_id) {
            return true;
        }

        extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .is_some_and(|selector| selector_references_dom_id(&selector, controls_dom_id))
    })
}

fn recent_typed_autocomplete_value_for_control(
    history: &[ChatMessage],
    control: &SnapshotAutocompleteControlState,
) -> Option<String> {
    history.iter().rev().find_map(|message| {
        let state = autocomplete_tool_state(message)?;
        if !matches!(state.action, RecentAutocompleteAction::Typed) {
            return None;
        }

        let matches_control = autocomplete_control_locator_matches(
            state.selector.as_deref(),
            state.dom_id.as_deref(),
            control,
        );
        matches_control.then_some(state.value).flatten()
    })
}
