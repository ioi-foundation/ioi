pub(super) fn snapshot_link_states(snapshot: &str) -> Vec<SnapshotLinkState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("link ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let context = extract_browser_xml_attr(fragment, "context")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let visible = !fragment.contains(r#" visible="false""#);

        states.push(SnapshotLinkState {
            semantic_id,
            name,
            dom_id,
            selector,
            context,
            visible,
        });
    }

    states
}

pub(super) fn snapshot_tab_states(snapshot: &str) -> Vec<SnapshotTabState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("tab ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let controls_dom_id = extract_browser_xml_attr(fragment, "controls_dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotTabState {
            semantic_id,
            name,
            dom_id,
            selector,
            controls_dom_id,
            focused: fragment.contains(r#" focused="true""#),
        });
    }

    states
}

pub(super) fn snapshot_tabpanel_states(snapshot: &str) -> Vec<SnapshotTabPanelState> {
    let mut states = Vec::new();

    for fragment in snapshot.split('<') {
        if !fragment.trim_start().starts_with("tabpanel ") {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };

        let name = extract_browser_xml_attr(fragment, "name")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        states.push(SnapshotTabPanelState {
            semantic_id,
            name,
            dom_id,
            selector,
            visible: !fragment.contains(r#" visible="false""#),
        });
    }

    states
}

pub(super) fn visible_target_role_priority(semantic_role: &str) -> u8 {
    match semantic_role {
        "link" | "button" | "menuitem" | "option" | "tab" | "checkbox" | "radio" => 4,
        "generic" | "label" | "text" | "heading" => 3,
        "textbox" | "searchbox" | "combobox" => 2,
        _ => 1,
    }
}

fn snapshot_fragment_metadata_values(fragment: &str) -> Vec<String> {
    ["name", "dom_id", "selector", "class_name", "placeholder"]
        .into_iter()
        .filter_map(|attr| {
            extract_browser_xml_attr(fragment, attr)
                .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
                .filter(|value| !value.is_empty())
        })
        .collect()
}

pub(super) fn snapshot_visible_search_affordance(
    snapshot: &str,
) -> Option<SnapshotSearchAffordanceState> {
    let mut best_match: Option<((u8, u8, u8, u8), SnapshotSearchAffordanceState)> = None;

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

        let dom_id = extract_browser_xml_attr(fragment, "dom_id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let selector = extract_browser_xml_attr(fragment, "selector")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());
        let search_metadata = snapshot_fragment_metadata_values(fragment);
        if !search_metadata
            .iter()
            .any(|value| value.to_ascii_lowercase().contains("search"))
        {
            continue;
        }

        let kind = if matches!(semantic_role.as_str(), "textbox" | "searchbox" | "combobox") {
            SnapshotSearchAffordanceKind::Field
        } else if matches!(
            semantic_role.as_str(),
            "button" | "link" | "generic" | "menuitem"
        ) {
            SnapshotSearchAffordanceKind::Activator
        } else {
            continue;
        };

        let candidate = SnapshotSearchAffordanceState {
            semantic_id,
            semantic_role: semantic_role.clone(),
            kind: kind.clone(),
            dom_id,
            selector,
        };
        let candidate_rank = (
            u8::from(matches!(kind, SnapshotSearchAffordanceKind::Field)),
            u8::from(fragment.contains(r#" dom_clickable="true""#)),
            u8::from(candidate.selector.is_some()),
            visible_target_role_priority(&semantic_role),
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

pub(super) fn snapshot_visible_message_recipient_control(
    snapshot: &str,
) -> Option<SnapshotMessageRecipientControlState> {
    let mut best_match: Option<((u8, u8, u8), SnapshotMessageRecipientControlState)> = None;

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
        let value = extract_browser_xml_attr(fragment, "value")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty());

        let looks_like_recipient_field =
            snapshot_fragment_metadata_values(fragment)
                .iter()
                .any(|value| {
                    let normalized = normalized_exact_target_text(value);
                    normalized == "to"
                        || normalized == "recipient"
                        || normalized.contains(" recipient ")
                        || normalized.starts_with("recipient ")
                        || normalized.ends_with(" recipient")
                        || normalized == "forward sender"
                        || normalized.contains("forward sender")
                        || normalized == "reply recipient"
                        || normalized.contains("reply recipient")
                });
        if !looks_like_recipient_field {
            continue;
        }

        let candidate = SnapshotMessageRecipientControlState {
            semantic_id,
            dom_id,
            selector,
            value,
        };
        let candidate_rank = (
            u8::from(candidate.selector.is_some()),
            u8::from(candidate.dom_id.is_some()),
            u8::from(fragment.contains(r#" focused="true""#)),
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

pub(super) fn snapshot_visible_exact_text_target(
    snapshot: &str,
    target: &str,
) -> Option<SnapshotVisibleTargetState> {
    let normalized_target = normalized_exact_target_text(target);
    if normalized_target.is_empty() {
        return None;
    }

    let mut best_match: Option<(
        (u8, u8, u8, u8, u8, u8, u8, usize),
        SnapshotVisibleTargetState,
    )> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) {
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
        if normalized_exact_target_text(&name) != normalized_target {
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
        let dom_clickable = u8::from(fragment.contains(r#" dom_clickable="true""#));
        let selector_present = u8::from(fragment.contains(r#" selector=""#));
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
            visible_target_role_priority(&semantic_role),
            dom_clickable,
            selector_present,
            area_bucket,
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

fn browser_fragment_is_start_gate_label(name: &str) -> bool {
    matches!(
        normalized_exact_target_text(name).as_str(),
        "start" | "begin" | "continue"
    )
}

#[derive(Clone, Copy)]
struct BrowserFragmentRect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

fn browser_fragment_rect(fragment: &str) -> Option<BrowserFragmentRect> {
    let rect = extract_browser_xml_attr(fragment, "rect")?;
    let mut parts = rect.split(',');
    let x = parts.next()?.parse::<f64>().ok()?;
    let y = parts.next()?.parse::<f64>().ok()?;
    let width = parts.next()?.parse::<f64>().ok()?;
    let height = parts.next()?.parse::<f64>().ok()?;
    if parts.next().is_some() || width <= 0.0 || height <= 0.0 {
        return None;
    }

    Some(BrowserFragmentRect {
        x,
        y,
        width,
        height,
    })
}

fn browser_rect_contains(outer: BrowserFragmentRect, inner: BrowserFragmentRect) -> bool {
    let tolerance = 1.0;
    let outer_right = outer.x + outer.width;
    let outer_bottom = outer.y + outer.height;
    let inner_right = inner.x + inner.width;
    let inner_bottom = inner.y + inner.height;

    inner.x >= outer.x - tolerance
        && inner.y >= outer.y - tolerance
        && inner_right <= outer_right + tolerance
        && inner_bottom <= outer_bottom + tolerance
}

fn browser_fragment_is_start_gate_role(semantic_role: &str) -> bool {
    matches!(
        semantic_role,
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
    )
}

pub(super) fn snapshot_visible_start_gate_target(
    snapshot: &str,
) -> Option<SnapshotVisibleTargetState> {
    let mut best_match: Option<((u8, u8, u8, u8, u8, usize), SnapshotVisibleTargetState)> = None;

    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) {
            continue;
        }

        let Some(semantic_role) = browser_fragment_tag_name(fragment)
            .map(str::to_string)
            .filter(|role| !role.is_empty())
        else {
            continue;
        };
        if !browser_fragment_is_start_gate_role(&semantic_role) {
            continue;
        }

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
        if !browser_fragment_is_start_gate_label(&name) {
            continue;
        }

        let instruction_context =
            browser_fragment_looks_like_instruction_context(fragment, &semantic_role);
        let actionable_target =
            browser_fragment_is_actionable_goal_target(fragment, &semantic_role);
        let has_action_locator = browser_fragment_has_action_locator(fragment);
        let area_bucket = browser_fragment_visual_area_bucket(fragment);
        let candidate = SnapshotVisibleTargetState {
            semantic_id,
            name: name.clone(),
            semantic_role: semantic_role.clone(),
            already_active: false,
        };
        let candidate_rank = (
            u8::from(has_action_locator),
            u8::from(actionable_target),
            area_bucket,
            visible_target_role_priority(&semantic_role),
            u8::from(!instruction_context),
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

fn snapshot_visible_start_gate_priority_summary(snapshot: &str) -> Option<(String, String)> {
    let start_gate = snapshot_visible_start_gate_target(snapshot)?;
    let summary = snapshot_priority_summary_for_semantic_id(snapshot, &start_gate.semantic_id)?;
    Some((start_gate.semantic_id, summary))
}

fn snapshot_visible_start_gate_covered_semantic_ids(snapshot: &str) -> HashSet<String> {
    let Some(start_gate) = snapshot_visible_start_gate_target(snapshot) else {
        return HashSet::new();
    };

    let mut gate_rect = None;
    for fragment in snapshot.split('<') {
        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if semantic_id != start_gate.semantic_id {
            continue;
        }
        gate_rect = browser_fragment_rect(fragment);
        if gate_rect.is_some() {
            break;
        }
    }

    let Some(gate_rect) = gate_rect else {
        return HashSet::new();
    };

    let mut covered = HashSet::new();
    for fragment in snapshot.split('<') {
        if fragment.contains(r#" omitted="true""#) || fragment.contains(r#" visible="false""#) {
            continue;
        }

        let Some(semantic_id) = extract_browser_xml_attr(fragment, "id")
            .map(|value| compact_ws_for_prompt(&decode_browser_xml_text(&value)))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if semantic_id == start_gate.semantic_id {
            continue;
        }

        let Some(rect) = browser_fragment_rect(fragment) else {
            continue;
        };
        if browser_rect_contains(gate_rect, rect) {
            covered.insert(semantic_id);
        }
    }

    covered
}
