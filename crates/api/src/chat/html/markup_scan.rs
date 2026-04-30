fn html_void_element(tag: &str) -> bool {
    matches!(
        tag,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn html_has_optional_closing_behavior(tag: &str) -> bool {
    matches!(
        tag,
        "p" | "li"
            | "dt"
            | "dd"
            | "option"
            | "optgroup"
            | "thead"
            | "tbody"
            | "tfoot"
            | "tr"
            | "td"
            | "th"
            | "colgroup"
            | "caption"
            | "rb"
            | "rt"
            | "rtc"
            | "rp"
    )
}

fn html_is_raw_text_tag(tag: &str) -> bool {
    matches!(tag, "script" | "style" | "textarea" | "title")
}

fn html_markup_tag_end_index(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut quote: Option<u8> = None;
    let mut index = start;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(active) if byte == active => quote = None,
            Some(_) => {}
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            None if byte == b'>' => return Some(index),
            None => {}
        }
        index += 1;
    }
    None
}

fn html_markup_tag_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'_')
}

pub(super) fn normalize_html_interactions(html: &str) -> String {
    let modal_first = chat_modal_first_html_enabled();
    let lower = html.to_ascii_lowercase();
    let had_alert = lower.contains("alert(");
    let mut normalized = normalize_html_external_runtime_dependencies(html);
    normalized = replace_case_insensitive(
        &replace_case_insensitive(&normalized, "window.alert(", "console.info("),
        "alert(",
        "console.info(",
    );
    let _ = had_alert;
    if modal_first {
        return normalized;
    }
    normalized = ensure_html_button_accessibility_contract(&normalized);
    normalized = ensure_html_mapped_panels_define_referenced_ids(&normalized);
    normalized = ensure_html_view_switch_contract(&normalized);
    normalized = ensure_minimum_html_shared_detail_region(&normalized);
    normalized = ensure_minimum_html_mapped_panel_content(&normalized);
    normalized = ensure_minimum_html_rollover_detail_payloads(&normalized);
    normalized = ensure_grouped_html_rollover_detail_marks(&normalized);
    normalized = ensure_focusable_html_rollover_marks(&normalized);
    normalized = ensure_html_interaction_polish_styles(&normalized);
    normalized = ensure_html_rollover_detail_contract(&normalized);
    normalized
}

fn html_has_trailing_fragment(html: &str) -> bool {
    let trimmed = html.trim_end();
    if trimmed.is_empty() {
        return true;
    }
    let Some(last_gt) = trimmed.rfind('>') else {
        return true;
    };
    !trimmed[last_gt + 1..].trim().is_empty()
}

pub(super) fn ensure_html_mapped_panels_define_referenced_ids(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let defined_ids = collect_html_attribute_ids(&lower);
    let mut missing_refs = collect_html_referenced_ids(&lower)
        .into_iter()
        .filter(|id| !defined_ids.contains(id))
        .collect::<HashSet<_>>();
    missing_refs.extend(
        collect_html_explicit_panel_id_targets(&lower)
            .into_iter()
            .filter(|id| !defined_ids.contains(id)),
    );
    if missing_refs.is_empty() {
        return html.to_string();
    }

    let panels = collect_html_mapped_view_panels(html);
    if panels.is_empty() {
        return html.to_string();
    }

    let mut replacements = Vec::<(usize, usize, String)>::new();
    for panel in panels {
        let open_tag = &html[panel.open_start..panel.open_end];
        let open_tag_lower = &lower[panel.open_start..panel.open_end];
        if open_tag_lower.contains("id=") {
            continue;
        }

        let preferred_id = preferred_missing_panel_id(&panel, &missing_refs);
        let Some(preferred_id) = preferred_id else {
            continue;
        };

        let repaired = inject_html_attributes_into_open_tag(
            open_tag,
            &[("id", &preferred_id), ("data-view-panel", &panel.token)],
        );
        replacements.push((panel.open_start, panel.open_end, repaired));
    }

    if replacements.is_empty() {
        return html.to_string();
    }

    replacements.sort_by_key(|(start, _, _)| *start);
    let mut rebuilt = String::with_capacity(html.len() + replacements.len() * 48);
    let mut cursor = 0usize;
    for (start, end, replacement) in replacements {
        if start < cursor {
            continue;
        }
        rebuilt.push_str(&html[cursor..start]);
        rebuilt.push_str(&replacement);
        cursor = end;
    }
    rebuilt.push_str(&html[cursor..]);
    rebuilt
}
