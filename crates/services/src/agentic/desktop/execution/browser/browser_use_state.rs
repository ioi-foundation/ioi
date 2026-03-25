use ioi_drivers::gui::accessibility::AccessibilityNode;

const BROWSER_USE_INCLUDE_ATTRS: &[&str] = &[
    "title",
    "type",
    "checked",
    "dom_id",
    "name",
    "role",
    "value",
    "placeholder",
    "data-date-format",
    "alt",
    "aria-label",
    "aria-expanded",
    "data-state",
    "aria-checked",
    "pattern",
    "min",
    "max",
    "minlength",
    "maxlength",
    "step",
    "accept",
    "multiple",
    "inputmode",
    "autocomplete",
    "aria-autocomplete",
    "list",
    "data-mask",
    "data-inputmask",
    "data-datepicker",
    "format",
    "expected_format",
    "contenteditable",
    "selected",
    "expanded",
    "pressed",
    "disabled",
    "invalid",
    "valuemin",
    "valuemax",
    "valuenow",
    "keyshortcuts",
    "haspopup",
    "multiselectable",
    "required",
    "valuetext",
    "level",
    "busy",
    "live",
    "hidden_below_count",
    "hidden_below",
    "has_js_click_listener",
];

fn node_attr<'a>(node: &'a AccessibilityNode, key: &str) -> Option<&'a str> {
    node.attributes
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn node_attr_flag(node: &AccessibilityNode, key: &str) -> bool {
    node_attr(node, key).is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn inline_value(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('\n', " ")
}

fn browser_use_tag(node: &AccessibilityNode) -> Option<String> {
    node_attr(node, "tag_name").map(str::to_string).or_else(|| {
        let role = node.role.trim();
        (!role.is_empty()).then(|| role.to_ascii_lowercase().replace(' ', "_"))
    })
}

fn browser_use_text_line(node: &AccessibilityNode) -> Option<String> {
    let role = node.role.trim().to_ascii_lowercase();
    let text = node
        .name
        .as_deref()
        .or(node.value.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;

    if matches!(
        role.as_str(),
        "statictext" | "inline_text_box" | "inline_textbox" | "text"
    ) {
        return Some(inline_value(text));
    }

    None
}

fn interactive_display_id(node: &AccessibilityNode) -> Option<String> {
    node_attr(node, "backend_dom_node_id")
        .map(str::to_string)
        .or_else(|| node.som_id.map(|som_id| som_id.to_string()))
}

fn render_attributes(node: &AccessibilityNode) -> String {
    let mut attrs = Vec::new();

    if let Some(name) = node
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push(format!("name={}", inline_value(name)));
    }
    if let Some(value) = node
        .value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push(format!("value={}", inline_value(value)));
    }

    for key in BROWSER_USE_INCLUDE_ATTRS {
        let Some(value) = node_attr(node, key) else {
            continue;
        };
        if matches!(*key, "dom_id" | "name" | "value")
            && attrs
                .iter()
                .any(|entry| entry.starts_with(&format!("{key}=")))
        {
            continue;
        }
        attrs.push(format!("{key}={}", inline_value(value)));
    }

    attrs.join(" ")
}

fn render_hidden_iframe_hints(node: &AccessibilityNode, depth: usize, out: &mut Vec<String>) {
    let Some(count) = node_attr(node, "hidden_below_count") else {
        return;
    };

    let depth_str = "\t".repeat(depth);
    if let Some(summary) = node_attr(node, "hidden_below") {
        out.push(format!(
            "{depth_str}... ({count} more elements below - scroll to reveal):"
        ));
        for entry in summary
            .split('|')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (kind, rest) = entry.split_once(':').unwrap_or(("element", entry));
            let (label, pages) = rest.split_once('@').unwrap_or((rest, "0.0p"));
            out.push(format!(
                "{depth_str}\t<{kind}> \"{}\" ~{} pages down",
                inline_value(label),
                pages.trim_end_matches('p')
            ));
        }
    } else {
        out.push(format!(
            "{depth_str}... ({count} more elements below - scroll to reveal)"
        ));
    }
}

fn render_browser_use_node(node: &AccessibilityNode, depth: usize, out: &mut Vec<String>) {
    if !node.is_visible {
        return;
    }

    let depth_str = "\t".repeat(depth);
    let is_scrollable = node_attr_flag(node, "scrollable");
    let is_iframe = matches!(
        browser_use_tag(node).as_deref(),
        Some("iframe") | Some("frame")
    ) || matches!(node.role.as_str(), "iframe" | "frame");

    if let Some(text) = browser_use_text_line(node) {
        out.push(format!("{depth_str}{text}"));
        return;
    }

    let tag = browser_use_tag(node);
    let attrs = render_attributes(node);
    let display_id = interactive_display_id(node);
    let has_line = display_id.is_some() || is_scrollable || is_iframe;

    if has_line {
        let mut prefix = String::new();
        if is_scrollable && display_id.is_none() {
            prefix.push_str("|scroll element|");
        } else if let Some(display_id) = display_id.as_deref() {
            prefix.push_str("|scroll element");
            prefix.push_str(&format!("[{display_id}]"));
        } else if matches!(browser_use_tag(node).as_deref(), Some("frame"))
            || matches!(node.role.as_str(), "frame")
        {
            prefix.push_str("|FRAME|");
        } else if is_iframe {
            prefix.push_str("|IFRAME|");
        }

        if !is_scrollable {
            if let Some(display_id) = display_id.as_deref() {
                prefix.push_str(&format!("[{display_id}]"));
            }
        }

        let tag = tag.unwrap_or_else(|| "node".to_string());
        let mut line = format!("{depth_str}{prefix}<{tag}");
        if !attrs.is_empty() {
            line.push(' ');
            line.push_str(&attrs);
        }
        line.push_str(" />");
        out.push(line);
    }

    let next_depth = if has_line { depth + 1 } else { depth };
    for child in &node.children {
        render_browser_use_node(child, next_depth, out);
    }

    if is_iframe {
        render_hidden_iframe_hints(node, next_depth, out);
    }
}

pub(super) fn render_browser_use_state_text(tree: &AccessibilityNode) -> Option<String> {
    let mut lines = Vec::new();
    render_browser_use_node(tree, 0, &mut lines);
    (!lines.is_empty()).then(|| lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::render_browser_use_state_text;
    use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
    use std::collections::HashMap;

    fn node(
        role: &str,
        name: Option<&str>,
        attrs: &[(&str, &str)],
        som_id: Option<u32>,
        children: Vec<AccessibilityNode>,
    ) -> AccessibilityNode {
        AccessibilityNode {
            id: format!("node-{role}"),
            role: role.to_string(),
            name: name.map(str::to_string),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            },
            children,
            is_visible: true,
            attributes: attrs
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<HashMap<_, _>>(),
            som_id,
        }
    }

    #[test]
    fn render_browser_use_state_text_includes_interactive_and_iframe_hints() {
        let tree = node(
            "root",
            None,
            &[],
            None,
            vec![node(
                "iframe",
                Some("Embedded"),
                &[
                    ("tag_name", "iframe"),
                    ("hidden_below_count", "2"),
                    ("hidden_below", "textbox:Search@1.1p|button:Submit@1.5p"),
                ],
                None,
                vec![
                    node(
                        "button",
                        Some("Submit"),
                        &[("tag_name", "button")],
                        Some(3),
                        vec![],
                    ),
                    node("StaticText", Some("Helpful text"), &[], None, vec![]),
                ],
            )],
        );

        let text = render_browser_use_state_text(&tree).expect("state text");

        assert!(text.contains("|IFRAME|<iframe name=Embedded hidden_below_count=2"));
        assert!(text.contains("[3]<button name=Submit"));
        assert!(text.contains("Helpful text"));
        assert!(text.contains("... (2 more elements below - scroll to reveal):"));
        assert!(text.contains("<textbox> \"Search\" ~1.1 pages down"));
    }
}
