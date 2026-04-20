use super::identity::BrowserUseElementIdentity;
use super::BrowserUseDomTreeNode;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserUsePaginationButton {
    pub(crate) button_type: String,
    pub(crate) backend_node_id: i64,
    pub(crate) text: String,
    pub(crate) selector: String,
    pub(crate) is_disabled: bool,
    pub(crate) target_id: String,
    pub(crate) som_id: Option<u32>,
}

const NEXT_PATTERNS: &[&str] = &[
    "next",
    ">",
    "»",
    "→",
    "siguiente",
    "suivant",
    "weiter",
    "volgende",
];
const PREV_PATTERNS: &[&str] = &[
    "prev",
    "previous",
    "<",
    "«",
    "←",
    "anterior",
    "précédent",
    "zurück",
    "vorige",
];
const FIRST_PATTERNS: &[&str] = &["first", "⇤", "«", "primera", "première", "erste", "eerste"];
const LAST_PATTERNS: &[&str] = &["last", "⇥", "»", "última", "dernier", "letzte", "laatste"];

fn node_text_content(node: &BrowserUseDomTreeNode) -> String {
    let mut text = String::new();

    if let Some(value) = node.text_value() {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(value);
    }

    for child in &node.children {
        let child_text = node_text_content(child);
        if !child_text.is_empty() {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(&child_text);
        }
    }

    for shadow_root in &node.shadow_roots {
        let child_text = node_text_content(shadow_root);
        if !child_text.is_empty() {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(&child_text);
        }
    }

    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn detect_button_type(node: &BrowserUseDomTreeNode, text: &str) -> Option<String> {
    let aria_label = node
        .attributes
        .get("aria-label")
        .map(String::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let title = node
        .attributes
        .get("title")
        .map(String::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let class_name = node
        .attributes
        .get("class")
        .map(String::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let role = node
        .attributes
        .get("role")
        .map(String::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let all_text = format!("{text} {aria_label} {title} {class_name}");

    if NEXT_PATTERNS
        .iter()
        .any(|pattern| all_text.contains(pattern))
    {
        Some("next".to_string())
    } else if PREV_PATTERNS
        .iter()
        .any(|pattern| all_text.contains(pattern))
    {
        Some("prev".to_string())
    } else if FIRST_PATTERNS
        .iter()
        .any(|pattern| all_text.contains(pattern))
    {
        Some("first".to_string())
    } else if LAST_PATTERNS
        .iter()
        .any(|pattern| all_text.contains(pattern))
    {
        Some("last".to_string())
    } else if text.chars().all(|ch| ch.is_ascii_digit())
        && !text.is_empty()
        && text.len() <= 2
        && matches!(role.as_str(), "" | "button" | "link")
    {
        Some("page_number".to_string())
    } else {
        None
    }
}

fn is_disabled(node: &BrowserUseDomTreeNode) -> bool {
    node.attributes
        .get("disabled")
        .is_some_and(|value| value == "true")
        || node
            .attributes
            .get("aria-disabled")
            .is_some_and(|value| value == "true")
        || node
            .attributes
            .get("class")
            .is_some_and(|value| value.to_ascii_lowercase().contains("disabled"))
}

fn collect_pagination_buttons(
    node: &BrowserUseDomTreeNode,
    identities: &HashMap<(String, i64), BrowserUseElementIdentity>,
    out: &mut Vec<BrowserUsePaginationButton>,
) {
    if node
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.is_clickable)
    {
        let text = node_text_content(node).trim().to_ascii_lowercase();
        if let (Some(button_type), Some(backend_node_id)) =
            (detect_button_type(node, &text), node.backend_node_id)
        {
            let selector = identities
                .get(&(node.target_id.clone(), backend_node_id))
                .and_then(|identity| identity.x_path.clone())
                .unwrap_or_default();
            let rendered_text = node_text_content(node).trim().to_string();
            let fallback_text = node
                .attributes
                .get("aria-label")
                .cloned()
                .or_else(|| node.attributes.get("title").cloned())
                .unwrap_or_default();

            out.push(BrowserUsePaginationButton {
                button_type,
                backend_node_id,
                text: if rendered_text.is_empty() {
                    fallback_text
                } else {
                    rendered_text
                },
                selector,
                is_disabled: is_disabled(node),
                target_id: node.target_id.clone(),
                som_id: node.som_id,
            });
        }
    }

    for shadow_root in &node.shadow_roots {
        collect_pagination_buttons(shadow_root, identities, out);
    }
    for child in &node.children {
        collect_pagination_buttons(child, identities, out);
    }
    if let Some(content_document) = node.content_document.as_deref() {
        collect_pagination_buttons(content_document, identities, out);
    }
}

pub(crate) fn detect_pagination_buttons_from_tree(
    root: &BrowserUseDomTreeNode,
    identities: &HashMap<(String, i64), BrowserUseElementIdentity>,
) -> Vec<BrowserUsePaginationButton> {
    let mut buttons = Vec::new();
    collect_pagination_buttons(root, identities, &mut buttons);
    buttons
}

pub(crate) fn render_pagination_buttons_text(
    buttons: &[BrowserUsePaginationButton],
) -> Option<String> {
    if buttons.is_empty() {
        return None;
    }

    let lines = buttons
        .iter()
        .map(|button| {
            let mut prefix = String::new();
            if let Some(som_id) = button.som_id {
                prefix.push_str(&format!("[{som_id}] "));
            }

            format!(
                "{}type={} text=\"{}\" disabled={} backend_dom_node_id={} target_id={} selector=\"{}\"",
                prefix,
                button.button_type,
                button.text.replace('"', "'"),
                button.is_disabled,
                button.backend_node_id,
                button.target_id,
                button.selector.replace('"', "'"),
            )
        })
        .collect::<Vec<_>>();

    Some(lines.join("\n"))
}

#[cfg(test)]
#[path = "pagination/tests.rs"]
mod tests;
