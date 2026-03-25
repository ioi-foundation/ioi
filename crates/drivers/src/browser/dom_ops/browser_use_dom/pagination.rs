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
mod tests {
    use super::{detect_pagination_buttons_from_tree, render_pagination_buttons_text};
    use crate::browser::dom_ops::browser_use::BrowserUseSnapshotNode;
    use crate::browser::dom_ops::browser_use_dom::identity::build_browser_use_element_identity_map;
    use crate::browser::dom_ops::browser_use_dom::{BrowserUseAxData, BrowserUseDomTreeNode};
    use std::collections::HashMap;

    fn node(
        node_type: i64,
        node_name: &str,
        backend_node_id: Option<i64>,
        clickable: bool,
    ) -> BrowserUseDomTreeNode {
        BrowserUseDomTreeNode {
            target_id: "target-1".to_string(),
            frame_id: None,
            backend_node_id,
            node_type,
            node_name: node_name.to_string(),
            node_value: None,
            attribute_pairs: Vec::new(),
            attributes: HashMap::new(),
            snapshot: Some(BrowserUseSnapshotNode {
                is_clickable: clickable,
                ..Default::default()
            }),
            rect: None,
            visibility_ratio: None,
            is_visible: true,
            has_js_click_listener: false,
            ax_data: BrowserUseAxData::default(),
            som_id: None,
            shadow_root_type: None,
            children: Vec::new(),
            shadow_roots: Vec::new(),
            content_document: None,
            hidden_elements_info: Vec::new(),
            has_hidden_content: false,
            should_display: true,
            assigned_interactive: clickable,
            is_new: false,
            ignored_by_paint_order: false,
            excluded_by_parent: false,
            is_shadow_host: false,
            compound_children: Vec::new(),
        }
    }

    fn text(value: &str) -> BrowserUseDomTreeNode {
        BrowserUseDomTreeNode {
            target_id: "target-1".to_string(),
            frame_id: None,
            backend_node_id: None,
            node_type: 3,
            node_name: "#text".to_string(),
            node_value: Some(value.to_string()),
            attribute_pairs: Vec::new(),
            attributes: HashMap::new(),
            snapshot: None,
            rect: None,
            visibility_ratio: None,
            is_visible: true,
            has_js_click_listener: false,
            ax_data: BrowserUseAxData::default(),
            som_id: None,
            shadow_root_type: None,
            children: Vec::new(),
            shadow_roots: Vec::new(),
            content_document: None,
            hidden_elements_info: Vec::new(),
            has_hidden_content: false,
            should_display: true,
            assigned_interactive: false,
            is_new: false,
            ignored_by_paint_order: false,
            excluded_by_parent: false,
            is_shadow_host: false,
            compound_children: Vec::new(),
        }
    }

    #[test]
    fn pagination_detection_matches_numeric_and_next_buttons() {
        let mut root = node(9, "#document", None, false);
        let mut next = node(1, "A", Some(10), true);
        next.children.push(text("Next"));
        next.som_id = Some(4);

        let mut page_two = node(1, "BUTTON", Some(11), true);
        page_two.children.push(text("2"));

        root.children.push(next);
        root.children.push(page_two);

        let identities = build_browser_use_element_identity_map(&root);
        let buttons = detect_pagination_buttons_from_tree(&root, &identities);
        let rendered = render_pagination_buttons_text(&buttons).expect("pagination text");

        assert_eq!(buttons.len(), 2);
        assert!(rendered.contains("type=next"), "{rendered}");
        assert!(rendered.contains("type=page_number"), "{rendered}");
        assert!(rendered.contains("[4]"), "{rendered}");
    }
}
