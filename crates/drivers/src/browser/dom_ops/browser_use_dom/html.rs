use super::BrowserUseDomTreeNode;

const NON_CONTENT_ELEMENTS: &[&str] = &["style", "script", "head", "meta", "link", "title"];
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

fn is_hidden_json_code(node: &BrowserUseDomTreeNode, tag: &str) -> bool {
    if tag != "code" {
        return false;
    }

    let style = node
        .attributes
        .get("style")
        .map(String::as_str)
        .unwrap_or_default();
    let compact_style = style.replace(' ', "").to_ascii_lowercase();
    if compact_style.contains("display:none") {
        return true;
    }

    let element_id = node
        .attributes
        .get("id")
        .map(String::as_str)
        .unwrap_or_default();
    let element_id = element_id.to_ascii_lowercase();
    element_id.contains("bpr-guid") || element_id.contains("data") || element_id.contains("state")
}

fn should_skip_element(node: &BrowserUseDomTreeNode, tag: &str) -> bool {
    if NON_CONTENT_ELEMENTS.contains(&tag) {
        return true;
    }

    if is_hidden_json_code(node, tag) {
        return true;
    }

    if tag == "img" {
        if let Some(src) = node.attributes.get("src").map(String::as_str) {
            if src.starts_with("data:image/") {
                return true;
            }
        }
    }

    false
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn serialize_attributes(node: &BrowserUseDomTreeNode, extract_links: bool) -> String {
    let mut parts = Vec::new();
    for (key, value) in &node.attribute_pairs {
        if !extract_links && key == "href" {
            continue;
        }
        if key.starts_with("data-") {
            continue;
        }
        if value.is_empty() {
            parts.push(key.clone());
        } else {
            parts.push(format!(r#"{key}="{}""#, escape_attribute(value)));
        }
    }
    parts.join(" ")
}

fn serialize_children(children: &[BrowserUseDomTreeNode], extract_links: bool) -> String {
    children
        .iter()
        .map(|child| serialize_node(child, extract_links))
        .collect::<String>()
}

fn serialize_content_document(node: &BrowserUseDomTreeNode, extract_links: bool) -> String {
    match node.node_type {
        9 => serialize_children(&node.children, extract_links),
        _ => serialize_node(node, extract_links),
    }
}

fn serialize_table_children(table_node: &BrowserUseDomTreeNode, extract_links: bool) -> String {
    if table_node.children.is_empty() {
        return String::new();
    }

    let child_tags = table_node
        .children
        .iter()
        .filter(|child| child.node_type == 1)
        .filter_map(|child| child.tag_name())
        .collect::<Vec<_>>();
    let has_thead = child_tags.iter().any(|tag| tag == "thead");
    let has_tbody = child_tags.iter().any(|tag| tag == "tbody");

    if has_thead || child_tags.is_empty() {
        return serialize_children(&table_node.children, extract_links);
    }

    let first_header_row = table_node.children.iter().enumerate().find(|(_, child)| {
        child.node_type == 1
            && child.tag_name().as_deref() == Some("tr")
            && child.children.iter().any(|grandchild| {
                grandchild.node_type == 1 && grandchild.tag_name().as_deref() == Some("th")
            })
    });

    let Some((header_index, header_row)) = first_header_row else {
        return serialize_children(&table_node.children, extract_links);
    };

    let mut parts = Vec::new();
    parts.push(serialize_children(
        &table_node.children[..header_index],
        extract_links,
    ));
    parts.push("<thead>".to_string());
    parts.push(serialize_node(header_row, extract_links));
    parts.push("</thead>".to_string());

    let remaining = &table_node.children[header_index + 1..];
    if !remaining.is_empty() && !has_tbody {
        parts.push("<tbody>".to_string());
        parts.push(serialize_children(remaining, extract_links));
        parts.push("</tbody>".to_string());
    } else {
        parts.push(serialize_children(remaining, extract_links));
    }

    parts.concat()
}

fn serialize_node(node: &BrowserUseDomTreeNode, extract_links: bool) -> String {
    match node.node_type {
        9 => {
            let mut parts = Vec::new();
            parts.push(serialize_children(&node.children, extract_links));
            parts.push(serialize_children(&node.shadow_roots, extract_links));
            parts.concat()
        }
        11 => {
            let shadow_type = node
                .shadow_root_type
                .as_deref()
                .unwrap_or("open")
                .to_ascii_lowercase();
            let mut parts = vec![format!(r#"<template shadowroot="{shadow_type}">"#)];
            parts.push(serialize_children(&node.children, extract_links));
            parts.push("</template>".to_string());
            parts.concat()
        }
        1 => {
            let tag = node.tag_name().unwrap_or_else(|| node.node_name_for_text());
            if should_skip_element(node, &tag) {
                return String::new();
            }

            let attrs = serialize_attributes(node, extract_links);
            let mut parts = vec![format!("<{tag}")];
            if !attrs.is_empty() {
                parts.push(format!(" {attrs}"));
            }
            if VOID_ELEMENTS.contains(&tag.as_str()) {
                parts.push(" />".to_string());
                return parts.concat();
            }
            parts.push(">".to_string());

            if tag == "table" {
                parts.push(serialize_children(&node.shadow_roots, extract_links));
                parts.push(serialize_table_children(node, extract_links));
            } else if matches!(tag.as_str(), "iframe" | "frame") {
                if let Some(content_document) = node.content_document.as_deref() {
                    parts.push(serialize_content_document(content_document, extract_links));
                }
            } else {
                parts.push(serialize_children(&node.shadow_roots, extract_links));
                parts.push(serialize_children(&node.children, extract_links));
            }

            parts.push(format!("</{tag}>"));
            parts.concat()
        }
        3 => node.text_value().map(escape_html).unwrap_or_default(),
        8 => String::new(),
        _ => String::new(),
    }
}

pub(super) fn render_browser_use_html_from_tree(
    root: &BrowserUseDomTreeNode,
    extract_links: bool,
) -> Option<String> {
    let html = serialize_node(root, extract_links);
    (!html.trim().is_empty()).then_some(html)
}

#[cfg(test)]
mod tests {
    use super::render_browser_use_html_from_tree;
    use crate::browser::dom_ops::browser_use_dom::BrowserUseDomTreeNode;
    use std::collections::HashMap;

    fn node(node_type: i64, node_name: &str) -> BrowserUseDomTreeNode {
        BrowserUseDomTreeNode {
            target_id: "target".to_string(),
            frame_id: None,
            backend_node_id: None,
            node_type,
            node_name: node_name.to_string(),
            node_value: None,
            attribute_pairs: Vec::new(),
            attributes: HashMap::new(),
            snapshot: None,
            rect: None,
            visibility_ratio: None,
            is_visible: true,
            has_js_click_listener: false,
            ax_data: Default::default(),
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
    fn html_serializer_includes_shadow_dom_and_iframe_documents() {
        let mut root = node(9, "#document");
        let mut host = node(1, "DIV");
        host.attribute_pairs
            .push(("id".to_string(), "host".to_string()));
        host.attributes.insert("id".to_string(), "host".to_string());

        let mut shadow_root = node(11, "#document-fragment");
        shadow_root.shadow_root_type = Some("open".to_string());
        let mut shadow_button = node(1, "BUTTON");
        shadow_button.children.push(BrowserUseDomTreeNode {
            node_type: 3,
            node_name: "#text".to_string(),
            node_value: Some("Shadow".to_string()),
            ..node(3, "#text")
        });
        shadow_root.children.push(shadow_button);
        host.shadow_roots.push(shadow_root);
        let mut light_span = node(1, "SPAN");
        light_span.children.push(BrowserUseDomTreeNode {
            node_type: 3,
            node_name: "#text".to_string(),
            node_value: Some("Light".to_string()),
            ..node(3, "#text")
        });
        host.children.push(light_span);

        let mut iframe = node(1, "IFRAME");
        let mut content_document = node(9, "#document");
        let mut paragraph = node(1, "P");
        paragraph.children.push(BrowserUseDomTreeNode {
            node_type: 3,
            node_name: "#text".to_string(),
            node_value: Some("Iframe body".to_string()),
            ..node(3, "#text")
        });
        content_document.children.push(paragraph);
        iframe.content_document = Some(Box::new(content_document));

        root.children = vec![host, iframe];

        let html = render_browser_use_html_from_tree(&root, false).expect("html");
        assert_eq!(
            html,
            r#"<div id="host"><template shadowroot="open"><button>Shadow</button></template><span>Light</span></div><iframe><p>Iframe body</p></iframe>"#
        );
    }

    #[test]
    fn html_serializer_drops_data_attributes_and_optional_links() {
        let mut root = node(9, "#document");
        let mut link = node(1, "A");
        link.attribute_pairs
            .push(("href".to_string(), "https://example.com".to_string()));
        link.attributes
            .insert("href".to_string(), "https://example.com".to_string());
        link.attribute_pairs
            .push(("data-state".to_string(), "{\"a\":1}".to_string()));
        link.attributes
            .insert("data-state".to_string(), "{\"a\":1}".to_string());
        link.children.push(BrowserUseDomTreeNode {
            node_type: 3,
            node_name: "#text".to_string(),
            node_value: Some("Example".to_string()),
            ..node(3, "#text")
        });
        root.children.push(link);

        let html = render_browser_use_html_from_tree(&root, false).expect("html");
        assert_eq!(html, "<a>Example</a>");
    }

    #[test]
    fn html_serializer_preserves_attribute_order_when_links_are_enabled() {
        let mut root = node(9, "#document");
        let mut link = node(1, "A");
        for (key, value) in [
            ("title", "Docs"),
            ("href", "https://example.com"),
            ("rel", "noopener"),
            ("data-state", "{\"a\":1}"),
        ] {
            link.attribute_pairs
                .push((key.to_string(), value.to_string()));
            link.attributes.insert(key.to_string(), value.to_string());
        }
        link.children.push(BrowserUseDomTreeNode {
            node_type: 3,
            node_name: "#text".to_string(),
            node_value: Some("Example".to_string()),
            ..node(3, "#text")
        });
        root.children.push(link);

        let html = render_browser_use_html_from_tree(&root, true).expect("html");
        assert_eq!(
            html,
            r#"<a title="Docs" href="https://example.com" rel="noopener">Example</a>"#
        );
    }
}
