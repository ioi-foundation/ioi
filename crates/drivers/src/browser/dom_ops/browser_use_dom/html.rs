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
#[path = "html/tests.rs"]
mod tests;
