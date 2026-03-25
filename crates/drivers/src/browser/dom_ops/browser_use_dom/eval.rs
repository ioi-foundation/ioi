use super::BrowserUseDomTreeNode;

const EVAL_KEY_ATTRIBUTES: &[&str] = &[
    "id",
    "class",
    "name",
    "type",
    "placeholder",
    "aria-label",
    "role",
    "value",
    "data-testid",
    "alt",
    "title",
    "checked",
    "selected",
    "disabled",
    "required",
    "readonly",
    "aria-expanded",
    "aria-pressed",
    "aria-checked",
    "aria-selected",
    "aria-invalid",
    "pattern",
    "min",
    "max",
    "minlength",
    "maxlength",
    "step",
    "aria-valuemin",
    "aria-valuemax",
    "aria-valuenow",
];

const SEMANTIC_ELEMENTS: &[&str] = &[
    "html", "body", "h1", "h2", "h3", "h4", "h5", "h6", "a", "button", "input", "textarea",
    "select", "form", "label", "nav", "header", "footer", "main", "article", "section", "table",
    "thead", "tbody", "tr", "th", "td", "ul", "ol", "li", "img", "iframe", "video", "audio",
];

const CONTAINER_TAGS: &[&str] = &[
    "html", "body", "div", "main", "section", "article", "aside", "header", "footer", "nav",
];

const SVG_ELEMENTS: &[&str] = &[
    "path", "rect", "g", "circle", "ellipse", "line", "polyline", "polygon", "use", "defs",
    "clipPath", "mask", "pattern", "image", "text", "tspan",
];

fn cap_text_length(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn build_compact_attributes(node: &BrowserUseDomTreeNode) -> String {
    let mut attrs = Vec::new();
    for attr in EVAL_KEY_ATTRIBUTES {
        let Some(value) = node
            .attributes
            .get(*attr)
            .map(String::as_str)
            .map(str::trim)
        else {
            continue;
        };
        if value.is_empty() {
            continue;
        }

        let value = match *attr {
            "class" => value
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" "),
            "href" => cap_text_length(value, 80),
            _ => cap_text_length(value, 80),
        };
        attrs.push(format!(r#"{attr}="{value}""#));
    }
    attrs.join(" ")
}

fn has_direct_text(node: &BrowserUseDomTreeNode) -> bool {
    node.children.iter().any(|child| {
        child.node_type == 3
            && child
                .node_value
                .as_deref()
                .map(str::trim)
                .is_some_and(|text| text.len() > 1)
    })
}

fn get_inline_text(node: &BrowserUseDomTreeNode) -> String {
    let text = node
        .children
        .iter()
        .filter(|child| child.node_type == 3)
        .filter_map(|child| child.node_value.as_deref().map(str::trim))
        .filter(|text| !text.is_empty() && text.len() > 1)
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        String::new()
    } else {
        cap_text_length(&text, 80)
    }
}

fn serialize_children(node: &BrowserUseDomTreeNode, depth: usize) -> String {
    let is_list_container = node
        .tag_name()
        .is_some_and(|tag| matches!(tag.as_str(), "ul" | "ol"));

    let mut li_count = 0usize;
    let max_list_items = 50usize;
    let mut consecutive_link_count = 0usize;
    let max_consecutive_links = 50usize;
    let mut total_links_skipped = 0usize;
    let mut output = Vec::new();

    for child in node.children.iter().chain(node.shadow_roots.iter()) {
        let current_tag = (child.node_type == 1).then(|| child.tag_name()).flatten();

        if is_list_container && current_tag.as_deref() == Some("li") {
            li_count += 1;
            if li_count > max_list_items {
                continue;
            }
        }

        if current_tag.as_deref() == Some("a") {
            consecutive_link_count += 1;
            if consecutive_link_count > max_consecutive_links {
                total_links_skipped += 1;
                continue;
            }
        } else {
            if total_links_skipped > 0 {
                let depth_str = "\t".repeat(depth);
                output.push(format!(
                    "{depth_str}... ({total_links_skipped} more links in this list)"
                ));
                total_links_skipped = 0;
            }
            consecutive_link_count = 0;
        }

        let child_text = serialize_tree(child, depth);
        if !child_text.is_empty() {
            output.push(child_text);
        }
    }

    if is_list_container && li_count > max_list_items {
        let depth_str = "\t".repeat(depth);
        output.push(format!(
            "{depth_str}... ({} more items in this list (truncated) use evaluate to get more.",
            li_count - max_list_items
        ));
    }

    if total_links_skipped > 0 {
        let depth_str = "\t".repeat(depth);
        output.push(format!(
            "{depth_str}... ({total_links_skipped} more links in this list) (truncated) use evaluate to get more."
        ));
    }

    output.join("\n")
}

fn serialize_document_node(
    node: &BrowserUseDomTreeNode,
    output: &mut Vec<String>,
    depth: usize,
    is_iframe_content: bool,
) {
    let depth_str = "\t".repeat(depth);

    match node.node_type {
        1 => {
            let tag = node.tag_name().unwrap_or_else(|| node.node_name_for_text());
            let is_visible = if is_iframe_content {
                node.snapshot.is_none() || node.is_visible
            } else {
                node.snapshot.is_some() && node.is_visible
            };
            if !is_visible {
                return;
            }

            let is_semantic = SEMANTIC_ELEMENTS.contains(&tag.as_str());
            let attributes_str = build_compact_attributes(node);
            if !is_semantic && attributes_str.is_empty() {
                for child in node.children.iter().chain(node.shadow_roots.iter()) {
                    serialize_document_node(child, output, depth, is_iframe_content);
                }
                return;
            }

            let mut line = format!("{depth_str}<{tag}");
            if !attributes_str.is_empty() {
                line.push(' ');
                line.push_str(&attributes_str);
            }

            let text = node
                .children
                .iter()
                .filter(|child| child.node_type == 3)
                .filter_map(|child| child.node_value.as_deref().map(str::trim))
                .filter(|text| !text.is_empty() && text.len() > 1)
                .collect::<Vec<_>>()
                .join(" ");
            if text.is_empty() {
                line.push_str(" />");
            } else {
                line.push('>');
                line.push_str(&cap_text_length(&text, 100));
            }
            output.push(line);

            for child in node.children.iter().chain(node.shadow_roots.iter()) {
                if child.node_type != 3 {
                    serialize_document_node(child, output, depth + 1, is_iframe_content);
                }
            }
        }
        11 | 9 => {
            for child in node.children.iter().chain(node.shadow_roots.iter()) {
                serialize_document_node(child, output, depth, is_iframe_content);
            }
        }
        _ => {}
    }
}

fn serialize_iframe(node: &BrowserUseDomTreeNode, depth: usize) -> String {
    let depth_str = "\t".repeat(depth);
    let tag = node.tag_name().unwrap_or_else(|| node.node_name_for_text());
    let attributes_str = build_compact_attributes(node);

    let mut formatted = Vec::new();
    let mut line = format!("{depth_str}<{tag}");
    if !attributes_str.is_empty() {
        line.push(' ');
        line.push_str(&attributes_str);
    }
    if node.should_show_scroll_info() {
        if let Some(scroll_text) = node.scroll_info_text() {
            line.push_str(&format!(r#" scroll="{scroll_text}""#));
        }
    }
    line.push_str(" />");
    formatted.push(line);

    if let Some(content_document) = node.content_document.as_deref() {
        formatted.push(format!("{depth_str}\t#iframe-content"));
        for child in &content_document.children {
            if child.tag_name().as_deref() == Some("html") {
                for html_child in &child.children {
                    if html_child.tag_name().as_deref() == Some("body") {
                        for body_child in &html_child.children {
                            serialize_document_node(body_child, &mut formatted, depth + 2, true);
                        }
                        break;
                    }
                }
            } else {
                serialize_document_node(child, &mut formatted, depth + 1, true);
            }
        }
    }

    formatted.join("\n")
}

fn serialize_tree(node: &BrowserUseDomTreeNode, depth: usize) -> String {
    if node.excluded_by_parent || !node.should_display {
        return serialize_children(node, depth);
    }

    match node.node_type {
        9 => serialize_children(node, depth),
        11 => {
            let children_text = serialize_children(node, depth + 1);
            if children_text.is_empty() {
                String::new()
            } else {
                format!("{}#shadow\n{}", "\t".repeat(depth), children_text)
            }
        }
        3 => String::new(),
        1 => {
            let tag = node.tag_name().unwrap_or_else(|| node.node_name_for_text());
            let is_visible = node.snapshot.is_some() && node.is_visible;

            if !is_visible
                && !CONTAINER_TAGS.contains(&tag.as_str())
                && !matches!(tag.as_str(), "iframe" | "frame")
            {
                return serialize_children(node, depth);
            }

            if matches!(tag.as_str(), "iframe" | "frame") {
                return serialize_iframe(node, depth);
            }

            if tag == "svg" {
                let mut line = "\t".repeat(depth);
                if node.assigned_interactive {
                    if let Some(backend) = node.backend_node_id {
                        line.push_str(&format!("[i_{backend}] "));
                    }
                }
                line.push_str("<svg");
                let attributes_str = build_compact_attributes(node);
                if !attributes_str.is_empty() {
                    line.push(' ');
                    line.push_str(&attributes_str);
                }
                line.push_str(" /> <!-- SVG content collapsed -->");
                return line;
            }

            if SVG_ELEMENTS.contains(&tag.as_str()) {
                return String::new();
            }

            let attributes_str = build_compact_attributes(node);
            let inline_text = get_inline_text(node);
            let is_container = CONTAINER_TAGS.contains(&tag.as_str());
            let has_children = !node.shadow_roots.is_empty() || !node.children.is_empty();

            let mut line = "\t".repeat(depth);
            if node.assigned_interactive {
                if let Some(backend) = node.backend_node_id {
                    line.push_str(&format!("[i_{backend}] "));
                }
            }
            line.push_str(&format!("<{tag}"));
            if !attributes_str.is_empty() {
                line.push(' ');
                line.push_str(&attributes_str);
            }
            if node.should_show_scroll_info() {
                if let Some(scroll_text) = node.scroll_info_text() {
                    line.push_str(&format!(r#" scroll="{scroll_text}""#));
                }
            }
            if !inline_text.is_empty() && !is_container {
                line.push('>');
                line.push_str(&inline_text);
            } else {
                line.push_str(" />");
            }

            let mut formatted = vec![line];
            if has_children && (is_container || inline_text.is_empty() || has_direct_text(node)) {
                let children_text = serialize_children(node, depth + 1);
                if !children_text.is_empty() {
                    formatted.push(children_text);
                }
            }
            formatted.join("\n")
        }
        _ => serialize_children(node, depth),
    }
}

pub(super) fn render_browser_use_eval_from_tree(root: &BrowserUseDomTreeNode) -> Option<String> {
    let text = serialize_tree(root, 0);
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::render_browser_use_eval_from_tree;
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
    fn eval_serializer_includes_backend_ids_and_iframe_content() {
        let mut root = node(9, "#document");
        let mut button = node(1, "BUTTON");
        button.backend_node_id = Some(7);
        button.assigned_interactive = true;
        button.snapshot = Some(Default::default());
        button
            .attributes
            .insert("type".to_string(), "button".to_string());
        button.children.push(BrowserUseDomTreeNode {
            node_type: 3,
            node_name: "#text".to_string(),
            node_value: Some("Save".to_string()),
            ..node(3, "#text")
        });

        let mut iframe = node(1, "IFRAME");
        iframe.snapshot = Some(Default::default());
        let mut content_document = node(9, "#document");
        let mut html = node(1, "HTML");
        let mut body = node(1, "BODY");
        let mut heading = node(1, "H2");
        heading.children.push(BrowserUseDomTreeNode {
            node_type: 3,
            node_name: "#text".to_string(),
            node_value: Some("Inside frame".to_string()),
            ..node(3, "#text")
        });
        body.children.push(heading);
        html.children.push(body);
        content_document.children.push(html);
        iframe.content_document = Some(Box::new(content_document));

        root.children = vec![button, iframe];

        let text = render_browser_use_eval_from_tree(&root).expect("eval");
        assert!(text.contains("[i_7] <button type=\"button\">Save"));
        assert!(text.contains("<iframe />"));
        assert!(text.contains("#iframe-content"));
        assert!(text.contains("<h2>Inside frame"));
    }
}
