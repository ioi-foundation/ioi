use super::serializer::build_attributes_string;
use super::{inline_value, BrowserUseDomTreeNode};

fn interactive_display_id(node: &BrowserUseDomTreeNode) -> Option<i64> {
    node.backend_node_id
}

fn render_hidden_iframe_hints(node: &BrowserUseDomTreeNode, depth: usize, out: &mut Vec<String>) {
    if !node.hidden_elements_info.is_empty() {
        let depth_str = "\t".repeat(depth);
        out.push(format!(
            "{depth_str}... ({} more elements below - scroll to reveal):",
            node.hidden_elements_info.len()
        ));
        for (tag, text, pages) in &node.hidden_elements_info {
            out.push(format!(
                "{depth_str}\t<{tag}> \"{}\" ~{pages:.1} pages down",
                inline_value(text)
            ));
        }
    } else if node.has_hidden_content {
        let depth_str = "\t".repeat(depth);
        out.push(format!(
            "{depth_str}... (more content below viewport - scroll to reveal)"
        ));
    }
}

fn render_browser_use_dom_node(node: &BrowserUseDomTreeNode, depth: usize, out: &mut Vec<String>) {
    if node.excluded_by_parent || !node.should_display || node.ignored_by_paint_order {
        for child in &node.children {
            render_browser_use_dom_node(child, depth, out);
        }
        for shadow_root in &node.shadow_roots {
            render_browser_use_dom_node(shadow_root, depth, out);
        }
        if let Some(content_document) = node.content_document.as_deref() {
            render_browser_use_dom_node(content_document, depth, out);
        }
        return;
    }

    let depth_str = "\t".repeat(depth);
    match node.node_type {
        9 => {
            for child in &node.children {
                render_browser_use_dom_node(child, depth, out);
            }
            for shadow_root in &node.shadow_roots {
                render_browser_use_dom_node(shadow_root, depth, out);
            }
        }
        11 => {
            let kind = node.shadow_root_type.as_deref().unwrap_or("open");
            if kind.eq_ignore_ascii_case("closed") {
                out.push(format!("{depth_str}Closed Shadow"));
            } else {
                out.push(format!("{depth_str}Open Shadow"));
            }
            for child in &node.children {
                render_browser_use_dom_node(child, depth + 1, out);
            }
            if !node.children.is_empty() {
                out.push(format!("{depth_str}Shadow End"));
            }
        }
        1 => {
            let tag = node.tag_name().unwrap_or_else(|| node.node_name_for_text());
            let shadow_prefix = if node.is_shadow_host {
                let kind = node
                    .shadow_roots
                    .iter()
                    .find_map(|child| child.shadow_root_type.as_deref())
                    .unwrap_or("open");
                format!("|SHADOW({kind})|")
            } else {
                String::new()
            };

            if tag == "svg" {
                let mut line = format!("{depth_str}{shadow_prefix}");
                if node.assigned_interactive {
                    if node.is_new {
                        line.push('*');
                    }
                    if let Some(display_id) = interactive_display_id(node) {
                        line.push_str(&format!("[{display_id}]"));
                    }
                }
                line.push_str("<svg");
                let attrs = build_attributes_string(node);
                if !attrs.is_empty() {
                    line.push(' ');
                    line.push_str(&attrs);
                }
                line.push_str(" /> <!-- SVG content collapsed -->");
                out.push(line);
                return;
            }

            let is_iframe = matches!(tag.as_str(), "iframe" | "frame");
            let is_scrollable = node.is_scrollable();
            let should_emit = node.assigned_interactive || is_scrollable || is_iframe;

            if should_emit {
                let mut line = format!("{depth_str}{shadow_prefix}");
                if is_scrollable && !node.assigned_interactive {
                    line.push_str("|scroll element|");
                } else if node.assigned_interactive {
                    if node.is_new {
                        line.push('*');
                    }
                    if is_scrollable {
                        line.push_str("|scroll element[");
                    } else {
                        line.push('[');
                    }
                    if let Some(display_id) = interactive_display_id(node) {
                        line.push_str(&display_id.to_string());
                    }
                    line.push(']');
                } else if tag == "iframe" {
                    line.push_str("|IFRAME|");
                } else if tag == "frame" {
                    line.push_str("|FRAME|");
                }
                line.push_str(&format!("<{tag}"));
                let attrs = build_attributes_string(node);
                if !attrs.is_empty() {
                    line.push(' ');
                    line.push_str(&attrs);
                }
                line.push_str(" />");
                if node.should_show_scroll_info() {
                    if let Some(scroll_text) = node.scroll_info_text() {
                        line.push_str(&format!(" ({scroll_text})"));
                    }
                }
                out.push(line);
            }

            let next_depth = if should_emit { depth + 1 } else { depth };
            for child in &node.children {
                render_browser_use_dom_node(child, next_depth, out);
            }
            for shadow_root in &node.shadow_roots {
                render_browser_use_dom_node(shadow_root, next_depth, out);
            }
            if let Some(content_document) = node.content_document.as_deref() {
                render_browser_use_dom_node(content_document, next_depth, out);
            }
            if is_iframe {
                render_hidden_iframe_hints(node, depth, out);
            }
        }
        3 => {
            if node.is_visible {
                if let Some(text) = node.text_value().filter(|text| text.len() > 1) {
                    out.push(format!("{depth_str}{}", inline_value(text)));
                }
            }
        }
        _ => {
            for child in &node.children {
                render_browser_use_dom_node(child, depth, out);
            }
            for shadow_root in &node.shadow_roots {
                render_browser_use_dom_node(shadow_root, depth, out);
            }
            if let Some(content_document) = node.content_document.as_deref() {
                render_browser_use_dom_node(content_document, depth, out);
            }
        }
    }
}

pub(super) fn render_browser_use_state_from_tree(root: &BrowserUseDomTreeNode) -> Option<String> {
    let mut lines = Vec::new();
    render_browser_use_dom_node(root, 0, &mut lines);
    (!lines.is_empty()).then(|| lines.join("\n"))
}
