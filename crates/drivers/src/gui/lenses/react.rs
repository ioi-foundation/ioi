// Path: crates/drivers/src/gui/lenses/react.rs

use super::AppLens;
use crate::gui::accessibility::AccessibilityNode;

/// A lens for reducing "div soup" in React/Electron applications.
///
/// It prioritizes semantic attributes (`data-testid`, `aria-label`) and flattens
/// deeply nested generic containers to expose the functional UI structure to the Agent.
pub struct ReactLens;

impl AppLens for ReactLens {
    fn name(&self) -> &str {
        "react_semantic"
    }

    fn matches(&self, title: &str) -> bool {
        // Heuristic: Match common web-tech window titles or process names.
        // In a production environment, this would check process metadata (e.g. "electron").
        title.contains("React") || 
        title.contains("Electron") || 
        title.contains("Chrome") || 
        title.contains("Firefox") ||
        title.contains("Edge")
    }

    fn transform(&self, node: &AccessibilityNode) -> Option<AccessibilityNode> {
        // 1. Prune invisible nodes immediately.
        if !node.is_visible {
            return None;
        }

        let mut node = node.clone();

        // 2. Semantic ID Hoisting (The "LiDAR" feature).
        // If a test ID exists, it is the most reliable handle for this element.
        if let Some(test_id) = node.attributes.get("data-testid") {
            node.id = test_id.clone();
        } else if let Some(test_id) = node.attributes.get("data-test-id") {
            node.id = test_id.clone();
        } else if let Some(id) = node.attributes.get("id") {
            // Fallback to HTML ID if no test ID
            if !id.is_empty() {
                node.id = id.clone();
            }
        }
        
        // Hoist ARIA label to name if name is missing
        if node.name.is_none() {
            if let Some(aria) = node.attributes.get("aria-label") {
                node.name = Some(aria.clone());
            }
        }

        // 3. Flattening "Div Soup".
        // If a node is a generic container (group/generic) with NO semantic ID 
        // and ONLY ONE child, it is likely a layout wrapper (Flexbox/Grid).
        // We skip it and return the child directly.
        let is_semantic_container = node.attributes.contains_key("data-testid") 
            || node.attributes.contains_key("id") 
            || node.role == "button" 
            || node.role == "link" 
            || node.role == "textbox"
            || node.role == "window";

        if !is_semantic_container && (node.role == "group" || node.role == "generic") {
            if node.children.len() == 1 {
                return self.transform(&node.children[0]);
            }
        }

        // Recursively transform children
        node.children = node.children
            .into_iter()
            .filter_map(|c| self.transform(&c))
            .collect();

        // 4. Post-recursion prune: Empty containers
        // If a container has no children after filtering, and no content itself, drop it.
        // Exception: Interactable elements (inputs) might not have children.
        if !node.is_interactive() && !node.has_content() && node.children.is_empty() && node.role != "window" {
            return None;
        }

        Some(node)
    }

    fn render(&self, node: &AccessibilityNode, depth: usize) -> String {
        let indent = "  ".repeat(depth);
        
        // 1. Determine Tag Name
        // Prefer semantic component names if available (e.g. from class names), otherwise role.
        let tag = if let Some(class) = node.attributes.get("class") {
            // Heuristic: Extract the last meaningful word from BEM/Tailwind classes
            // e.g. "Button_root__1x2y" -> "Button"
            if class.contains("Button") { "Button".to_string() }
            else if class.contains("Input") { "Input".to_string() }
            else { node.role.clone() }
        } else {
            node.role.clone()
        };

        // 2. Build Attributes String
        let mut attrs = format!(" id=\"{}\"", node.id);
        
        if let Some(val) = &node.value {
            attrs.push_str(&format!(" value=\"{}\"", escape_xml(val)));
        }
        if let Some(name) = &node.name {
            attrs.push_str(&format!(" label=\"{}\"", escape_xml(name)));
        }
        
        // Key logic for React apps: Expose custom attributes relevant to automation
        for (k, v) in &node.attributes {
            if k.starts_with("data-") || k == "aria-role" || k == "placeholder" {
                attrs.push_str(&format!(" {}=\"{}\"", k, escape_xml(v)));
            }
        }
        
        // Add compact coordinates
        attrs.push_str(&format!(" rect=\"{},{},{},{}\"", node.rect.x, node.rect.y, node.rect.width, node.rect.height));

        // 3. Render Children
        if node.children.is_empty() {
            format!("{}<{}{}/>\n", indent, tag, attrs)
        } else {
            let mut children_xml = String::new();
            for c in &node.children {
                children_xml.push_str(&self.render(c, depth + 1));
            }
            format!("{}<{}{}>\n{}{}</{}>\n", indent, tag, attrs, children_xml, indent, tag)
        }
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&apos;")
}