// Path: crates/drivers/src/gui/lenses/react.rs

use super::AppLens;
use crate::gui::accessibility::AccessibilityNode;
use std::collections::{HashMap, HashSet};

/// A lens for reducing "div soup" in React/Electron applications.
///
/// It prioritizes semantic attributes (`data-testid`, `aria-label`) and flattens
/// deeply nested generic containers to expose the functional UI structure to the Agent.
pub struct ReactLens;

fn has_non_empty_attr(node: &AccessibilityNode, key: &str) -> bool {
    node.attributes
        .get(key)
        .is_some_and(|value| !value.trim().is_empty())
}

fn has_semantic_signal(node: &AccessibilityNode) -> bool {
    [
        "data-testid",
        "data-test-id",
        "id",
        "aria-label",
        "aria-labelledby",
        "aria-description",
        "aria-describedby",
        "title",
        "placeholder",
    ]
    .iter()
    .any(|key| has_non_empty_attr(node, key))
        || node
            .name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || node
            .value
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
}

fn normalized_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn normalize_name_token(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn is_low_information_name(node: &AccessibilityNode) -> bool {
    let Some(name) = normalized_text(node.name.as_deref()) else {
        return true;
    };

    let name_norm = normalize_name_token(&name);
    if name_norm.is_empty() {
        return true;
    }

    let role_norm = normalize_name_token(&node.role);
    if !role_norm.is_empty() && name_norm == role_norm {
        return true;
    }

    matches!(
        name_norm.as_str(),
        "button"
            | "link"
            | "textbox"
            | "text"
            | "input"
            | "field"
            | "control"
            | "image"
            | "icon"
            | "label"
            | "group"
            | "generic"
            | "window"
            | "pane"
    )
}

fn first_non_empty_attr(node: &AccessibilityNode, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| normalized_text(node.attributes.get(*key).map(String::as_str)))
}

fn node_semantic_text(node: &AccessibilityNode) -> Option<String> {
    normalized_text(node.name.as_deref())
        .or_else(|| normalized_text(node.value.as_deref()))
        .or_else(|| first_non_empty_attr(node, &["aria-label", "title", "placeholder"]))
}

fn push_deduped_text(parts: &mut Vec<String>, seen: &mut HashSet<String>, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }

    let folded = trimmed.to_ascii_lowercase();
    if seen.insert(folded) {
        parts.push(trimmed.to_string());
    }
}

fn index_text_for_id(index: &mut HashMap<String, String>, raw_id: &str, text: &str) {
    let trimmed = raw_id.trim().trim_start_matches('#');
    if trimmed.is_empty() {
        return;
    }

    index
        .entry(trimmed.to_string())
        .or_insert_with(|| text.to_string());
    index
        .entry(trimmed.to_ascii_lowercase())
        .or_insert_with(|| text.to_string());
}

fn collect_text_index(
    node: &AccessibilityNode,
    index: &mut HashMap<String, String>,
) -> Option<String> {
    let mut child_parts = Vec::new();
    let mut seen_child_parts = HashSet::new();

    for child in &node.children {
        if let Some(child_text) = collect_text_index(child, index) {
            push_deduped_text(&mut child_parts, &mut seen_child_parts, &child_text);
        }
        if child_parts.len() >= 4 {
            break;
        }
    }

    let text = node_semantic_text(node).or_else(|| {
        if child_parts.is_empty() {
            None
        } else {
            Some(child_parts.join(" "))
        }
    });

    if let Some(text) = text.clone() {
        index_text_for_id(index, &node.id, &text);
        if let Some(raw_id) = node.attributes.get("id") {
            index_text_for_id(index, raw_id, &text);
        }
    }
    text
}

fn resolve_idref_text(
    node: &AccessibilityNode,
    attr_key: &str,
    index: &HashMap<String, String>,
) -> Option<String> {
    let refs = node.attributes.get(attr_key)?.trim();
    if refs.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    let mut seen = HashSet::new();

    for raw_ref in refs.split_whitespace() {
        let idref = raw_ref.trim().trim_start_matches('#');
        if idref.is_empty() {
            continue;
        }

        let folded = idref.to_ascii_lowercase();
        if !seen.insert(folded.clone()) {
            continue;
        }

        if let Some(text) = index.get(idref).or_else(|| index.get(&folded)) {
            let text = text.trim();
            if !text.is_empty() {
                parts.push(text.to_string());
            }
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn normalize_idref(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_start_matches('#');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn merge_label_text(existing: &mut String, next: &str) {
    let next_trimmed = next.trim();
    if next_trimmed.is_empty() {
        return;
    }

    let next_lc = next_trimmed.to_ascii_lowercase();
    if existing.to_ascii_lowercase().contains(&next_lc) {
        return;
    }

    if !existing.trim().is_empty() {
        existing.push(' ');
    }
    existing.push_str(next_trimmed);
}

fn collect_label_for_index(
    node: &AccessibilityNode,
    text_index: &HashMap<String, String>,
    index: &mut HashMap<String, String>,
) {
    let label_text = node_semantic_text(node).or_else(|| {
        for candidate in [
            Some(node.id.as_str()),
            node.attributes.get("id").map(String::as_str),
        ]
        .into_iter()
        .flatten()
        {
            let trimmed_id = candidate.trim();
            if trimmed_id.is_empty() {
                continue;
            }

            if let Some(text) = text_index
                .get(trimmed_id)
                .or_else(|| text_index.get(&trimmed_id.to_ascii_lowercase()))
            {
                return Some(text.clone());
            }
        }

        None
    });
    if let Some(text) = label_text {
        for (attr_key, attr_value) in &node.attributes {
            let attr_key_lc = attr_key.to_ascii_lowercase();
            if !matches!(attr_key_lc.as_str(), "for" | "htmlfor" | "html-for") {
                continue;
            }

            for raw_ref in attr_value.split_whitespace() {
                let Some(target_id) = normalize_idref(raw_ref) else {
                    continue;
                };
                match index.get_mut(&target_id) {
                    Some(existing) => merge_label_text(existing, &text),
                    None => {
                        index.insert(target_id, text.clone());
                    }
                }
            }
        }
    }

    for child in &node.children {
        collect_label_for_index(child, text_index, index);
    }
}

fn label_for_text(
    node: &AccessibilityNode,
    label_for_index: &HashMap<String, String>,
) -> Option<String> {
    let mut candidates = Vec::new();
    candidates.push(node.id.as_str());
    if let Some(raw_id) = node.attributes.get("id").map(String::as_str) {
        candidates.push(raw_id);
    }

    for candidate in candidates {
        let Some(key) = normalize_idref(candidate) else {
            continue;
        };
        if let Some(text) = label_for_index.get(&key) {
            return Some(text.clone());
        }
    }
    None
}

impl ReactLens {
    fn transform_with_index(
        &self,
        node: &AccessibilityNode,
        index: &HashMap<String, String>,
        label_for_index: &HashMap<String, String>,
    ) -> Option<AccessibilityNode> {
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

        // Hoist direct ARIA labels to `name`.
        if is_low_information_name(&node) {
            if let Some(aria) =
                normalized_text(node.attributes.get("aria-label").map(String::as_str))
            {
                node.name = Some(aria);
            }
        }

        // Resolve ARIA IDREF relations (`aria-labelledby`, `aria-describedby`) into semantic text.
        if is_low_information_name(&node) {
            if let Some(labelled_text) = resolve_idref_text(&node, "aria-labelledby", index) {
                node.name = Some(labelled_text.clone());
                node.attributes
                    .entry("aria-label".to_string())
                    .or_insert(labelled_text);
            }
        }
        if let Some(described_text) = resolve_idref_text(&node, "aria-describedby", index) {
            node.attributes
                .entry("description".to_string())
                .or_insert(described_text);
        }

        // Recover form semantics in React trees where labels use `for/htmlFor`.
        if is_low_information_name(&node) {
            if let Some(for_label) = label_for_text(&node, label_for_index) {
                node.name = Some(for_label.clone());
                node.attributes
                    .entry("aria-label".to_string())
                    .or_insert(for_label);
            }
        }

        // 3. Flattening "Div Soup".
        // If a node is a generic container (group/generic) with NO semantic ID
        // and ONLY ONE child, it is likely a layout wrapper (Flexbox/Grid).
        // We skip it and return the child directly.
        let is_semantic_container = has_semantic_signal(&node)
            || node.role == "button"
            || node.role == "link"
            || node.role == "textbox"
            || node.role == "window";

        if !is_semantic_container && (node.role == "group" || node.role == "generic") {
            if node.children.len() == 1 {
                return self.transform_with_index(&node.children[0], index, label_for_index);
            }
        }

        // Recursively transform children
        node.children = node
            .children
            .into_iter()
            .filter_map(|c| self.transform_with_index(&c, index, label_for_index))
            .collect();

        // 4. Post-recursion prune: Empty containers
        // If a container has no children after filtering, and no content itself, drop it.
        // Exception: Interactable elements (inputs) might not have children.
        if !node.is_interactive()
            && !node.has_content()
            && node.children.is_empty()
            && node.role != "window"
        {
            return None;
        }

        Some(node)
    }
}

impl AppLens for ReactLens {
    fn name(&self) -> &str {
        "react_semantic"
    }

    fn matches(&self, title: &str) -> bool {
        // Do not hijack generic web pages in browser windows; let AutoLens handle those.
        let t = title.to_ascii_lowercase();
        let is_browser_window = t.contains("chrome")
            || t.contains("firefox")
            || t.contains("edge")
            || t.contains("safari");
        if is_browser_window {
            return false;
        }

        t.contains("react")
            || t.contains("electron")
            || t.contains("vscode")
            || t.contains("visual studio code")
            || t.contains("slack")
            || t.contains("discord")
            || t.contains("notion")
    }

    fn transform(&self, node: &AccessibilityNode) -> Option<AccessibilityNode> {
        let mut index = HashMap::new();
        collect_text_index(node, &mut index);
        let mut label_for_index = HashMap::new();
        collect_label_for_index(node, &index, &mut label_for_index);
        self.transform_with_index(node, &index, &label_for_index)
    }

    fn render(&self, node: &AccessibilityNode, depth: usize) -> String {
        let indent = "  ".repeat(depth);

        // 1. Determine Tag Name
        // Prefer semantic component names if available (e.g. from class names), otherwise role.
        let tag = if let Some(class) = node.attributes.get("class") {
            // Heuristic: Extract the last meaningful word from BEM/Tailwind classes
            // e.g. "Button_root__1x2y" -> "Button"
            if class.contains("Button") {
                "Button".to_string()
            } else if class.contains("Input") {
                "Input".to_string()
            } else {
                node.role.clone()
            }
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
        attrs.push_str(&format!(
            " rect=\"{},{},{},{}\"",
            node.rect.x, node.rect.y, node.rect.width, node.rect.height
        ));

        // 3. Render Children
        if node.children.is_empty() {
            format!("{}<{}{}/>\n", indent, tag, attrs)
        } else {
            let mut children_xml = String::new();
            for c in &node.children {
                children_xml.push_str(&self.render(c, depth + 1));
            }
            format!(
                "{}<{}{}>\n{}{}</{}>\n",
                indent, tag, attrs, children_xml, indent, tag
            )
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
