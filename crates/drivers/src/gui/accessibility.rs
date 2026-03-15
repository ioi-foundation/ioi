// Path: crates/drivers/src/gui/accessibility.rs

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::{ActionRequest, ContextSlice};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet}; // [NEW] Added for attributes map

/// A simplified, VLM-friendly representation of a UI element.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessibilityNode {
    pub id: String,
    pub role: String, // button, link, window, etc.
    pub name: Option<String>,
    pub value: Option<String>,
    pub rect: Rect,
    pub children: Vec<AccessibilityNode>,
    pub is_visible: bool,

    // [NEW] Store raw platform attributes for Application Lens processing.
    // This holds raw data like "data-testid", "aria-label", "class", etc.
    // that Lenses use to semanticize the tree.
    #[serde(default)]
    pub attributes: HashMap<String, String>,

    // [NEW] Transient Visual Grounding ID (Set-of-Marks).
    // This connects the Visual Overlay (screenshot) to the Semantic Tree (XML).
    // It is populated during the Perception phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub som_id: Option<u32>,
}

impl AccessibilityNode {
    /// Heuristic to determine if a node is relevant for interaction.
    /// Used for semantic filtering (Phase 1.1).
    pub fn is_interactive(&self) -> bool {
        let role = self.role.to_ascii_lowercase();
        role.contains("button")
            || role.contains("link")
            || role.contains("checkbox")
            || role.contains("check_box")
            || role.contains("radio")
            || role.contains("slider")
            || role.contains("textbox")
            || role.contains("text_box")
            || role.contains("combobox")
            || role.contains("combo_box")
            || role.contains("menuitem")
            || role.contains("menu_item")
            || role.contains("listitem")
            || role.contains("list_item")
            || role.contains("searchbox")
            || role.contains("search_box")
            || role.contains("entry")
            || self
                .attributes
                .get("dom_clickable")
                .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    }

    /// Checks if the node carries meaningful text content.
    pub fn has_content(&self) -> bool {
        self.name.as_ref().map_or(false, |s| !s.trim().is_empty())
            || self.value.as_ref().map_or(false, |s| !s.trim().is_empty())
    }

    /// [NEW] Recursively shifts the coordinates of this node and all children.
    /// Used to align browser DOM trees with OS window coordinates.
    pub fn offset(&mut self, dx: i32, dy: i32) {
        self.rect.x += dx;
        self.rect.y += dy;
        for child in &mut self.children {
            child.offset(dx, dy);
        }
    }

    /// Recursively searches the tree for nodes matching the text query.
    /// Returns a list of (ID, Role, Name, Rect).
    pub fn find_matches(&self, query: &str) -> Vec<(String, String, String, Rect)> {
        let mut results = Vec::new();
        let q = query.to_lowercase();
        let normalized_q: String = q.chars().filter(|c| c.is_ascii_alphanumeric()).collect();

        // Check self
        let id_lc = self.id.to_lowercase();
        let id_match = !q.is_empty() && id_lc.contains(&q);
        let name_match = self
            .name
            .as_ref()
            .map_or(false, |n| n.to_lowercase().contains(&q));
        let value_match = self
            .value
            .as_ref()
            .map_or(false, |v| v.to_lowercase().contains(&q));
        let role_match = self.role.to_lowercase().contains(&q);
        let normalized_id_match = if normalized_q.is_empty() {
            false
        } else {
            let normalized_id: String = id_lc
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            normalized_id.contains(&normalized_q)
        };

        // Also check attributes (e.g. data-testid)
        let attr_match = self
            .attributes
            .values()
            .any(|v| v.to_lowercase().contains(&q));

        if (id_match
            || normalized_id_match
            || name_match
            || value_match
            || role_match
            || attr_match)
            && self.is_visible
        {
            let label = self
                .name
                .clone()
                .or(self.value.clone())
                .unwrap_or(self.role.clone());
            results.push((self.id.clone(), self.role.clone(), label, self.rect));
        }

        // Recurse children
        for child in &self.children {
            results.extend(child.find_matches(query));
        }

        results
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Merges a child accessibility tree (e.g. Browser DOM) into a parent tree (e.g. OS Window)
/// at the node matching the `target_app_name`.
///
/// If `target_app_name` is found, its children are replaced/augmented with the `graft_tree`.
pub fn merge_trees(
    mut root: AccessibilityNode,
    graft_tree: AccessibilityNode,
    target_app_name: &str,
    offset: (i32, i32),
) -> AccessibilityNode {
    // 1. Find target node in OS tree
    // We look for a window or application node that matches the target name.

    // Helper recursive finder/replacer
    fn recurse_graft(
        node: &mut AccessibilityNode,
        graft: &AccessibilityNode,
        target: &str,
        offset: (i32, i32),
    ) -> bool {
        // Simple case-insensitive contains match for robustness
        let name_match = node
            .name
            .as_ref()
            .map_or(false, |n| n.to_lowercase().contains(&target.to_lowercase()));

        if name_match && (node.role == "window" || node.role == "application") {
            // Found it!
            // The graft tree (DOM) is usually screen-relative or window-relative.
            // If it's window-relative, we add the window offset.
            // If it's screen-relative (which CDP usually gives if configured right), we might not need offset.
            // Assuming here the graft needs the offset applied.

            let mut shifted_graft = graft.clone();
            shifted_graft.offset(offset.0, offset.1);

            // We append the DOM as a child of the Window.
            // We don't replace children because the window might have other UI (title bar, menus) we want to keep.
            node.children.push(shifted_graft);
            return true;
        }

        for child in &mut node.children {
            if recurse_graft(child, graft, target, offset) {
                return true;
            }
        }
        false
    }

    recurse_graft(&mut root, &graft_tree, target_app_name, offset);
    root
}

/// Serializes the accessibility tree into a simplified XML-like format optimized for LLM token usage.
/// Applies semantic filtering to reduce noise.
///
/// Note: This is the DEFAULT serialization strategy. Specialized Lenses (e.g. ReactLens)
/// will implement their own `render` logic to utilize the `attributes` field effectively.
pub fn serialize_tree_to_xml(node: &AccessibilityNode, depth: usize) -> String {
    let assistive_hint = node.attributes.contains_key("assistive_hint");

    // 1. Prune invisible leaf nodes immediately, but keep structural containers so
    // we can still traverse to visible descendants (common with AT-SPI roots/windows).
    let structural_container = matches!(
        node.role.as_str(),
        "root" | "window" | "application" | "frame" | "pane" | "panel"
    );
    if !node.is_visible && node.children.is_empty() && !structural_container && !assistive_hint {
        return String::new();
    }

    // Enforce hard depth limit to prevent deep recursion in complex UIs (e.g. IDEs, Webviews)
    if depth > 10 {
        return String::new();
    }

    // 2. Semantic Filter Logic (Early Exit)
    // Check if the node is "interesting" enough to render or recurse.
    let is_container = !node.children.is_empty();

    // Heuristic: If a node has > 200 chars of text, it's likely a document/log/code block.
    // Unless we are explicitly reading text, treat it as "Content" and summary-tag it to save tokens.
    let content_len = node.value.as_ref().map(|s| s.len()).unwrap_or(0)
        + node.name.as_ref().map(|s| s.len()).unwrap_or(0);
    let is_bulk_text = content_len > 200;

    // [MODIFIED] If node has a SoM ID, it is ALWAYS interesting because the VLM can see it tagged.
    let is_interesting = node.som_id.is_some()
        || node.is_interactive()
        || assistive_hint
        || (node.has_content() && !is_bulk_text)
        || is_container // Must traverse containers to find interactive children
        || structural_container;

    if !is_interesting {
        // If it's a boring leaf (empty div), prune it.
        return String::new();
    }

    // 3. Recursively serialize children.
    // Limit the number of children to prevent context explosion in lists/tables.
    let mut children_xml = String::new();
    let max_children = 25; // Strict limit

    let indent = "  ".repeat(depth + 1);
    let selected_indices = selected_child_indices(&node.children, max_children);
    let selected_set = selected_indices.iter().copied().collect::<HashSet<_>>();

    for &i in &selected_indices {
        let child = &node.children[i];
        children_xml.push_str(&serialize_tree_to_xml(child, depth + 1));
    }
    if selected_indices.len() < node.children.len() {
        let omitted_children = node
            .children
            .iter()
            .enumerate()
            .filter_map(|(idx, child)| (!selected_set.contains(&idx)).then_some(child))
            .collect::<Vec<_>>();
        for omitted in collect_omitted_high_priority_nodes(&omitted_children, 6) {
            children_xml.push_str(&render_omitted_high_priority_node(&omitted, depth + 1));
        }
        children_xml.push_str(&format!(
            "{}<!-- ... {} siblings truncated ... -->\n",
            indent,
            node.children.len() - selected_indices.len()
        ));
    }

    // 4. Post-recursion prune: If a container has no interesting children and isn't interesting itself, return empty.
    // Exception: Keep windows/roots to maintain structure, and keep nodes with IDs.
    if node.som_id.is_none()
        && !node.is_interactive()
        && !assistive_hint
        && !node.has_content()
        && children_xml.is_empty()
        && !structural_container
    {
        return String::new();
    }

    // 5. Construct XML
    let indent_self = "  ".repeat(depth);

    // [NEW] Inject SoM ID into attributes
    let som_attr = if let Some(id) = node.som_id {
        format!(" som_id=\"{}\"", id)
    } else {
        String::new()
    };

    let name_attr = node
        .name
        .as_ref()
        .map(|n| format!(" name=\"{}\"", escape_xml(&truncate_attr_value(n, 50))))
        .unwrap_or_default();

    let value_attr = node
        .value
        .as_ref()
        .map(|v| format!(" value=\"{}\"", escape_xml(&truncate_attr_value(v, 50))))
        .unwrap_or_default();

    let coords_attr = format!(
        " rect=\"{},{},{},{}\"",
        node.rect.x, node.rect.y, node.rect.width, node.rect.height
    );

    let mut state_attrs = String::new();
    if node.attributes.contains_key("disabled") {
        state_attrs.push_str(" disabled=\"true\"");
    }
    if node.attributes.contains_key("checked") {
        state_attrs.push_str(" checked=\"true\"");
    }
    if node.attributes.contains_key("selected") {
        state_attrs.push_str(" selected=\"true\"");
    }
    if node.attributes.contains_key("focused") {
        state_attrs.push_str(" focused=\"true\"");
    }
    if node.attributes.contains_key("expanded") {
        state_attrs.push_str(" expanded=\"true\"");
    }
    if !node.is_visible {
        state_attrs.push_str(" visible=\"false\"");
    }
    if assistive_hint {
        state_attrs.push_str(" assistive_hint=\"true\"");
    }
    if let Some(reason) = node.attributes.get("assistive_reason") {
        state_attrs.push_str(&format!(
            " assistive_reason=\"{}\"",
            escape_xml(&truncate_attr_value(reason, 32))
        ));
    }
    state_attrs.push_str(&browser_locator_attrs(node, 64));

    // Ensure tag names are XML-safe even if upstream role strings include spaces or symbols.
    let tag_name = xml_tag_name(&node.role);
    let role_attr = if tag_name != node.role {
        format!(" role=\"{}\"", escape_xml(&node.role))
    } else {
        String::new()
    };

    // [MODIFIED] Include som_attr in output (Fixed argument count mismatch)
    let mut output = format!(
        "{}<{} id=\"{}\"{}{}{}{}{}{}",
        indent_self,
        tag_name,
        node.id,
        role_attr,
        som_attr,
        name_attr,
        value_attr,
        state_attrs,
        coords_attr
    );

    if children_xml.is_empty() {
        output.push_str(" />\n");
    } else {
        output.push_str(">\n");
        output.push_str(&children_xml);
        output.push_str(&format!("{}</{}>\n", indent_self, tag_name));
    }

    output
}

fn node_has_high_priority_signal(node: &AccessibilityNode) -> bool {
    node.som_id.is_some()
        || node.is_interactive()
        || node.attributes.contains_key("focused")
        || node.attributes.contains_key("dom_id")
        || node.attributes.contains_key("data_index")
        || node.attributes.contains_key("shape_kind")
        || node.attributes.contains_key("assistive_hint")
}

fn node_or_descendant_has_high_priority_signal(node: &AccessibilityNode) -> bool {
    node_has_high_priority_signal(node)
        || node
            .children
            .iter()
            .any(node_or_descendant_has_high_priority_signal)
}

fn node_actionability_priority(node: &AccessibilityNode) -> Option<u8> {
    let role = node.role.to_ascii_lowercase();
    let mut score = 0u8;

    if node.attributes.contains_key("dom_id") {
        score = score.saturating_add(8);
    }
    if node.attributes.contains_key("data_index") || node.attributes.contains_key("shape_kind") {
        score = score.saturating_add(4);
    }
    if role.contains("button")
        || role.contains("link")
        || role.contains("textbox")
        || role.contains("text_box")
        || role.contains("combobox")
        || role.contains("combo_box")
        || role.contains("checkbox")
        || role.contains("check_box")
        || role.contains("radio")
        || role.contains("searchbox")
        || role.contains("search_box")
        || role.contains("menuitem")
        || role.contains("menu_item")
        || role.contains("option")
    {
        score = score.saturating_add(6);
    } else if role.contains("listitem") || role.contains("list_item") {
        score = score.saturating_add(2);
    }
    if node.attributes.contains_key("focused")
        || node.attributes.contains_key("checked")
        || node.attributes.contains_key("selected")
    {
        score = score.saturating_add(4);
    }
    if node.attributes.contains_key("assistive_hint") {
        score = score.saturating_add(2);
    }
    if node.som_id.is_some() {
        score = score.saturating_add(1);
    }

    (score > 0).then_some(score)
}

struct OmittedHighPriorityNode<'a> {
    node: &'a AccessibilityNode,
    context: Option<String>,
}

fn compact_text_for_attr(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn vertical_overlap(a: &Rect, b: &Rect) -> i32 {
    let top = a.y.max(b.y);
    let bottom = (a.y.saturating_add(a.height)).min(b.y.saturating_add(b.height));
    bottom.saturating_sub(top)
}

fn omitted_context_text(node: &AccessibilityNode) -> Option<String> {
    let text = node
        .name
        .as_deref()
        .or(node.value.as_deref())
        .map(compact_text_for_attr)?;
    (!text.is_empty()).then_some(text)
}

fn omitted_row_context(
    node: &AccessibilityNode,
    omitted_nodes: &[&AccessibilityNode],
) -> Option<String> {
    if !node.is_interactive() {
        return None;
    }

    let target_name = node
        .name
        .as_deref()
        .map(compact_text_for_attr)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let target_center_y = node.rect.y.saturating_add(node.rect.height / 2);
    let mut ranked = Vec::new();
    let mut seen = HashSet::new();

    for (order, candidate) in omitted_nodes.iter().enumerate() {
        if candidate.id == node.id || candidate.is_interactive() {
            continue;
        }
        let Some(text) = omitted_context_text(candidate) else {
            continue;
        };
        let lowered = text.to_ascii_lowercase();
        if !target_name.is_empty() && lowered == target_name {
            continue;
        }

        let overlap = vertical_overlap(&node.rect, &candidate.rect);
        let candidate_center_y = candidate.rect.y.saturating_add(candidate.rect.height / 2);
        let center_distance = target_center_y.abs_diff(candidate_center_y);
        let overlap_significant =
            overlap > 0 && overlap.saturating_mul(6) >= candidate.rect.height.max(1);
        let center_aligned = center_distance
            <= node.rect.height.max(candidate.rect.height).max(24) as u32
            && candidate.rect.height <= node.rect.height.max(1).saturating_mul(2);
        let same_row = overlap_significant || center_aligned;
        if !same_row {
            continue;
        }

        if !seen.insert(lowered) {
            continue;
        }

        let mut score = 0u8;
        if overlap > 0 {
            score = score.saturating_add(8);
        }
        if candidate.rect.x >= node.rect.x {
            score = score.saturating_add(4);
        }
        if candidate.rect.width > 0 && candidate.rect.height > 0 {
            score = score.saturating_add(1);
        }

        ranked.push((score, order, candidate.rect.x, text));
    }

    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then(left.2.cmp(&right.2))
            .then(left.1.cmp(&right.1))
    });

    let mut chosen = Vec::new();
    let mut total_chars = 0usize;
    for (_, _, _, text) in ranked {
        let next_len = total_chars + text.chars().count();
        if !chosen.is_empty() && next_len > 96 {
            break;
        }
        total_chars = next_len;
        chosen.push(text);
        if chosen.len() == 3 {
            break;
        }
    }

    (!chosen.is_empty()).then_some(chosen.join(" / "))
}

fn collect_omitted_high_priority_nodes<'a>(
    nodes: &'a [&'a AccessibilityNode],
    max_nodes: usize,
) -> Vec<OmittedHighPriorityNode<'a>> {
    fn collect_recursive<'a>(
        node: &'a AccessibilityNode,
        order: &mut usize,
        collected: &mut Vec<(u8, usize, &'a AccessibilityNode)>,
        seen_ids: &mut HashSet<&'a str>,
        all_nodes: &mut Vec<&'a AccessibilityNode>,
    ) {
        all_nodes.push(node);
        if let Some(score) = node_actionability_priority(node) {
            if seen_ids.insert(node.id.as_str()) {
                collected.push((score, *order, node));
                *order += 1;
            }
        }

        for child in &node.children {
            collect_recursive(child, order, collected, seen_ids, all_nodes);
        }
    }

    let mut collected = Vec::new();
    let mut seen_ids = HashSet::new();
    let mut order = 0usize;
    let mut all_nodes = Vec::new();
    for node in nodes {
        collect_recursive(
            node,
            &mut order,
            &mut collected,
            &mut seen_ids,
            &mut all_nodes,
        );
    }

    collected.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    collected
        .into_iter()
        .take(max_nodes)
        .map(|(_, _, node)| OmittedHighPriorityNode {
            node,
            context: omitted_row_context(node, &all_nodes),
        })
        .collect()
}

fn render_omitted_high_priority_node(node: &OmittedHighPriorityNode<'_>, depth: usize) -> String {
    let indent = "  ".repeat(depth);
    let tag_name = xml_tag_name(&node.node.role);
    let role_attr = if tag_name != node.node.role {
        format!(" role=\"{}\"", escape_xml(&node.node.role))
    } else {
        String::new()
    };
    let name_attr = node
        .node
        .name
        .as_ref()
        .map(|name| format!(" name=\"{}\"", escape_xml(&truncate_attr_value(name, 40))))
        .unwrap_or_default();
    let value_attr = node
        .node
        .value
        .as_ref()
        .map(|value| format!(" value=\"{}\"", escape_xml(&truncate_attr_value(value, 40))))
        .unwrap_or_default();
    let context_attr = node
        .context
        .as_ref()
        .map(|value| {
            format!(
                " context=\"{}\"",
                escape_xml(&truncate_attr_value(value, 96))
            )
        })
        .unwrap_or_default();
    let coords_attr = format!(
        " rect=\"{},{},{},{}\"",
        node.node.rect.x, node.node.rect.y, node.node.rect.width, node.node.rect.height
    );

    let mut state_attrs = String::from(" omitted=\"true\"");
    if node.node.attributes.contains_key("focused") {
        state_attrs.push_str(" focused=\"true\"");
    }
    if node.node.attributes.contains_key("checked") {
        state_attrs.push_str(" checked=\"true\"");
    }
    if node.node.attributes.contains_key("selected") {
        state_attrs.push_str(" selected=\"true\"");
    }
    state_attrs.push_str(&browser_locator_attrs(node.node, 48));

    format!(
        "{}<{} id=\"{}\"{}{}{}{}{}{} />\n",
        indent,
        tag_name,
        node.node.id,
        role_attr,
        name_attr,
        value_attr,
        context_attr,
        state_attrs,
        coords_attr
    )
}

fn selected_child_indices(children: &[AccessibilityNode], max_children: usize) -> Vec<usize> {
    if children.len() <= max_children {
        return (0..children.len()).collect();
    }

    let mut selected = Vec::new();
    let mut selected_set = HashSet::new();

    for (idx, child) in children.iter().enumerate() {
        if node_or_descendant_has_high_priority_signal(child) && selected_set.insert(idx) {
            selected.push(idx);
            if selected.len() == max_children {
                selected.sort_unstable();
                return selected;
            }
        }
    }

    for idx in 0..children.len() {
        if selected_set.insert(idx) {
            selected.push(idx);
            if selected.len() == max_children {
                break;
            }
        }
    }

    selected.sort_unstable();
    selected
}

/// A less aggressive XML serializer used as a fallback when strict semantic
/// pruning yields an empty snapshot.
pub fn serialize_tree_to_xml_relaxed(node: &AccessibilityNode, depth: usize) -> String {
    if depth > 12 {
        return String::new();
    }

    let structural_container = matches!(
        node.role.as_str(),
        "root" | "window" | "application" | "frame" | "pane" | "panel"
    );

    let mut children_xml = String::new();
    let max_children = 40usize;
    let indent_child = "  ".repeat(depth + 1);
    for (i, child) in node.children.iter().enumerate() {
        if i >= max_children {
            children_xml.push_str(&format!(
                "{}<!-- ... {} siblings truncated ... -->\n",
                indent_child,
                node.children.len() - max_children
            ));
            break;
        }
        children_xml.push_str(&serialize_tree_to_xml_relaxed(child, depth + 1));
    }

    let has_signal = node.som_id.is_some()
        || node.is_interactive()
        || node.has_content()
        || structural_container
        || !children_xml.is_empty();
    if !has_signal {
        return String::new();
    }

    let tag_name = xml_tag_name(&node.role);
    let role_attr = if tag_name != node.role {
        format!(" role=\"{}\"", escape_xml(&node.role))
    } else {
        String::new()
    };

    let name_attr = node
        .name
        .as_ref()
        .map(|n| format!(" name=\"{}\"", escape_xml(n)))
        .unwrap_or_default();
    let value_attr = node
        .value
        .as_ref()
        .map(|v| format!(" value=\"{}\"", escape_xml(v)))
        .unwrap_or_default();
    let som_attr = node
        .som_id
        .map(|som_id| format!(" som_id=\"{}\"", som_id))
        .unwrap_or_default();
    let vis_attr = if node.is_visible {
        String::new()
    } else {
        " visible=\"false\"".to_string()
    };
    let coords_attr = format!(
        " rect=\"{},{},{},{}\"",
        node.rect.x, node.rect.y, node.rect.width, node.rect.height
    );
    let browser_attrs = browser_locator_attrs(node, 96);

    let indent_self = "  ".repeat(depth);
    let mut output = format!(
        "{}<{} id=\"{}\"{}{}{}{}{}{}{}",
        indent_self,
        tag_name,
        node.id,
        role_attr,
        som_attr,
        name_attr,
        value_attr,
        vis_attr,
        browser_attrs,
        coords_attr
    );
    if children_xml.is_empty() {
        output.push_str(" />\n");
    } else {
        output.push_str(">\n");
        output.push_str(&children_xml);
        output.push_str(&format!("{}</{}>\n", indent_self, tag_name));
    }
    output
}

/// Debug serializer that keeps structure with minimal pruning.
/// Used as a last resort to avoid empty GUI snapshots in CI diagnostics.
pub fn serialize_tree_to_xml_debug(node: &AccessibilityNode, depth: usize) -> String {
    if depth > 8 {
        return String::new();
    }

    let tag_name = xml_tag_name(&node.role);
    let role_attr = if tag_name != node.role {
        format!(" role=\"{}\"", escape_xml(&node.role))
    } else {
        String::new()
    };
    let name_attr = node
        .name
        .as_ref()
        .map(|n| format!(" name=\"{}\"", escape_xml(n)))
        .unwrap_or_default();
    let value_attr = node
        .value
        .as_ref()
        .map(|v| format!(" value=\"{}\"", escape_xml(v)))
        .unwrap_or_default();
    let vis_attr = if node.is_visible {
        String::new()
    } else {
        " visible=\"false\"".to_string()
    };
    let browser_attrs = browser_locator_attrs(node, 96);
    let coords_attr = format!(
        " rect=\"{},{},{},{}\"",
        node.rect.x, node.rect.y, node.rect.width, node.rect.height
    );

    let indent_self = "  ".repeat(depth);
    let mut children_xml = String::new();
    let max_children = 80usize;
    let indent_child = "  ".repeat(depth + 1);
    for (i, child) in node.children.iter().enumerate() {
        if i >= max_children {
            children_xml.push_str(&format!(
                "{}<!-- ... {} siblings truncated ... -->\n",
                indent_child,
                node.children.len() - max_children
            ));
            break;
        }
        children_xml.push_str(&serialize_tree_to_xml_debug(child, depth + 1));
    }

    let mut output = format!(
        "{}<{} id=\"{}\"{}{}{}{}{}{}",
        indent_self,
        tag_name,
        node.id,
        role_attr,
        name_attr,
        value_attr,
        vis_attr,
        browser_attrs,
        coords_attr
    );
    if children_xml.is_empty() {
        output.push_str(" />\n");
    } else {
        output.push_str(">\n");
        output.push_str(&children_xml);
        output.push_str(&format!("{}</{}>\n", indent_self, tag_name));
    }
    output
}

fn truncate_attr_value(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

fn selector_for_dom_id(dom_id: &str) -> String {
    let escaped = dom_id.replace('\\', "\\\\").replace('"', "\\\"");
    format!(r#"[id="{}"]"#, escaped)
}

fn browser_locator_attrs(node: &AccessibilityNode, max_len: usize) -> String {
    let mut attrs = String::new();

    if let Some(dom_id) = node
        .attributes
        .get("dom_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push_str(&format!(
            " dom_id=\"{}\"",
            escape_xml(&truncate_attr_value(dom_id, max_len))
        ));
        attrs.push_str(&format!(
            " selector=\"{}\"",
            escape_xml(&truncate_attr_value(
                &selector_for_dom_id(dom_id),
                max_len + 12
            ))
        ));
    }

    if let Some(tag_name) = node
        .attributes
        .get("tag_name")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push_str(&format!(
            " tag_name=\"{}\"",
            escape_xml(&truncate_attr_value(tag_name, max_len))
        ));
    }

    if let Some(class_name) = node
        .attributes
        .get("class_name")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push_str(&format!(
            " class_name=\"{}\"",
            escape_xml(&truncate_attr_value(class_name, max_len))
        ));
    }

    if let Some(dom_clickable) = node
        .attributes
        .get("dom_clickable")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push_str(&format!(
            " dom_clickable=\"{}\"",
            escape_xml(&truncate_attr_value(dom_clickable, max_len))
        ));
    }

    if let Some(autocomplete) = node
        .attributes
        .get("autocomplete")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push_str(&format!(
            " autocomplete=\"{}\"",
            escape_xml(&truncate_attr_value(autocomplete, max_len))
        ));
    }

    if let Some(controls_dom_id) = node
        .attributes
        .get("controls_dom_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push_str(&format!(
            " controls_dom_id=\"{}\"",
            escape_xml(&truncate_attr_value(controls_dom_id, max_len))
        ));
    }

    if let Some(active_descendant_dom_id) = node
        .attributes
        .get("active_descendant_dom_id")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        attrs.push_str(&format!(
            " active_descendant_dom_id=\"{}\"",
            escape_xml(&truncate_attr_value(active_descendant_dom_id, max_len))
        ));
    }

    for key in ["shape_kind", "shape_size", "shape_color", "data_index"] {
        if let Some(value) = node
            .attributes
            .get(key)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            attrs.push_str(&format!(
                " {}=\"{}\"",
                key,
                escape_xml(&truncate_attr_value(value, max_len))
            ));
        }
    }

    if node.attributes.contains_key("shape_kind") || node.attributes.contains_key("data_index") {
        attrs.push_str(&format!(
            " center_x=\"{}\" center_y=\"{}\"",
            node.rect.x.saturating_add(node.rect.width / 2),
            node.rect.y.saturating_add(node.rect.height / 2)
        ));
    }

    for key in [
        "scroll_top",
        "scroll_height",
        "client_height",
        "can_scroll_up",
        "can_scroll_down",
    ] {
        if let Some(value) = node
            .attributes
            .get(key)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            attrs.push_str(&format!(
                " {}=\"{}\"",
                key,
                escape_xml(&truncate_attr_value(value, max_len))
            ));
        }
    }

    attrs
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_tag_name(role: &str) -> String {
    let mut out = String::with_capacity(role.len());
    for ch in role.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }

    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "node".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{selected_child_indices, serialize_tree_to_xml, AccessibilityNode, Rect};
    use std::collections::HashMap;

    #[test]
    fn serialize_tree_to_xml_includes_browser_locator_attrs_for_native_selects() {
        let node = AccessibilityNode {
            id: "inp_turkey".to_string(),
            role: "combobox".to_string(),
            name: Some("Turkey".to_string()),
            value: Some("Turkey".to_string()),
            rect: Rect {
                x: 2,
                y: 57,
                width: 150,
                height: 19,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("dom_id".to_string(), "options".to_string()),
                ("tag_name".to_string(), "select".to_string()),
                ("focused".to_string(), "true".to_string()),
            ]),
            som_id: None,
        };

        let xml = serialize_tree_to_xml(&node, 0);
        assert!(xml.contains(r#"dom_id="options""#), "{xml}");
        assert!(xml.contains(r#"tag_name="select""#), "{xml}");
        assert!(
            xml.contains(r#"selector="[id=&quot;options&quot;]""#),
            "{xml}"
        );
        assert!(xml.contains(r#"focused="true""#), "{xml}");
    }

    #[test]
    fn serialize_tree_to_xml_includes_dom_clickable_locator_attr_for_generic_targets() {
        let node = AccessibilityNode {
            id: "grp_trash".to_string(),
            role: "generic".to_string(),
            name: Some("trash".to_string()),
            value: None,
            rect: Rect {
                x: 117,
                y: 119,
                width: 12,
                height: 12,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("tag_name".to_string(), "span".to_string()),
                ("class_name".to_string(), "trash".to_string()),
                ("dom_clickable".to_string(), "true".to_string()),
            ]),
            som_id: None,
        };

        let xml = serialize_tree_to_xml(&node, 0);
        assert!(xml.contains(r#"class_name="trash""#), "{xml}");
        assert!(xml.contains(r#"dom_clickable="true""#), "{xml}");
    }

    #[test]
    fn serialize_tree_to_xml_keeps_hidden_assistive_autocomplete_hints() {
        let tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 160,
                height: 210,
            },
            children: vec![
                AccessibilityNode {
                    id: "inp_poland".to_string(),
                    role: "textbox".to_string(),
                    name: Some("Poland".to_string()),
                    value: Some("Poland".to_string()),
                    rect: Rect {
                        x: 10,
                        y: 71,
                        width: 128,
                        height: 21,
                    },
                    children: vec![],
                    is_visible: true,
                    attributes: HashMap::from([
                        ("dom_id".to_string(), "tags".to_string()),
                        ("tag_name".to_string(), "input".to_string()),
                        ("focused".to_string(), "true".to_string()),
                        ("autocomplete".to_string(), "list".to_string()),
                        ("controls_dom_id".to_string(), "ui-id-1".to_string()),
                        (
                            "active_descendant_dom_id".to_string(),
                            "ui-id-2".to_string(),
                        ),
                    ]),
                    som_id: None,
                },
                AccessibilityNode {
                    id: "assistive-ui-id-2".to_string(),
                    role: "status".to_string(),
                    name: Some(
                        "1 result is available, use up and down arrow keys to navigate. Poland"
                            .to_string(),
                    ),
                    value: None,
                    rect: Rect {
                        x: -1,
                        y: 209,
                        width: 1,
                        height: 16,
                    },
                    children: vec![],
                    is_visible: false,
                    attributes: HashMap::from([
                        ("dom_id".to_string(), "ui-id-2".to_string()),
                        ("tag_name".to_string(), "div".to_string()),
                        ("assistive_hint".to_string(), "true".to_string()),
                        (
                            "assistive_reason".to_string(),
                            "assistive_live_region".to_string(),
                        ),
                    ]),
                    som_id: None,
                },
            ],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let xml = serialize_tree_to_xml(&tree, 0);
        assert!(xml.contains(r#"autocomplete="list""#), "{xml}");
        assert!(xml.contains(r#"controls_dom_id="ui-id-1""#), "{xml}");
        assert!(
            xml.contains(r#"active_descendant_dom_id="ui-id-2""#),
            "{xml}"
        );
        assert!(xml.contains(r#"assistive_hint="true""#), "{xml}");
        assert!(xml.contains(r#"visible="false""#), "{xml}");
        assert!(xml.contains("use up and down arrow keys"), "{xml}");
    }

    #[test]
    fn serialize_tree_to_xml_includes_scrollable_control_attrs() {
        let node = AccessibilityNode {
            id: "inp_scrollbox".to_string(),
            role: "textbox".to_string(),
            name: Some("Scrollable note".to_string()),
            value: Some("Line 1 Line 2 Line 3".to_string()),
            rect: Rect {
                x: 2,
                y: 57,
                width: 156,
                height: 106,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("dom_id".to_string(), "text-area".to_string()),
                ("tag_name".to_string(), "textarea".to_string()),
                ("scroll_top".to_string(), "120".to_string()),
                ("scroll_height".to_string(), "510".to_string()),
                ("client_height".to_string(), "104".to_string()),
                ("can_scroll_up".to_string(), "true".to_string()),
                ("can_scroll_down".to_string(), "true".to_string()),
            ]),
            som_id: None,
        };

        let xml = serialize_tree_to_xml(&node, 0);
        assert!(xml.contains(r#"scroll_top="120""#), "{xml}");
        assert!(xml.contains(r#"scroll_height="510""#), "{xml}");
        assert!(xml.contains(r#"client_height="104""#), "{xml}");
        assert!(xml.contains(r#"can_scroll_up="true""#), "{xml}");
        assert!(xml.contains(r#"can_scroll_down="true""#), "{xml}");
    }

    #[test]
    fn serialize_tree_to_xml_includes_svg_shape_attrs() {
        let node = AccessibilityNode {
            id: "grp_2".to_string(),
            role: "generic".to_string(),
            name: Some("2".to_string()),
            value: None,
            rect: Rect {
                x: 30,
                y: 100,
                width: 20,
                height: 20,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("tag_name".to_string(), "rect".to_string()),
                ("shape_kind".to_string(), "rectangle".to_string()),
                ("shape_size".to_string(), "large".to_string()),
                ("data_index".to_string(), "2".to_string()),
            ]),
            som_id: None,
        };

        let xml = serialize_tree_to_xml(&node, 0);
        assert!(xml.contains(r#"tag_name="rect""#), "{xml}");
        assert!(xml.contains(r#"shape_kind="rectangle""#), "{xml}");
        assert!(xml.contains(r#"shape_size="large""#), "{xml}");
        assert!(xml.contains(r#"data_index="2""#), "{xml}");
        assert!(xml.contains(r#"center_x="40""#), "{xml}");
        assert!(xml.contains(r#"center_y="110""#), "{xml}");
    }

    #[test]
    fn selected_child_indices_preserve_late_interactive_children_under_truncation() {
        let mut children = (0..30)
            .map(|idx| AccessibilityNode {
                id: format!("grp_{idx}"),
                role: "generic".to_string(),
                name: Some(format!("Group {idx}")),
                value: None,
                rect: Rect {
                    x: 0,
                    y: idx,
                    width: 10,
                    height: 10,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
            })
            .collect::<Vec<_>>();
        children[29].id = "lnk_target".to_string();
        children[29].role = "link".to_string();
        children[29].name = Some("T-215".to_string());
        children[29].attributes =
            HashMap::from([("dom_id".to_string(), "ticket-link-t-215".to_string())]);

        let selected = selected_child_indices(&children, 25);
        assert_eq!(selected.len(), 25);
        assert!(selected.contains(&29), "{selected:?}");
        assert!(!selected.contains(&28), "{selected:?}");
    }

    #[test]
    fn selected_child_indices_preserve_late_svg_targets_under_truncation() {
        let mut children = (0..30)
            .map(|idx| AccessibilityNode {
                id: format!("grp_{idx}"),
                role: "generic".to_string(),
                name: Some(format!("Group {idx}")),
                value: None,
                rect: Rect {
                    x: 0,
                    y: idx,
                    width: 10,
                    height: 10,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
            })
            .collect::<Vec<_>>();
        children[29].id = "grp_2".to_string();
        children[29].name = Some("2".to_string());
        children[29].attributes = HashMap::from([
            ("tag_name".to_string(), "rect".to_string()),
            ("shape_kind".to_string(), "rectangle".to_string()),
            ("data_index".to_string(), "2".to_string()),
        ]);

        let selected = selected_child_indices(&children, 25);
        assert_eq!(selected.len(), 25);
        assert!(selected.contains(&29), "{selected:?}");
        assert!(!selected.contains(&28), "{selected:?}");
    }

    #[test]
    fn selected_child_indices_preserve_late_children_with_interactive_descendants() {
        let mut children = (0..30)
            .map(|idx| AccessibilityNode {
                id: format!("grp_{idx}"),
                role: "generic".to_string(),
                name: Some(format!("Group {idx}")),
                value: None,
                rect: Rect {
                    x: 0,
                    y: idx,
                    width: 10,
                    height: 10,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
            })
            .collect::<Vec<_>>();
        children[29].children.push(AccessibilityNode {
            id: "lnk_target".to_string(),
            role: "link".to_string(),
            name: Some("T-215".to_string()),
            value: None,
            rect: Rect {
                x: 1,
                y: 29,
                width: 8,
                height: 8,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([("dom_id".to_string(), "ticket-link-t-215".to_string())]),
            som_id: None,
        });

        let selected = selected_child_indices(&children, 25);
        assert_eq!(selected.len(), 25);
        assert!(selected.contains(&29), "{selected:?}");
        assert!(!selected.contains(&28), "{selected:?}");
    }

    #[test]
    fn serialize_tree_to_xml_surfaces_omitted_high_priority_targets() {
        let children = (0..26)
            .map(|idx| AccessibilityNode {
                id: format!("grp_{idx}"),
                role: "generic".to_string(),
                name: Some(format!("Row {idx}")),
                value: None,
                rect: Rect {
                    x: 0,
                    y: idx,
                    width: 10,
                    height: 10,
                },
                children: vec![AccessibilityNode {
                    id: format!("lnk_{idx}"),
                    role: "link".to_string(),
                    name: Some(format!("T-{idx}")),
                    value: None,
                    rect: Rect {
                        x: 1,
                        y: idx,
                        width: 8,
                        height: 8,
                    },
                    children: vec![],
                    is_visible: true,
                    attributes: HashMap::from([(
                        "dom_id".to_string(),
                        format!("ticket-link-t-{idx}"),
                    )]),
                    som_id: None,
                }],
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
            })
            .collect::<Vec<_>>();
        let root = AccessibilityNode {
            id: "root_dom_fallback_tree".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
            },
            children,
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let xml = serialize_tree_to_xml(&root, 0);
        assert!(xml.contains(r#"id="lnk_25""#), "{xml}");
        assert!(xml.contains(r#"omitted="true""#), "{xml}");
        assert!(xml.contains(r#"dom_id="ticket-link-t-25""#), "{xml}");
    }

    #[test]
    fn serialize_tree_to_xml_prefers_locator_bearing_omitted_targets_over_structural_noise() {
        let mut children = (0..25)
            .map(|idx| AccessibilityNode {
                id: format!("grp_{idx}"),
                role: "generic".to_string(),
                name: Some(format!("Group {idx}")),
                value: None,
                rect: Rect {
                    x: 0,
                    y: idx,
                    width: 10,
                    height: 10,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::new(),
                som_id: None,
            })
            .collect::<Vec<_>>();
        let tickets = ["T-202", "T-204", "T-215"];
        for idx in 0..6 {
            children.push(AccessibilityNode {
                id: format!("row_noise_{idx}"),
                role: "listitem".to_string(),
                name: Some(format!("Noise row {idx}")),
                value: None,
                rect: Rect {
                    x: 0,
                    y: 25 + idx,
                    width: 10,
                    height: 10,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([("tag_name".to_string(), "td".to_string())]),
                som_id: None,
            });
            if idx < 3 {
                let ticket = tickets[idx as usize].to_string();
                let suffix = ticket.to_ascii_lowercase();
                children.push(AccessibilityNode {
                    id: format!("lnk_{suffix}"),
                    role: "link".to_string(),
                    name: Some(ticket.clone()),
                    value: None,
                    rect: Rect {
                        x: 1,
                        y: 40 + idx,
                        width: 8,
                        height: 8,
                    },
                    children: vec![],
                    is_visible: true,
                    attributes: HashMap::from([(
                        "dom_id".to_string(),
                        format!("ticket-link-{}", suffix),
                    )]),
                    som_id: None,
                });
            }
        }
        let root = AccessibilityNode {
            id: "root_dom_fallback_tree".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
            },
            children,
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let xml = serialize_tree_to_xml(&root, 0);
        assert!(xml.contains(r#"ticket-link-t-202"#), "{xml}");
        assert!(xml.contains(r#"ticket-link-t-204"#), "{xml}");
        assert!(xml.contains(r#"ticket-link-t-215"#), "{xml}");
    }

    #[test]
    fn serialize_tree_to_xml_adds_same_row_context_to_omitted_actionable_targets() {
        let mut children = (0..25)
            .map(|idx| AccessibilityNode {
                id: format!("btn_{idx}"),
                role: "button".to_string(),
                name: Some(format!("Action {idx}")),
                value: None,
                rect: Rect {
                    x: 0,
                    y: idx * 12,
                    width: 10,
                    height: 10,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([("dom_id".to_string(), format!("action-{idx}"))]),
                som_id: None,
            })
            .collect::<Vec<_>>();
        children.push(AccessibilityNode {
            id: "lnk_t_204".to_string(),
            role: "link".to_string(),
            name: Some("T-204".to_string()),
            value: None,
            rect: Rect {
                x: 20,
                y: 420,
                width: 40,
                height: 18,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([("dom_id".to_string(), "ticket-link-t-204".to_string())]),
            som_id: None,
        });
        children.push(AccessibilityNode {
            id: "cell_assignee".to_string(),
            role: "generic".to_string(),
            name: Some("Unassigned".to_string()),
            value: None,
            rect: Rect {
                x: 180,
                y: 418,
                width: 90,
                height: 22,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([("tag_name".to_string(), "td".to_string())]),
            som_id: None,
        });
        children.push(AccessibilityNode {
            id: "cell_status".to_string(),
            role: "generic".to_string(),
            name: Some("Awaiting Dispatch".to_string()),
            value: None,
            rect: Rect {
                x: 300,
                y: 418,
                width: 120,
                height: 22,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([("tag_name".to_string(), "td".to_string())]),
            som_id: None,
        });
        let root = AccessibilityNode {
            id: "root_dom_fallback_tree".to_string(),
            role: "root".to_string(),
            name: Some("DOM fallback tree".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
            },
            children,
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let xml = serialize_tree_to_xml(&root, 0);
        assert!(xml.contains(r#"id="lnk_t_204""#), "{xml}");
        assert!(xml.contains(r#"omitted="true""#), "{xml}");
        assert!(
            xml.contains(r#"context="Unassigned / Awaiting Dispatch""#),
            "{xml}"
        );
    }
}

/// The interface for the Sovereign Context Substrate (SCS).
/// Unlike a passive file system, the SCS actively filters data based on agentic intent.
#[async_trait]
pub trait SovereignSubstrateProvider: Send + Sync {
    /// Retrieves a context slice authorized and filtered by the provided intent.
    async fn get_intent_constrained_slice(
        &self,
        intent: &ActionRequest,
        monitor_handle: u32,
    ) -> Result<ContextSlice>;
}

// --- Mock Implementation for Development/Testing ---
pub struct MockSubstrateProvider;

#[async_trait]
impl SovereignSubstrateProvider for MockSubstrateProvider {
    async fn get_intent_constrained_slice(
        &self,
        intent: &ActionRequest,
        _monitor_handle: u32,
    ) -> Result<ContextSlice> {
        // 1. Capture Raw Context (Simulated)
        let raw_tree = AccessibilityNode {
            id: "win-1".to_string(),
            role: "window".to_string(),
            name: Some("IOI Autopilot".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            is_visible: true,
            attributes: HashMap::new(), // [NEW] Init
            children: vec![
                AccessibilityNode {
                    id: "btn-1".to_string(),
                    role: "button".to_string(),
                    name: Some("Connect Wallet".to_string()),
                    value: None,
                    rect: Rect {
                        x: 100,
                        y: 100,
                        width: 200,
                        height: 50,
                    },
                    is_visible: true,
                    attributes: HashMap::from([(
                        "data-testid".to_string(),
                        "connect-wallet-btn".to_string(),
                    )]), // [NEW] Init with mock attr
                    som_id: None,
                    children: vec![],
                },
                // This node should be filtered out by logic if it has no content and isn't interactive
                AccessibilityNode {
                    id: "div-empty".to_string(),
                    role: "group".to_string(),
                    name: None,
                    value: None,
                    rect: Rect {
                        x: 0,
                        y: 0,
                        width: 10,
                        height: 10,
                    },
                    is_visible: true,
                    attributes: HashMap::new(), // [NEW] Init
                    som_id: None,
                    children: vec![],
                },
                AccessibilityNode {
                    id: "ad-1".to_string(),
                    role: "frame".to_string(),
                    name: Some("Irrelevant Ads".to_string()),
                    value: None,
                    rect: Rect {
                        x: 1500,
                        y: 0,
                        width: 300,
                        height: 600,
                    },
                    is_visible: true,
                    attributes: HashMap::new(), // [NEW] Init
                    som_id: None,
                    children: vec![],
                },
            ],
            som_id: None,
        };

        // 2. Apply Intent-Constraint (The Filter)
        let xml_data = serialize_tree_to_xml(&raw_tree, 0).into_bytes();

        // 3. Generate Provenance Proof
        let intent_hash = intent.hash();
        let mut proof_input = xml_data.clone();
        proof_input.extend_from_slice(&intent_hash);

        let proof =
            sha256(&proof_input).map_err(|e| anyhow!("Provenance generation failed: {}", e))?;
        let mut proof_arr = [0u8; 32];
        let len = proof.as_ref().len().min(32);
        // Copy bytes manually
        proof_arr[..len].copy_from_slice(&proof.as_ref()[..len]);

        let slice_id = sha256(&xml_data).map_err(|e| anyhow!("Slice ID gen failed: {}", e))?;
        let mut slice_id_arr = [0u8; 32];
        let len = slice_id.as_ref().len().min(32);
        slice_id_arr[..len].copy_from_slice(&slice_id.as_ref()[..len]);

        Ok(ContextSlice {
            slice_id: slice_id_arr,
            frame_id: 0,
            chunks: vec![xml_data],
            mhnsw_root: [0u8; 32],
            traversal_proof: Some(proof.to_vec()),
            intent_id: intent_hash,
        })
    }
}
