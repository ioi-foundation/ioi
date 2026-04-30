use super::super::*;
use super::browser_use::{
    annotate_tree_with_browser_use_identities, annotate_tree_with_browser_use_metadata,
    build_snapshot_lookup, extract_dom_node_metadata, BrowserUseDomNodeMetadata,
    BrowserUseSnapshotNode,
};
use super::browser_use_dom::{
    build_ax_lookup_by_target_backend, collect_som_ids_by_target_backend,
    render_browser_use_observation_from_dom,
};
use super::browsergym::{
    annotate_tree_with_browsergym_metadata, cleanup_ax_tree_browsergym_ids,
    extract_browsergym_extra_properties, extract_browsergym_snapshot_metadata,
    render_browsergym_extra_properties_text,
};
use super::browsergym_flatten::{
    flatten_ax_tree_to_string, flatten_dom_snapshot_to_string, BrowserGymAxFlattenOptions,
    BrowserGymDomFlattenOptions,
};
use super::targets::{MultiTargetObservationContext, TemporaryBrowserConnection};
use crate::browser::BrowserObservationArtifacts;
use std::collections::{HashMap, HashSet};

const ACCESSIBILITY_TREE_TIMEOUT: Duration = Duration::from_millis(1_500);
const PROMPT_OBSERVATION_CACHE_MAX_AGE: Duration = Duration::from_millis(12_000);

#[derive(Debug, serde::Deserialize)]
struct DomFallbackRect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Debug, serde::Deserialize)]
struct DomFallbackNode {
    id: String,
    role: String,
    name: Option<String>,
    value: Option<String>,
    rect: DomFallbackRect,
    #[serde(default)]
    is_visible: Option<bool>,
    #[serde(default)]
    attributes: HashMap<String, String>,
    #[serde(default)]
    children: Vec<DomFallbackNode>,
}

fn clamp_coord(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32
}

fn clamp_extent(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(0.0, i32::MAX as f64) as i32
}

fn allow_dom_fallback_for_ax_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("uninteresting")
        || lower.contains("empty accessibility tree")
        || lower.contains("empty tree")
        || lower.contains("notrendered")
        || lower.contains("not rendered")
        || lower.contains("labelfor")
}

fn ax_value_to_string(value: &Option<accessibility::AxValue>) -> Option<String> {
    value.as_ref().and_then(|entry| {
        entry.value.as_ref().and_then(|inner| {
            if let Some(text) = inner.as_str() {
                (!text.is_empty()).then(|| text.to_string())
            } else if let Some(flag) = inner.as_bool() {
                Some(flag.to_string())
            } else if let Some(number) = inner.as_f64() {
                Some(number.to_string())
            } else {
                None
            }
        })
    })
}

fn collect_frame_ids(
    frame_tree: &chromiumoxide::cdp::browser_protocol::page::FrameTree,
    out: &mut Vec<chromiumoxide::cdp::browser_protocol::page::FrameId>,
) {
    out.push(frame_tree.frame.id.clone());
    if let Some(children) = frame_tree.child_frames.as_ref() {
        for child in children {
            collect_frame_ids(child, out);
        }
    }
}

#[derive(Debug, Default)]
struct MultiTargetBrowserGymCapture {
    nodes: Vec<accessibility::AxNode>,
    node_target_ids: HashMap<String, String>,
    node_frame_ids: HashMap<String, String>,
    extra_properties: HashMap<String, super::browsergym::BrowserGymElementProperties>,
    snapshot_metadata_by_target: HashMap<String, super::browsergym::BrowserGymSnapshotMetadata>,
    dom_metadata_by_target: HashMap<String, HashMap<i64, BrowserUseDomNodeMetadata>>,
    dom_roots_by_target: HashMap<String, chromiumoxide::cdp::browser_protocol::dom::Node>,
    snapshot_lookup_by_target: HashMap<String, HashMap<i64, BrowserUseSnapshotNode>>,
    js_listener_backend_ids_by_target: HashMap<String, HashSet<i64>>,
    dom_text_by_target: HashMap<String, String>,
    focused_bid: Option<String>,
}

fn node_attr_value<'a>(node: &'a AccessibilityNode, key: &str) -> Option<&'a str> {
    node.attributes
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.trim().is_empty())
}

fn rect_contains(outer: &AccessibilityRect, inner: &AccessibilityRect) -> bool {
    if outer.width <= 0 || outer.height <= 0 || inner.width <= 0 || inner.height <= 0 {
        return false;
    }

    let tolerance = 1;
    let outer_right = outer.x.saturating_add(outer.width);
    let outer_bottom = outer.y.saturating_add(outer.height);
    let inner_right = inner.x.saturating_add(inner.width);
    let inner_bottom = inner.y.saturating_add(inner.height);

    inner.x >= outer.x.saturating_sub(tolerance)
        && inner.y >= outer.y.saturating_sub(tolerance)
        && inner_right <= outer_right.saturating_add(tolerance)
        && inner_bottom <= outer_bottom.saturating_add(tolerance)
}

fn default_browsergym_dom_flatten_options() -> BrowserGymDomFlattenOptions {
    BrowserGymDomFlattenOptions {
        with_visible: true,
        with_clickable: true,
        with_center_coords: true,
        with_bounding_box_coords: true,
        with_som: true,
        filter_visible_only: true,
        hide_bid_if_invisible: true,
        ..Default::default()
    }
}

fn default_browsergym_ax_flatten_options() -> BrowserGymAxFlattenOptions {
    BrowserGymAxFlattenOptions {
        with_visible: true,
        with_clickable: true,
        with_center_coords: true,
        with_bounding_box_coords: true,
        with_som: true,
        filter_visible_only: true,
        hide_bid_if_invisible: true,
        ..Default::default()
    }
}

fn join_browsergym_dom_sections(dom_text_by_target: &HashMap<String, String>) -> Option<String> {
    if dom_text_by_target.is_empty() {
        return None;
    }

    let mut target_ids = dom_text_by_target.keys().cloned().collect::<Vec<_>>();
    target_ids.sort();

    let mut sections = Vec::new();
    for target_id in target_ids {
        let Some(text) = dom_text_by_target.get(&target_id) else {
            continue;
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }

        if dom_text_by_target.len() == 1 {
            sections.push(trimmed.to_string());
        } else {
            sections.push(format!("[target:{target_id}]\n{trimmed}"));
        }
    }

    (!sections.is_empty()).then(|| sections.join("\n\n"))
}

fn normalized_text_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn node_text_tokens(node: &AccessibilityNode) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for text in [node.name.as_deref(), node.value.as_deref()]
        .into_iter()
        .flatten()
    {
        for token in normalized_text_tokens(text) {
            tokens.insert(token);
        }
    }
    tokens
}

fn normalize_exact_prompt_text(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn node_contains_visible_start_gate(node: &AccessibilityNode) -> bool {
    let semantic_role = node.role.trim().to_ascii_lowercase();
    let role_allows_gate = matches!(
        semantic_role.as_str(),
        "button"
            | "link"
            | "menuitem"
            | "statictext"
            | "text"
            | "label"
            | "labeltext"
            | "generic"
            | "group"
            | "presentation"
    );
    let dom_id_is_cover = node_attr_value(node, "dom_id")
        .is_some_and(|dom_id| dom_id.eq_ignore_ascii_case("sync-task-cover"));
    let label_matches = [node.name.as_deref(), node.value.as_deref()]
        .into_iter()
        .flatten()
        .map(normalize_exact_prompt_text)
        .any(|text| matches!(text.as_str(), "start" | "begin" | "continue"));

    if node.is_visible && (dom_id_is_cover || (role_allows_gate && label_matches)) {
        return true;
    }

    node.children.iter().any(node_contains_visible_start_gate)
}

fn node_contains_grounded_prompt_target(node: &AccessibilityNode) -> bool {
    let dom_id_is_cover = node_attr_value(node, "dom_id")
        .is_some_and(|dom_id| dom_id.eq_ignore_ascii_case("sync-task-cover"));
    let has_locator =
        node_attr_value(node, "selector").is_some() || node_attr_value(node, "dom_id").is_some();
    let has_shape_target = node_attr_value(node, "shape_kind").is_some() && has_locator;
    let has_interactive_target = node.is_interactive() && has_locator;

    if node.is_visible && !dom_id_is_cover && (has_shape_target || has_interactive_target) {
        return true;
    }

    node.children
        .iter()
        .any(node_contains_grounded_prompt_target)
}

fn should_cache_prompt_observation_warmup(tree: &AccessibilityNode) -> bool {
    if node_attr_value(tree, "snapshot_fallback_cause") != Some("navigate_warmup") {
        return true;
    }

    if node_contains_visible_start_gate(tree) {
        return false;
    }

    node_contains_grounded_prompt_target(tree)
}

fn is_semantic_dom_hint_token(token: &str) -> bool {
    if token.len() <= 1 || token.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }

    !matches!(
        token,
        "ui" | "btn"
            | "button"
            | "icon"
            | "img"
            | "image"
            | "item"
            | "row"
            | "col"
            | "container"
            | "content"
            | "wrapper"
            | "wrap"
            | "name"
            | "username"
            | "details"
            | "detail"
            | "body"
            | "media"
            | "controls"
            | "control"
            | "toolbar"
            | "actions"
            | "action"
            | "spacer"
            | "time"
            | "left"
            | "right"
            | "top"
            | "bottom"
            | "current"
            | "selected"
            | "clicked"
            | "active"
            | "inactive"
            | "disabled"
            | "enabled"
            | "hover"
    )
}

fn dom_fallback_semantic_name(attributes: &HashMap<String, String>) -> Option<String> {
    let mut seen = HashSet::new();
    let mut tokens = Vec::new();

    for key in ["dom_id", "class_name"] {
        let Some(raw) = attributes.get(key) else {
            continue;
        };
        for token in normalized_text_tokens(raw) {
            if !is_semantic_dom_hint_token(&token) || !seen.insert(token.clone()) {
                continue;
            }
            tokens.push(token);
            if tokens.len() >= 3 {
                return Some(tokens.join(" "));
            }
        }
    }

    (!tokens.is_empty()).then(|| tokens.join(" "))
}

fn is_dom_fallback_aggregate_candidate(node: &AccessibilityNode) -> bool {
    if node_attr_value(node, "dom_fallback") != Some("true") || node.is_interactive() {
        return false;
    }

    let role = node.role.trim().to_ascii_lowercase();
    if !matches!(role.as_str(), "generic" | "group" | "presentation") {
        return false;
    }

    let tag_name = node_attr_value(node, "tag_name")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        tag_name.as_str(),
        "div" | "section" | "main" | "article" | "form" | "fieldset" | "td"
    ) {
        return false;
    }

    ![
        "focused",
        "checked",
        "selected",
        "scroll_top",
        "scroll_height",
        "client_height",
        "can_scroll_up",
        "can_scroll_down",
        "autocomplete",
    ]
    .iter()
    .any(|key| node_attr_value(node, key).is_some())
}

fn is_redundant_dom_fallback_aggregate(
    candidate: &AccessibilityNode,
    siblings: &[AccessibilityNode],
) -> bool {
    if !is_dom_fallback_aggregate_candidate(candidate) {
        return false;
    }

    let candidate_tokens = node_text_tokens(candidate);
    if candidate_tokens.is_empty() {
        return false;
    }

    let mut descendant_tokens = HashSet::new();
    let mut interactive_descendants = 0usize;
    let mut contained_descendants = 0usize;

    for sibling in siblings {
        if sibling.id == candidate.id || !sibling.is_visible {
            continue;
        }
        if !rect_contains(&candidate.rect, &sibling.rect) {
            continue;
        }

        contained_descendants += 1;
        descendant_tokens.extend(node_text_tokens(sibling));
        if sibling.is_interactive() {
            interactive_descendants += 1;
        }
    }

    contained_descendants > 0
        && interactive_descendants > 0
        && candidate_tokens
            .iter()
            .all(|token| descendant_tokens.contains(token))
}

fn prune_redundant_dom_fallback_aggregates(mut root: AccessibilityNode) -> AccessibilityNode {
    if node_attr_value(&root, "snapshot_fallback") != Some("dom") {
        return root;
    }

    let snapshot = root.children.clone();
    let before = root.children.len();
    root.children
        .retain(|node| !is_redundant_dom_fallback_aggregate(node, &snapshot));
    let pruned = before.saturating_sub(root.children.len());
    if pruned > 0 {
        root.attributes.insert(
            "dom_fallback_pruned_aggregate_count".to_string(),
            pruned.to_string(),
        );
    }

    root
}

#[allow(dead_code)]
fn rects_are_equivalent_or_nested(left: &AccessibilityRect, right: &AccessibilityRect) -> bool {
    if rect_contains(left, right) || rect_contains(right, left) {
        return true;
    }

    let left_center_x = left.x.saturating_add(left.width / 2);
    let left_center_y = left.y.saturating_add(left.height / 2);
    let right_center_x = right.x.saturating_add(right.width / 2);
    let right_center_y = right.y.saturating_add(right.height / 2);

    (left_center_x - right_center_x).abs() <= 12
        && (left_center_y - right_center_y).abs() <= 12
        && (left.width - right.width).abs() <= 24
        && (left.height - right.height).abs() <= 24
}

#[allow(dead_code)]
fn node_locator_hint(node: &AccessibilityNode, key: &str) -> Option<String> {
    node_attr_value(node, key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[allow(dead_code)]
fn dom_fallback_locator_matches(
    candidate: &AccessibilityNode,
    existing: &AccessibilityNode,
) -> bool {
    for key in ["dom_id", "selector"] {
        let Some(candidate_hint) = node_locator_hint(candidate, key) else {
            continue;
        };
        let Some(existing_hint) = node_locator_hint(existing, key) else {
            continue;
        };
        if candidate_hint == existing_hint {
            return true;
        }
    }

    false
}

#[allow(dead_code)]
fn nodes_semantically_overlap(candidate: &AccessibilityNode, existing: &AccessibilityNode) -> bool {
    if !existing.is_visible {
        return false;
    }

    if dom_fallback_locator_matches(candidate, existing) {
        return true;
    }

    let candidate_tokens = node_text_tokens(candidate);
    if candidate_tokens.is_empty() {
        return false;
    }
    let existing_tokens = node_text_tokens(existing);
    if existing_tokens.is_empty() || candidate_tokens != existing_tokens {
        return false;
    }

    let candidate_role = candidate.role.trim().to_ascii_lowercase();
    let existing_role = existing.role.trim().to_ascii_lowercase();
    if candidate_role != existing_role && !(candidate.is_interactive() && existing.is_interactive())
    {
        return false;
    }

    rects_are_equivalent_or_nested(&candidate.rect, &existing.rect)
}

#[allow(dead_code)]
fn should_merge_dom_fallback_candidate(node: &AccessibilityNode) -> bool {
    if node_attr_value(node, "dom_fallback") != Some("true") || !node.is_visible {
        return false;
    }

    if is_dom_fallback_aggregate_candidate(node) {
        return false;
    }

    node.is_interactive()
        || [
            "focused",
            "checked",
            "selected",
            "scroll_top",
            "scroll_height",
            "client_height",
            "can_scroll_up",
            "can_scroll_down",
            "autocomplete",
        ]
        .iter()
        .any(|key| node_attr_value(node, key).is_some())
}

#[allow(dead_code)]
fn collect_visible_nodes(node: &AccessibilityNode, out: &mut Vec<AccessibilityNode>) {
    if node.is_visible {
        out.push(node.clone());
    }
    for child in &node.children {
        collect_visible_nodes(child, out);
    }
}

#[allow(dead_code)]
fn merge_missing_dom_fallback_nodes(
    mut ax_tree: AccessibilityNode,
    dom_tree: AccessibilityNode,
) -> AccessibilityNode {
    if node_attr_value(&dom_tree, "snapshot_fallback") != Some("dom") {
        return ax_tree;
    }

    let mut existing_nodes = Vec::new();
    collect_visible_nodes(&ax_tree, &mut existing_nodes);

    let mut merged = 0usize;
    for candidate in dom_tree.children {
        if !should_merge_dom_fallback_candidate(&candidate) {
            continue;
        }
        if existing_nodes
            .iter()
            .any(|existing| nodes_semantically_overlap(&candidate, existing))
        {
            continue;
        }

        existing_nodes.push(candidate.clone());
        ax_tree.children.push(candidate);
        merged += 1;
    }

    if merged > 0 {
        ax_tree
            .attributes
            .insert("dom_fallback_overlay_count".to_string(), merged.to_string());
    }

    ax_tree
}

impl DomFallbackNode {
    fn into_accessibility(self) -> AccessibilityNode {
        let synthesized_name = dom_fallback_semantic_name(&self.attributes);
        AccessibilityNode {
            id: if self.id.trim().is_empty() {
                "dom-node".to_string()
            } else {
                self.id
            },
            role: if self.role.trim().is_empty() {
                "generic".to_string()
            } else {
                self.role.to_ascii_lowercase()
            },
            name: self
                .name
                .and_then(|v| {
                    let trimmed = v.trim().to_string();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed)
                    }
                })
                .or(synthesized_name),
            value: self.value.and_then(|v| {
                let trimmed = v.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }),
            rect: AccessibilityRect {
                x: clamp_coord(self.rect.x),
                y: clamp_coord(self.rect.y),
                width: clamp_extent(self.rect.width),
                height: clamp_extent(self.rect.height),
            },
            children: self
                .children
                .into_iter()
                .map(DomFallbackNode::into_accessibility)
                .collect(),
            is_visible: self.is_visible.unwrap_or(true),
            attributes: self.attributes,
            som_id: None,
        }
    }
}

include!("accessibility/capture.rs");

#[cfg(test)]
#[path = "accessibility/tests.rs"]
mod tests;
