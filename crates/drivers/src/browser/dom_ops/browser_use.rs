use super::super::*;
use super::browser_use_dom::BrowserUseElementIdentity;
use crate::gui::accessibility::AccessibilityNode;
use chromiumoxide::cdp::browser_protocol::dom_snapshot::{CaptureSnapshotReturns, StringIndex};
use chromiumoxide::cdp::{
    browser_protocol::dom::DescribeNodeParams,
    js_protocol::runtime::{EvaluateParams, GetPropertiesParams, ReleaseObjectParams},
};
use std::collections::{HashMap, HashSet};

pub(crate) const REQUIRED_COMPUTED_STYLES: &[&str] = &[
    "display",
    "visibility",
    "opacity",
    "overflow",
    "overflow-x",
    "overflow-y",
    "cursor",
    "pointer-events",
    "position",
    "background-color",
];

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BrowserUseDomRect {
    pub(crate) x: f64,
    pub(crate) y: f64,
    pub(crate) width: f64,
    pub(crate) height: f64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct BrowserUseSnapshotNode {
    pub(crate) is_clickable: bool,
    pub(crate) cursor_style: Option<String>,
    pub(crate) bounds: Option<BrowserUseDomRect>,
    pub(crate) client_rects: Option<BrowserUseDomRect>,
    pub(crate) scroll_rects: Option<BrowserUseDomRect>,
    pub(crate) computed_styles: HashMap<String, String>,
    pub(crate) paint_order: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct BrowserUseDomNodeMetadata {
    pub(crate) tag_name: Option<String>,
    pub(crate) attributes: HashMap<String, String>,
}

pub(crate) fn required_snapshot_computed_styles() -> Vec<String> {
    REQUIRED_COMPUTED_STYLES
        .iter()
        .map(|style| (*style).to_string())
        .collect()
}

fn string_at<'a>(strings: &'a [String], index: &StringIndex) -> Option<&'a str> {
    let idx = usize::try_from(*index.inner()).ok()?;
    strings.get(idx).map(String::as_str)
}

fn rectangle_to_dom_rect(rect: &[f64]) -> Option<BrowserUseDomRect> {
    (rect.len() >= 4).then(|| BrowserUseDomRect {
        x: rect[0],
        y: rect[1],
        width: rect[2],
        height: rect[3],
    })
}

fn parse_computed_styles(
    strings: &[String],
    style_indices: &[StringIndex],
) -> HashMap<String, String> {
    let mut styles = HashMap::new();
    for (idx, style_index) in style_indices.iter().enumerate() {
        let Some(name) = REQUIRED_COMPUTED_STYLES.get(idx) else {
            continue;
        };
        let Some(value) = string_at(strings, style_index) else {
            continue;
        };
        if !value.is_empty() {
            styles.insert((*name).to_string(), value.to_string());
        }
    }
    styles
}

pub(crate) fn build_snapshot_lookup(
    snapshot: &CaptureSnapshotReturns,
) -> HashMap<i64, BrowserUseSnapshotNode> {
    let mut lookup = HashMap::new();

    for document in &snapshot.documents {
        let backend_node_ids = match document.nodes.backend_node_id.as_ref() {
            Some(ids) => ids,
            None => continue,
        };

        let mut layout_index_by_snapshot_index = HashMap::new();
        for (layout_idx, node_index) in document.layout.node_index.iter().enumerate() {
            layout_index_by_snapshot_index
                .entry(*node_index)
                .or_insert(layout_idx);
        }

        for (snapshot_index, backend_node_id) in backend_node_ids.iter().enumerate() {
            let backend_key = *backend_node_id.inner();
            let mut entry = BrowserUseSnapshotNode::default();

            if let Some(clickable_nodes) = document.nodes.is_clickable.as_ref() {
                entry.is_clickable = clickable_nodes
                    .index
                    .iter()
                    .any(|idx| usize::try_from(*idx).ok() == Some(snapshot_index));
            }

            let Some(layout_idx) = layout_index_by_snapshot_index
                .get(&(snapshot_index as i64))
                .copied()
            else {
                lookup.insert(backend_key, entry);
                continue;
            };

            if let Some(bounds) = document.layout.bounds.get(layout_idx) {
                entry.bounds = rectangle_to_dom_rect(bounds.inner());
            }
            if let Some(client_rects) = document.layout.client_rects.as_ref() {
                if let Some(rect) = client_rects.get(layout_idx) {
                    entry.client_rects = rectangle_to_dom_rect(rect.inner());
                }
            }
            if let Some(scroll_rects) = document.layout.scroll_rects.as_ref() {
                if let Some(rect) = scroll_rects.get(layout_idx) {
                    entry.scroll_rects = rectangle_to_dom_rect(rect.inner());
                }
            }
            if let Some(style_indices) = document.layout.styles.get(layout_idx) {
                entry.computed_styles =
                    parse_computed_styles(&snapshot.strings, style_indices.inner());
                entry.cursor_style = entry.computed_styles.get("cursor").cloned();
            }
            if let Some(paint_order) = document
                .layout
                .paint_orders
                .as_ref()
                .and_then(|paint_orders| paint_orders.get(layout_idx))
            {
                entry.paint_order = Some(*paint_order);
            }

            lookup.insert(backend_key, entry);
        }
    }

    lookup
}

const JS_CLICK_LISTENER_DETECTION_SCRIPT: &str = r#"
(() => {
    if (typeof getEventListeners !== 'function') {
        return null;
    }

    const elementsWithListeners = [];
    const allElements = document.querySelectorAll('*');

    for (const el of allElements) {
        try {
            const listeners = getEventListeners(el);
            if (
                listeners.click ||
                listeners.mousedown ||
                listeners.mouseup ||
                listeners.pointerdown ||
                listeners.pointerup
            ) {
                elementsWithListeners.push(el);
            }
        } catch (_) {
        }
    }

    return elementsWithListeners;
})()
"#;

impl BrowserDriver {
    pub(crate) async fn detect_browser_use_js_click_listener_backend_ids(
        &self,
        page: &Page,
    ) -> std::result::Result<HashSet<i64>, BrowserError> {
        let params = EvaluateParams::builder()
            .expression(JS_CLICK_LISTENER_DETECTION_SCRIPT)
            .include_command_line_api(true)
            .return_by_value(false)
            .build()
            .map_err(|error| {
                BrowserError::Internal(format!(
                    "Browser-use JS listener detection params failed: {}",
                    error
                ))
            })?;
        let evaluation = self
            .await_request_with_timeout(
                "Browser-use JS click listener detection",
                page.execute(params),
            )
            .await?;

        let Some(array_object_id) = evaluation.result.result.object_id.clone() else {
            return Ok(HashSet::new());
        };

        let property_params = GetPropertiesParams::builder()
            .object_id(array_object_id.clone())
            .own_properties(true)
            .build()
            .map_err(|error| {
                BrowserError::Internal(format!(
                    "Browser-use JS listener property params failed: {}",
                    error
                ))
            })?;
        let property_result = self
            .await_request_with_timeout(
                "Browser-use JS click listener properties",
                page.execute(property_params),
            )
            .await?;

        let mut backend_node_ids = HashSet::new();
        for property in property_result.result.result {
            if !property.name.chars().all(|ch| ch.is_ascii_digit()) {
                continue;
            }

            let Some(object_id) = property.value.and_then(|value| value.object_id) else {
                continue;
            };

            let describe = self
                .await_request_with_timeout(
                    "Browser-use JS click listener describeNode",
                    page.execute(DescribeNodeParams::builder().object_id(object_id).build()),
                )
                .await;
            if let Ok(description) = describe {
                backend_node_ids.insert(*description.result.node.backend_node_id.inner());
            }
        }

        let _ = self
            .await_request_with_timeout(
                "Browser-use JS click listener cleanup",
                page.execute(ReleaseObjectParams::new(array_object_id)),
            )
            .await;

        Ok(backend_node_ids)
    }
}

pub(crate) fn extract_dom_node_metadata(
    snapshot: &CaptureSnapshotReturns,
) -> HashMap<i64, BrowserUseDomNodeMetadata> {
    let mut metadata = HashMap::new();

    for document in &snapshot.documents {
        let Some(backend_node_ids) = document.nodes.backend_node_id.as_ref() else {
            continue;
        };
        let node_names = document.nodes.node_name.as_ref();
        let attrs = document.nodes.attributes.as_ref();

        for (node_idx, backend_node_id) in backend_node_ids.iter().enumerate() {
            let mut entry = BrowserUseDomNodeMetadata::default();

            if let Some(node_names) = node_names {
                if let Some(name_idx) = node_names.get(node_idx) {
                    entry.tag_name = string_at(&snapshot.strings, name_idx)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(|value| value.to_ascii_lowercase());
                }
            }

            if let Some(attrs) = attrs.and_then(|all| all.get(node_idx)) {
                for pair in attrs.inner().chunks_exact(2) {
                    let Some(name) = string_at(&snapshot.strings, &pair[0]) else {
                        continue;
                    };
                    let value = string_at(&snapshot.strings, &pair[1]).unwrap_or("");
                    entry.attributes.insert(name.to_string(), value.to_string());
                }
            }

            metadata.insert(*backend_node_id.inner(), entry);
        }
    }

    metadata
}

fn browser_use_input_format_hint(attributes: &HashMap<String, String>) -> Option<&'static str> {
    let input_type = attributes.get("type")?.trim().to_ascii_lowercase();
    match input_type.as_str() {
        "date" => Some("YYYY-MM-DD"),
        "time" => Some("HH:MM"),
        "datetime-local" => Some("YYYY-MM-DDTHH:MM"),
        "month" => Some("YYYY-MM"),
        "week" => Some("YYYY-W##"),
        _ => None,
    }
}

fn lookup_for_target<'a, T>(
    lookups_by_target: &'a HashMap<String, T>,
    target_id: Option<&str>,
) -> Option<&'a T> {
    if let Some(target_id) = target_id {
        if let Some(lookup) = lookups_by_target.get(target_id) {
            return Some(lookup);
        }
    }

    (lookups_by_target.len() == 1)
        .then(|| lookups_by_target.values().next())
        .flatten()
}

pub(crate) fn snapshot_node_scrollable(node: &BrowserUseSnapshotNode) -> bool {
    let Some(scroll_rect) = node.scroll_rects.as_ref() else {
        return false;
    };
    let Some(client_rect) = node.client_rects.as_ref() else {
        return false;
    };

    let has_vertical_overflow = scroll_rect.height > client_rect.height + 1.0;
    let has_horizontal_overflow = scroll_rect.width > client_rect.width + 1.0;
    if !has_vertical_overflow && !has_horizontal_overflow {
        return false;
    }

    let overflow = node
        .computed_styles
        .get("overflow")
        .map(String::as_str)
        .unwrap_or("visible")
        .to_ascii_lowercase();
    let overflow_x = node
        .computed_styles
        .get("overflow-x")
        .map(String::as_str)
        .unwrap_or(overflow.as_str())
        .to_ascii_lowercase();
    let overflow_y = node
        .computed_styles
        .get("overflow-y")
        .map(String::as_str)
        .unwrap_or(overflow.as_str())
        .to_ascii_lowercase();

    [overflow.as_str(), overflow_x.as_str(), overflow_y.as_str()]
        .iter()
        .any(|value| matches!(*value, "auto" | "scroll" | "overlay"))
}

fn node_label(node: &AccessibilityNode) -> Option<String> {
    node.name
        .as_ref()
        .or(node.value.as_ref())
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .or_else(|| {
            node.attributes
                .get("aria-label")
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string())
        })
}

fn actionable_descendants_below_viewport(
    node: &AccessibilityNode,
    iframe_rect: AccessibilityRect,
    out: &mut Vec<(String, String, f64)>,
) {
    for child in &node.children {
        if child.rect.width > 0
            && child.rect.height > 0
            && child.rect.y.saturating_add(child.rect.height)
                > iframe_rect.y.saturating_add(iframe_rect.height)
            && child.is_visible
            && child.is_interactive()
        {
            let label = node_label(child).unwrap_or_else(|| child.role.clone());
            let pages_down = if iframe_rect.height > 0 {
                ((child.rect.y - iframe_rect.y) as f64 / iframe_rect.height as f64 * 10.0).round()
                    / 10.0
            } else {
                0.0
            };
            out.push((child.role.clone(), label, pages_down));
        }
        actionable_descendants_below_viewport(child, iframe_rect, out);
    }
}

pub(crate) fn annotate_tree_with_browser_use_metadata(
    node: &mut AccessibilityNode,
    dom_metadata_by_target: &HashMap<String, HashMap<i64, BrowserUseDomNodeMetadata>>,
    snapshot_lookup_by_target: &HashMap<String, HashMap<i64, BrowserUseSnapshotNode>>,
    js_listener_backend_ids_by_target: &HashMap<String, HashSet<i64>>,
) {
    let target_id = node.attributes.get("target_id").cloned();
    let backend_node_id = node
        .attributes
        .get("backend_dom_node_id")
        .and_then(|value| value.trim().parse::<i64>().ok());

    if let Some(backend_node_id) = backend_node_id {
        if let Some(dom_metadata) = lookup_for_target(dom_metadata_by_target, target_id.as_deref())
            .and_then(|lookup| lookup.get(&backend_node_id))
        {
            if let Some(tag_name) = dom_metadata.tag_name.as_deref() {
                node.attributes
                    .entry("tag_name".to_string())
                    .or_insert_with(|| tag_name.to_string());
            }
            if let Some(dom_id) = dom_metadata.attributes.get("id").map(String::as_str) {
                if !dom_id.trim().is_empty() {
                    node.attributes
                        .entry("dom_id".to_string())
                        .or_insert_with(|| dom_id.to_string());
                }
            }
            if let Some(class_name) = dom_metadata.attributes.get("class").map(String::as_str) {
                if !class_name.trim().is_empty() {
                    node.attributes
                        .entry("class_name".to_string())
                        .or_insert_with(|| class_name.to_string());
                }
            }

            for key in [
                "type",
                "name",
                "role",
                "placeholder",
                "data-date-format",
                "alt",
                "aria-label",
                "aria-expanded",
                "data-state",
                "aria-checked",
                "aria-autocomplete",
                "list",
                "data-mask",
                "data-inputmask",
                "data-datepicker",
                "contenteditable",
                "pattern",
                "min",
                "max",
                "minlength",
                "maxlength",
                "step",
                "accept",
                "multiple",
                "inputmode",
                "autocomplete",
                "href",
                "title",
                "for",
            ] {
                if let Some(value) = dom_metadata.attributes.get(key) {
                    if !value.trim().is_empty() {
                        node.attributes
                            .entry(key.to_string())
                            .or_insert_with(|| value.clone());
                    }
                }
            }

            if node.value.is_none() {
                if let Some(value) = dom_metadata.attributes.get("value") {
                    if !value.trim().is_empty() {
                        node.value = Some(value.clone());
                    }
                }
            }

            if node
                .attributes
                .get("tag_name")
                .is_some_and(|tag_name| tag_name.eq_ignore_ascii_case("input"))
            {
                if let Some(format_hint) = browser_use_input_format_hint(&dom_metadata.attributes) {
                    node.attributes
                        .entry("format".to_string())
                        .or_insert_with(|| format_hint.to_string());
                }
            }
        }

        if let Some(snapshot_node) =
            lookup_for_target(snapshot_lookup_by_target, target_id.as_deref())
                .and_then(|lookup| lookup.get(&backend_node_id))
        {
            if snapshot_node.is_clickable {
                node.attributes
                    .entry("dom_clickable".to_string())
                    .or_insert_with(|| "true".to_string());
            }
            if let Some(cursor_style) = snapshot_node.cursor_style.as_deref() {
                node.attributes
                    .insert("cursor_style".to_string(), cursor_style.to_string());
            }
            if let Some(paint_order) = snapshot_node.paint_order {
                node.attributes
                    .insert("paint_order".to_string(), paint_order.to_string());
            }
            for key in ["display", "visibility", "opacity", "pointer-events"] {
                if let Some(value) = snapshot_node.computed_styles.get(key) {
                    node.attributes
                        .insert(format!("css_{}", key.replace('-', "_")), value.clone());
                }
            }
            if snapshot_node_scrollable(snapshot_node) {
                node.attributes
                    .insert("scrollable".to_string(), "true".to_string());
                if let Some(scroll_rect) = snapshot_node.scroll_rects.as_ref() {
                    node.attributes
                        .insert("scroll_top".to_string(), scroll_rect.y.round().to_string());
                    node.attributes.insert(
                        "scroll_height".to_string(),
                        scroll_rect.height.round().to_string(),
                    );
                    node.attributes
                        .insert("scroll_left".to_string(), scroll_rect.x.round().to_string());
                    node.attributes.insert(
                        "scroll_width".to_string(),
                        scroll_rect.width.round().to_string(),
                    );
                }
                if let Some(client_rect) = snapshot_node.client_rects.as_ref() {
                    node.attributes.insert(
                        "client_height".to_string(),
                        client_rect.height.round().to_string(),
                    );
                    node.attributes.insert(
                        "client_width".to_string(),
                        client_rect.width.round().to_string(),
                    );
                }

                let can_scroll_down = snapshot_node
                    .scroll_rects
                    .as_ref()
                    .zip(snapshot_node.client_rects.as_ref())
                    .map(|(scroll_rect, client_rect)| {
                        scroll_rect.height > client_rect.height + scroll_rect.y + 1.0
                    })
                    .unwrap_or(false);
                let can_scroll_up = snapshot_node
                    .scroll_rects
                    .as_ref()
                    .is_some_and(|scroll_rect| scroll_rect.y > 1.0);
                node.attributes
                    .insert("can_scroll_down".to_string(), can_scroll_down.to_string());
                node.attributes
                    .insert("can_scroll_up".to_string(), can_scroll_up.to_string());
            }

            let tag_name = node
                .attributes
                .get("tag_name")
                .map(String::as_str)
                .unwrap_or_default();
            if matches!(tag_name, "iframe" | "frame")
                && snapshot_node
                    .bounds
                    .as_ref()
                    .is_some_and(|rect| rect.width > 100.0 && rect.height > 100.0)
            {
                node.attributes
                    .entry("dom_clickable".to_string())
                    .or_insert_with(|| "true".to_string());
            }
        }

        if lookup_for_target(js_listener_backend_ids_by_target, target_id.as_deref())
            .is_some_and(|backend_ids| backend_ids.contains(&backend_node_id))
        {
            node.attributes
                .insert("has_js_click_listener".to_string(), "true".to_string());
            node.attributes
                .entry("dom_clickable".to_string())
                .or_insert_with(|| "true".to_string());
        }
    }

    for child in &mut node.children {
        annotate_tree_with_browser_use_metadata(
            child,
            dom_metadata_by_target,
            snapshot_lookup_by_target,
            js_listener_backend_ids_by_target,
        );
    }

    let tag_name = node
        .attributes
        .get("tag_name")
        .map(String::as_str)
        .unwrap_or_default();
    if matches!(tag_name, "iframe" | "frame") || matches!(node.role.as_str(), "iframe" | "frame") {
        let mut hidden = Vec::new();
        actionable_descendants_below_viewport(node, node.rect, &mut hidden);
        hidden.sort_by(|left, right| {
            left.2
                .partial_cmp(&right.2)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hidden.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
        if !hidden.is_empty() {
            let summary = hidden
                .iter()
                .take(5)
                .map(|(role, label, pages)| format!("{role}:{label}@{pages:.1}p"))
                .collect::<Vec<_>>()
                .join("|");
            node.attributes
                .insert("hidden_below_count".to_string(), hidden.len().to_string());
            node.attributes.insert("hidden_below".to_string(), summary);
        }
    }
}

pub(crate) fn annotate_tree_with_browser_use_identities(
    node: &mut AccessibilityNode,
    default_target_id: &str,
    identities_by_target_backend: &HashMap<(String, i64), BrowserUseElementIdentity>,
) {
    let target_id = node
        .attributes
        .get("target_id")
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(default_target_id);
    let backend_node_id = node
        .attributes
        .get("backend_dom_node_id")
        .and_then(|value| value.trim().parse::<i64>().ok());

    if let Some(backend_node_id) = backend_node_id {
        if let Some(identity) =
            identities_by_target_backend.get(&(target_id.to_string(), backend_node_id))
        {
            if let Some(x_path) = identity.x_path.as_deref() {
                node.attributes
                    .insert("x_path".to_string(), x_path.to_string());
            }
            if let Some(element_hash) = identity.element_hash {
                node.attributes
                    .insert("element_hash".to_string(), element_hash.to_string());
            }
            if let Some(stable_hash) = identity.stable_hash {
                node.attributes
                    .insert("stable_hash".to_string(), stable_hash.to_string());
            }
            if let Some(parent_branch_hash) = identity.parent_branch_hash {
                node.attributes.insert(
                    "parent_branch_hash".to_string(),
                    parent_branch_hash.to_string(),
                );
            }
            if let Some(ax_name) = identity.ax_name.as_deref() {
                node.attributes
                    .insert("ax_name".to_string(), ax_name.to_string());
            }
        }
    }

    for child in &mut node.children {
        annotate_tree_with_browser_use_identities(
            child,
            default_target_id,
            identities_by_target_backend,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        annotate_tree_with_browser_use_identities, annotate_tree_with_browser_use_metadata,
        build_snapshot_lookup, extract_dom_node_metadata, required_snapshot_computed_styles,
    };
    use crate::browser::dom_ops::browser_use_dom::BrowserUseElementIdentity;
    use crate::gui::accessibility::{AccessibilityNode, Rect as AccessibilityRect};
    use chromiumoxide::cdp::browser_protocol::dom::BackendNodeId;
    use chromiumoxide::cdp::browser_protocol::dom_snapshot::{
        ArrayOfStrings, CaptureSnapshotReturns, DocumentSnapshot, LayoutTreeSnapshot,
        NodeTreeSnapshot, RareBooleanData, Rectangle, StringIndex, TextBoxSnapshot,
    };
    use std::collections::{HashMap, HashSet};

    fn test_snapshot() -> CaptureSnapshotReturns {
        let strings = vec![
            "https://example.test".to_string(),
            "title".to_string(),
            "base".to_string(),
            "lang".to_string(),
            "utf-8".to_string(),
            "".to_string(),
            "root-frame".to_string(),
            "html".to_string(),
            "iframe".to_string(),
            "input".to_string(),
            "id".to_string(),
            "cross-origin-frame".to_string(),
            "name".to_string(),
            "search".to_string(),
            "type".to_string(),
            "text".to_string(),
            "placeholder".to_string(),
            "Search".to_string(),
            "display".to_string(),
            "block".to_string(),
            "visibility".to_string(),
            "visible".to_string(),
            "opacity".to_string(),
            "1".to_string(),
            "overflow".to_string(),
            "auto".to_string(),
            "overflow-x".to_string(),
            "hidden".to_string(),
            "overflow-y".to_string(),
            "scroll".to_string(),
            "cursor".to_string(),
            "pointer".to_string(),
            "pointer-events".to_string(),
            "auto".to_string(),
            "position".to_string(),
            "relative".to_string(),
            "background-color".to_string(),
            "rgb(255,255,255)".to_string(),
        ];

        let styles = ArrayOfStrings::new(
            (19..=37)
                .step_by(2)
                .map(StringIndex::new)
                .collect::<Vec<_>>(),
        );

        let document = DocumentSnapshot::builder()
            .document_url(StringIndex::new(0))
            .title(StringIndex::new(1))
            .base_url(StringIndex::new(2))
            .content_language(StringIndex::new(3))
            .encoding_name(StringIndex::new(4))
            .public_id(StringIndex::new(5))
            .system_id(StringIndex::new(5))
            .frame_id(StringIndex::new(6))
            .nodes(
                NodeTreeSnapshot::builder()
                    .parent_indexs(vec![-1, 0, 0])
                    .node_types(vec![9, 1, 1])
                    .node_names(vec![
                        StringIndex::new(7),
                        StringIndex::new(8),
                        StringIndex::new(9),
                    ])
                    .node_values(vec![
                        StringIndex::new(5),
                        StringIndex::new(5),
                        StringIndex::new(5),
                    ])
                    .backend_node_ids(vec![
                        BackendNodeId::new(1),
                        BackendNodeId::new(2),
                        BackendNodeId::new(3),
                    ])
                    .attributes(vec![
                        ArrayOfStrings::new(Vec::<StringIndex>::new()),
                        ArrayOfStrings::new(vec![StringIndex::new(10), StringIndex::new(11)]),
                        ArrayOfStrings::new(vec![
                            StringIndex::new(12),
                            StringIndex::new(13),
                            StringIndex::new(14),
                            StringIndex::new(15),
                            StringIndex::new(16),
                            StringIndex::new(17),
                        ]),
                    ])
                    .is_clickable(
                        RareBooleanData::builder()
                            .index(1)
                            .index(2)
                            .build()
                            .expect("clickable"),
                    )
                    .build(),
            )
            .layout(
                LayoutTreeSnapshot::builder()
                    .node_indexs(vec![1, 2])
                    .styles(vec![styles.clone(), styles])
                    .bounds(vec![
                        Rectangle::new(vec![10.0, 20.0, 320.0, 240.0]),
                        Rectangle::new(vec![40.0, 280.0, 200.0, 48.0]),
                    ])
                    .texts(vec![StringIndex::new(5), StringIndex::new(5)])
                    .stacking_contexts(RareBooleanData::new(Vec::new()))
                    .paint_orders(vec![7, 8])
                    .offset_rects(vec![
                        Rectangle::new(vec![10.0, 20.0, 320.0, 240.0]),
                        Rectangle::new(vec![40.0, 280.0, 200.0, 48.0]),
                    ])
                    .scroll_rects(vec![
                        Rectangle::new(vec![0.0, 20.0, 320.0, 800.0]),
                        Rectangle::new(vec![0.0, 0.0, 200.0, 48.0]),
                    ])
                    .client_rects(vec![
                        Rectangle::new(vec![0.0, 0.0, 320.0, 240.0]),
                        Rectangle::new(vec![0.0, 0.0, 200.0, 48.0]),
                    ])
                    .build()
                    .expect("layout"),
            )
            .text_boxes(TextBoxSnapshot::new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ))
            .scroll_offset_x(0.0)
            .scroll_offset_y(0.0)
            .content_width(1280.0)
            .content_height(960.0)
            .build()
            .expect("document");

        CaptureSnapshotReturns::new(vec![document], strings)
    }

    #[test]
    fn annotate_tree_with_browser_use_identities_projects_hashes_and_xpath() {
        let mut tree = AccessibilityNode {
            id: "button".to_string(),
            role: "button".to_string(),
            name: Some("Next".to_string()),
            value: None,
            rect: AccessibilityRect {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            },
            children: Vec::new(),
            is_visible: true,
            attributes: HashMap::from([
                ("backend_dom_node_id".to_string(), "41".to_string()),
                ("target_id".to_string(), "target-1".to_string()),
            ]),
            som_id: Some(7),
        };

        annotate_tree_with_browser_use_identities(
            &mut tree,
            "target-1",
            &HashMap::from([(
                ("target-1".to_string(), 41),
                BrowserUseElementIdentity {
                    x_path: Some("nav/a[2]".to_string()),
                    element_hash: Some(11),
                    stable_hash: Some(22),
                    parent_branch_hash: Some(33),
                    ax_name: Some("Next".to_string()),
                },
            )]),
        );

        assert_eq!(
            tree.attributes.get("x_path").map(String::as_str),
            Some("nav/a[2]")
        );
        assert_eq!(
            tree.attributes.get("stable_hash").map(String::as_str),
            Some("22")
        );
        assert_eq!(
            tree.attributes.get("ax_name").map(String::as_str),
            Some("Next")
        );
    }

    #[test]
    fn required_styles_include_browser_use_fields() {
        let styles = required_snapshot_computed_styles();
        assert!(styles.iter().any(|value| value == "cursor"));
        assert!(styles.iter().any(|value| value == "overflow-y"));
    }

    #[test]
    fn snapshot_lookup_extracts_clickability_scroll_and_cursor() {
        let snapshot = test_snapshot();
        let lookup = build_snapshot_lookup(&snapshot);
        let iframe = lookup.get(&2).expect("iframe metadata");
        let input = lookup.get(&3).expect("input metadata");

        assert!(iframe.is_clickable);
        assert_eq!(iframe.cursor_style.as_deref(), Some("pointer"));
        assert_eq!(iframe.paint_order, Some(7));
        assert_eq!(input.bounds.as_ref().map(|rect| rect.width), Some(200.0));
    }

    #[test]
    fn dom_metadata_extracts_tag_and_attributes() {
        let snapshot = test_snapshot();
        let metadata = extract_dom_node_metadata(&snapshot);
        let iframe = metadata.get(&2).expect("iframe node");
        let input = metadata.get(&3).expect("input node");

        assert_eq!(iframe.tag_name.as_deref(), Some("iframe"));
        assert_eq!(
            iframe.attributes.get("id").map(String::as_str),
            Some("cross-origin-frame")
        );
        assert_eq!(
            input.attributes.get("placeholder").map(String::as_str),
            Some("Search")
        );
    }

    #[test]
    fn annotation_merges_dom_metadata_and_iframe_hints() {
        let snapshot = test_snapshot();
        let dom_metadata =
            HashMap::from([("target-1".to_string(), extract_dom_node_metadata(&snapshot))]);
        let snapshot_lookup =
            HashMap::from([("target-1".to_string(), build_snapshot_lookup(&snapshot))]);

        let mut tree = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: None,
            value: None,
            rect: AccessibilityRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            children: vec![AccessibilityNode {
                id: "iframe".to_string(),
                role: "iframe".to_string(),
                name: Some("Embedded frame".to_string()),
                value: None,
                rect: AccessibilityRect {
                    x: 10,
                    y: 20,
                    width: 320,
                    height: 240,
                },
                children: vec![AccessibilityNode {
                    id: "search".to_string(),
                    role: "textbox".to_string(),
                    name: Some("Search".to_string()),
                    value: None,
                    rect: AccessibilityRect {
                        x: 40,
                        y: 280,
                        width: 200,
                        height: 48,
                    },
                    children: vec![],
                    is_visible: true,
                    attributes: HashMap::from([
                        ("target_id".to_string(), "target-1".to_string()),
                        ("backend_dom_node_id".to_string(), "3".to_string()),
                    ]),
                    som_id: None,
                }],
                is_visible: true,
                attributes: HashMap::from([
                    ("target_id".to_string(), "target-1".to_string()),
                    ("backend_dom_node_id".to_string(), "2".to_string()),
                ]),
                som_id: None,
            }],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        annotate_tree_with_browser_use_metadata(
            &mut tree,
            &dom_metadata,
            &snapshot_lookup,
            &HashMap::new(),
        );
        let iframe = &tree.children[0];
        let input = &iframe.children[0];
        assert_eq!(
            iframe.attributes.get("dom_id").map(String::as_str),
            Some("cross-origin-frame")
        );
        assert_eq!(
            iframe.attributes.get("scrollable").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            iframe
                .attributes
                .get("hidden_below_count")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            input.attributes.get("placeholder").map(String::as_str),
            Some("Search")
        );
        assert_eq!(
            input.attributes.get("dom_clickable").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn annotation_marks_js_click_listener_nodes_clickable() {
        let mut tree = AccessibilityNode {
            id: "button-like".to_string(),
            role: "generic".to_string(),
            name: Some("Open menu".to_string()),
            value: None,
            rect: AccessibilityRect {
                x: 10,
                y: 10,
                width: 120,
                height: 32,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("target_id".to_string(), "target-1".to_string()),
                ("backend_dom_node_id".to_string(), "42".to_string()),
            ]),
            som_id: None,
        };

        annotate_tree_with_browser_use_metadata(
            &mut tree,
            &HashMap::new(),
            &HashMap::new(),
            &HashMap::from([("target-1".to_string(), HashSet::from([42_i64]))]),
        );

        assert_eq!(
            tree.attributes
                .get("has_js_click_listener")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            tree.attributes.get("dom_clickable").map(String::as_str),
            Some("true")
        );
    }
}
