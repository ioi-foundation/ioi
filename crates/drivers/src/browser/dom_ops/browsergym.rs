use super::super::*;
use super::browser_use::required_snapshot_computed_styles;
use chromiumoxide::cdp::browser_protocol::accessibility;
use chromiumoxide::cdp::browser_protocol::dom_snapshot::{
    CaptureSnapshotParams, CaptureSnapshotReturns, RareIntegerData, StringIndex,
};
use std::collections::{BTreeMap, HashMap};

pub(crate) const BROWSERGYM_ID_ATTRIBUTE: &str = "bid";
pub(crate) const BROWSERGYM_VISIBILITY_ATTRIBUTE: &str = "browsergym_visibility_ratio";
pub(crate) const BROWSERGYM_SETOFMARKS_ATTRIBUTE: &str = "browsergym_set_of_marks";

const BROWSERGYM_MARK_SCRIPT: &str = include_str!("browsergym_mark.js");
const BROWSERGYM_UNMARK_SCRIPT: &str = include_str!("browsergym_unmark.js");
const BROWSERGYM_FOCUSED_BID_SCRIPT: &str = include_str!("browsergym_focused_bid.js");

fn quoted_browsergym_parent_bid(parent_bid: &str) -> std::result::Result<String, BrowserError> {
    serde_json::to_string(parent_bid).map_err(|e| {
        BrowserError::Internal(format!(
            "BrowserGym parent bid encoding failed for '{}': {}",
            parent_bid, e
        ))
    })
}

fn browsergym_mark_script(parent_bid: &str) -> std::result::Result<String, BrowserError> {
    let quoted_parent_bid = quoted_browsergym_parent_bid(parent_bid)?;
    Ok(BROWSERGYM_MARK_SCRIPT.replacen(
        "return markDocument(document, \"\");",
        &format!("return markDocument(document, {});", quoted_parent_bid),
        1,
    ))
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct BrowserGymElementProperties {
    pub(crate) visibility_ratio: Option<f64>,
    pub(crate) bbox: Option<AccessibilityRect>,
    pub(crate) clickable: bool,
    pub(crate) set_of_marks: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BrowserGymSnapshotMetadata {
    pub(crate) extra_properties: HashMap<String, BrowserGymElementProperties>,
    pub(crate) backend_node_bids: HashMap<i64, String>,
}

#[derive(Debug, Clone, Default)]
struct BrowserGymNodeScratch {
    backend_node_id: Option<i64>,
    bid: Option<String>,
    visibility_ratio: Option<f64>,
    bbox: Option<AccessibilityRect>,
    clickable: bool,
    set_of_marks: bool,
}

#[derive(Debug, Clone, Default)]
struct BrowserGymDocumentScratch {
    parent: Option<(usize, usize)>,
    abs_x: f64,
    abs_y: f64,
    nodes: Vec<BrowserGymNodeScratch>,
}

impl BrowserDriver {
    pub(crate) async fn mark_browsergym_page(
        &self,
        page: &Page,
    ) -> std::result::Result<(), BrowserError> {
        self.mark_browsergym_page_with_parent_bid(page, "").await
    }

    pub(crate) async fn mark_browsergym_page_with_parent_bid(
        &self,
        page: &Page,
        parent_bid: &str,
    ) -> std::result::Result<(), BrowserError> {
        let script = browsergym_mark_script(parent_bid)?;
        let warnings = self
            .await_request_with_timeout("BrowserGym DOM marking", page.evaluate(script))
            .await?
            .into_value::<Vec<String>>()
            .map_err(|e| {
                BrowserError::Internal(format!("BrowserGym DOM marking decode failed: {}", e))
            })?;

        for warning in warnings {
            log::debug!(target: "browser", "BrowserGym marking warning: {}", warning);
        }

        Ok(())
    }

    pub(crate) async fn unmark_browsergym_page(
        &self,
        page: &Page,
    ) -> std::result::Result<(), BrowserError> {
        let _ = self
            .await_request_with_timeout(
                "BrowserGym DOM cleanup",
                page.evaluate(BROWSERGYM_UNMARK_SCRIPT),
            )
            .await?
            .into_value::<bool>()
            .map_err(|e| {
                BrowserError::Internal(format!("BrowserGym DOM cleanup decode failed: {}", e))
            })?;
        Ok(())
    }

    pub(crate) async fn capture_browsergym_snapshot(
        &self,
        page: &Page,
    ) -> std::result::Result<CaptureSnapshotReturns, BrowserError> {
        let params = CaptureSnapshotParams::builder()
            .computed_styles(required_snapshot_computed_styles())
            .include_dom_rects(true)
            .include_paint_order(true)
            .build()
            .map_err(|e| {
                BrowserError::Internal(format!("BrowserGym snapshot params failed: {}", e))
            })?;

        Ok(self
            .await_request_with_timeout("BrowserGym DOM snapshot", page.execute(params))
            .await?
            .result)
    }

    pub(crate) async fn extract_browsergym_focused_bid(
        &self,
        page: &Page,
    ) -> std::result::Result<Option<String>, BrowserError> {
        let bid = self
            .await_request_with_timeout(
                "BrowserGym focused element query",
                page.evaluate(BROWSERGYM_FOCUSED_BID_SCRIPT),
            )
            .await?
            .into_value::<String>()
            .map_err(|e| {
                BrowserError::Internal(format!("BrowserGym focused element decode failed: {}", e))
            })?;

        Ok((!bid.trim().is_empty()).then(|| bid))
    }
}

fn string_at<'a>(strings: &'a [String], index: &StringIndex) -> Option<&'a str> {
    let idx = usize::try_from(*index.inner()).ok()?;
    strings.get(idx).map(String::as_str)
}

fn attr_string_id(strings: &[String], name: &str) -> Option<i64> {
    strings
        .iter()
        .position(|entry| entry == name)
        .and_then(|idx| i64::try_from(idx).ok())
}

fn string_index_at(strings: &[String], name: &str) -> Option<usize> {
    strings.iter().position(|entry| entry == name)
}

fn extract_browsergym_data_from_aria_text(text: &str) -> (Option<String>, String) {
    const PREFIX: &str = "browsergym_id_";

    let Some(rest) = text.strip_prefix(PREFIX) else {
        return (None, text.to_string());
    };

    let split_idx = rest
        .char_indices()
        .find_map(|(idx, ch)| ch.is_ascii_whitespace().then_some(idx))
        .unwrap_or(rest.len());
    let bid = &rest[..split_idx];
    if bid.is_empty() || !bid.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return (None, text.to_string());
    }

    let original = rest[split_idx..].trim_start_matches(char::is_whitespace);
    (Some(bid.to_string()), original.to_string())
}

fn ax_value_string(value: &accessibility::AxValue) -> Option<String> {
    value.value.as_ref()?.as_str().map(ToOwned::to_owned)
}

fn set_ax_value_string(value: &mut accessibility::AxValue, text: String) {
    value.value = Some(serde_json::Value::String(text));
}

pub(crate) fn cleanup_ax_tree_browsergym_ids(
    nodes: &mut [accessibility::AxNode],
) -> HashMap<String, String> {
    let mut browsergym_ids = HashMap::new();

    for node in nodes {
        let mut browsergym_id: Option<String> = None;

        if let Some(properties) = node.properties.take() {
            let mut cleaned = Vec::new();
            for mut property in properties {
                if property.name == accessibility::AxPropertyName::Roledescription {
                    if let Some(text) = ax_value_string(&property.value) {
                        let (found_id, cleaned_text) =
                            extract_browsergym_data_from_aria_text(&text);
                        if browsergym_id.is_none() {
                            browsergym_id = found_id;
                        }
                        if !cleaned_text.is_empty() {
                            set_ax_value_string(&mut property.value, cleaned_text);
                            cleaned.push(property);
                        }
                        continue;
                    }
                }
                cleaned.push(property);
            }
            if !cleaned.is_empty() {
                node.properties = Some(cleaned);
            }
        }

        if let Some(description) = node.description.as_mut() {
            if let Some(text) = ax_value_string(description) {
                let (found_id, cleaned_text) = extract_browsergym_data_from_aria_text(&text);
                if browsergym_id.is_none() {
                    browsergym_id = found_id;
                }
                if cleaned_text.is_empty() {
                    node.description = None;
                } else {
                    set_ax_value_string(description, cleaned_text);
                }
            }
        }

        if let Some(id) = browsergym_id {
            let node_id: String = node.node_id.clone().into();
            browsergym_ids.insert(node_id, id);
        }
    }

    browsergym_ids
}

fn rare_integer_lookup(data: &Option<RareIntegerData>, node_idx: usize) -> Option<i64> {
    let data = data.as_ref()?;
    data.index
        .iter()
        .zip(data.value.iter())
        .find_map(|(idx, value)| (*idx == node_idx as i64).then_some(*value))
}

fn round_css_coord(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32
}

fn round_css_extent(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    value.round().clamp(0.0, i32::MAX as f64) as i32
}

fn rectangle_to_accessibility_rect(
    rect: &[f64],
    abs_x: f64,
    abs_y: f64,
) -> Option<AccessibilityRect> {
    if rect.len() < 4 {
        return None;
    }

    let width = rect[2];
    let height = rect[3];
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return None;
    }

    Some(AccessibilityRect {
        x: round_css_coord(rect[0] + abs_x),
        y: round_css_coord(rect[1] + abs_y),
        width: round_css_extent(width),
        height: round_css_extent(height),
    })
}

pub(crate) fn extract_browsergym_extra_properties(
    snapshot: &CaptureSnapshotReturns,
) -> HashMap<String, BrowserGymElementProperties> {
    extract_browsergym_snapshot_metadata(snapshot).extra_properties
}

pub(crate) fn extract_browsergym_snapshot_metadata(
    snapshot: &CaptureSnapshotReturns,
) -> BrowserGymSnapshotMetadata {
    let bid_attr_id = attr_string_id(&snapshot.strings, BROWSERGYM_ID_ATTRIBUTE);
    let vis_attr_id = attr_string_id(&snapshot.strings, BROWSERGYM_VISIBILITY_ATTRIBUTE);
    let som_attr_id = attr_string_id(&snapshot.strings, BROWSERGYM_SETOFMARKS_ATTRIBUTE);

    let mut docs = vec![BrowserGymDocumentScratch::default(); snapshot.documents.len()];
    let mut discovered = vec![false; snapshot.documents.len()];
    if !discovered.is_empty() {
        discovered[0] = true;
    }

    let mut docs_to_process = if snapshot.documents.is_empty() {
        Vec::new()
    } else {
        vec![0usize]
    };

    while let Some(doc_idx) = docs_to_process.pop() {
        let document = &snapshot.documents[doc_idx];

        if let Some(content_docs) = document.nodes.content_document_index.as_ref() {
            for (node_idx, child_doc) in content_docs.index.iter().zip(content_docs.value.iter()) {
                let Ok(child_doc_idx) = usize::try_from(*child_doc) else {
                    continue;
                };
                if child_doc_idx >= docs.len() {
                    continue;
                }
                docs[child_doc_idx].parent = Some((doc_idx, *node_idx as usize));
                if !discovered[child_doc_idx] {
                    discovered[child_doc_idx] = true;
                    docs_to_process.push(child_doc_idx);
                }
            }
        }

        let (parent_abs_x, parent_abs_y) =
            if let Some((parent_doc_idx, parent_node_idx)) = docs[doc_idx].parent {
                let parent_doc = &snapshot.documents[parent_doc_idx];
                if let Some(layout_idx) = parent_doc
                    .layout
                    .node_index
                    .iter()
                    .position(|node_idx| *node_idx == parent_node_idx as i64)
                {
                    if let Some(bounds) = parent_doc.layout.bounds.get(layout_idx) {
                        let coords = bounds.inner();
                        if coords.len() >= 2 {
                            (
                                docs[parent_doc_idx].abs_x + coords[0],
                                docs[parent_doc_idx].abs_y + coords[1],
                            )
                        } else {
                            (0.0, 0.0)
                        }
                    } else {
                        (0.0, 0.0)
                    }
                } else {
                    (0.0, 0.0)
                }
            } else {
                (0.0, 0.0)
            };

        docs[doc_idx].abs_x = parent_abs_x - document.scroll_offset_x.unwrap_or(0.0);
        docs[doc_idx].abs_y = parent_abs_y - document.scroll_offset_y.unwrap_or(0.0);

        let node_count = document
            .nodes
            .parent_index
            .as_ref()
            .map(Vec::len)
            .or_else(|| document.nodes.node_name.as_ref().map(Vec::len))
            .unwrap_or(0);
        docs[doc_idx].nodes = vec![BrowserGymNodeScratch::default(); node_count];

        if let Some(clickable_nodes) = document.nodes.is_clickable.as_ref() {
            for idx in &clickable_nodes.index {
                let Ok(node_idx) = usize::try_from(*idx) else {
                    continue;
                };
                if let Some(node) = docs[doc_idx].nodes.get_mut(node_idx) {
                    node.clickable = true;
                }
            }
        }

        if let Some(attributes) = document.nodes.attributes.as_ref() {
            for (node_idx, attrs) in attributes.iter().enumerate() {
                let Some(node) = docs[doc_idx].nodes.get_mut(node_idx) else {
                    continue;
                };
                node.backend_node_id = document
                    .nodes
                    .backend_node_id
                    .as_ref()
                    .and_then(|backend_node_ids| backend_node_ids.get(node_idx))
                    .map(|backend_node_id| *backend_node_id.inner());

                let raw = attrs.inner();
                let mut iter = raw.chunks_exact(2);
                for pair in iter.by_ref() {
                    let name_id = *pair[0].inner();
                    let Some(value) = string_at(&snapshot.strings, &pair[1]) else {
                        continue;
                    };

                    if bid_attr_id == Some(name_id) {
                        node.bid = Some(value.to_string());
                    }
                    if vis_attr_id == Some(name_id) {
                        node.visibility_ratio = value.parse::<f64>().ok();
                    }
                    if som_attr_id == Some(name_id) {
                        node.set_of_marks = value == "1";
                    }
                }
            }
        }

        if let Some(client_rects) = document.layout.client_rects.as_ref() {
            let abs_x = docs[doc_idx].abs_x;
            let abs_y = docs[doc_idx].abs_y;
            for (layout_idx, node_idx) in document.layout.node_index.iter().enumerate() {
                let Ok(node_idx) = usize::try_from(*node_idx) else {
                    continue;
                };
                let Some(node) = docs[doc_idx].nodes.get_mut(node_idx) else {
                    continue;
                };
                let Some(client_rect) = client_rects.get(layout_idx) else {
                    continue;
                };
                if client_rect.inner().is_empty() {
                    node.bbox = None;
                    continue;
                }
                let Some(bounds) = document.layout.bounds.get(layout_idx) else {
                    continue;
                };
                node.bbox = rectangle_to_accessibility_rect(bounds.inner(), abs_x, abs_y);
            }
        }
    }

    let mut metadata = BrowserGymSnapshotMetadata::default();
    for doc in docs {
        for node in doc.nodes {
            let Some(bid) = node.bid else {
                continue;
            };
            if let Some(backend_node_id) = node.backend_node_id {
                metadata
                    .backend_node_bids
                    .insert(backend_node_id, bid.clone());
            }
            metadata.extra_properties.insert(
                bid,
                BrowserGymElementProperties {
                    visibility_ratio: node.visibility_ratio,
                    bbox: node.bbox,
                    clickable: node.clickable,
                    set_of_marks: node.set_of_marks,
                },
            );
        }
    }

    metadata
}

pub(crate) fn cleanup_dom_snapshot_browsergym_ids(snapshot: &mut CaptureSnapshotReturns) {
    let attr_ids = ["aria-roledescription", "aria-description"]
        .into_iter()
        .filter_map(|name| string_index_at(&snapshot.strings, name))
        .map(|idx| idx as i64)
        .collect::<Vec<_>>();
    if attr_ids.is_empty() {
        return;
    }

    let mut processed_string_ids = HashMap::<usize, String>::new();
    for document in &mut snapshot.documents {
        let Some(attributes) = document.nodes.attributes.as_mut() else {
            continue;
        };

        for node_attrs in attributes {
            let raw = node_attrs.inner();
            if raw.is_empty() {
                continue;
            }

            let mut rebuilt = Vec::with_capacity(raw.len());
            let mut idx = 0usize;
            while idx + 1 < raw.len() {
                let name_id = *raw[idx].inner();
                let value_idx = usize::try_from(*raw[idx + 1].inner()).ok();

                if attr_ids
                    .iter()
                    .any(|target_attr_id| *target_attr_id == name_id)
                {
                    let cleaned_value = value_idx
                        .and_then(|string_idx| {
                            if let Some(existing) = processed_string_ids.get(&string_idx) {
                                return Some(existing.clone());
                            }
                            let value = snapshot.strings.get(string_idx)?;
                            let (_, cleaned) = extract_browsergym_data_from_aria_text(value);
                            processed_string_ids.insert(string_idx, cleaned.clone());
                            Some(cleaned)
                        })
                        .unwrap_or_default();

                    if cleaned_value.is_empty() {
                        idx += 2;
                        continue;
                    }

                    if let Some(string_idx) = value_idx {
                        if let Some(value) = snapshot.strings.get_mut(string_idx) {
                            *value = cleaned_value;
                        }
                    }
                }

                rebuilt.push(raw[idx]);
                rebuilt.push(raw[idx + 1]);
                idx += 2;
            }

            *node_attrs =
                chromiumoxide::cdp::browser_protocol::dom_snapshot::ArrayOfStrings::new(rebuilt);
        }
    }
}

pub(crate) fn annotate_tree_with_browsergym_metadata(
    node: &mut AccessibilityNode,
    extra_properties: &HashMap<String, BrowserGymElementProperties>,
    focused_bid: Option<&str>,
) {
    let bid = node
        .attributes
        .get("browsergym_id")
        .or_else(|| node.attributes.get("bid"))
        .cloned();

    if let Some(bid) = bid {
        node.attributes
            .insert("browsergym_id".to_string(), bid.clone());
        node.attributes.insert("bid".to_string(), bid.clone());

        if let Some(extra) = extra_properties.get(&bid) {
            if let Some(visibility_ratio) = extra.visibility_ratio {
                node.attributes.insert(
                    "browsergym_visibility_ratio".to_string(),
                    visibility_ratio.to_string(),
                );
                if visibility_ratio < 0.5 {
                    node.is_visible = false;
                }
            }

            if let Some(bbox) = extra.bbox {
                node.rect = bbox;
            }

            if extra.clickable {
                node.attributes
                    .insert("clickable".to_string(), "true".to_string());
                node.attributes
                    .entry("dom_clickable".to_string())
                    .or_insert_with(|| "true".to_string());
            }

            if extra.set_of_marks {
                node.attributes
                    .insert("set_of_marks".to_string(), "true".to_string());
                node.attributes
                    .insert("browsergym_set_of_marks".to_string(), "1".to_string());
            }
        }

        if focused_bid == Some(bid.as_str()) {
            node.attributes
                .insert("focused".to_string(), "true".to_string());
        }
    }

    for child in &mut node.children {
        annotate_tree_with_browsergym_metadata(child, extra_properties, focused_bid);
    }
}

pub(crate) fn render_browsergym_extra_properties_text(
    extra_properties: &HashMap<String, BrowserGymElementProperties>,
) -> Option<String> {
    if extra_properties.is_empty() {
        return None;
    }

    let mut by_bid = BTreeMap::new();
    for (bid, properties) in extra_properties {
        let bbox = properties
            .bbox
            .map(|rect| vec![rect.x, rect.y, rect.width, rect.height]);
        by_bid.insert(
            bid.clone(),
            serde_json::json!({
                "visibility": properties.visibility_ratio,
                "bbox": bbox,
                "clickable": properties.clickable,
                "set_of_marks": properties.set_of_marks,
            }),
        );
    }

    serde_json::to_string_pretty(&by_bid).ok()
}

#[cfg(test)]
#[path = "browsergym/tests.rs"]
mod tests;
