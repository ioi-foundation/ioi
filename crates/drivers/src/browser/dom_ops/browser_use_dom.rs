mod eval;
mod html;
mod identity;
mod markdown;
mod pagination;
mod serializer;
mod state;

use super::browser_use::{snapshot_node_scrollable, BrowserUseSnapshotNode};
use super::browsergym::BrowserGymSnapshotMetadata;
use super::targets::BrowserFrameTarget;
use crate::gui::accessibility::{AccessibilityNode, Rect as AccessibilityRect};
use chromiumoxide::cdp::browser_protocol::{accessibility, dom};
use eval::render_browser_use_eval_from_tree;
use html::render_browser_use_html_from_tree;
use identity::build_browser_use_element_identity_map;
use markdown::render_browser_use_markdown_from_tree;
use pagination::{detect_pagination_buttons_from_tree, render_pagination_buttons_text};
use serializer::{prepare_tree_for_browser_use_render, render_selector_map_from_dom};
use state::render_browser_use_state_from_tree;
use std::collections::{HashMap, HashSet};

const BROWSER_USE_INCLUDE_ATTRS: &[&str] = &[
    "title",
    "type",
    "checked",
    "dom_id",
    "name",
    "role",
    "value",
    "placeholder",
    "data-date-format",
    "alt",
    "aria-label",
    "aria-expanded",
    "data-state",
    "aria-checked",
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
    "aria-autocomplete",
    "list",
    "data-mask",
    "data-inputmask",
    "data-datepicker",
    "format",
    "expected_format",
    "contenteditable",
    "selected",
    "expanded",
    "pressed",
    "disabled",
    "invalid",
    "valuemin",
    "valuemax",
    "valuenow",
    "keyshortcuts",
    "haspopup",
    "multiselectable",
    "required",
    "valuetext",
    "level",
    "busy",
    "live",
];

#[derive(Debug, Clone, Default)]
pub(crate) struct BrowserUseAxData {
    pub(crate) role: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct BrowserUseCompoundChild {
    role: Option<String>,
    name: Option<String>,
    valuemin: Option<String>,
    valuemax: Option<String>,
    valuenow: Option<String>,
    options_count: Option<usize>,
    first_options: Vec<String>,
    format_hint: Option<String>,
}

#[derive(Debug, Clone)]
struct BrowserUseDomTreeNode {
    target_id: String,
    frame_id: Option<String>,
    backend_node_id: Option<i64>,
    node_type: i64,
    node_name: String,
    node_value: Option<String>,
    attribute_pairs: Vec<(String, String)>,
    attributes: HashMap<String, String>,
    snapshot: Option<BrowserUseSnapshotNode>,
    rect: Option<AccessibilityRect>,
    visibility_ratio: Option<f64>,
    is_visible: bool,
    has_js_click_listener: bool,
    ax_data: BrowserUseAxData,
    som_id: Option<u32>,
    shadow_root_type: Option<String>,
    children: Vec<BrowserUseDomTreeNode>,
    shadow_roots: Vec<BrowserUseDomTreeNode>,
    content_document: Option<Box<BrowserUseDomTreeNode>>,
    hidden_elements_info: Vec<(String, String, f64)>,
    has_hidden_content: bool,
    should_display: bool,
    assigned_interactive: bool,
    is_new: bool,
    ignored_by_paint_order: bool,
    excluded_by_parent: bool,
    is_shadow_host: bool,
    compound_children: Vec<BrowserUseCompoundChild>,
}

impl BrowserUseDomTreeNode {
    fn tag_name(&self) -> Option<String> {
        (self.node_type == 1).then(|| self.node_name.trim().to_ascii_lowercase())
    }

    fn node_name_for_text(&self) -> String {
        self.tag_name()
            .unwrap_or_else(|| self.node_name.trim().to_ascii_lowercase())
    }

    fn role(&self) -> Option<&str> {
        self.ax_data
            .role
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }

    fn accessible_name(&self) -> Option<&str> {
        self.ax_data
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn text_value(&self) -> Option<&str> {
        self.node_value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn name_for_render(&self) -> Option<String> {
        self.accessible_name()
            .map(str::to_string)
            .or_else(|| {
                self.attributes
                    .get("aria-label")
                    .map(String::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
            .or_else(|| {
                self.attributes
                    .get("placeholder")
                    .map(String::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
    }

    fn is_css_hidden(&self) -> bool {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return false;
        };

        let display = snapshot
            .computed_styles
            .get("display")
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if display == "none" {
            return true;
        }

        let visibility = snapshot
            .computed_styles
            .get("visibility")
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if visibility == "hidden" {
            return true;
        }

        snapshot
            .computed_styles
            .get("opacity")
            .and_then(|value| value.parse::<f64>().ok())
            .is_some_and(|opacity| opacity <= 0.0)
    }

    fn is_scrollable(&self) -> bool {
        self.snapshot.as_ref().is_some_and(snapshot_node_scrollable)
    }

    fn should_show_scroll_info(&self) -> bool {
        if matches!(self.tag_name().as_deref(), Some("iframe") | Some("frame")) {
            return true;
        }

        if !self.is_scrollable() {
            return false;
        }

        if matches!(self.tag_name().as_deref(), Some("html") | Some("body")) {
            return true;
        }

        true
    }

    fn scroll_info_text(&self) -> Option<String> {
        if matches!(self.tag_name().as_deref(), Some("iframe") | Some("frame")) {
            if !self.hidden_elements_info.is_empty() || self.has_hidden_content {
                return Some("scroll".to_string());
            }
            return None;
        }

        let snapshot = self.snapshot.as_ref()?;
        let scroll_rect = snapshot.scroll_rects.as_ref()?;
        let client_rect = snapshot.client_rects.as_ref()?;

        let pages_above = if client_rect.height > 0.0 {
            (scroll_rect.y / client_rect.height * 10.0).round() / 10.0
        } else {
            0.0
        };
        let pages_below = if client_rect.height > 0.0 {
            ((scroll_rect.height - client_rect.height - scroll_rect.y).max(0.0)
                / client_rect.height
                * 10.0)
                .round()
                / 10.0
        } else {
            0.0
        };

        Some(format!(
            "{pages_above:.1} pages above, {pages_below:.1} pages below"
        ))
    }

    fn is_interactive(&self) -> bool {
        if self.node_type != 1 {
            return false;
        }

        let tag_name = self.tag_name().unwrap_or_default();
        if matches!(tag_name.as_str(), "html" | "body") {
            return false;
        }

        if self
            .ax_data
            .properties
            .get("disabled")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            return false;
        }
        if self
            .ax_data
            .properties
            .get("hidden")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            return false;
        }

        if self.has_js_click_listener {
            return true;
        }

        if matches!(
            tag_name.as_str(),
            "button"
                | "input"
                | "select"
                | "textarea"
                | "a"
                | "details"
                | "summary"
                | "option"
                | "optgroup"
        ) {
            return true;
        }

        if matches!(tag_name.as_str(), "label" | "span") && self.has_form_control_descendant(2) {
            return true;
        }

        if self.search_like() {
            return true;
        }

        if self.ax_data.properties.keys().any(|name| {
            matches!(
                name.as_str(),
                "focusable"
                    | "editable"
                    | "settable"
                    | "required"
                    | "autocomplete"
                    | "checked"
                    | "expanded"
                    | "pressed"
                    | "selected"
                    | "keyshortcuts"
            )
        }) {
            return true;
        }

        if self.attributes.keys().any(|name| {
            matches!(
                name.as_str(),
                "onclick" | "onmousedown" | "onmouseup" | "onkeydown" | "onkeyup" | "tabindex"
            )
        }) {
            return true;
        }

        if self
            .attributes
            .get("role")
            .is_some_and(|role| browser_use_interactive_role(role))
        {
            return true;
        }

        if self.role().is_some_and(browser_use_interactive_role) {
            return true;
        }

        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.cursor_style.as_deref())
            .is_some_and(|cursor| cursor.eq_ignore_ascii_case("pointer"))
    }

    fn has_form_control_descendant(&self, max_depth: usize) -> bool {
        if max_depth == 0 {
            return false;
        }

        self.children
            .iter()
            .chain(self.shadow_roots.iter())
            .any(|child| {
                child.node_type == 1
                    && child
                        .tag_name()
                        .is_some_and(|tag| matches!(tag.as_str(), "input" | "select" | "textarea"))
                    || child.has_form_control_descendant(max_depth - 1)
            })
    }

    fn search_like(&self) -> bool {
        let joined_classes = self
            .attributes
            .get("class")
            .map(String::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let element_id = self
            .attributes
            .get("id")
            .map(String::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let indicators = [
            "search",
            "magnify",
            "glass",
            "lookup",
            "find",
            "query",
            "search-icon",
            "search-btn",
            "search-button",
            "searchbox",
        ];
        indicators.iter().any(|indicator| {
            joined_classes.contains(indicator)
                || element_id.contains(indicator)
                || self.attributes.iter().any(|(name, value)| {
                    name.starts_with("data-") && value.to_ascii_lowercase().contains(indicator)
                })
        })
    }

    fn is_input_type(&self, input_type: &str) -> bool {
        matches!(self.tag_name().as_deref(), Some("input"))
            && self
                .attributes
                .get("type")
                .map(String::as_str)
                .map(str::trim)
                .is_some_and(|value| value.eq_ignore_ascii_case(input_type))
    }

    fn is_file_input(&self) -> bool {
        self.is_input_type("file")
    }

    fn is_password_input(&self) -> bool {
        self.is_input_type("password")
    }
}

fn browser_use_interactive_role(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "button"
            | "link"
            | "menuitem"
            | "option"
            | "radio"
            | "checkbox"
            | "tab"
            | "textbox"
            | "combobox"
            | "slider"
            | "spinbutton"
            | "listbox"
            | "search"
            | "searchbox"
            | "row"
            | "cell"
            | "gridcell"
    )
}

fn ax_value_to_string(value: &Option<accessibility::AxValue>) -> Option<String> {
    value.as_ref().and_then(|entry| {
        entry.value.as_ref().and_then(|inner| {
            if let Some(text) = inner.as_str() {
                Some(text.to_string())
            } else if let Some(flag) = inner.as_bool() {
                Some(flag.to_string())
            } else {
                inner.as_f64().map(|number| number.to_string())
            }
        })
    })
}

fn inline_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn collect_hidden_elements(
    node: &BrowserUseDomTreeNode,
    iframe_rect: AccessibilityRect,
    out: &mut Vec<(String, String, f64)>,
) {
    let css_hidden = node.is_css_hidden();
    let tag = node.tag_name().unwrap_or_else(|| node.node_name_for_text());
    let label = node
        .name_for_render()
        .or_else(|| node.text_value().map(str::to_string))
        .unwrap_or_else(|| node.role().unwrap_or(tag.as_str()).to_string());

    if !css_hidden
        && !node.is_visible
        && node.is_interactive()
        && node
            .rect
            .as_ref()
            .is_some_and(|rect| rect.y + rect.height > iframe_rect.y + iframe_rect.height)
    {
        if let Some(rect) = node.rect {
            let pages = if iframe_rect.height > 0 {
                (((rect.y - iframe_rect.y) as f64 / iframe_rect.height as f64) * 10.0).round()
                    / 10.0
            } else {
                0.0
            };
            out.push((tag, label, pages));
        }
    }

    for shadow_root in &node.shadow_roots {
        collect_hidden_elements(shadow_root, iframe_rect, out);
    }
    for child in &node.children {
        collect_hidden_elements(child, iframe_rect, out);
    }
    if let Some(content_document) = node.content_document.as_deref() {
        collect_hidden_elements(content_document, iframe_rect, out);
    }
}

fn subtree_has_non_css_hidden_content(node: &BrowserUseDomTreeNode) -> bool {
    if !node.is_visible && !node.is_css_hidden() {
        return true;
    }
    node.shadow_roots
        .iter()
        .any(subtree_has_non_css_hidden_content)
        || node.children.iter().any(subtree_has_non_css_hidden_content)
        || node
            .content_document
            .as_deref()
            .is_some_and(subtree_has_non_css_hidden_content)
}

fn annotate_hidden_iframe_content(node: &mut BrowserUseDomTreeNode) {
    if matches!(node.tag_name().as_deref(), Some("iframe") | Some("frame")) {
        if let (Some(content_document), Some(iframe_rect)) =
            (node.content_document.as_deref(), node.rect)
        {
            let mut hidden = Vec::new();
            collect_hidden_elements(content_document, iframe_rect, &mut hidden);
            hidden.sort_by(|left, right| {
                left.2
                    .partial_cmp(&right.2)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            hidden.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
            node.hidden_elements_info = hidden.into_iter().take(10).collect();
            if node.hidden_elements_info.is_empty()
                && subtree_has_non_css_hidden_content(content_document)
            {
                node.has_hidden_content = true;
            }
        }
    }

    for shadow_root in &mut node.shadow_roots {
        annotate_hidden_iframe_content(shadow_root);
    }
    for child in &mut node.children {
        annotate_hidden_iframe_content(child);
    }
    if let Some(content_document) = node.content_document.as_deref_mut() {
        annotate_hidden_iframe_content(content_document);
    }
}

fn attribute_pairs(attributes: Option<&Vec<String>>) -> Vec<(String, String)> {
    let mut parsed = Vec::new();
    let Some(attributes) = attributes else {
        return parsed;
    };
    for pair in attributes.chunks_exact(2) {
        parsed.push((pair[0].clone(), pair[1].clone()));
    }
    parsed
}

fn attributes_map(attribute_pairs: &[(String, String)]) -> HashMap<String, String> {
    let mut parsed = HashMap::new();
    for (key, value) in attribute_pairs {
        parsed.insert(key.clone(), value.clone());
    }
    parsed
}

fn build_dom_tree_node(
    node: &dom::Node,
    current_target_id: &str,
    dom_roots_by_target: &HashMap<String, dom::Node>,
    frame_to_target: &HashMap<String, String>,
    snapshot_metadata_by_target: &HashMap<String, BrowserGymSnapshotMetadata>,
    snapshot_lookup_by_target: &HashMap<String, HashMap<i64, BrowserUseSnapshotNode>>,
    js_listener_backend_ids_by_target: &HashMap<String, HashSet<i64>>,
    ax_data_by_target_backend: &HashMap<(String, i64), BrowserUseAxData>,
    som_by_target_backend: &HashMap<(String, i64), u32>,
    external_target_stack: &mut HashSet<String>,
    parent_visible: bool,
) -> BrowserUseDomTreeNode {
    let backend_node_id = Some(*node.backend_node_id.inner());
    let attribute_pairs = attribute_pairs(node.attributes.as_ref());
    let attributes = attributes_map(&attribute_pairs);
    let browsergym_bid = attributes.get("bid").cloned();
    let snapshot_metadata = snapshot_metadata_by_target.get(current_target_id);
    let browsergym_props = browsergym_bid
        .as_deref()
        .and_then(|bid| snapshot_metadata.and_then(|metadata| metadata.extra_properties.get(bid)));
    let snapshot = backend_node_id.and_then(|backend| {
        snapshot_lookup_by_target
            .get(current_target_id)
            .and_then(|lookup| lookup.get(&backend))
            .cloned()
    });
    let is_visible = browsergym_props
        .and_then(|props| props.visibility_ratio)
        .map(|ratio| ratio >= 0.5)
        .unwrap_or(parent_visible)
        && !snapshot.as_ref().is_some_and(|snapshot| {
            let display = snapshot
                .computed_styles
                .get("display")
                .map(String::as_str)
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if display == "none" {
                return true;
            }
            let visibility = snapshot
                .computed_styles
                .get("visibility")
                .map(String::as_str)
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if visibility == "hidden" {
                return true;
            }
            snapshot
                .computed_styles
                .get("opacity")
                .and_then(|value| value.parse::<f64>().ok())
                .is_some_and(|opacity| opacity <= 0.0)
        });

    let mut built = BrowserUseDomTreeNode {
        target_id: current_target_id.to_string(),
        frame_id: node
            .frame_id
            .as_ref()
            .map(|frame_id| frame_id.as_ref().to_string()),
        backend_node_id,
        node_type: node.node_type,
        node_name: node.node_name.clone(),
        node_value: (!node.node_value.trim().is_empty()).then(|| node.node_value.clone()),
        attribute_pairs,
        attributes: attributes.clone(),
        snapshot,
        rect: browsergym_props.and_then(|props| props.bbox),
        visibility_ratio: browsergym_props.and_then(|props| props.visibility_ratio),
        is_visible,
        has_js_click_listener: backend_node_id.is_some_and(|backend| {
            js_listener_backend_ids_by_target
                .get(current_target_id)
                .is_some_and(|backend_ids| backend_ids.contains(&backend))
        }),
        ax_data: backend_node_id
            .and_then(|backend| {
                ax_data_by_target_backend
                    .get(&(current_target_id.to_string(), backend))
                    .cloned()
            })
            .unwrap_or_default(),
        som_id: backend_node_id.and_then(|backend| {
            som_by_target_backend
                .get(&(current_target_id.to_string(), backend))
                .copied()
        }),
        shadow_root_type: node
            .shadow_root_type
            .as_ref()
            .map(|shadow_root| shadow_root.as_ref().to_string()),
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
    };

    if let Some(shadow_roots) = node.shadow_roots.as_ref() {
        built.shadow_roots = shadow_roots
            .iter()
            .map(|shadow_root| {
                build_dom_tree_node(
                    shadow_root,
                    current_target_id,
                    dom_roots_by_target,
                    frame_to_target,
                    snapshot_metadata_by_target,
                    snapshot_lookup_by_target,
                    js_listener_backend_ids_by_target,
                    ax_data_by_target_backend,
                    som_by_target_backend,
                    external_target_stack,
                    built.is_visible,
                )
            })
            .collect();
    }

    if let Some(children) = node.children.as_ref() {
        built.children = children
            .iter()
            .map(|child| {
                build_dom_tree_node(
                    child,
                    current_target_id,
                    dom_roots_by_target,
                    frame_to_target,
                    snapshot_metadata_by_target,
                    snapshot_lookup_by_target,
                    js_listener_backend_ids_by_target,
                    ax_data_by_target_backend,
                    som_by_target_backend,
                    external_target_stack,
                    built.is_visible,
                )
            })
            .collect();
    }

    if let Some(content_document) = node.content_document.as_deref() {
        built.content_document = Some(Box::new(build_dom_tree_node(
            content_document,
            current_target_id,
            dom_roots_by_target,
            frame_to_target,
            snapshot_metadata_by_target,
            snapshot_lookup_by_target,
            js_listener_backend_ids_by_target,
            ax_data_by_target_backend,
            som_by_target_backend,
            external_target_stack,
            built.is_visible,
        )));
    } else if matches!(built.tag_name().as_deref(), Some("iframe") | Some("frame")) {
        if let Some(frame_id) = built.frame_id.as_deref() {
            if let Some(external_target_id) = frame_to_target.get(frame_id) {
                if external_target_id != current_target_id
                    && external_target_stack.insert(external_target_id.clone())
                {
                    if let Some(dom_root) = dom_roots_by_target.get(external_target_id) {
                        built.content_document = Some(Box::new(build_dom_tree_node(
                            dom_root,
                            external_target_id,
                            dom_roots_by_target,
                            frame_to_target,
                            snapshot_metadata_by_target,
                            snapshot_lookup_by_target,
                            js_listener_backend_ids_by_target,
                            ax_data_by_target_backend,
                            som_by_target_backend,
                            external_target_stack,
                            built.is_visible,
                        )));
                    }
                    external_target_stack.remove(external_target_id);
                }
            }
        }
    }

    built
}

pub(crate) fn build_ax_lookup_by_target_backend(
    nodes: &[accessibility::AxNode],
    node_target_ids: &HashMap<String, String>,
    default_target_id: &str,
) -> HashMap<(String, i64), BrowserUseAxData> {
    let mut lookup = HashMap::new();
    for node in nodes {
        let Some(backend_node_id) = node.backend_dom_node_id else {
            continue;
        };
        let node_id: String = node.node_id.clone().into();
        let target_id = node_target_ids
            .get(&node_id)
            .cloned()
            .unwrap_or_else(|| default_target_id.to_string());

        let mut properties = HashMap::new();
        if let Some(raw_properties) = node.properties.as_ref() {
            for property in raw_properties {
                let Some(value) = ax_value_to_string(&Some(property.value.clone())) else {
                    continue;
                };
                properties.insert(format!("{:?}", property.name).to_ascii_lowercase(), value);
            }
        }

        lookup.insert(
            (target_id, *backend_node_id.inner()),
            BrowserUseAxData {
                role: ax_value_to_string(&node.role),
                name: ax_value_to_string(&node.name),
                properties,
            },
        );
    }
    lookup
}

pub(crate) fn collect_som_ids_by_target_backend(
    node: &AccessibilityNode,
    default_target_id: &str,
    out: &mut HashMap<(String, i64), u32>,
) {
    if let (Some(som_id), Some(backend_node_id)) = (
        node.som_id,
        node.attributes
            .get("backend_dom_node_id")
            .and_then(|value| value.trim().parse::<i64>().ok()),
    ) {
        let target_id = node
            .attributes
            .get("target_id")
            .cloned()
            .unwrap_or_else(|| default_target_id.to_string());
        out.insert((target_id, backend_node_id), som_id);
    }

    for child in &node.children {
        collect_som_ids_by_target_backend(child, default_target_id, out);
    }
}

pub(crate) use identity::BrowserUseElementIdentity;

#[derive(Debug, Clone, Default)]
pub(crate) struct BrowserUseObservationText {
    pub(crate) state_text: Option<String>,
    pub(crate) selector_map_text: Option<String>,
    pub(crate) html_text: Option<String>,
    pub(crate) eval_text: Option<String>,
    pub(crate) markdown_text: Option<String>,
    pub(crate) pagination_text: Option<String>,
    pub(crate) identities_by_target_backend: HashMap<(String, i64), BrowserUseElementIdentity>,
    pub(crate) interactive_backend_keys: HashSet<(String, i64)>,
}

pub(crate) fn render_browser_use_observation_from_dom(
    active_target_id: &str,
    dom_roots_by_target: &HashMap<String, dom::Node>,
    frames_by_id: Option<&HashMap<String, BrowserFrameTarget>>,
    snapshot_metadata_by_target: &HashMap<String, BrowserGymSnapshotMetadata>,
    snapshot_lookup_by_target: &HashMap<String, HashMap<i64, BrowserUseSnapshotNode>>,
    js_listener_backend_ids_by_target: &HashMap<String, HashSet<i64>>,
    ax_data_by_target_backend: &HashMap<(String, i64), BrowserUseAxData>,
    som_by_target_backend: &HashMap<(String, i64), u32>,
    previous_interactive_backend_keys: Option<&HashSet<(String, i64)>>,
) -> BrowserUseObservationText {
    let Some(root) = dom_roots_by_target.get(active_target_id) else {
        return BrowserUseObservationText::default();
    };

    let frame_to_target = frames_by_id
        .map(|frames| {
            frames
                .iter()
                .map(|(frame_id, frame)| (frame_id.clone(), frame.target_id.clone()))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();

    let mut external_target_stack = HashSet::from([active_target_id.to_string()]);
    let mut tree = build_dom_tree_node(
        root,
        active_target_id,
        dom_roots_by_target,
        &frame_to_target,
        snapshot_metadata_by_target,
        snapshot_lookup_by_target,
        js_listener_backend_ids_by_target,
        ax_data_by_target_backend,
        som_by_target_backend,
        &mut external_target_stack,
        true,
    );
    annotate_hidden_iframe_content(&mut tree);
    prepare_tree_for_browser_use_render(&mut tree, previous_interactive_backend_keys);
    let interactive_backend_keys = serializer::collect_interactive_backend_keys(&tree);
    let identities_by_target_backend = build_browser_use_element_identity_map(&tree);
    let pagination_buttons =
        detect_pagination_buttons_from_tree(&tree, &identities_by_target_backend);
    let html_text = render_browser_use_html_from_tree(&tree, false);
    BrowserUseObservationText {
        state_text: render_browser_use_state_from_tree(&tree),
        selector_map_text: render_selector_map_from_dom(&tree),
        html_text: html_text.clone(),
        eval_text: render_browser_use_eval_from_tree(&tree),
        markdown_text: render_browser_use_markdown_from_tree(&tree),
        pagination_text: render_pagination_buttons_text(&pagination_buttons),
        identities_by_target_backend,
        interactive_backend_keys,
    }
}

#[cfg(test)]
#[path = "browser_use_dom/tests.rs"]
mod tests;
