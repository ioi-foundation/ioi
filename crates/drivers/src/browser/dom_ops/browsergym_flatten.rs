use super::browsergym::BrowserGymElementProperties;
use chromiumoxide::cdp::browser_protocol::accessibility;
use chromiumoxide::cdp::browser_protocol::dom_snapshot::CaptureSnapshotReturns;
use kuchiki::traits::TendrilSink;
use kuchiki::NodeRef;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone)]
pub(crate) struct BrowserGymDomFlattenOptions {
    pub(crate) with_visible: bool,
    pub(crate) with_clickable: bool,
    pub(crate) with_center_coords: bool,
    pub(crate) with_bounding_box_coords: bool,
    pub(crate) with_som: bool,
    pub(crate) filter_visible_only: bool,
    pub(crate) filter_with_bid_only: bool,
    pub(crate) filter_som_only: bool,
    pub(crate) coord_decimals: usize,
    pub(crate) hide_bid_if_invisible: bool,
    pub(crate) hide_all_bids: bool,
}

impl Default for BrowserGymDomFlattenOptions {
    fn default() -> Self {
        Self {
            with_visible: false,
            with_clickable: false,
            with_center_coords: false,
            with_bounding_box_coords: false,
            with_som: false,
            filter_visible_only: false,
            filter_with_bid_only: false,
            filter_som_only: false,
            coord_decimals: 0,
            hide_bid_if_invisible: false,
            hide_all_bids: false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BrowserGymAxFlattenOptions {
    pub(crate) with_visible: bool,
    pub(crate) with_clickable: bool,
    pub(crate) with_center_coords: bool,
    pub(crate) with_bounding_box_coords: bool,
    pub(crate) with_som: bool,
    pub(crate) skip_generic: bool,
    pub(crate) filter_visible_only: bool,
    pub(crate) filter_with_bid_only: bool,
    pub(crate) filter_som_only: bool,
    pub(crate) coord_decimals: usize,
    pub(crate) remove_redundant_static_text: bool,
    pub(crate) hide_bid_if_invisible: bool,
    pub(crate) hide_all_children: bool,
    pub(crate) hide_all_bids: bool,
}

impl Default for BrowserGymAxFlattenOptions {
    fn default() -> Self {
        Self {
            with_visible: false,
            with_clickable: false,
            with_center_coords: false,
            with_bounding_box_coords: false,
            with_som: false,
            skip_generic: true,
            filter_visible_only: false,
            filter_with_bid_only: false,
            filter_som_only: false,
            coord_decimals: 0,
            remove_redundant_static_text: true,
            hide_bid_if_invisible: false,
            hide_all_children: false,
            hide_all_bids: false,
        }
    }
}

const IGNORED_AXTREE_ROLES: &[&str] = &["LineBreak"];
const IGNORED_AXTREE_PROPERTIES: &[&str] = &[
    "editable",
    "readonly",
    "level",
    "settable",
    "multiline",
    "invalid",
    "focusable",
];
const HTML_VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

fn string_at<'a>(
    strings: &'a [String],
    index: &chromiumoxide::cdp::browser_protocol::dom_snapshot::StringIndex,
) -> Option<&'a str> {
    let idx = usize::try_from(*index.inner()).ok()?;
    strings.get(idx).map(String::as_str)
}

fn ax_value_to_string(value: &Option<accessibility::AxValue>) -> Option<String> {
    value.as_ref().and_then(|entry| {
        entry.value.as_ref().and_then(|inner| {
            if let Some(text) = inner.as_str() {
                (!text.is_empty()).then(|| text.to_string())
            } else if let Some(flag) = inner.as_bool() {
                Some(flag.to_string())
            } else {
                inner.as_f64().map(|number| number.to_string())
            }
        })
    })
}

fn get_coord_str(coords: &[f64], decimals: usize) -> String {
    let format_coord = |value: f64| format!("{value:.decimals$}");
    format!(
        "({})",
        coords
            .iter()
            .map(|value| format_coord(*value))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn process_bid(
    bid: Option<&str>,
    extra_properties: Option<&HashMap<String, BrowserGymElementProperties>>,
    with_visible: bool,
    with_clickable: bool,
    with_center_coords: bool,
    with_bounding_box_coords: bool,
    with_som: bool,
    filter_visible_only: bool,
    filter_with_bid_only: bool,
    filter_som_only: bool,
    coord_decimals: usize,
) -> (bool, Vec<String>) {
    let mut skip_element = false;
    let mut attributes = Vec::new();

    let empty_extra_properties = HashMap::new();
    let extra_properties = extra_properties.unwrap_or(&empty_extra_properties);
    let Some(bid) = bid else {
        if filter_with_bid_only || filter_som_only {
            skip_element = true;
        }
        return (skip_element, attributes);
    };

    let Some(extra) = extra_properties.get(bid) else {
        if filter_visible_only || filter_som_only {
            skip_element = true;
        }
        return (skip_element, attributes);
    };

    let is_visible = extra.visibility_ratio.unwrap_or(1.0) >= 0.5;
    if filter_visible_only && !is_visible {
        skip_element = true;
    }
    if filter_som_only && !extra.set_of_marks {
        skip_element = true;
    }

    if with_som && extra.set_of_marks {
        attributes.insert(0, "som".to_string());
    }
    if with_visible && is_visible {
        attributes.insert(0, "visible".to_string());
    }
    if with_clickable && extra.clickable {
        attributes.insert(0, "clickable".to_string());
    }
    if with_center_coords {
        if let Some(bbox) = extra.bbox {
            let center = [
                bbox.x as f64 + bbox.width as f64 / 2.0,
                bbox.y as f64 + bbox.height as f64 / 2.0,
            ];
            attributes.insert(
                0,
                format!("center=\"{}\"", get_coord_str(&center, coord_decimals)),
            );
        }
    }
    if with_bounding_box_coords {
        if let Some(bbox) = extra.bbox {
            let box_coords = [
                bbox.x as f64,
                bbox.y as f64,
                bbox.x as f64 + bbox.width as f64,
                bbox.y as f64 + bbox.height as f64,
            ];
            attributes.insert(
                0,
                format!("box=\"{}\"", get_coord_str(&box_coords, coord_decimals)),
            );
        }
    }

    (skip_element, attributes)
}

fn render_dom_document(
    snapshot: &CaptureSnapshotReturns,
    document_idx: usize,
    extra_properties: Option<&HashMap<String, BrowserGymElementProperties>>,
    options: &BrowserGymDomFlattenOptions,
) -> String {
    let document = &snapshot.documents[document_idx];
    let mut children_by_parent = BTreeMap::<usize, Vec<usize>>::new();

    if let Some(parent_indexes) = document.nodes.parent_index.as_ref() {
        for (node_idx, parent_idx) in parent_indexes.iter().enumerate() {
            if *parent_idx >= 0 {
                children_by_parent
                    .entry(*parent_idx as usize)
                    .or_default()
                    .push(node_idx);
            }
        }
    }

    let content_doc_map = document
        .nodes
        .content_document_index
        .as_ref()
        .map(|data| {
            data.index
                .iter()
                .zip(data.value.iter())
                .filter_map(|(node_idx, child_doc)| {
                    let node_idx = usize::try_from(*node_idx).ok()?;
                    let child_doc = usize::try_from(*child_doc).ok()?;
                    Some((node_idx, child_doc))
                })
                .collect::<HashMap<usize, usize>>()
        })
        .unwrap_or_default();

    let node_types = document.nodes.node_type.as_ref();
    let node_names = document.nodes.node_name.as_ref();
    let node_values = document.nodes.node_value.as_ref();
    let attrs = document.nodes.attributes.as_ref();

    fn dfs(
        snapshot: &CaptureSnapshotReturns,
        document_idx: usize,
        node_idx: usize,
        children_by_parent: &BTreeMap<usize, Vec<usize>>,
        content_doc_map: &HashMap<usize, usize>,
        node_types: Option<&Vec<i64>>,
        node_names: Option<&Vec<chromiumoxide::cdp::browser_protocol::dom_snapshot::StringIndex>>,
        node_values: Option<&Vec<chromiumoxide::cdp::browser_protocol::dom_snapshot::StringIndex>>,
        attrs: Option<&Vec<chromiumoxide::cdp::browser_protocol::dom_snapshot::ArrayOfStrings>>,
        extra_properties: Option<&HashMap<String, BrowserGymElementProperties>>,
        options: &BrowserGymDomFlattenOptions,
        parent_skipped: bool,
    ) -> String {
        let node_type = node_types
            .and_then(|values| values.get(node_idx))
            .copied()
            .unwrap_or(0);
        let node_name = node_names
            .and_then(|values| values.get(node_idx))
            .and_then(|value| string_at(&snapshot.strings, value))
            .unwrap_or("");
        let node_value = node_values
            .and_then(|values| values.get(node_idx))
            .and_then(|value| string_at(&snapshot.strings, value));

        let mut before = String::new();
        let mut after = String::new();
        let mut skip_node = false;

        match node_type {
            3 => {
                if !parent_skipped {
                    if let Some(value) = node_value {
                        before.push_str(value);
                    }
                }
            }
            4 => {
                if !parent_skipped {
                    if let Some(value) = node_value {
                        before.push_str("<!CDATA[[");
                        before.push_str(value);
                        before.push_str("]]>");
                    }
                }
            }
            7 | 8 | 9 | 10 | 11 => {
                skip_node = true;
            }
            _ => {
                let tag_name = node_name.to_ascii_lowercase();
                let mut bid = None::<String>;
                let mut rendered_attrs = Vec::new();

                if let Some(attrs) = attrs.and_then(|values| values.get(node_idx)) {
                    for pair in attrs.inner().chunks_exact(2) {
                        let Some(name) = string_at(&snapshot.strings, &pair[0]) else {
                            continue;
                        };
                        let value = string_at(&snapshot.strings, &pair[1]).unwrap_or("");
                        match name {
                            "bid" => bid = Some(value.to_string()),
                            "browsergym_visibility_ratio" | "browsergym_set_of_marks" => {}
                            _ if value.is_empty() => rendered_attrs.push(name.to_string()),
                            _ => rendered_attrs.push(format!("{name}=\"{value}\"")),
                        }
                    }
                }

                let (filtered, extra_attrs) = process_bid(
                    bid.as_deref(),
                    extra_properties,
                    options.with_visible,
                    options.with_clickable,
                    options.with_center_coords,
                    options.with_bounding_box_coords,
                    options.with_som,
                    options.filter_visible_only,
                    options.filter_with_bid_only,
                    options.filter_som_only,
                    options.coord_decimals,
                );
                skip_node = filtered;
                let mut attrs_out = extra_attrs;

                if let Some(bid) = bid.as_deref() {
                    let should_hide_bid = options.hide_all_bids
                        || (options.hide_bid_if_invisible
                            && extra_properties
                                .and_then(|extra_properties| extra_properties.get(bid))
                                .and_then(|extra| extra.visibility_ratio)
                                .is_some_and(|visibility| visibility < 0.5));
                    if !should_hide_bid {
                        attrs_out.push(format!("bid=\"{bid}\""));
                    }
                }
                attrs_out.extend(rendered_attrs);

                if !skip_node {
                    if attrs_out.is_empty() {
                        before.push_str(&format!("<{tag_name}>"));
                    } else {
                        before.push_str(&format!("<{tag_name} {}>", attrs_out.join(" ")));
                    }
                    after.push_str(&format!("</{tag_name}>"));
                }
            }
        }

        let mut html = before;
        if let Some(child_doc) = content_doc_map.get(&node_idx).copied() {
            html.push_str(&render_dom_document(
                snapshot,
                child_doc,
                extra_properties,
                options,
            ));
        }
        if let Some(children) = children_by_parent.get(&node_idx) {
            for child_idx in children {
                html.push_str(&dfs(
                    snapshot,
                    document_idx,
                    *child_idx,
                    children_by_parent,
                    content_doc_map,
                    node_types,
                    node_names,
                    node_values,
                    attrs,
                    extra_properties,
                    options,
                    skip_node,
                ));
            }
        }
        html.push_str(&after);
        html
    }

    dfs(
        snapshot,
        document_idx,
        0,
        &children_by_parent,
        &content_doc_map,
        node_types,
        node_names,
        node_values,
        attrs,
        extra_properties,
        options,
        false,
    )
}

fn html_tag_name(fragment: &str) -> Option<String> {
    let fragment = fragment.trim();
    let fragment = fragment
        .strip_prefix("</")
        .or_else(|| fragment.strip_prefix('<'))
        .unwrap_or(fragment);
    let tag = fragment
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '-'))
        .collect::<String>()
        .to_ascii_lowercase();
    (!tag.is_empty()).then_some(tag)
}

fn unwrap_html_node(node: &NodeRef) {
    let children = node.children().collect::<Vec<_>>();
    for child in children {
        node.insert_before(child);
    }
    node.detach();
}

fn serialize_html_fragment(node: &NodeRef) -> String {
    let mut rendered = String::new();
    for child in node.children() {
        let mut bytes = Vec::new();
        if child.serialize(&mut bytes).is_ok() {
            rendered.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
    rendered
}

fn pretty_format_html(html: &str) -> String {
    let mut tokens = Vec::new();
    let mut cursor = 0usize;
    while cursor < html.len() {
        if let Some(next_tag_start) = html[cursor..].find('<') {
            let tag_start = cursor + next_tag_start;
            if tag_start > cursor {
                let text = html[cursor..tag_start].trim();
                if !text.is_empty() {
                    tokens.push(text.to_string());
                }
            }

            if let Some(tag_end_rel) = html[tag_start..].find('>') {
                let tag_end = tag_start + tag_end_rel + 1;
                tokens.push(html[tag_start..tag_end].trim().to_string());
                cursor = tag_end;
            } else {
                let text = html[tag_start..].trim();
                if !text.is_empty() {
                    tokens.push(text.to_string());
                }
                break;
            }
        } else {
            let text = html[cursor..].trim();
            if !text.is_empty() {
                tokens.push(text.to_string());
            }
            break;
        }
    }

    let mut lines = Vec::new();
    let mut depth = 0usize;
    let mut idx = 0usize;
    while idx < tokens.len() {
        let token = tokens[idx].trim();
        if token.is_empty() {
            idx += 1;
            continue;
        }

        if token.starts_with("</") {
            if html_tag_name(token)
                .as_deref()
                .is_some_and(|tag| HTML_VOID_ELEMENTS.contains(&tag))
            {
                idx += 1;
                continue;
            }
            depth = depth.saturating_sub(1);
            lines.push(format!("{}{}", " ".repeat(depth), token));
            idx += 1;
            continue;
        }

        if token.starts_with('<') {
            let tag_name = html_tag_name(token);
            let is_void = token.ends_with("/>")
                || tag_name
                    .as_deref()
                    .is_some_and(|tag| HTML_VOID_ELEMENTS.contains(&tag));
            if is_void {
                let self_closed = if token.ends_with("/>") {
                    token.to_string()
                } else {
                    format!("{}/>", token.trim_end_matches('>'))
                };
                lines.push(format!("{}{}", " ".repeat(depth), self_closed));
                idx += 1;
                continue;
            }

            lines.push(format!("{}{}", " ".repeat(depth), token));
            if !is_void && !token.starts_with("<!") && !token.starts_with("<?") {
                depth += 1;
            }
            idx += 1;
            continue;
        }

        lines.push(format!("{}{}", " ".repeat(depth), token));
        idx += 1;
    }

    lines.join("\n")
}

pub(crate) fn flatten_dom_snapshot_to_string(
    snapshot: &CaptureSnapshotReturns,
    extra_properties: Option<&HashMap<String, BrowserGymElementProperties>>,
    options: &BrowserGymDomFlattenOptions,
) -> String {
    if snapshot.documents.is_empty() {
        return String::new();
    }
    pretty_format_html(&render_dom_document(snapshot, 0, extra_properties, options))
}

pub(crate) fn flatten_ax_tree_to_string(
    nodes: &[accessibility::AxNode],
    browsergym_ids_by_ax_node_id: &HashMap<String, String>,
    extra_properties: Option<&HashMap<String, BrowserGymElementProperties>>,
    options: &BrowserGymAxFlattenOptions,
) -> String {
    if nodes.is_empty() {
        return String::new();
    }

    let node_id_to_idx = nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| {
            let node_id: String = node.node_id.clone().into();
            (node_id, idx)
        })
        .collect::<HashMap<_, _>>();

    fn dfs(
        nodes: &[accessibility::AxNode],
        node_idx: usize,
        node_id_to_idx: &HashMap<String, usize>,
        browsergym_ids_by_ax_node_id: &HashMap<String, String>,
        extra_properties: Option<&HashMap<String, BrowserGymElementProperties>>,
        options: &BrowserGymAxFlattenOptions,
        depth: usize,
        parent_filtered: bool,
        parent_name: &str,
    ) -> String {
        let node = &nodes[node_idx];
        let role = ax_value_to_string(&node.role).unwrap_or_else(|| "generic".to_string());
        let name = ax_value_to_string(&node.name).unwrap_or_default();
        let value = ax_value_to_string(&node.value);
        let node_id: String = node.node_id.clone().into();

        let mut skip_node = false;
        let mut filter_node = false;
        let mut attributes = Vec::new();

        if IGNORED_AXTREE_ROLES.iter().any(|ignored| *ignored == role) {
            skip_node = true;
        } else if node.name.is_none() {
            skip_node = true;
        } else if options.skip_generic
            && role == "generic"
            && node
                .properties
                .as_ref()
                .is_none_or(|properties| properties.is_empty())
        {
            skip_node = true;
        } else if options.hide_all_children && parent_filtered {
            skip_node = true;
        } else if role == "StaticText" {
            if parent_filtered {
                skip_node = true;
            } else if options.remove_redundant_static_text
                && !name.is_empty()
                && parent_name.contains(name.as_str())
            {
                skip_node = true;
            }
        } else {
            let bid = browsergym_ids_by_ax_node_id
                .get(&node_id)
                .map(String::as_str);
            let (filtered, extra_attrs) = process_bid(
                bid,
                extra_properties,
                options.with_visible,
                options.with_clickable,
                options.with_center_coords,
                options.with_bounding_box_coords,
                options.with_som,
                options.filter_visible_only,
                options.filter_with_bid_only,
                options.filter_som_only,
                options.coord_decimals,
            );
            filter_node = filtered;
            skip_node |= filtered;
            attributes.extend(extra_attrs);
        }

        if let Some(properties) = node.properties.as_ref() {
            for property in properties {
                let prop_name = property.name.as_ref().to_ascii_lowercase();
                if IGNORED_AXTREE_PROPERTIES
                    .iter()
                    .any(|ignored| *ignored == prop_name)
                {
                    continue;
                }
                let prop_value = property.value.value.as_ref().and_then(|value| {
                    value
                        .as_str()
                        .map(|value| value.to_string())
                        .or_else(|| value.as_bool().map(|value| value.to_string()))
                        .or_else(|| value.as_f64().map(|value| value.to_string()))
                });
                match (prop_name.as_str(), prop_value) {
                    ("required" | "focused" | "atomic", Some(value))
                        if value.eq_ignore_ascii_case("true") =>
                    {
                        attributes.push(prop_name)
                    }
                    (_, Some(value)) if !value.is_empty() => {
                        attributes.push(format!("{}={:?}", prop_name, value))
                    }
                    _ => {}
                }
            }
        }

        let mut current_line = String::new();
        if !skip_node {
            let mut node_str = if role == "generic" && name.trim().is_empty() {
                role.clone()
            } else {
                format!("{} {:?}", role, name.trim())
            };

            if let Some(bid) = browsergym_ids_by_ax_node_id
                .get(&node_id)
                .map(String::as_str)
            {
                let hide_bid = options.hide_all_bids
                    || (options.hide_bid_if_invisible
                        && extra_properties
                            .and_then(|extra_properties| extra_properties.get(bid))
                            .and_then(|extra| extra.visibility_ratio)
                            .is_some_and(|visibility| visibility < 0.5));
                if !hide_bid {
                    node_str = format!("[{bid}] {node_str}");
                }
            }
            if let Some(value) = value {
                node_str.push_str(&format!(" value={value:?}"));
            }
            if !attributes.is_empty() {
                node_str.push_str(", ");
                node_str.push_str(&attributes.join(", "));
            }
            current_line = format!("{}{}", "\t".repeat(depth), node_str);
        }

        let mut lines = Vec::new();
        if !current_line.is_empty() {
            lines.push(current_line);
        }
        if let Some(child_ids) = node.child_ids.as_ref() {
            for child_id in child_ids {
                let child_id: String = child_id.clone().into();
                let Some(child_idx) = node_id_to_idx.get(&child_id).copied() else {
                    continue;
                };
                if child_idx == node_idx {
                    continue;
                }
                let child_depth = if skip_node { depth } else { depth + 1 };
                let child = dfs(
                    nodes,
                    child_idx,
                    node_id_to_idx,
                    browsergym_ids_by_ax_node_id,
                    extra_properties,
                    options,
                    child_depth,
                    filter_node,
                    &name,
                );
                if !child.is_empty() {
                    lines.push(child);
                }
            }
        }

        lines.join("\n")
    }

    dfs(
        nodes,
        0,
        &node_id_to_idx,
        browsergym_ids_by_ax_node_id,
        extra_properties,
        options,
        0,
        false,
        "",
    )
}

pub(crate) fn prune_html(html: &str) -> String {
    let mut cleaned = html.replace('\n', " ");
    while let Some(start) = cleaned.find("<!--") {
        let Some(end_rel) = cleaned[start..].find("-->") else {
            break;
        };
        let end = start + end_rel + 3;
        cleaned.replace_range(start..end, "");
    }

    let document = kuchiki::parse_html().one(cleaned);
    let mut elements = document
        .descendants()
        .filter(|node| node.as_element().is_some())
        .collect::<Vec<_>>();
    elements.reverse();

    for node in elements {
        let Some(element) = node.as_element() else {
            continue;
        };

        let tag_name = element.name.local.to_string().to_ascii_lowercase();
        match tag_name.as_str() {
            "html" | "body" => unwrap_html_node(&node),
            "style" | "link" | "script" | "br" => node.detach(),
            "div" | "span" | "i" | "p" => {
                let attributes = element.attributes.borrow();
                let has_bid_only = attributes.map.len() == 1
                    && attributes
                        .map
                        .keys()
                        .next()
                        .is_some_and(|name| name.local.as_ref() == "bid");
                drop(attributes);

                if has_bid_only {
                    if node.children().next().is_none() {
                        node.detach();
                    } else {
                        unwrap_html_node(&node);
                    }
                }
            }
            _ => {}
        }
    }

    pretty_format_html(&serialize_html_fragment(&document))
}

#[cfg(test)]
mod tests {
    use super::{
        flatten_ax_tree_to_string, flatten_dom_snapshot_to_string, prune_html,
        BrowserGymAxFlattenOptions, BrowserGymDomFlattenOptions,
    };
    use crate::browser::dom_ops::browsergym::{
        cleanup_ax_tree_browsergym_ids, extract_browsergym_extra_properties,
    };
    use chromiumoxide::cdp::browser_protocol::accessibility::{
        AxNode, AxProperty, AxPropertyName, AxValue, AxValueType,
    };
    use chromiumoxide::cdp::browser_protocol::dom::BackendNodeId;
    use chromiumoxide::cdp::browser_protocol::dom_snapshot::{
        ArrayOfStrings, CaptureSnapshotReturns, DocumentSnapshot, LayoutTreeSnapshot,
        NodeTreeSnapshot, RareBooleanData, Rectangle, StringIndex, TextBoxSnapshot,
    };
    use std::collections::HashMap;
    fn ax_string(value: &str) -> AxValue {
        AxValue::builder()
            .r#type(AxValueType::String)
            .value(serde_json::Value::String(value.to_string()))
            .build()
            .expect("ax string")
    }

    fn dom_snapshot() -> CaptureSnapshotReturns {
        let strings = vec![
            "".to_string(),
            "html".to_string(),
            "body".to_string(),
            "input".to_string(),
            "#text".to_string(),
            "bid".to_string(),
            "n1".to_string(),
            "type".to_string(),
            "checkbox".to_string(),
            "browsergym_visibility_ratio".to_string(),
            "1".to_string(),
            "browsergym_set_of_marks".to_string(),
            "Text within a non-html tag".to_string(),
        ];

        let document = DocumentSnapshot::builder()
            .document_url(StringIndex::new(0))
            .title(StringIndex::new(0))
            .base_url(StringIndex::new(0))
            .content_language(StringIndex::new(0))
            .encoding_name(StringIndex::new(0))
            .public_id(StringIndex::new(0))
            .system_id(StringIndex::new(0))
            .frame_id(StringIndex::new(0))
            .nodes(
                NodeTreeSnapshot::builder()
                    .parent_indexs(vec![-1, 0, 1, 2, 2])
                    .node_types(vec![9, 1, 1, 1, 3])
                    .node_names(vec![
                        StringIndex::new(1),
                        StringIndex::new(1),
                        StringIndex::new(2),
                        StringIndex::new(3),
                        StringIndex::new(4),
                    ])
                    .node_values(vec![
                        StringIndex::new(0),
                        StringIndex::new(0),
                        StringIndex::new(0),
                        StringIndex::new(0),
                        StringIndex::new(12),
                    ])
                    .backend_node_ids(vec![
                        BackendNodeId::new(1),
                        BackendNodeId::new(2),
                        BackendNodeId::new(3),
                        BackendNodeId::new(4),
                        BackendNodeId::new(5),
                    ])
                    .attributes(vec![
                        ArrayOfStrings::new(Vec::<StringIndex>::new()),
                        ArrayOfStrings::new(Vec::<StringIndex>::new()),
                        ArrayOfStrings::new(Vec::<StringIndex>::new()),
                        ArrayOfStrings::new(vec![
                            StringIndex::new(5),
                            StringIndex::new(6),
                            StringIndex::new(7),
                            StringIndex::new(8),
                            StringIndex::new(9),
                            StringIndex::new(10),
                            StringIndex::new(11),
                            StringIndex::new(10),
                        ]),
                        ArrayOfStrings::new(Vec::<StringIndex>::new()),
                    ])
                    .is_clickable(
                        RareBooleanData::builder()
                            .index(3)
                            .build()
                            .expect("clickable"),
                    )
                    .build(),
            )
            .layout(
                LayoutTreeSnapshot::builder()
                    .node_indexs(vec![3])
                    .styles(vec![ArrayOfStrings::new(Vec::<StringIndex>::new())])
                    .bounds(vec![Rectangle::new(vec![10.0, 20.0, 100.0, 30.0])])
                    .texts(vec![StringIndex::new(0)])
                    .stacking_contexts(RareBooleanData::new(Vec::new()))
                    .paint_orders(vec![1])
                    .offset_rects(vec![Rectangle::new(vec![10.0, 20.0, 100.0, 30.0])])
                    .scroll_rects(vec![Rectangle::new(vec![0.0, 0.0, 100.0, 30.0])])
                    .client_rects(vec![Rectangle::new(vec![0.0, 0.0, 100.0, 30.0])])
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
            .content_width(800.0)
            .content_height(600.0)
            .build()
            .expect("document");

        CaptureSnapshotReturns::new(vec![document], strings)
    }

    #[test]
    fn flatten_dom_snapshot_renders_browsergym_metadata() {
        let snapshot = dom_snapshot();
        let extra = extract_browsergym_extra_properties(&snapshot);
        let html = flatten_dom_snapshot_to_string(
            &snapshot,
            Some(&extra),
            &BrowserGymDomFlattenOptions {
                with_visible: true,
                with_clickable: true,
                with_center_coords: true,
                with_bounding_box_coords: true,
                with_som: true,
                ..Default::default()
            },
        );

        assert!(html.contains("center=\"(60,35)\""));
        assert!(html.contains("box=\"(10,20,110,50)\""));
        assert!(html.contains("clickable"));
        assert!(html.contains("som"));
        assert!(html.contains("Text within a non-html tag"));
        assert!(html.contains("\n <html>") || html.starts_with("<html>"));
        let box_idx = html.find("box=\"(10,20,110,50)\"").expect("box attr");
        let center_idx = html.find("center=\"(60,35)\"").expect("center attr");
        let clickable_idx = html.find("clickable").expect("clickable attr");
        let visible_idx = html.find("visible").expect("visible attr");
        let som_idx = html.find("som").expect("som attr");
        let input_idx = html.find("<input").expect("input");
        let self_close_idx = html[input_idx..].find("/>").expect("self close") + input_idx;
        let text_idx = html
            .find("Text within a non-html tag")
            .expect("inline text");
        assert!(box_idx < center_idx);
        assert!(center_idx < clickable_idx);
        assert!(clickable_idx < visible_idx);
        assert!(visible_idx < som_idx);
        assert!(self_close_idx < text_idx);
    }

    #[test]
    fn prune_html_matches_browsergym_unwrap_and_decompose_rules() {
        let pruned = prune_html(
            r#"<html><body><div bid="1"><span bid="2">Hello</span></div><style>ignored</style><script>ignored</script><link rel="stylesheet" href="/x.css"><br><p bid="3"></p><p bid="4">World</p><section><b>Keep</b></section><!-- removed --></body></html>"#,
        );

        assert_eq!(
            pruned,
            "<head>\n</head>\nHelloWorld\n<section>\n <b>\n  Keep\n </b>\n</section>"
        );
    }

    #[test]
    fn flatten_ax_tree_renders_browsergym_ids() {
        let mut nodes = vec![
            AxNode::builder()
                .node_id("root".to_string())
                .ignored(false)
                .role(ax_string("RootWebArea"))
                .name(ax_string("Page"))
                .child_id("child".to_string())
                .build()
                .expect("root"),
            AxNode::builder()
                .node_id("child".to_string())
                .ignored(false)
                .role(ax_string("button"))
                .name(ax_string("Submit"))
                .propertie(
                    AxProperty::builder()
                        .name(AxPropertyName::Focused)
                        .value(ax_string("true"))
                        .build()
                        .expect("prop"),
                )
                .description(ax_string("browsergym_id_n1"))
                .build()
                .expect("child"),
        ];

        let ids = cleanup_ax_tree_browsergym_ids(&mut nodes);
        let snapshot = dom_snapshot();
        let extra = extract_browsergym_extra_properties(&snapshot);
        let text = flatten_ax_tree_to_string(
            &nodes,
            &ids,
            Some(&extra),
            &BrowserGymAxFlattenOptions {
                with_visible: true,
                with_clickable: true,
                with_center_coords: true,
                with_bounding_box_coords: true,
                with_som: true,
                ..Default::default()
            },
        );

        assert!(text.contains("[n1] button \"Submit\""));
        assert!(text.contains("focused"));
        assert!(text.contains("center=\"(60,35)\""));
        assert!(text.contains("box=\"(10,20,110,50)\""));
    }

    #[test]
    fn flatten_ax_tree_skips_nodes_without_names_like_browsergym() {
        let nodes = vec![
            AxNode::builder()
                .node_id("root".to_string())
                .ignored(false)
                .role(ax_string("RootWebArea"))
                .name(ax_string("Page"))
                .child_id("child".to_string())
                .build()
                .expect("root"),
            AxNode::builder()
                .node_id("child".to_string())
                .ignored(false)
                .role(ax_string("button"))
                .build()
                .expect("child"),
        ];

        let text = flatten_ax_tree_to_string(
            &nodes,
            &HashMap::new(),
            None,
            &BrowserGymAxFlattenOptions::default(),
        );

        assert!(!text.contains("button"));
    }
}
