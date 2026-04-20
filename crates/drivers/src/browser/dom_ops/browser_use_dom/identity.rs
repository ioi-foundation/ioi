use super::BrowserUseDomTreeNode;
use ioi_crypto::algorithms::hash::sha256;
use std::collections::HashMap;

const STATIC_ATTRIBUTES: &[&str] = &[
    "class",
    "id",
    "name",
    "type",
    "placeholder",
    "aria-label",
    "title",
    "role",
    "data-testid",
    "data-test",
    "data-cy",
    "data-selenium",
    "for",
    "required",
    "disabled",
    "readonly",
    "checked",
    "selected",
    "multiple",
    "accept",
    "href",
    "target",
    "rel",
    "aria-describedby",
    "aria-labelledby",
    "aria-controls",
    "aria-owns",
    "aria-live",
    "aria-atomic",
    "aria-busy",
    "aria-disabled",
    "aria-hidden",
    "aria-pressed",
    "aria-autocomplete",
    "aria-checked",
    "aria-selected",
    "list",
    "tabindex",
    "alt",
    "src",
    "lang",
    "itemscope",
    "itemtype",
    "itemprop",
    "pseudo",
    "aria-valuemin",
    "aria-valuemax",
    "aria-valuenow",
    "aria-placeholder",
];

const DYNAMIC_CLASS_PATTERNS: &[&str] = &[
    "focus",
    "hover",
    "active",
    "selected",
    "disabled",
    "animation",
    "transition",
    "loading",
    "open",
    "closed",
    "expanded",
    "collapsed",
    "visible",
    "hidden",
    "pressed",
    "checked",
    "highlighted",
    "current",
    "entering",
    "leaving",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BrowserUseElementIdentity {
    pub(crate) x_path: Option<String>,
    pub(crate) element_hash: Option<u64>,
    pub(crate) stable_hash: Option<u64>,
    pub(crate) parent_branch_hash: Option<u64>,
    pub(crate) ax_name: Option<String>,
}

fn trimmed_attr<'a>(node: &'a BrowserUseDomTreeNode, key: &str) -> Option<&'a str> {
    node.attributes
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn filter_dynamic_classes(class_str: Option<&str>) -> Option<String> {
    let class_str = class_str?;
    let mut stable = class_str
        .split_whitespace()
        .filter(|class_name| {
            !DYNAMIC_CLASS_PATTERNS
                .iter()
                .any(|pattern| class_name.to_ascii_lowercase().contains(pattern))
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    stable.sort();
    stable.dedup();
    (!stable.is_empty()).then(|| stable.join(" "))
}

fn hash_prefix_u64(value: &str) -> Option<u64> {
    let digest = sha256(value.as_bytes()).ok()?;
    let prefix = digest.get(..8)?;
    let bytes: [u8; 8] = prefix.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn sibling_position(siblings: &[BrowserUseDomTreeNode], index: usize, tag_name: &str) -> usize {
    let same_tag_indices = siblings
        .iter()
        .enumerate()
        .filter(|(_, sibling)| {
            sibling.node_type == 1
                && sibling
                    .tag_name()
                    .as_deref()
                    .is_some_and(|candidate| candidate == tag_name)
        })
        .map(|(sibling_index, _)| sibling_index)
        .collect::<Vec<_>>();

    if same_tag_indices.len() <= 1 {
        return 0;
    }

    same_tag_indices
        .iter()
        .position(|sibling_index| *sibling_index == index)
        .map(|position| position + 1)
        .unwrap_or(0)
}

fn static_attributes_string(
    node: &BrowserUseDomTreeNode,
    filter_dynamic_class_state: bool,
) -> String {
    let mut attrs = Vec::new();
    for key in STATIC_ATTRIBUTES {
        let Some(raw_value) = trimmed_attr(node, key) else {
            continue;
        };

        let value = if *key == "class" && filter_dynamic_class_state {
            let Some(filtered) = filter_dynamic_classes(Some(raw_value)) else {
                continue;
            };
            filtered
        } else {
            raw_value.to_string()
        };
        attrs.push(((*key).to_string(), value));
    }

    attrs.sort_by(|left, right| left.0.cmp(&right.0));
    attrs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<String>()
}

fn accessible_name(node: &BrowserUseDomTreeNode) -> Option<String> {
    node.ax_data
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn record_identity(
    node: &BrowserUseDomTreeNode,
    branch_path: &[String],
    xpath_segments: &[String],
    out: &mut HashMap<(String, i64), BrowserUseElementIdentity>,
) {
    let Some(backend_node_id) = node.backend_node_id else {
        return;
    };

    let parent_branch_path_string = branch_path.join("/");
    let ax_name = accessible_name(node);
    let ax_name_suffix = ax_name
        .as_deref()
        .map(|name| format!("|ax_name={name}"))
        .unwrap_or_default();

    let element_hash = hash_prefix_u64(&format!(
        "{parent_branch_path_string}|{}{}",
        static_attributes_string(node, false),
        ax_name_suffix
    ));
    let stable_hash = hash_prefix_u64(&format!(
        "{parent_branch_path_string}|{}{}",
        static_attributes_string(node, true),
        ax_name_suffix
    ));
    let parent_branch_hash = hash_prefix_u64(&parent_branch_path_string);

    out.insert(
        (node.target_id.clone(), backend_node_id),
        BrowserUseElementIdentity {
            x_path: (!xpath_segments.is_empty()).then(|| xpath_segments.join("/")),
            element_hash,
            stable_hash,
            parent_branch_hash,
            ax_name,
        },
    );
}

fn collect_from_siblings(
    siblings: &[BrowserUseDomTreeNode],
    branch_prefix: &[String],
    xpath_prefix: &[String],
    out: &mut HashMap<(String, i64), BrowserUseElementIdentity>,
) {
    for (index, node) in siblings.iter().enumerate() {
        collect_node(node, siblings, index, branch_prefix, xpath_prefix, out);
    }
}

fn collect_node(
    node: &BrowserUseDomTreeNode,
    siblings: &[BrowserUseDomTreeNode],
    sibling_index: usize,
    branch_prefix: &[String],
    xpath_prefix: &[String],
    out: &mut HashMap<(String, i64), BrowserUseElementIdentity>,
) {
    match node.node_type {
        1 => {
            let tag_name = node.tag_name().unwrap_or_else(|| node.node_name_for_text());
            let position = sibling_position(siblings, sibling_index, &tag_name);
            let xpath_segment = if position > 0 {
                format!("{tag_name}[{position}]")
            } else {
                tag_name.clone()
            };

            let mut next_branch = branch_prefix.to_vec();
            next_branch.push(tag_name);
            let mut next_xpath = xpath_prefix.to_vec();
            next_xpath.push(xpath_segment);

            record_identity(node, &next_branch, &next_xpath, out);

            for shadow_root in &node.shadow_roots {
                collect_node(
                    shadow_root,
                    &node.shadow_roots,
                    0,
                    &next_branch,
                    &next_xpath,
                    out,
                );
            }
            collect_from_siblings(&node.children, &next_branch, &next_xpath, out);
            if let Some(content_document) = node.content_document.as_deref() {
                collect_node(content_document, &[], 0, &[], &[], out);
            }
        }
        9 => {
            collect_from_siblings(&node.children, branch_prefix, xpath_prefix, out);
        }
        11 => {
            collect_from_siblings(&node.children, branch_prefix, xpath_prefix, out);
        }
        _ => {
            collect_from_siblings(&node.children, branch_prefix, xpath_prefix, out);
        }
    }
}

pub(crate) fn build_browser_use_element_identity_map(
    root: &BrowserUseDomTreeNode,
) -> HashMap<(String, i64), BrowserUseElementIdentity> {
    let mut identities = HashMap::new();
    collect_node(root, &[], 0, &[], &[], &mut identities);
    identities
}

#[cfg(test)]
#[path = "identity/tests.rs"]
mod tests;
