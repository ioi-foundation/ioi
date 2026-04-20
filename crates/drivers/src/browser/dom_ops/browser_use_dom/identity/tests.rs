use super::build_browser_use_element_identity_map;
use crate::browser::dom_ops::browser_use_dom::{BrowserUseAxData, BrowserUseDomTreeNode};
use std::collections::HashMap;

fn node(node_type: i64, node_name: &str, backend_node_id: Option<i64>) -> BrowserUseDomTreeNode {
    BrowserUseDomTreeNode {
        target_id: "target-1".to_string(),
        frame_id: None,
        backend_node_id,
        node_type,
        node_name: node_name.to_string(),
        node_value: None,
        attribute_pairs: Vec::new(),
        attributes: HashMap::new(),
        snapshot: None,
        rect: None,
        visibility_ratio: None,
        is_visible: true,
        has_js_click_listener: false,
        ax_data: BrowserUseAxData::default(),
        som_id: None,
        shadow_root_type: None,
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
    }
}

#[test]
fn identity_map_builds_xpath_and_hashes_for_shadow_dom_children() {
    let mut root = node(9, "#document", None);
    let mut host = node(1, "DIV", Some(10));
    host.attributes.insert("id".to_string(), "host".to_string());
    let mut shadow_root = node(11, "#document-fragment", None);
    let mut button = node(1, "BUTTON", Some(11));
    button.ax_data.name = Some("Shadow Button".to_string());
    button
        .attributes
        .insert("class".to_string(), "menu-item is-active".to_string());
    shadow_root.children.push(button);
    host.shadow_roots.push(shadow_root);
    root.children.push(host);

    let identities = build_browser_use_element_identity_map(&root);
    let identity = identities
        .get(&("target-1".to_string(), 11))
        .expect("button identity");

    assert_eq!(identity.x_path.as_deref(), Some("div/button"));
    assert_eq!(identity.ax_name.as_deref(), Some("Shadow Button"));
    assert!(identity.element_hash.is_some());
    assert!(identity.stable_hash.is_some());
    assert_ne!(identity.element_hash, identity.stable_hash);
}

#[test]
fn identity_map_resets_xpath_inside_iframe_content_documents() {
    let mut root = node(9, "#document", None);
    let mut iframe = node(1, "IFRAME", Some(20));
    let mut iframe_doc = node(9, "#document", None);
    let mut html = node(1, "HTML", Some(21));
    let body = node(1, "BODY", Some(22));
    html.children.push(body);
    iframe_doc.children.push(html);
    iframe.content_document = Some(Box::new(iframe_doc));
    root.children.push(iframe);

    let identities = build_browser_use_element_identity_map(&root);
    let body_identity = identities
        .get(&("target-1".to_string(), 22))
        .expect("body identity");

    assert_eq!(body_identity.x_path.as_deref(), Some("html/body"));
}
