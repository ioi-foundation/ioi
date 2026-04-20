use super::render_browser_use_eval_from_tree;
use crate::browser::dom_ops::browser_use_dom::BrowserUseDomTreeNode;
use std::collections::HashMap;

fn node(node_type: i64, node_name: &str) -> BrowserUseDomTreeNode {
    BrowserUseDomTreeNode {
        target_id: "target".to_string(),
        frame_id: None,
        backend_node_id: None,
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
        ax_data: Default::default(),
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
fn eval_serializer_includes_backend_ids_and_iframe_content() {
    let mut root = node(9, "#document");
    let mut button = node(1, "BUTTON");
    button.backend_node_id = Some(7);
    button.assigned_interactive = true;
    button.snapshot = Some(Default::default());
    button
        .attributes
        .insert("type".to_string(), "button".to_string());
    button.children.push(BrowserUseDomTreeNode {
        node_type: 3,
        node_name: "#text".to_string(),
        node_value: Some("Save".to_string()),
        ..node(3, "#text")
    });

    let mut iframe = node(1, "IFRAME");
    iframe.snapshot = Some(Default::default());
    let mut content_document = node(9, "#document");
    let mut html = node(1, "HTML");
    let mut body = node(1, "BODY");
    let mut heading = node(1, "H2");
    heading.children.push(BrowserUseDomTreeNode {
        node_type: 3,
        node_name: "#text".to_string(),
        node_value: Some("Inside frame".to_string()),
        ..node(3, "#text")
    });
    body.children.push(heading);
    html.children.push(body);
    content_document.children.push(html);
    iframe.content_document = Some(Box::new(content_document));

    root.children = vec![button, iframe];

    let text = render_browser_use_eval_from_tree(&root).expect("eval");
    assert!(text.contains("[i_7] <button type=\"button\">Save"));
    assert!(text.contains("<iframe />"));
    assert!(text.contains("#iframe-content"));
    assert!(text.contains("<h2>Inside frame"));
}
