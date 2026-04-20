use super::render_browser_use_html_from_tree;
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
fn html_serializer_includes_shadow_dom_and_iframe_documents() {
    let mut root = node(9, "#document");
    let mut host = node(1, "DIV");
    host.attribute_pairs
        .push(("id".to_string(), "host".to_string()));
    host.attributes.insert("id".to_string(), "host".to_string());

    let mut shadow_root = node(11, "#document-fragment");
    shadow_root.shadow_root_type = Some("open".to_string());
    let mut shadow_button = node(1, "BUTTON");
    shadow_button.children.push(BrowserUseDomTreeNode {
        node_type: 3,
        node_name: "#text".to_string(),
        node_value: Some("Shadow".to_string()),
        ..node(3, "#text")
    });
    shadow_root.children.push(shadow_button);
    host.shadow_roots.push(shadow_root);
    let mut light_span = node(1, "SPAN");
    light_span.children.push(BrowserUseDomTreeNode {
        node_type: 3,
        node_name: "#text".to_string(),
        node_value: Some("Light".to_string()),
        ..node(3, "#text")
    });
    host.children.push(light_span);

    let mut iframe = node(1, "IFRAME");
    let mut content_document = node(9, "#document");
    let mut paragraph = node(1, "P");
    paragraph.children.push(BrowserUseDomTreeNode {
        node_type: 3,
        node_name: "#text".to_string(),
        node_value: Some("Iframe body".to_string()),
        ..node(3, "#text")
    });
    content_document.children.push(paragraph);
    iframe.content_document = Some(Box::new(content_document));

    root.children = vec![host, iframe];

    let html = render_browser_use_html_from_tree(&root, false).expect("html");
    assert_eq!(
        html,
        r#"<div id="host"><template shadowroot="open"><button>Shadow</button></template><span>Light</span></div><iframe><p>Iframe body</p></iframe>"#
    );
}

#[test]
fn html_serializer_drops_data_attributes_and_optional_links() {
    let mut root = node(9, "#document");
    let mut link = node(1, "A");
    link.attribute_pairs
        .push(("href".to_string(), "https://example.com".to_string()));
    link.attributes
        .insert("href".to_string(), "https://example.com".to_string());
    link.attribute_pairs
        .push(("data-state".to_string(), "{\"a\":1}".to_string()));
    link.attributes
        .insert("data-state".to_string(), "{\"a\":1}".to_string());
    link.children.push(BrowserUseDomTreeNode {
        node_type: 3,
        node_name: "#text".to_string(),
        node_value: Some("Example".to_string()),
        ..node(3, "#text")
    });
    root.children.push(link);

    let html = render_browser_use_html_from_tree(&root, false).expect("html");
    assert_eq!(html, "<a>Example</a>");
}

#[test]
fn html_serializer_preserves_attribute_order_when_links_are_enabled() {
    let mut root = node(9, "#document");
    let mut link = node(1, "A");
    for (key, value) in [
        ("title", "Docs"),
        ("href", "https://example.com"),
        ("rel", "noopener"),
        ("data-state", "{\"a\":1}"),
    ] {
        link.attribute_pairs
            .push((key.to_string(), value.to_string()));
        link.attributes.insert(key.to_string(), value.to_string());
    }
    link.children.push(BrowserUseDomTreeNode {
        node_type: 3,
        node_name: "#text".to_string(),
        node_value: Some("Example".to_string()),
        ..node(3, "#text")
    });
    root.children.push(link);

    let html = render_browser_use_html_from_tree(&root, true).expect("html");
    assert_eq!(
        html,
        r#"<a title="Docs" href="https://example.com" rel="noopener">Example</a>"#
    );
}
