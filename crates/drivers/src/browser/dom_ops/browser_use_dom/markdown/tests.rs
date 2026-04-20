use super::{
    chunk_markdown_by_structure, extract_clean_markdown_from_html,
    render_markdown_from_tree_with_options, MarkdownRenderOptions,
};
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
fn markdown_extractor_removes_large_json_blobs() {
    let html = r#"<html><body><p>Hello</p><code style="display:none">{"$type":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}</code></body></html>"#;
    let markdown = extract_clean_markdown_from_html(html).expect("markdown");
    assert!(markdown.contains("Hello"));
    assert!(!markdown.contains("$type"));
}

#[test]
fn chunk_markdown_preserves_table_headers_in_overlap() {
    let markdown = [
        "# Report",
        "",
        "| Name | Value |",
        "| --- | --- |",
        "| Alpha | 1 |",
        "| Beta | 2 |",
        "| Gamma | 3 |",
    ]
    .join("\n");

    let chunks = chunk_markdown_by_structure(&markdown, 55, 2, 0);
    assert!(chunks.len() >= 2);
    assert!(chunks[1].overlap_prefix.contains("| Name | Value |"));
    assert!(chunks[1].overlap_prefix.contains("| --- | --- |"));
}

#[test]
fn tree_markdown_excludes_table_cell_image_urls_by_default() {
    let mut root = node(9, "#document");
    let mut table = node(1, "TABLE");
    let mut row = node(1, "TR");
    let mut cell = node(1, "TD");
    let mut img = node(1, "IMG");
    img.attributes.insert(
        "src".to_string(),
        "http://localhost/images/widget-a.jpg".to_string(),
    );
    img.attributes
        .insert("alt".to_string(), "Widget A".to_string());
    cell.children.push(img);
    row.children.push(cell);
    table.children.push(row);
    root.children.push(table);

    let markdown = render_markdown_from_tree_with_options(&root, MarkdownRenderOptions::default())
        .expect("markdown");
    assert!(markdown.contains("Widget A"));
    assert!(!markdown.contains("widget-a.jpg"));
    assert!(!markdown.contains("!["));
}

#[test]
fn tree_markdown_includes_table_cell_image_urls_when_enabled() {
    let mut root = node(9, "#document");
    let mut table = node(1, "TABLE");
    let mut row = node(1, "TR");
    let mut cell = node(1, "TD");
    let mut img = node(1, "IMG");
    img.attributes.insert(
        "src".to_string(),
        "http://localhost/images/widget-a.jpg".to_string(),
    );
    img.attributes
        .insert("alt".to_string(), "Widget A".to_string());
    cell.children.push(img);
    row.children.push(cell);
    table.children.push(row);
    root.children.push(table);

    let markdown = render_markdown_from_tree_with_options(
        &root,
        MarkdownRenderOptions {
            extract_links: false,
            extract_images: true,
        },
    )
    .expect("markdown");
    assert!(markdown.contains("widget-a.jpg"));
    assert!(markdown.contains("![Widget A]"));
}

#[test]
fn tree_markdown_always_keeps_block_images() {
    let mut root = node(9, "#document");
    let mut div = node(1, "DIV");
    let mut img = node(1, "IMG");
    img.attributes.insert(
        "src".to_string(),
        "http://localhost/images/widget-a.jpg".to_string(),
    );
    img.attributes
        .insert("alt".to_string(), "Widget A".to_string());
    div.children.push(img);
    root.children.push(div);

    let markdown = render_markdown_from_tree_with_options(&root, MarkdownRenderOptions::default())
        .expect("markdown");
    assert!(markdown.contains("![Widget A](http://localhost/images/widget-a.jpg)"));
}

#[test]
fn tree_markdown_preserves_links_only_when_requested() {
    let mut root = node(9, "#document");
    let mut paragraph = node(1, "P");
    let mut link = node(1, "A");
    link.attributes
        .insert("href".to_string(), "https://example.com/docs".to_string());
    let mut text = node(3, "#text");
    text.node_value = Some("Docs".to_string());
    link.children.push(text);
    paragraph.children.push(link);
    root.children.push(paragraph);

    let without_links =
        render_markdown_from_tree_with_options(&root, MarkdownRenderOptions::default())
            .expect("markdown");
    assert_eq!(without_links, "Docs");

    let with_links = render_markdown_from_tree_with_options(
        &root,
        MarkdownRenderOptions {
            extract_links: true,
            extract_images: false,
        },
    )
    .expect("markdown");
    assert_eq!(with_links, "[Docs](https://example.com/docs)");
}
