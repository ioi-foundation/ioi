use super::{append_browser_snapshot_supplement, render_browser_use_prompt_context_section};
use ioi_drivers::browser::BrowserObservationArtifacts;
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use std::collections::HashMap;
use std::time::Instant;

fn node(
    role: &str,
    name: Option<&str>,
    attrs: &[(&str, &str)],
    som_id: Option<u32>,
) -> AccessibilityNode {
    AccessibilityNode {
        id: format!("node-{role}"),
        role: role.to_string(),
        name: name.map(str::to_string),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        },
        children: Vec::new(),
        is_visible: true,
        attributes: attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
        som_id,
    }
}

#[test]
fn append_browser_snapshot_supplement_includes_selector_and_browsergym_sections() {
    let tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: None,
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
        },
        children: vec![node(
            "button",
            Some("Submit"),
            &[
                ("tag_name", "button"),
                ("dom_id", "submit"),
                ("focused", "true"),
            ],
            Some(3),
        )],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };
    let artifacts = BrowserObservationArtifacts {
        captured_at: Instant::now(),
        url: None,
        page_title: Some("Example".to_string()),
        browser_use_state_text: Some("[3]<button name=Submit />".to_string()),
        browser_use_selector_map_text: Some("[3] <button name=Submit dom_id=submit />".to_string()),
        browser_use_html_text: Some("<button id=\"submit\">Submit</button>".to_string()),
        browser_use_eval_text: Some("[i_4] <button id=\"submit\">Submit".to_string()),
        browser_use_markdown_text: Some("Submit".to_string()),
        browser_use_pagination_text: Some(
            "[3] type=next text=\"Next\" disabled=false backend_dom_node_id=88".to_string(),
        ),
        browser_use_tabs_text: Some(
            "[\n  {\n    \"tab_id\": \"tab-1\",\n    \"title\": \"Example\",\n    \"url\": \"https://example.com\",\n    \"active\": true\n  }\n]"
                .to_string(),
        ),
        browser_use_page_info_text: Some(
            "{\n  \"viewport_width\": 1280,\n  \"viewport_height\": 720,\n  \"page_width\": 2400,\n  \"page_height\": 3600,\n  \"scroll_x\": 0,\n  \"scroll_y\": 400,\n  \"pixels_above\": 400,\n  \"pixels_below\": 2480,\n  \"pixels_left\": 0,\n  \"pixels_right\": 1120\n}"
                .to_string(),
        ),
        browser_use_pending_requests_text: Some(
            "[\n  {\n    \"url\": \"https://cdn.example.com/app.js\",\n    \"method\": \"GET\",\n    \"loading_duration_ms\": 812,\n    \"resource_type\": \"script\"\n  }\n]"
                .to_string(),
        ),
        browser_use_recent_events_text: Some(
            "[{\"event_type\":\"NavigateToUrlEvent\",\"timestamp\":\"2026-03-25T00:00:00Z\",\"url\":\"https://example.com\"}]".to_string(),
        ),
        browser_use_closed_popup_messages_text: Some(
            "[\n  \"[alert] Example popup\"\n]".to_string(),
        ),
        browsergym_extra_properties_text: Some(
            "{\n  \"a1\": {\n    \"visibility\": 1.0,\n    \"bbox\": [0, 0, 10, 10],\n    \"clickable\": true,\n    \"set_of_marks\": true\n  }\n}"
                .to_string(),
        ),
        browsergym_focused_bid: Some("a1".to_string()),
        browsergym_dom_text: Some("<button bid=\"a1\">Submit</button>".to_string()),
        browsergym_axtree_text: Some("[a1] button \"Submit\"".to_string()),
    };

    let output = append_browser_snapshot_supplement(
        "<root id=\"root\" rect=\"0,0,1,1\" />",
        &tree,
        &tree,
        Some(&artifacts),
    );

    assert!(output.contains("BROWSER_USE_STATE_TXT:"));
    assert!(output.contains("BROWSER_USE_PROMPT_CONTEXT_TXT:"));
    assert!(output.contains("<page_stats>"));
    assert!(output.contains("Available tabs:"));
    assert!(output.contains("Recent browser events:"));
    assert!(output.contains("Auto-closed JavaScript dialogs:"));
    assert!(output.contains("Interactive elements:"));
    assert!(output.contains("BROWSER_USE_SELECTOR_MAP:"));
    assert!(output.contains("BROWSER_USE_EVAL_TXT:"));
    assert!(output.contains("BROWSER_USE_MARKDOWN:"));
    assert!(output.contains("BROWSER_USE_PAGINATION_TXT:"));
    assert!(output.contains("BROWSER_USE_TABS_JSON:"));
    assert!(output.contains("BROWSER_USE_PAGE_INFO_JSON:"));
    assert!(output.contains("BROWSER_USE_PENDING_REQUESTS_JSON:"));
    assert!(output.contains("BROWSER_USE_RECENT_EVENTS_JSON:"));
    assert!(output.contains("BROWSER_USE_CLOSED_POPUP_MESSAGES_JSON:"));
    assert!(output.contains("BROWSER_USE_HTML:"));
    assert!(output.contains("[3] <button name=Submit dom_id=submit />"));
    assert!(output.contains("BROWSERGYM_EXTRA_PROPERTIES_JSON:"));
    assert!(output.contains("BROWSERGYM_FOCUSED_BID:"));
    assert!(output.contains("BROWSERGYM_AXTREE_TXT:"));
    assert!(output.contains("BROWSERGYM_DOM_TXT:"));
}

#[test]
fn browser_use_prompt_context_matches_browser_use_layout() {
    let artifacts = BrowserObservationArtifacts {
        captured_at: Instant::now(),
        url: Some("https://example.com".to_string()),
        page_title: Some("Example".to_string()),
        browser_use_state_text: Some("[3]<button name=Submit />".to_string()),
        browser_use_selector_map_text: Some("[3] <button name=Submit dom_id=submit />".to_string()),
        browser_use_html_text: Some("<button id=\"submit\">Submit</button>".to_string()),
        browser_use_eval_text: None,
        browser_use_markdown_text: None,
        browser_use_pagination_text: None,
        browser_use_tabs_text: Some(
            "[\n  {\n    \"tab_id\": \"tab-1\",\n    \"title\": \"Example\",\n    \"url\": \"https://example.com\",\n    \"active\": true\n  }\n]"
                .to_string(),
        ),
        browser_use_page_info_text: Some(
            "{\n  \"viewport_width\": 1280,\n  \"viewport_height\": 720,\n  \"page_width\": 2400,\n  \"page_height\": 3600,\n  \"scroll_x\": 0,\n  \"scroll_y\": 400,\n  \"pixels_above\": 400,\n  \"pixels_below\": 2480,\n  \"pixels_left\": 0,\n  \"pixels_right\": 1120\n}"
                .to_string(),
        ),
        browser_use_pending_requests_text: None,
        browser_use_recent_events_text: Some(
            "[{\"event_type\":\"NavigateToUrlEvent\",\"timestamp\":\"2026-03-25T00:00:00Z\",\"url\":\"https://example.com\"}]".to_string(),
        ),
        browser_use_closed_popup_messages_text: Some(
            "[\n  \"[alert] Example popup\"\n]".to_string(),
        ),
        browsergym_extra_properties_text: None,
        browsergym_focused_bid: None,
        browsergym_dom_text: None,
        browsergym_axtree_text: None,
    };

    let rendered = render_browser_use_prompt_context_section(
        Some(&artifacts),
        artifacts.browser_use_state_text.as_deref().unwrap(),
    )
    .expect("prompt context");

    let expected = concat!(
        "<page_stats>Page appears empty (SPA not loaded?) - 0 links, 1 interactive, 0 iframes, 1 total elements</page_stats>\n",
        "Current tab: ab-1\n",
        "Available tabs:\n",
        "Tab ab-1: https://example.com - Example\n",
        "\n",
        "<page_info>0.6 pages above, 3.4 pages below — scroll down to reveal more content</page_info>\n",
        "\n",
        "Recent browser events: [{\"event_type\":\"NavigateToUrlEvent\",\"timestamp\":\"2026-03-25T00:00:00Z\",\"url\":\"https://example.com\"}]\n",
        "Auto-closed JavaScript dialogs:\n",
        "  - [alert] Example popup\n",
        "\n",
        "Interactive elements:\n",
        "[3]<button name=Submit />\n"
    );

    assert_eq!(rendered, expected);
}
