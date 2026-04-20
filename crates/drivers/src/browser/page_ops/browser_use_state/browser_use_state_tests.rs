use super::{
    browser_use_pending_request_default_method, browser_use_short_target_id,
    render_browser_use_page_info_text, render_browser_use_pending_requests_text,
    render_browser_use_tabs_text, BrowserUsePageInfo, BrowserUsePendingRequest,
};
use crate::browser::BrowserTabInfo;

#[test]
fn renders_tabs_page_info_and_pending_requests_as_pretty_json() {
    let tabs = vec![BrowserTabInfo {
        tab_id: "target-ab-1".to_string(),
        title: "Example".to_string(),
        url: "https://example.com".to_string(),
        active: true,
    }];
    let page_info = BrowserUsePageInfo {
        viewport_width: 1280,
        viewport_height: 720,
        page_width: 2400,
        page_height: 3600,
        scroll_x: 0,
        scroll_y: 400,
        pixels_above: 400,
        pixels_below: 2480,
        pixels_left: 0,
        pixels_right: 1120,
    };
    let requests = vec![BrowserUsePendingRequest {
        url: "https://cdn.example.com/app.js".to_string(),
        method: browser_use_pending_request_default_method(),
        loading_duration_ms: 812,
        resource_type: Some("script".to_string()),
    }];

    let tabs_text = render_browser_use_tabs_text(&tabs).expect("tabs json");
    let page_info_text = render_browser_use_page_info_text(&page_info).expect("page info json");
    let requests_text =
        render_browser_use_pending_requests_text(&requests).expect("pending requests json");

    assert!(tabs_text.contains("\"tab_id\": \"ab-1\""));
    assert!(!tabs_text.contains("\"active\": true"));
    assert!(page_info_text.contains("\"pixels_below\": 2480"));
    assert!(requests_text.contains("\"resource_type\": \"script\""));
}

#[test]
fn browser_use_short_target_id_keeps_last_four_characters() {
    assert_eq!(browser_use_short_target_id("target-0001"), "0001");
    assert_eq!(browser_use_short_target_id("abc"), "abc");
}
