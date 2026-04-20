use super::{browser_snapshot_payload, extract_browser_snapshot_xml};
use ioi_types::app::agentic::ChatMessage;

#[test]
fn extract_browser_snapshot_xml_strips_appended_selector_and_browsergym_sections() {
    let payload = concat!(
        "<root id=\"root\" rect=\"0,0,10,10\"><button id=\"btn_submit\" /></root>\n\n",
        "BROWSER_USE_PROMPT_CONTEXT_TXT:\n<page_stats>1 links, 2 interactive, 0 iframes, 3 total elements</page_stats>\n\n",
        "BROWSER_USE_SELECTOR_MAP:\n[1] <button name=\"Submit\" />\n\n",
        "BROWSER_USE_EVAL_TXT:\n[i_4] <button>Submit\n\n",
        "BROWSER_USE_MARKDOWN:\nSubmit\n\n",
        "BROWSER_USE_PAGINATION_TXT:\n[3] type=next text=\"Next\"\n\n",
        "BROWSER_USE_TABS_JSON:\n[{\"tab_id\":\"tab-1\"}]\n\n",
        "BROWSER_USE_PAGE_INFO_JSON:\n{\"viewport_width\":1280}\n\n",
        "BROWSER_USE_PENDING_REQUESTS_JSON:\n[{\"url\":\"https://cdn.example.com/app.js\"}]\n\n",
        "BROWSER_USE_HTML:\n<button>Submit</button>\n\n",
        "BROWSERGYM_EXTRA_PROPERTIES_JSON:\n{\"a1\":{\"visibility\":1.0}}\n\n",
        "BROWSERGYM_FOCUSED_BID:\na1\n\n",
        "BROWSERGYM_AXTREE_TXT:\n[a1] button \"Submit\""
    );

    assert_eq!(
        extract_browser_snapshot_xml(payload),
        Some("<root id=\"root\" rect=\"0,0,10,10\"><button id=\"btn_submit\" /></root>")
    );
}

#[test]
fn browser_snapshot_payload_returns_only_root_xml_when_tool_output_has_supplement() {
    let message = ChatMessage {
        role: "tool".to_string(),
        content: concat!(
            "Tool Output (browser__inspect): ",
            "<root id=\"root\" rect=\"0,0,10,10\"></root>\n\n",
            "BROWSER_USE_SELECTOR_MAP:\n[1] <button />"
        )
        .to_string(),
        timestamp: 0,
        trace_hash: None,
    };

    assert_eq!(
        browser_snapshot_payload(&message),
        Some("<root id=\"root\" rect=\"0,0,10,10\"></root>")
    );
}
