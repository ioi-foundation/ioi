use super::browser_use_state::render_browser_use_state_text;
use ioi_drivers::browser::BrowserObservationArtifacts;
use ioi_drivers::gui::accessibility::AccessibilityNode;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

const MAX_SNAPSHOT_SUPPLEMENT_SECTION_CHARS: usize = 40_000;

#[derive(Debug, Clone, Default)]
struct BrowserUsePageStats {
    links: usize,
    interactive_elements: usize,
    iframes: usize,
    shadow_open: usize,
    shadow_closed: usize,
    images: usize,
    total_elements: usize,
    text_chars: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct BrowserUsePageInfoSummary {
    viewport_height: usize,
    pixels_above: usize,
    pixels_below: usize,
}

fn html_open_tag_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?i)<([a-z][a-z0-9:_-]*)\b").expect("valid html tag regex"))
}

fn html_strip_tags_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?s)<[^>]+>").expect("valid html strip regex"))
}

fn node_attr<'a>(node: &'a AccessibilityNode, key: &str) -> Option<&'a str> {
    node.attributes
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn inline_value(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('"', "'")
}

fn push_selector_map_lines(node: &AccessibilityNode, out: &mut Vec<String>) {
    if let Some(som_id) = node.som_id {
        let tag = node_attr(node, "tag_name").unwrap_or(node.role.as_str());
        let mut parts = vec![format!("[{som_id}] <{tag}")];

        if !node.role.eq_ignore_ascii_case(tag) {
            parts.push(format!(r#"role="{}""#, inline_value(&node.role)));
        }
        if let Some(name) = node
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            parts.push(format!(r#"name="{}""#, inline_value(name)));
        }
        if let Some(value) = node
            .value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            parts.push(format!(r#"value="{}""#, inline_value(value)));
        }

        for key in [
            "type",
            "placeholder",
            "dom_id",
            "selector",
            "target_id",
            "frame_id",
            "autocomplete",
            "format",
            "expected_format",
            "hidden_below_count",
            "hidden_below",
        ] {
            if let Some(value) = node_attr(node, key) {
                parts.push(format!(r#"{key}="{}""#, inline_value(value)));
            }
        }

        for key in [
            "focused",
            "checked",
            "selected",
            "expanded",
            "pressed",
            "disabled",
            "readonly",
            "required",
            "scrollable",
            "can_scroll_up",
            "can_scroll_down",
            "dom_clickable",
        ] {
            if node_attr(node, key).is_some_and(|value| value.eq_ignore_ascii_case("true")) {
                parts.push(key.to_string());
            }
        }

        out.push(format!("{} />", parts.join(" ")));
    }

    for child in &node.children {
        push_selector_map_lines(child, out);
    }
}

fn render_selector_map_text(tree: &AccessibilityNode) -> Option<String> {
    let mut lines = Vec::new();
    push_selector_map_lines(tree, &mut lines);
    (!lines.is_empty()).then(|| lines.join("\n"))
}

fn truncate_section(text: &str) -> String {
    let compact = text.trim();
    if compact.chars().count() <= MAX_SNAPSHOT_SUPPLEMENT_SECTION_CHARS {
        return compact.to_string();
    }

    let truncated = compact
        .chars()
        .take(MAX_SNAPSHOT_SUPPLEMENT_SECTION_CHARS)
        .collect::<String>();
    format!("{truncated}\n...[truncated]...")
}

fn count_selector_map_entries(selector_map_text: &str) -> usize {
    selector_map_text
        .lines()
        .filter(|line| line.trim_start().starts_with('['))
        .count()
}

fn compute_browser_use_page_stats(
    html_text: Option<&str>,
    selector_map_text: Option<&str>,
) -> Option<BrowserUsePageStats> {
    let html = html_text?.trim();
    if html.is_empty() {
        return None;
    }

    let mut stats = BrowserUsePageStats::default();
    stats.interactive_elements = selector_map_text
        .map(count_selector_map_entries)
        .unwrap_or(0);

    for captures in html_open_tag_regex().captures_iter(html) {
        let tag = captures
            .get(1)
            .map(|entry| entry.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        stats.total_elements += 1;
        match tag.as_str() {
            "a" => stats.links += 1,
            "iframe" | "frame" => stats.iframes += 1,
            "img" => stats.images += 1,
            "template" => {
                let full_tag = captures
                    .get(0)
                    .map(|entry| entry.as_str())
                    .unwrap_or_default();
                let lower = full_tag.to_ascii_lowercase();
                if lower.contains("shadowroot=\"open\"") {
                    stats.shadow_open += 1;
                } else if lower.contains("shadowroot=\"closed\"") {
                    stats.shadow_closed += 1;
                }
            }
            _ => {}
        }
    }

    let text_only = html_strip_tags_regex()
        .replace_all(html, " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    stats.text_chars = text_only.chars().count();

    Some(stats)
}

fn render_browser_use_page_stats_text(stats: &BrowserUsePageStats) -> String {
    let mut text = String::from("<page_stats>");
    if stats.total_elements < 10 {
        text.push_str("Page appears empty (SPA not loaded?) - ");
    } else if stats.total_elements > 20 && stats.text_chars < stats.total_elements * 5 {
        text.push_str("Page appears to show skeleton/placeholder content (still loading?) - ");
    }
    text.push_str(&format!(
        "{} links, {} interactive, {} iframes",
        stats.links, stats.interactive_elements, stats.iframes
    ));
    if stats.shadow_open > 0 || stats.shadow_closed > 0 {
        text.push_str(&format!(
            ", {} shadow(open), {} shadow(closed)",
            stats.shadow_open, stats.shadow_closed
        ));
    }
    if stats.images > 0 {
        text.push_str(&format!(", {} images", stats.images));
    }
    text.push_str(&format!(
        ", {} total elements</page_stats>",
        stats.total_elements
    ));
    text
}

fn parse_browser_use_page_info_summary(page_info_text: &str) -> Option<BrowserUsePageInfoSummary> {
    let value: Value = serde_json::from_str(page_info_text).ok()?;
    Some(BrowserUsePageInfoSummary {
        viewport_height: value
            .get("viewport_height")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        pixels_above: value
            .get("pixels_above")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        pixels_below: value
            .get("pixels_below")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
    })
}

fn render_browser_use_page_info_summary_text(page_info_text: &str) -> Option<(String, bool, bool)> {
    let summary = parse_browser_use_page_info_summary(page_info_text)?;
    if summary.viewport_height == 0 {
        return None;
    }

    let pages_above = summary.pixels_above as f64 / summary.viewport_height as f64;
    let pages_below = summary.pixels_below as f64 / summary.viewport_height as f64;
    let has_content_above = pages_above > 0.0;
    let has_content_below = pages_below > 0.0;

    let mut text = format!("<page_info>{pages_above:.1} pages above, {pages_below:.1} pages below");
    if pages_below > 0.2 {
        text.push_str(" — scroll down to reveal more content");
    }
    text.push_str("</page_info>");

    Some((text, has_content_above, has_content_below))
}

fn parse_browser_use_tabs_summary(
    current_url: Option<&str>,
    current_title: Option<&str>,
    tabs_text: &str,
) -> Option<(Option<String>, Vec<String>)> {
    let value: Value = serde_json::from_str(tabs_text).ok()?;
    let tabs = value.as_array()?;
    let current_url = current_url.unwrap_or_default();
    let current_title = current_title.unwrap_or_default();

    let mut current_tab_candidates = Vec::new();
    let mut lines = Vec::new();
    for tab in tabs {
        let tab_id = tab
            .get("tab_id")
            .or_else(|| tab.get("target_id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let short_id = if tab_id.chars().count() > 4 {
            tab_id
                .chars()
                .rev()
                .take(4)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
        } else {
            tab_id.to_string()
        };
        let url = tab.get("url").and_then(Value::as_str).unwrap_or_default();
        let title = tab.get("title").and_then(Value::as_str).unwrap_or_default();
        if !current_url.is_empty()
            && !current_title.is_empty()
            && url == current_url
            && title == current_title
        {
            current_tab_candidates.push(short_id.clone());
        }
        lines.push(format!(
            "Tab {short_id}: {url} - {}",
            title.chars().take(30).collect::<String>()
        ));
    }

    let current_tab =
        (current_tab_candidates.len() == 1).then(|| current_tab_candidates[0].clone());
    Some((current_tab, lines))
}

fn browser_use_pdf_message(url: Option<&str>) -> Option<&'static str> {
    let url = url?.trim().to_ascii_lowercase();
    (url.ends_with(".pdf") || url.contains("/pdf/")).then_some(
        "PDF viewer cannot be rendered. In this page, DO NOT use the extract action as PDF content cannot be rendered. Use the read_file action on the downloaded PDF in available_file_paths to read the full text content.",
    )
}

fn render_browser_use_prompt_context_section(
    artifacts: Option<&BrowserObservationArtifacts>,
    browser_use_state_text: &str,
) -> Option<String> {
    let artifacts = artifacts?;
    let stats_text = compute_browser_use_page_stats(
        artifacts.browser_use_html_text.as_deref(),
        artifacts.browser_use_selector_map_text.as_deref(),
    )
    .map(|stats| format!("{}\n", render_browser_use_page_stats_text(&stats)))
    .unwrap_or_default();

    let (current_tab_text, tabs_text) = artifacts
        .browser_use_tabs_text
        .as_deref()
        .and_then(|tabs_text| {
            parse_browser_use_tabs_summary(
                artifacts.url.as_deref(),
                artifacts.page_title.as_deref(),
                tabs_text,
            )
        })
        .map(|(current_tab, tabs_lines)| {
            (
                current_tab
                    .map(|current_tab| format!("Current tab: {current_tab}"))
                    .unwrap_or_default(),
                if tabs_lines.is_empty() {
                    String::new()
                } else {
                    format!("{}\n", tabs_lines.join("\n"))
                },
            )
        })
        .unwrap_or_default();

    let mut has_content_above = false;
    let mut has_content_below = false;
    let page_info_text = artifacts
        .browser_use_page_info_text
        .as_deref()
        .and_then(|page_info_text| {
            render_browser_use_page_info_summary_text(page_info_text).map(
                |(page_info_summary, content_above, content_below)| {
                    has_content_above = content_above;
                    has_content_below = content_below;
                    format!("{page_info_summary}\n")
                },
            )
        })
        .unwrap_or_default();

    let recent_events_text = artifacts
        .browser_use_recent_events_text
        .as_deref()
        .map(str::trim)
        .filter(|recent_events| !recent_events.is_empty() && *recent_events != "[]")
        .map(|recent_events| format!("Recent browser events: {recent_events}\n"))
        .unwrap_or_default();

    let closed_popups_text = artifacts
        .browser_use_closed_popup_messages_text
        .as_deref()
        .and_then(|closed_popup_messages_text| {
            let popup_messages =
                serde_json::from_str::<Vec<String>>(closed_popup_messages_text).ok()?;
            (!popup_messages.is_empty()).then(|| {
                let mut text = String::from("Auto-closed JavaScript dialogs:\n");
                for popup_message in popup_messages {
                    text.push_str(&format!("  - {}\n", popup_message.trim()));
                }
                text.push('\n');
                text
            })
        })
        .unwrap_or_default();

    let pdf_message = browser_use_pdf_message(artifacts.url.as_deref())
        .map(|message| format!("{message}\n\n"))
        .unwrap_or_default();

    let mut elements_text = browser_use_state_text.trim().to_string();
    let mut truncated_text = String::new();
    if elements_text.chars().count() > MAX_SNAPSHOT_SUPPLEMENT_SECTION_CHARS {
        elements_text = elements_text
            .chars()
            .take(MAX_SNAPSHOT_SUPPLEMENT_SECTION_CHARS)
            .collect::<String>();
        truncated_text =
            format!(" (truncated to {MAX_SNAPSHOT_SUPPLEMENT_SECTION_CHARS} characters)");
    }
    if !elements_text.is_empty() {
        if !has_content_above {
            elements_text = format!("[Start of page]\n{elements_text}");
        }
        if !has_content_below {
            elements_text = format!("{elements_text}\n[End of page]");
        }
    } else {
        elements_text = "empty page".to_string();
    }

    Some(format!(
        "{stats_text}{current_tab_text}\nAvailable tabs:\n{tabs_text}\n{page_info_text}\n{recent_events_text}{closed_popups_text}{pdf_message}Interactive elements{truncated_text}:\n{elements_text}\n"
    ))
}

pub(super) fn append_browser_snapshot_supplement(
    snapshot_xml: &str,
    raw_tree: &AccessibilityNode,
    transformed_tree: &AccessibilityNode,
    artifacts: Option<&BrowserObservationArtifacts>,
) -> String {
    let mut sections = Vec::new();

    if let Some(browser_use_state_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_state_text.as_deref())
        .map(str::to_string)
        .or_else(|| render_browser_use_state_text(raw_tree))
    {
        if let Some(prompt_context_text) =
            render_browser_use_prompt_context_section(artifacts, &browser_use_state_text)
        {
            sections.push(format!(
                "BROWSER_USE_PROMPT_CONTEXT_TXT:\n{}",
                truncate_section(&prompt_context_text)
            ));
        }
        sections.push(format!(
            "BROWSER_USE_STATE_TXT:\n{}",
            truncate_section(&browser_use_state_text)
        ));
    }

    if let Some(selector_map_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_selector_map_text.as_deref())
        .map(str::to_string)
        .or_else(|| render_selector_map_text(transformed_tree))
    {
        sections.push(format!(
            "BROWSER_USE_SELECTOR_MAP:\n{}",
            truncate_section(&selector_map_text)
        ));
    }

    if let Some(eval_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_eval_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_EVAL_TXT:\n{}",
            truncate_section(&eval_text)
        ));
    }

    if let Some(markdown_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_markdown_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_MARKDOWN:\n{}",
            truncate_section(&markdown_text)
        ));
    }

    if let Some(pagination_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_pagination_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_PAGINATION_TXT:\n{}",
            truncate_section(&pagination_text)
        ));
    }

    if let Some(tabs_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_tabs_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_TABS_JSON:\n{}",
            truncate_section(&tabs_text)
        ));
    }

    if let Some(page_info_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_page_info_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_PAGE_INFO_JSON:\n{}",
            truncate_section(&page_info_text)
        ));
    }

    if let Some(pending_requests_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_pending_requests_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_PENDING_REQUESTS_JSON:\n{}",
            truncate_section(&pending_requests_text)
        ));
    }

    if let Some(recent_events_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_recent_events_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_RECENT_EVENTS_JSON:\n{}",
            truncate_section(&recent_events_text)
        ));
    }

    if let Some(closed_popup_messages_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_closed_popup_messages_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_CLOSED_POPUP_MESSAGES_JSON:\n{}",
            truncate_section(&closed_popup_messages_text)
        ));
    }

    if let Some(html_text) = artifacts
        .and_then(|artifacts| artifacts.browser_use_html_text.as_deref())
        .map(str::to_string)
    {
        sections.push(format!(
            "BROWSER_USE_HTML:\n{}",
            truncate_section(&html_text)
        ));
    }

    if let Some(artifacts) = artifacts {
        if let Some(extra_properties_text) = artifacts.browsergym_extra_properties_text.as_deref() {
            if !extra_properties_text.trim().is_empty() {
                sections.push(format!(
                    "BROWSERGYM_EXTRA_PROPERTIES_JSON:\n{}",
                    truncate_section(extra_properties_text)
                ));
            }
        }
        if let Some(focused_bid) = artifacts.browsergym_focused_bid.as_deref() {
            if !focused_bid.trim().is_empty() {
                sections.push(format!(
                    "BROWSERGYM_FOCUSED_BID:\n{}",
                    truncate_section(focused_bid)
                ));
            }
        }
        if let Some(axtree_text) = artifacts.browsergym_axtree_text.as_deref() {
            if !axtree_text.trim().is_empty() {
                sections.push(format!(
                    "BROWSERGYM_AXTREE_TXT:\n{}",
                    truncate_section(axtree_text)
                ));
            }
        }
        if let Some(dom_text) = artifacts.browsergym_dom_text.as_deref() {
            if !dom_text.trim().is_empty() {
                sections.push(format!(
                    "BROWSERGYM_DOM_TXT:\n{}",
                    truncate_section(dom_text)
                ));
            }
        }
    }

    if sections.is_empty() {
        snapshot_xml.to_string()
    } else {
        format!("{}\n\n{}", snapshot_xml.trim_end(), sections.join("\n\n"))
    }
}

#[cfg(test)]
mod tests {
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
}
