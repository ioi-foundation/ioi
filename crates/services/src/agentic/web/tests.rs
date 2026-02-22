use anyhow::anyhow;
use ioi_types::app::agentic::WebSource;

use super::anchor_policy::{
    filter_provider_sources_by_query_anchors, provider_sources_match_query_anchors,
};
use super::constants::EDGE_WEB_SEARCH_TOTAL_BUDGET_MS;
use super::parsers::{
    parse_bing_sources_from_html, parse_ddg_sources_from_html, parse_google_news_sources_from_rss,
};
use super::readability::{build_document_text_and_spans, extract_read_blocks};
use super::search::{search_backend_profile, search_budget_exhausted, search_provider_plan};
use super::transport::{detect_human_challenge, retrieve_html_with_fallback};
use super::types::{SearchBackendProfile, SearchProviderStage};
use super::urls::{
    build_bing_serp_url, build_ddg_serp_url, build_google_serp_url, normalize_google_search_href,
    normalize_search_href,
};
use super::util::{domain_for_url, now_ms, source_id_for_url};

fn test_source(url: &str, title: &str, snippet: &str) -> WebSource {
    WebSource {
        source_id: source_id_for_url(url),
        rank: Some(1),
        url: url.to_string(),
        title: Some(title.to_string()),
        snippet: Some(snippet.to_string()),
        domain: domain_for_url(url),
    }
}

#[test]
fn ddg_serp_url_encodes_query() {
    let url = build_ddg_serp_url("internet of intelligence");
    assert!(url.starts_with("https://duckduckgo.com/"));
    assert!(url.contains("q=internet+of+intelligence"));
}

#[test]
fn provider_specific_search_urls_encode_query() {
    let google = build_google_serp_url("internet of intelligence");
    assert!(google.starts_with("https://www.google.com/search"));
    assert!(google.contains("q=internet+of+intelligence"));

    let bing = build_bing_serp_url("internet of intelligence");
    assert!(bing.starts_with("https://www.bing.com/search"));
    assert!(bing.contains("q=internet+of+intelligence"));
}

#[test]
fn search_backend_profile_uses_constraint_grounded_plan_for_time_sensitive_queries() {
    let profile = search_backend_profile("What's the weather right now in Anderson, SC?");
    assert_eq!(
        profile,
        SearchBackendProfile::ConstraintGroundedTimeSensitive
    );
    let plan = search_provider_plan(profile);
    assert_eq!(plan.first(), Some(&SearchProviderStage::BingHttp));
    assert_eq!(plan.get(1), Some(&SearchProviderStage::GoogleHttp));
    assert!(
        !plan.contains(&SearchProviderStage::GoogleNewsRss),
        "time-sensitive public-fact plan should avoid rss proxy fallback"
    );
}

#[test]
fn search_backend_profile_uses_general_plan_for_non_external_queries() {
    let profile = search_backend_profile("Summarize this local markdown file.");
    assert_eq!(profile, SearchBackendProfile::General);
    let plan = search_provider_plan(profile);
    assert_eq!(plan.first(), Some(&SearchProviderStage::DdgHttp));
    assert_eq!(plan.get(1), Some(&SearchProviderStage::DdgBrowser));
}

#[test]
fn search_budget_exhaustion_is_time_bounded() {
    let started = now_ms().saturating_sub(EDGE_WEB_SEARCH_TOTAL_BUDGET_MS + 1);
    assert!(search_budget_exhausted(started));
    assert!(!search_budget_exhausted(now_ms()));
}

#[test]
fn ddg_redirect_is_decoded() {
    let href = "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpath%3Fa%3Db%23frag";
    let decoded = normalize_search_href(href).expect("decoded url");
    assert_eq!(decoded, "https://example.com/path?a=b");
}

#[test]
fn google_redirect_is_decoded() {
    let href = "/url?q=https%3A%2F%2Fexample.com%2Fpath%3Fa%3Db%23frag&sa=U&ved=abc";
    let decoded = normalize_google_search_href(href).expect("decoded url");
    assert_eq!(decoded, "https://example.com/path?a=b");
}

#[test]
fn parses_minimal_ddg_serp_html() {
    let html = r#"
        <html>
          <body>
            <div class="result">
              <a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa">Example A</a>
              <div class="result__snippet">Snippet A</div>
            </div>
            <div class="result">
              <a class="result__a" href="https://example.com/b">Example B</a>
            </div>
          </body>
        </html>
        "#;
    let sources = parse_ddg_sources_from_html(html, 10);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].url, "https://example.com/a");
    assert_eq!(sources[0].title.as_deref(), Some("Example A"));
    assert_eq!(sources[0].snippet.as_deref(), Some("Snippet A"));
    assert_eq!(sources[0].rank, Some(1));
    assert_eq!(sources[1].url, "https://example.com/b");
    assert_eq!(sources[1].rank, Some(2));
}

#[test]
fn parses_minimal_bing_serp_html() {
    let html = r#"
        <html>
          <body>
            <li class="b_algo">
              <h2><a href="https://example.com/a">Example A</a></h2>
              <div class="b_caption"><p>Snippet A</p></div>
            </li>
            <li class="b_algo">
              <h2><a href="https://example.com/b">Example B</a></h2>
            </li>
          </body>
        </html>
        "#;
    let sources = parse_bing_sources_from_html(html, 10);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].url, "https://example.com/a");
    assert_eq!(sources[0].title.as_deref(), Some("Example A"));
    assert_eq!(sources[0].snippet.as_deref(), Some("Snippet A"));
    assert_eq!(sources[1].url, "https://example.com/b");
    assert_eq!(sources[1].title.as_deref(), Some("Example B"));
}

#[test]
fn parses_google_news_rss_items() {
    let rss = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Headline One</title>
              <link>https://news.google.com/rss/articles/abc?oc=5&amp;x=1</link>
              <source>Outlet A</source>
            </item>
            <item>
              <title><![CDATA[Headline Two]]></title>
              <link>https://example.com/story-two</link>
            </item>
          </channel>
        </rss>
        "#;

    let sources = parse_google_news_sources_from_rss(rss, 10);
    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources[0].url,
        "https://news.google.com/rss/articles/abc?oc=5&x=1"
    );
    assert_eq!(sources[0].title.as_deref(), Some("Headline One"));
    assert_eq!(sources[0].snippet.as_deref(), Some("Outlet A"));
    assert_eq!(sources[1].url, "https://example.com/story-two");
    assert_eq!(sources[1].title.as_deref(), Some("Headline Two"));
}

#[test]
fn read_extract_builds_quote_spans_with_offsets() {
    let html = r#"
        <html>
          <head><title>Doc</title></head>
          <body>
            <article>
              <p>Hello world.</p>
              <p>Second paragraph.</p>
            </article>
          </body>
        </html>
        "#;
    let (_title, blocks) = extract_read_blocks(html);
    let (content, spans) = build_document_text_and_spans(&blocks, None);
    assert!(content.contains("Hello world."));
    assert!(content.contains("Second paragraph."));
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].quote, "Hello world.");
    assert!(spans[0].end_byte > spans[0].start_byte);
    assert_eq!(
        &content[spans[0].start_byte as usize..spans[0].end_byte as usize],
        spans[0].quote
    );
}

#[test]
fn provider_anchor_policy_rejects_locality_only_overlap() {
    let query = "what's the weather right now in Anderson, SC";
    let sources = vec![test_source(
        "https://www.andersenwindows.com/locations/anderson-sc",
        "Andersen Windows in Anderson, SC",
        "Showroom details and replacement windows.",
    )];

    assert!(!provider_sources_match_query_anchors(query, &sources));
}

#[test]
fn provider_anchor_policy_accepts_semantic_plus_locality_overlap() {
    let query = "what's the weather right now in Anderson, SC";
    let sources = vec![test_source(
        "https://www.weather.com/weather/today/l/Anderson+SC",
        "Current weather in Anderson, SC",
        "Current conditions, temperature, humidity and wind in Anderson.",
    )];

    assert!(provider_sources_match_query_anchors(query, &sources));
}

#[test]
fn provider_anchor_policy_ignores_output_contract_markers_in_query() {
    let query = "Current weather in Anderson, SC right now with sources and UTC timestamp.";
    let sources = vec![
        test_source(
            "https://www.weather.com/weather/today/l/Anderson+SC",
            "Current weather in Anderson, SC",
            "Current conditions, temperature, humidity and wind in Anderson.",
        ),
        test_source(
            "https://example.com/anderson/source-references",
            "Anderson references and sources",
            "UTC timestamp and citation notes for publication metadata.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert!(
        filtered
            .iter()
            .any(|source| source.url.contains("weather.com")),
        "expected semantic weather result to survive anchor filtering: {:?}",
        filtered
            .iter()
            .map(|source| &source.url)
            .collect::<Vec<_>>()
    );
}

#[test]
fn provider_anchor_policy_filters_irrelevant_sources_when_one_match_exists() {
    let query = "what's the weather right now in Anderson, SC";
    let sources = vec![
        test_source(
            "https://www.bestbuy.com/discover-learn/what-does-a-sim-card-do/pcmcat1717534816751",
            "What Does a SIM Card Do? - Best Buy",
            "A SIM card stores subscriber identity information for mobile networks.",
        ),
        test_source(
            "https://www.weather.com/weather/today/l/Anderson+SC",
            "Current weather in Anderson, SC",
            "Current conditions, temperature, humidity and wind in Anderson.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert_eq!(filtered.len(), 1);
    assert!(filtered[0].url.contains("weather.com"));
}

#[test]
fn provider_anchor_policy_rejects_stopword_only_overlap() {
    let query = "what's the weather right now in Anderson, SC";
    let sources = vec![
        test_source(
            "https://english.stackexchange.com/questions/14369/is-wot-wot-or-what-what-an-authentic-british-expression-if-its-supposed-to",
            "Is \"wot wot\" or \"what-what\" an authentic British expression?",
            "Question about usage of \"what-what\" in colloquial English.",
        ),
        test_source(
            "https://www.bestbuy.com/discover-learn/whats-the-difference-between-1080p-full-hd-4k/pcmcat1650917375500",
            "What's the Difference Between 1080p (Full HD) and 4K",
            "Compare display resolutions and panel options.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert!(filtered.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn retrieval_timeout_uses_http_fallback_for_search_flow() {
    let html = retrieve_html_with_fallback(
        "https://duckduckgo.com/?q=latest+news",
        Err(anyhow!(
            "ERROR_CLASS=TimeoutOrHang browser retrieval timed out after 20s"
        )),
        || async {
            Ok(r#"
                <html><body>
                  <div class="result">
                    <a class="result__a" href="https://example.com/a">Result A</a>
                  </div>
                </body></html>
                "#
            .to_string())
        },
    )
    .await
    .expect("fallback should succeed");

    let sources = parse_ddg_sources_from_html(&html, 5);
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].url, "https://example.com/a");
}

#[tokio::test(flavor = "current_thread")]
async fn retrieval_timeout_uses_http_fallback_for_read_flow() {
    let html = retrieve_html_with_fallback(
        "https://example.com/article",
        Err(anyhow!(
            "browser retrieval navigate failed: Request timed out"
        )),
        || async {
            Ok(r#"
                <html><head><title>Doc</title></head>
                <body><article><p>Alpha.</p><p>Beta.</p></article></body></html>
                "#
            .to_string())
        },
    )
    .await
    .expect("fallback should succeed");

    let (title, blocks) = extract_read_blocks(&html);
    assert_eq!(title.as_deref(), Some("Doc"));
    assert_eq!(blocks.len(), 2);
}

#[test]
fn challenge_detection_still_triggers() {
    let reason = detect_human_challenge(
        "https://duckduckgo.com/?q=latest+news",
        "Please verify you are human to continue",
    );
    assert!(reason.is_some());
}
