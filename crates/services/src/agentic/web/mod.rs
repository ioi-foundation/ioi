use anyhow::{anyhow, Result};
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{WebDocument, WebEvidenceBundle, WebQuoteSpan, WebSource};
use reqwest::{redirect, Client};
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use url::Url;

const BROWSER_RETRIEVAL_TIMEOUT_SECS: u64 = 20;
const HTTP_FALLBACK_TIMEOUT_SECS: u64 = 15;

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|raw| {
            let normalized = raw.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sha256_hex(input: &[u8]) -> String {
    sha256(input)
        .map(|d| hex::encode(d.as_ref()))
        .unwrap_or_default()
}

fn normalize_url_for_id(url: &str) -> String {
    let trimmed = url.trim();
    let Ok(mut parsed) = Url::parse(trimmed) else {
        return trimmed.to_string();
    };
    parsed.set_fragment(None);
    // Url normalizes scheme/host casing; `to_string` is stable for the same logical URL.
    parsed.to_string()
}

fn source_id_for_url(url: &str) -> String {
    sha256_hex(normalize_url_for_id(url).as_bytes())
}

fn domain_for_url(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}

pub fn build_ddg_serp_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://duckduckgo.com/".to_string();
    }

    let mut url = Url::parse("https://duckduckgo.com/").expect("static base url parses");
    url.query_pairs_mut().append_pair("q", trimmed);
    url.to_string()
}

fn detect_human_challenge(url: &str, content: &str) -> Option<&'static str> {
    let url_lc = url.to_ascii_lowercase();
    let content_lc = content.to_ascii_lowercase();

    // Generic bot-check markers.
    if url_lc.contains("/sorry/") || content_lc.contains("/sorry/") {
        return Some("challenge redirect (/sorry/) detected");
    }
    if content_lc.contains("recaptcha") || content_lc.contains("g-recaptcha") {
        return Some("reCAPTCHA challenge marker detected");
    }
    if content_lc.contains("i'm not a robot") || content_lc.contains("i am not a robot") {
        return Some("robot-verification checkbox detected");
    }
    if content_lc.contains("verify you are human")
        || content_lc.contains("human verification")
        || content_lc.contains("please verify you are a human")
    {
        return Some("human-verification challenge detected");
    }

    // DuckDuckGo anomaly / bot-check flows.
    if content_lc.contains("anomaly")
        && (url_lc.contains("duckduckgo") || content_lc.contains("duckduckgo"))
    {
        return Some("duckduckgo anomaly/bot-check detected");
    }
    if content_lc.contains("challenge-form") && url_lc.contains("duckduckgo") {
        return Some("duckduckgo challenge form detected");
    }

    None
}

fn is_timeout_or_hang_message(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("request timed out")
        || lower.contains("deadline")
        || lower.contains("hang")
}

fn should_attempt_http_fallback(err: &anyhow::Error) -> bool {
    is_timeout_or_hang_message(&err.to_string())
}

async fn navigate_browser_retrieval(browser: &BrowserDriver, url: &str) -> Result<String> {
    if env_flag_enabled("IOI_WEB_TEST_FORCE_BROWSER_TIMEOUT") {
        return Err(anyhow!(
            "ERROR_CLASS=TimeoutOrHang browser retrieval timed out after {}s: {} (forced)",
            BROWSER_RETRIEVAL_TIMEOUT_SECS,
            url
        ));
    }

    let retrieval = timeout(
        Duration::from_secs(BROWSER_RETRIEVAL_TIMEOUT_SECS),
        browser.navigate_retrieval(url),
    )
    .await;

    match retrieval {
        Ok(Ok(html)) => Ok(html),
        Ok(Err(e)) => {
            let msg = format!("browser retrieval navigate failed: {}", e);
            if is_timeout_or_hang_message(&msg) {
                return Err(anyhow!("ERROR_CLASS=TimeoutOrHang {}", msg));
            }
            Err(anyhow!("{}", msg))
        }
        Err(_) => Err(anyhow!(
            "ERROR_CLASS=TimeoutOrHang browser retrieval timed out after {}s: {}",
            BROWSER_RETRIEVAL_TIMEOUT_SECS,
            url
        )),
    }
}

async fn fetch_html_http_fallback(url: &str) -> Result<String> {
    if env_flag_enabled("IOI_WEB_TEST_FORCE_HTTP_TIMEOUT") {
        return Err(anyhow!("HTTP fallback request timed out (forced): {}", url));
    }
    if let Ok(html) = std::env::var("IOI_WEB_TEST_HTTP_FALLBACK_HTML") {
        return Ok(html);
    }

    let client = Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(HTTP_FALLBACK_TIMEOUT_SECS))
        .user_agent("ioi-web-retrieve/1.0")
        .build()
        .map_err(|e| anyhow!("HTTP fallback client init failed: {}", e))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("HTTP fallback request failed: {}", e))?;

    response
        .text()
        .await
        .map_err(|e| anyhow!("HTTP fallback body read failed: {}", e))
}

async fn retrieve_html_with_fallback<FFut, F>(
    url: &str,
    primary: Result<String>,
    fallback_fetch: F,
) -> Result<String>
where
    F: FnOnce() -> FFut,
    FFut: Future<Output = Result<String>>,
{
    match primary {
        Ok(html) => Ok(html),
        Err(primary_err) => {
            if !should_attempt_http_fallback(&primary_err) {
                return Err(primary_err);
            }

            match fallback_fetch().await {
                Ok(html) => Ok(html),
                Err(fallback_err) => Err(anyhow!(
                    "ERROR_CLASS=TimeoutOrHang web retrieval timeout exhaustion for {}. primary_error={} fallback_error={}",
                    url,
                    primary_err,
                    fallback_err
                )),
            }
        }
    }
}

fn absolutize_ddg_href(href: &str) -> String {
    let trimmed = href.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if trimmed.starts_with("//") {
        return format!("https:{}", trimmed);
    }
    if trimmed.starts_with("/l/?") || trimmed.starts_with("/l/") {
        return format!("https://duckduckgo.com{}", trimmed);
    }
    trimmed.to_string()
}

fn decode_ddg_redirect(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !host.contains("duckduckgo.com") {
        return None;
    }
    if !parsed.path().starts_with("/l/") {
        return None;
    }

    let uddg = parsed
        .query_pairs()
        .find(|(k, _)| k == "uddg")
        .map(|(_, v)| v.to_string())?;
    if uddg.trim().is_empty() {
        return None;
    }

    // `query_pairs` returns a decoded value. Normalize by dropping fragments.
    let trimmed = uddg.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return None;
    }

    if let Ok(mut dest) = Url::parse(trimmed) {
        dest.set_fragment(None);
        return Some(dest.to_string());
    }

    Some(trimmed.to_string())
}

fn normalize_search_href(href: &str) -> Option<String> {
    let abs = absolutize_ddg_href(href);
    if abs.is_empty() {
        return None;
    }
    if let Some(decoded) = decode_ddg_redirect(&abs) {
        return Some(decoded);
    }
    if abs.starts_with("http://") || abs.starts_with("https://") {
        return Some(abs);
    }
    None
}

fn text_content(elem: scraper::ElementRef<'_>) -> String {
    elem.text().collect::<Vec<_>>().join(" ")
}

fn compact_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_ddg_sources_from_html(html: &str, limit: usize) -> Vec<WebSource> {
    let document = Html::parse_document(html);

    let container_selectors = [
        "div.result",
        "article[data-testid=\"result\"]",
        "div[data-testid=\"result\"]",
    ];
    let title_selectors = [
        "a[data-testid=\"result-title-a\"]",
        "a.result__a",
        "a[href]",
    ];
    let snippet_selector = Selector::parse(
        "a.result__snippet, div.result__snippet, span.result__snippet, div[data-testid=\"result-snippet\"]",
    )
    .ok();

    let mut out: Vec<WebSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for container_sel_str in container_selectors {
        let Ok(container_sel) = Selector::parse(container_sel_str) else {
            continue;
        };
        for container in document.select(&container_sel) {
            if out.len() >= limit {
                break;
            }

            let mut anchor = None;
            for title_sel_str in title_selectors {
                let Ok(sel) = Selector::parse(title_sel_str) else {
                    continue;
                };
                if let Some(found) = container.select(&sel).next() {
                    if found.value().attr("href").is_some() {
                        anchor = Some(found);
                        break;
                    }
                }
            }
            let Some(anchor) = anchor else {
                continue;
            };

            let href = anchor.value().attr("href").unwrap_or("").trim();
            let Some(final_url) = normalize_search_href(href) else {
                continue;
            };
            if seen.contains(&final_url) {
                continue;
            }
            seen.insert(final_url.clone());

            let title_raw = compact_ws(&text_content(anchor));
            let title = title_raw.trim();
            let title_opt = (!title.is_empty()).then(|| title.to_string());

            let snippet_opt = snippet_selector.as_ref().and_then(|sel| {
                container.select(sel).next().map(|s| {
                    let raw = compact_ws(&text_content(s));
                    raw.trim().to_string()
                })
            });
            let snippet_opt = snippet_opt.filter(|s| !s.trim().is_empty());

            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: title_opt,
                snippet: snippet_opt,
                domain: domain_for_url(&final_url),
            });
        }

        if !out.is_empty() {
            break;
        }
    }

    // Fallback: grab anchors globally.
    if out.is_empty() {
        let Ok(anchor_sel) = Selector::parse("a[href]") else {
            return out;
        };
        for a in document.select(&anchor_sel) {
            if out.len() >= limit {
                break;
            }
            let href = a.value().attr("href").unwrap_or("").trim();
            let Some(final_url) = normalize_search_href(href) else {
                continue;
            };
            if seen.contains(&final_url) {
                continue;
            }
            seen.insert(final_url.clone());

            let title_raw = compact_ws(&text_content(a));
            let title = title_raw.trim();
            let title_opt = (!title.is_empty()).then(|| title.to_string());

            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: title_opt,
                snippet: None,
                domain: domain_for_url(&final_url),
            });
        }
    }

    out
}

fn extract_read_blocks(html: &str) -> (Option<String>, Vec<String>) {
    let document = Html::parse_document(html);

    let title_sel = Selector::parse("title").ok();
    let title = title_sel
        .as_ref()
        .and_then(|sel| document.select(sel).next())
        .map(text_content)
        .map(|t| compact_ws(&t))
        .and_then(|t| (!t.trim().is_empty()).then(|| t.trim().to_string()));

    let root = Selector::parse("article")
        .ok()
        .and_then(|sel| document.select(&sel).next())
        .or_else(|| {
            Selector::parse("main")
                .ok()
                .and_then(|sel| document.select(&sel).next())
        })
        .or_else(|| {
            Selector::parse("body")
                .ok()
                .and_then(|sel| document.select(&sel).next())
        });

    let Some(root) = root else {
        return (title, vec![]);
    };

    let Ok(block_sel) = Selector::parse("p, li") else {
        return (title, vec![]);
    };

    let mut blocks: Vec<String> = Vec::new();
    for elem in root.select(&block_sel) {
        let raw = compact_ws(&text_content(elem));
        let text = raw.trim();
        if text.is_empty() {
            continue;
        }
        blocks.push(text.to_string());
    }

    (title, blocks)
}

fn build_document_text_and_spans(
    blocks: &[String],
    max_chars: Option<usize>,
) -> (String, Vec<WebQuoteSpan>) {
    let mut content = String::new();
    let mut spans = Vec::new();
    let mut used_chars = 0usize;

    for block in blocks {
        let block_chars = block.chars().count();
        let sep_chars = if content.is_empty() { 0 } else { 2 };

        if let Some(max) = max_chars {
            if used_chars + sep_chars + block_chars > max {
                break;
            }
        }

        if !content.is_empty() {
            content.push_str("\n\n");
            used_chars += 2;
        }

        let start = content.len();
        content.push_str(block);
        used_chars += block_chars;
        let end = content.len();

        spans.push(WebQuoteSpan {
            start_byte: start as u32,
            end_byte: end as u32,
            quote: block.clone(),
        });
    }

    (content, spans)
}

pub async fn edge_web_search(
    browser: &BrowserDriver,
    query: &str,
    limit: u32,
) -> Result<WebEvidenceBundle> {
    let serp_url = build_ddg_serp_url(query);
    let primary = navigate_browser_retrieval(browser, &serp_url).await;
    let html = retrieve_html_with_fallback(&serp_url, primary, || async {
        fetch_html_http_fallback(&serp_url).await
    })
    .await?;

    if let Some(reason) = detect_human_challenge(&serp_url, &html) {
        return Err(anyhow!(
            "ERROR_CLASS=HumanChallengeRequired {}. Complete the challenge manually, then retry: {}",
            reason,
            serp_url
        ));
    }

    let sources = parse_ddg_sources_from_html(&html, limit as usize);
    Ok(WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: now_ms(),
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some(query.trim().to_string()),
        url: Some(serp_url),
        sources,
        documents: vec![],
    })
}

pub async fn edge_web_read(
    browser: &BrowserDriver,
    url: &str,
    max_chars: Option<u32>,
) -> Result<WebEvidenceBundle> {
    let read_url = url.trim();
    if read_url.is_empty() {
        return Err(anyhow!("Empty URL"));
    }
    let primary = navigate_browser_retrieval(browser, read_url).await;
    let html = retrieve_html_with_fallback(read_url, primary, || async {
        fetch_html_http_fallback(read_url).await
    })
    .await?;

    if let Some(reason) = detect_human_challenge(read_url, &html) {
        return Err(anyhow!(
            "ERROR_CLASS=HumanChallengeRequired {}. Complete the challenge manually, then retry: {}",
            reason,
            read_url
        ));
    }

    let (title, blocks) = extract_read_blocks(&html);
    let max = max_chars.map(|v| v as usize);
    let (content_text, quote_spans) = build_document_text_and_spans(&blocks, max);
    let content_hash = sha256_hex(content_text.as_bytes());

    let source_id = source_id_for_url(read_url);
    let source = WebSource {
        source_id: source_id.clone(),
        rank: None,
        url: read_url.to_string(),
        title: title.clone(),
        snippet: None,
        domain: domain_for_url(read_url),
    };
    let doc = WebDocument {
        source_id,
        url: read_url.to_string(),
        title,
        content_text,
        content_hash,
        quote_spans,
    };

    Ok(WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: now_ms(),
        tool: "web__read".to_string(),
        backend: "edge:read".to_string(),
        query: None,
        url: Some(read_url.to_string()),
        sources: vec![source],
        documents: vec![doc],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddg_serp_url_encodes_query() {
        let url = build_ddg_serp_url("internet of intelligence");
        assert!(url.starts_with("https://duckduckgo.com/"));
        assert!(url.contains("q=internet+of+intelligence"));
    }

    #[test]
    fn ddg_redirect_is_decoded() {
        let href = "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpath%3Fa%3Db%23frag";
        let decoded = normalize_search_href(href).expect("decoded url");
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
}
