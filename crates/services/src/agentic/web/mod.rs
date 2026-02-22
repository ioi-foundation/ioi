use crate::agentic::desktop::service::step::signals::{
    analyze_metric_schema, analyze_query_facets, query_semantic_anchor_tokens,
};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use ioi_crypto::algorithms::hash::sha256;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{WebDocument, WebEvidenceBundle, WebQuoteSpan, WebSource};
use regex::Regex;
use reqwest::{redirect, Client};
use scraper::{Html, Selector};
use std::collections::HashSet;
#[cfg(test)]
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use url::Url;

const BROWSER_RETRIEVAL_TIMEOUT_SECS: u64 = 8;
const HTTP_FALLBACK_TIMEOUT_SECS: u64 = 4;
const EDGE_WEB_SEARCH_TOTAL_BUDGET_MS: u64 = 14_000;
const READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD: usize = 320;
const READ_BLOCK_SUPPLEMENTAL_MAX: usize = 40;
const READ_BLOCK_STRUCTURED_SCRIPT_MAX: usize = 12;
const READ_BLOCK_STRUCTURED_SCRIPT_TOKEN_LIMIT: usize = 3_000;
const READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_TOKENS: usize = 36;
const READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_STEP: usize = 12;
const READ_BLOCK_STRUCTURED_SCRIPT_MAX_SCRIPT_CHARS: usize = 40_000;
const READ_BLOCK_STRUCTURED_SCRIPT_MIN_SCORE: usize = 6;
const SEARCH_ANCHOR_MIN_TOKEN_CHARS: usize = 3;
const SEARCH_ANCHOR_REQUIRED_OVERLAP_RATIO_DENOMINATOR: usize = 3;
const SEARCH_ANCHOR_REQUIRED_OVERLAP_CAP: usize = 4;
const SEARCH_ANCHOR_GROUNDED_MIN_OVERLAP: usize = 2;
const SEARCH_ANCHOR_TIME_SENSITIVE_MIN_OVERLAP: usize = 2;
const SEARCH_ANCHOR_LOCALITY_MIN_OVERLAP: usize = 1;
const SEARCH_ANCHOR_SEMANTIC_MIN_OVERLAP: usize = 1;
const SEARCH_ANCHOR_STOPWORDS: [&str; 30] = [
    "a", "an", "the", "and", "or", "to", "of", "for", "with", "in", "on", "at", "by", "from",
    "into", "over", "under", "near", "around", "what", "whats", "is", "are", "was", "were",
    "right", "now", "current", "latest", "today",
];
const QUERY_SCOPE_MARKERS: [&str; 4] = [" in ", " near ", " around ", " at "];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchBackendProfile {
    ConstraintGroundedTimeSensitive,
    ConstraintGroundedExternal,
    General,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchProviderStage {
    DdgHttp,
    DdgBrowser,
    BingHttp,
    GoogleHttp,
    GoogleNewsRss,
}

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
        return "https://duckduckgo.com/html/".to_string();
    }

    let mut url = Url::parse("https://duckduckgo.com/html/").expect("static base url parses");
    url.query_pairs_mut().append_pair("q", trimmed);
    url.to_string()
}

fn build_google_serp_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://www.google.com/search".to_string();
    }
    let mut url = Url::parse("https://www.google.com/search").expect("static base url parses");
    url.query_pairs_mut().append_pair("q", trimmed);
    url.to_string()
}

fn build_bing_serp_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://www.bing.com/search".to_string();
    }
    let mut url = Url::parse("https://www.bing.com/search").expect("static base url parses");
    url.query_pairs_mut().append_pair("q", trimmed);
    url.to_string()
}

pub fn build_default_search_url(query: &str) -> String {
    let provider = std::env::var("IOI_WEB_DEFAULT_SEARCH_PROVIDER")
        .ok()
        .map(|raw| raw.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "duckduckgo".to_string());

    match provider.as_str() {
        "google" => build_google_serp_url(query),
        "bing" => build_bing_serp_url(query),
        "duckduckgo" | "ddg" | _ => build_ddg_serp_url(query),
    }
}

fn build_google_news_rss_url(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return "https://news.google.com/rss".to_string();
    }

    let mut url = Url::parse("https://news.google.com/rss/search").expect("static base url parses");
    url.query_pairs_mut()
        .append_pair("q", trimmed)
        .append_pair("hl", "en-US")
        .append_pair("gl", "US")
        .append_pair("ceid", "US:en");
    url.to_string()
}

fn search_backend_profile(query: &str) -> SearchBackendProfile {
    let facets = analyze_query_facets(query);
    if facets.time_sensitive_public_fact {
        return SearchBackendProfile::ConstraintGroundedTimeSensitive;
    }
    if facets.grounded_external_required {
        return SearchBackendProfile::ConstraintGroundedExternal;
    }
    SearchBackendProfile::General
}

fn search_anchor_tokens(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < SEARCH_ANCHOR_MIN_TOKEN_CHARS {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if SEARCH_ANCHOR_STOPWORDS.contains(&normalized.as_str()) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn semantic_search_anchor_tokens(text: &str) -> HashSet<String> {
    let semantic_tokens = query_semantic_anchor_tokens(text)
        .into_iter()
        .filter(|token| token.len() >= SEARCH_ANCHOR_MIN_TOKEN_CHARS)
        .filter(|token| !token.chars().all(|ch| ch.is_ascii_digit()))
        .filter(|token| !SEARCH_ANCHOR_STOPWORDS.contains(&token.as_str()))
        .collect::<HashSet<_>>();
    if semantic_tokens.is_empty() {
        search_anchor_tokens(text)
    } else {
        semantic_tokens
    }
}

fn scope_anchor_start(query_lower: &str) -> Option<usize> {
    for marker in QUERY_SCOPE_MARKERS {
        if let Some(idx) = query_lower.rfind(marker) {
            return Some(idx + marker.len());
        }
    }
    None
}

fn query_scope_tokens(query: &str) -> HashSet<String> {
    let normalized = format!(" {} ", query.trim().to_ascii_lowercase());
    let Some(start) = scope_anchor_start(&normalized) else {
        return HashSet::new();
    };
    search_anchor_tokens(&normalized[start..])
}

fn required_source_anchor_overlap(query: &str, query_token_count: usize) -> usize {
    if query_token_count == 0 {
        return 0;
    }

    let facets = analyze_query_facets(query);
    let mut required_overlap =
        (query_token_count + SEARCH_ANCHOR_REQUIRED_OVERLAP_RATIO_DENOMINATOR - 1)
            / SEARCH_ANCHOR_REQUIRED_OVERLAP_RATIO_DENOMINATOR;
    required_overlap = required_overlap
        .max(1)
        .min(SEARCH_ANCHOR_REQUIRED_OVERLAP_CAP)
        .min(query_token_count);
    if facets.grounded_external_required {
        required_overlap = required_overlap.max(SEARCH_ANCHOR_GROUNDED_MIN_OVERLAP);
    }
    if facets.time_sensitive_public_fact {
        required_overlap = required_overlap.max(SEARCH_ANCHOR_TIME_SENSITIVE_MIN_OVERLAP);
    }
    if facets.locality_sensitive_public_fact {
        required_overlap = required_overlap.max(SEARCH_ANCHOR_LOCALITY_MIN_OVERLAP);
    }

    required_overlap.min(query_token_count)
}

fn source_anchor_overlap_count(
    query_tokens: &HashSet<String>,
    source_tokens: &HashSet<String>,
) -> usize {
    if query_tokens.is_empty() {
        return 0;
    }
    query_tokens
        .iter()
        .filter(|token| source_tokens.contains(*token))
        .count()
}

fn source_anchor_overlap_metrics(
    source: &WebSource,
    query_tokens: &HashSet<String>,
    semantic_query_tokens: &HashSet<String>,
) -> (usize, usize) {
    let title = source.title.as_deref().unwrap_or_default();
    let snippet = source.snippet.as_deref().unwrap_or_default();
    let source_tokens = search_anchor_tokens(&format!("{} {} {}", source.url, title, snippet));
    let anchor_overlap = source_anchor_overlap_count(query_tokens, &source_tokens);
    let semantic_overlap = if semantic_query_tokens.is_empty() {
        0
    } else {
        semantic_query_tokens
            .iter()
            .filter(|token| source_tokens.contains(*token))
            .count()
    };
    (anchor_overlap, semantic_overlap)
}

fn source_matches_query_anchors(
    source: &WebSource,
    query_tokens: &HashSet<String>,
    semantic_query_tokens: &HashSet<String>,
    required_overlap: usize,
) -> bool {
    let (anchor_overlap, semantic_overlap) =
        source_anchor_overlap_metrics(source, query_tokens, semantic_query_tokens);
    if anchor_overlap < required_overlap {
        return false;
    }

    if semantic_query_tokens.is_empty() {
        return true;
    }

    semantic_overlap >= SEARCH_ANCHOR_SEMANTIC_MIN_OVERLAP
}

fn filter_provider_sources_by_query_anchors(
    query: &str,
    sources: Vec<WebSource>,
) -> Vec<WebSource> {
    let semantic_tokens = semantic_search_anchor_tokens(query);
    let query_scope_tokens = query_scope_tokens(query);
    let mut query_tokens = semantic_tokens.clone();
    query_tokens.extend(query_scope_tokens.iter().cloned());
    if query_tokens.is_empty() {
        return sources;
    }
    let semantic_query_tokens = semantic_tokens
        .difference(&query_scope_tokens)
        .cloned()
        .collect::<HashSet<_>>();
    let semantic_query_tokens = if semantic_query_tokens.is_empty() {
        semantic_tokens
    } else {
        semantic_query_tokens
    };
    let required_overlap = required_source_anchor_overlap(query, query_tokens.len());
    let mut strict_matches = Vec::new();
    let mut fallback_ranked = Vec::new();

    for source in sources {
        let (anchor_overlap, semantic_overlap) =
            source_anchor_overlap_metrics(&source, &query_tokens, &semantic_query_tokens);
        let strict_match = anchor_overlap >= required_overlap
            && (semantic_query_tokens.is_empty()
                || semantic_overlap >= SEARCH_ANCHOR_SEMANTIC_MIN_OVERLAP);
        if strict_match {
            strict_matches.push(source);
            continue;
        }
        if anchor_overlap > 0 || semantic_overlap > 0 {
            fallback_ranked.push((source, anchor_overlap, semantic_overlap));
        }
    }

    if !strict_matches.is_empty() {
        return strict_matches;
    }

    fallback_ranked.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.0.url.cmp(&right.0.url))
    });
    fallback_ranked
        .into_iter()
        .map(|(source, _, _)| source)
        .collect()
}

fn provider_sources_match_query_anchors(query: &str, sources: &[WebSource]) -> bool {
    let semantic_tokens = semantic_search_anchor_tokens(query);
    let query_scope_tokens = query_scope_tokens(query);
    let mut query_tokens = semantic_tokens.clone();
    query_tokens.extend(query_scope_tokens.iter().cloned());
    if query_tokens.is_empty() {
        return true;
    }
    let semantic_query_tokens = semantic_tokens
        .difference(&query_scope_tokens)
        .cloned()
        .collect::<HashSet<_>>();
    let semantic_query_tokens = if semantic_query_tokens.is_empty() {
        semantic_tokens
    } else {
        semantic_query_tokens
    };
    let required_overlap = required_source_anchor_overlap(query, query_tokens.len());

    sources.iter().any(|source| {
        source_matches_query_anchors(
            source,
            &query_tokens,
            &semantic_query_tokens,
            required_overlap,
        )
    })
}

fn search_provider_plan(profile: SearchBackendProfile) -> &'static [SearchProviderStage] {
    match profile {
        SearchBackendProfile::ConstraintGroundedTimeSensitive => &[
            SearchProviderStage::BingHttp,
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::DdgHttp,
            SearchProviderStage::DdgBrowser,
        ],
        SearchBackendProfile::ConstraintGroundedExternal => &[
            SearchProviderStage::BingHttp,
            SearchProviderStage::DdgHttp,
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::GoogleNewsRss,
            SearchProviderStage::DdgBrowser,
        ],
        SearchBackendProfile::General => &[
            SearchProviderStage::DdgHttp,
            SearchProviderStage::DdgBrowser,
            SearchProviderStage::BingHttp,
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::GoogleNewsRss,
        ],
    }
}

fn search_budget_exhausted(started_at_ms: u64) -> bool {
    now_ms().saturating_sub(started_at_ms) >= EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
}

fn record_challenge(
    challenge_reason: &mut Option<String>,
    challenge_url: &mut Option<String>,
    url: &str,
    reason: Option<&'static str>,
) {
    let Some(reason) = reason else {
        return;
    };
    if challenge_reason.is_none() {
        *challenge_reason = Some(reason.to_string());
        *challenge_url = Some(url.to_string());
    }
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

#[cfg(test)]
fn is_browser_unavailable_message(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("browser is cold")
        || lower.contains("no lease")
        || lower.contains("set_lease(true)")
}

#[cfg(test)]
fn should_attempt_http_fallback(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    is_timeout_or_hang_message(&msg) || is_browser_unavailable_message(&msg)
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

#[cfg(test)]
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

fn absolutize_provider_href(provider_origin: &str, href: &str) -> String {
    let trimmed = href.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if trimmed.starts_with("//") {
        return format!("https:{}", trimmed);
    }
    if trimmed.starts_with('/') {
        return format!("{}{}", provider_origin, trimmed);
    }
    trimmed.to_string()
}

fn decode_google_redirect(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !host.contains("google.") {
        return None;
    }
    if parsed.path() != "/url" {
        return None;
    }

    let candidate = parsed
        .query_pairs()
        .find(|(k, _)| k == "q" || k == "url")
        .map(|(_, v)| v.to_string())?;
    let trimmed = candidate.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return None;
    }
    if let Ok(mut dest) = Url::parse(trimmed) {
        dest.set_fragment(None);
        return Some(dest.to_string());
    }
    Some(trimmed.to_string())
}

fn decode_bing_redirect(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !host.ends_with("bing.com") {
        return None;
    }
    if !parsed.path().starts_with("/ck/") {
        return None;
    }

    let raw = parsed
        .query_pairs()
        .find(|(k, _)| k == "u")
        .map(|(_, v)| v.to_string())?;
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(trimmed.to_string());
    }

    let maybe_encoded = trimmed.strip_prefix("a1").unwrap_or(trimmed);
    if maybe_encoded.is_empty() {
        return None;
    }

    for candidate in [maybe_encoded, trimmed] {
        for engine in [
            &general_purpose::URL_SAFE_NO_PAD,
            &general_purpose::URL_SAFE,
            &general_purpose::STANDARD_NO_PAD,
            &general_purpose::STANDARD,
        ] {
            let Ok(bytes) = engine.decode(candidate) else {
                continue;
            };
            let Ok(decoded) = String::from_utf8(bytes) else {
                continue;
            };
            let decoded_trimmed = decoded.trim();
            if decoded_trimmed.starts_with("http://") || decoded_trimmed.starts_with("https://") {
                return Some(decoded_trimmed.to_string());
            }
        }
    }

    None
}

fn normalize_google_search_href(href: &str) -> Option<String> {
    let abs = absolutize_provider_href("https://www.google.com", href);
    if abs.is_empty() {
        return None;
    }
    if let Some(decoded) = decode_google_redirect(&abs) {
        return Some(decoded);
    }
    if abs.starts_with("http://") || abs.starts_with("https://") {
        return Some(abs);
    }
    None
}

fn normalize_bing_search_href(href: &str) -> Option<String> {
    let abs = absolutize_provider_href("https://www.bing.com", href);
    if abs.is_empty() {
        return None;
    }
    if let Some(decoded) = decode_bing_redirect(&abs) {
        return Some(decoded);
    }
    if abs.starts_with("http://") || abs.starts_with("https://") {
        return Some(abs);
    }
    None
}

fn is_search_engine_host(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    host.ends_with("duckduckgo.com") || host.ends_with("google.com") || host.ends_with("bing.com")
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

fn parse_google_sources_from_html(html: &str, limit: usize) -> Vec<WebSource> {
    let document = Html::parse_document(html);
    let container_selectors = ["div.g", "div.MjjYud", "div[data-hveid]"];
    let title_selectors = ["a[href]"];
    let snippet_selector =
        Selector::parse("div.VwiC3b, span.aCOpRe, div[data-sncf], div[data-content-feature]");

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

            let mut chosen: Option<(String, Option<String>, Option<String>)> = None;
            for title_sel_str in title_selectors {
                let Ok(title_sel) = Selector::parse(title_sel_str) else {
                    continue;
                };
                for anchor in container.select(&title_sel) {
                    let href = anchor.value().attr("href").unwrap_or("").trim();
                    let Some(final_url) = normalize_google_search_href(href) else {
                        continue;
                    };
                    if is_search_engine_host(&final_url) || seen.contains(&final_url) {
                        continue;
                    }
                    let title_raw = compact_ws(&text_content(anchor));
                    let title = title_raw.trim();
                    if title.is_empty() {
                        continue;
                    }
                    let title_opt = Some(title.to_string());
                    let snippet_opt = snippet_selector
                        .as_ref()
                        .ok()
                        .and_then(|sel| {
                            container.select(sel).next().map(|value| {
                                let raw = compact_ws(&text_content(value));
                                raw.trim().to_string()
                            })
                        })
                        .filter(|snippet| !snippet.trim().is_empty());
                    chosen = Some((final_url, title_opt, snippet_opt));
                    break;
                }
                if chosen.is_some() {
                    break;
                }
            }

            let Some((final_url, title_opt, snippet_opt)) = chosen else {
                continue;
            };

            seen.insert(final_url.clone());
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

    if out.is_empty() {
        let Ok(anchor_sel) = Selector::parse("a[href]") else {
            return out;
        };
        for anchor in document.select(&anchor_sel) {
            if out.len() >= limit {
                break;
            }
            let href = anchor.value().attr("href").unwrap_or("").trim();
            let Some(final_url) = normalize_google_search_href(href) else {
                continue;
            };
            if is_search_engine_host(&final_url) || seen.contains(&final_url) {
                continue;
            }
            let title_raw = compact_ws(&text_content(anchor));
            let title = title_raw.trim();
            if title.is_empty() {
                continue;
            }
            seen.insert(final_url.clone());
            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: Some(title.to_string()),
                snippet: None,
                domain: domain_for_url(&final_url),
            });
        }
    }

    out
}

fn parse_bing_sources_from_html(html: &str, limit: usize) -> Vec<WebSource> {
    let document = Html::parse_document(html);
    let container_selectors = ["li.b_algo", "div.b_algo", "li[data-bm]"];
    let title_selectors = ["h2 a[href]", "a[href]"];
    let snippet_selector = Selector::parse("div.b_caption p, p.b_paractl, p");

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
            let mut chosen: Option<(String, Option<String>, Option<String>)> = None;
            for title_sel_str in title_selectors {
                let Ok(title_sel) = Selector::parse(title_sel_str) else {
                    continue;
                };
                if let Some(anchor) = container.select(&title_sel).next() {
                    let href = anchor.value().attr("href").unwrap_or("").trim();
                    let Some(final_url) = normalize_bing_search_href(href) else {
                        continue;
                    };
                    if is_search_engine_host(&final_url) || seen.contains(&final_url) {
                        continue;
                    }
                    let title_raw = compact_ws(&text_content(anchor));
                    let title = title_raw.trim();
                    if title.is_empty() {
                        continue;
                    }
                    let title_opt = Some(title.to_string());
                    let snippet_opt = snippet_selector
                        .as_ref()
                        .ok()
                        .and_then(|sel| {
                            container.select(sel).next().map(|value| {
                                let raw = compact_ws(&text_content(value));
                                raw.trim().to_string()
                            })
                        })
                        .filter(|snippet| !snippet.trim().is_empty());
                    chosen = Some((final_url, title_opt, snippet_opt));
                    break;
                }
            }

            let Some((final_url, title_opt, snippet_opt)) = chosen else {
                continue;
            };
            seen.insert(final_url.clone());
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

    if out.is_empty() {
        let Ok(anchor_sel) = Selector::parse("a[href]") else {
            return out;
        };
        for anchor in document.select(&anchor_sel) {
            if out.len() >= limit {
                break;
            }
            let href = anchor.value().attr("href").unwrap_or("").trim();
            let Some(final_url) = normalize_bing_search_href(href) else {
                continue;
            };
            if is_search_engine_host(&final_url) || seen.contains(&final_url) {
                continue;
            }
            let title_raw = compact_ws(&text_content(anchor));
            let title = title_raw.trim();
            if title.is_empty() {
                continue;
            }
            seen.insert(final_url.clone());
            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: Some(title.to_string()),
                snippet: None,
                domain: domain_for_url(&final_url),
            });
        }
    }

    out
}

fn decode_rss_text(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_start_matches("<![CDATA[")
        .trim_end_matches("]]>")
        .trim();
    trimmed
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn parse_google_news_sources_from_rss(rss_xml: &str, limit: usize) -> Vec<WebSource> {
    let item_re = Regex::new(r"(?is)<item\b[^>]*>(.*?)</item>").expect("static regex compiles");
    let title_re = Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>").expect("static regex compiles");
    let link_re = Regex::new(r"(?is)<link\b[^>]*>(.*?)</link>").expect("static regex compiles");
    let source_re =
        Regex::new(r"(?is)<source\b[^>]*>(.*?)</source>").expect("static regex compiles");
    let mut out: Vec<WebSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for item_cap in item_re.captures_iter(rss_xml) {
        if out.len() >= limit {
            break;
        }
        let Some(item_match) = item_cap.get(1) else {
            continue;
        };
        let item = item_match.as_str();

        let raw_link = link_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .unwrap_or_default();
        let link_trimmed = raw_link.trim();
        if !(link_trimmed.starts_with("http://") || link_trimmed.starts_with("https://")) {
            continue;
        }
        let final_url = link_trimmed.to_string();
        if seen.contains(&final_url) {
            continue;
        }
        seen.insert(final_url.clone());

        let title_opt = title_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .map(|raw| compact_ws(&raw))
            .and_then(|raw| {
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });

        let snippet_opt = source_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .map(|raw| compact_ws(&raw))
            .and_then(|raw| {
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });

        out.push(WebSource {
            source_id: source_id_for_url(&final_url),
            rank: Some(out.len() as u32 + 1),
            url: final_url.clone(),
            title: title_opt,
            snippet: snippet_opt,
            domain: domain_for_url(&final_url),
        });
    }

    out
}

async fn fetch_google_news_rss_sources(query: &str, limit: usize) -> Result<Vec<WebSource>> {
    let rss_url = build_google_news_rss_url(query);
    let rss_xml = fetch_html_http_fallback(&rss_url).await?;
    Ok(parse_google_news_sources_from_rss(&rss_xml, limit))
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

    let primary_char_count = blocks.iter().map(|block| block.chars().count()).sum::<usize>();
    let primary_has_numeric_signal = blocks
        .iter()
        .any(|block| block.chars().any(|ch| ch.is_ascii_digit()));
    if blocks.is_empty()
        || primary_char_count < READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD
        || !primary_has_numeric_signal
    {
        let mut seen = blocks
            .iter()
            .map(|block| block.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        if let Ok(supplemental_sel) = Selector::parse("td, th, dd, dt, span") {
            for elem in root.select(&supplemental_sel) {
                if blocks.len() >= READ_BLOCK_SUPPLEMENTAL_MAX {
                    break;
                }
                let raw = compact_ws(&text_content(elem));
                let text = raw.trim();
                if text.is_empty() {
                    continue;
                }
                if text.chars().count() > 80 {
                    continue;
                }
                let has_digit = text.chars().any(|ch| ch.is_ascii_digit());
                let has_alpha = text.chars().any(|ch| ch.is_ascii_alphabetic());
                if !has_digit || !has_alpha {
                    continue;
                }
                let normalized = text.to_ascii_lowercase();
                if !seen.insert(normalized) {
                    continue;
                }
                blocks.push(text.to_string());
            }
        }
    }

    let low_signal_after_supplemental = {
        let char_count = blocks.iter().map(|block| block.chars().count()).sum::<usize>();
        let has_metric_payload = blocks.iter().any(|block| {
            let schema = analyze_metric_schema(block);
            schema.has_metric_payload() && schema.numeric_token_hits > 0
        });
        blocks.is_empty() || char_count < READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD || !has_metric_payload
    };
    if low_signal_after_supplemental {
        let mut seen = blocks
            .iter()
            .map(|block| block.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        for segment in structured_metric_blocks_from_scripts(&document) {
            if blocks.len() >= READ_BLOCK_SUPPLEMENTAL_MAX {
                break;
            }
            if seen.insert(segment.to_ascii_lowercase()) {
                blocks.push(segment);
            }
        }
    }

    (title, blocks)
}

fn structured_metric_window_score(segment: &str) -> usize {
    let schema = analyze_metric_schema(segment);
    if !schema.has_metric_payload() || schema.numeric_token_hits == 0 {
        return 0;
    }

    let mut score = schema
        .numeric_token_hits
        .saturating_add(schema.unit_hits.saturating_mul(2))
        .saturating_add(schema.axis_hits.len().saturating_mul(4))
        .saturating_add(schema.observation_hits)
        .saturating_add(schema.timestamp_hits);
    if schema.has_current_observation_payload() {
        score = score.saturating_add(8);
    }
    score
}

fn structured_metric_blocks_from_scripts(document: &Html) -> Vec<String> {
    let Ok(script_sel) = Selector::parse("script") else {
        return Vec::new();
    };

    let mut seen = HashSet::new();
    let mut scored_segments = Vec::<(usize, String)>::new();

    for script in document.select(&script_sel) {
        let raw = compact_ws(&text_content(script));
        if raw.is_empty() || !raw.chars().any(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let compact = raw
            .chars()
            .take(READ_BLOCK_STRUCTURED_SCRIPT_MAX_SCRIPT_CHARS)
            .collect::<String>();
        let tokens = compact
            .split_whitespace()
            .take(READ_BLOCK_STRUCTURED_SCRIPT_TOKEN_LIMIT)
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }

        if tokens.len() <= READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_TOKENS {
            let segment = tokens.join(" ");
            let score = structured_metric_window_score(&segment);
            if score >= READ_BLOCK_STRUCTURED_SCRIPT_MIN_SCORE
                && seen.insert(segment.to_ascii_lowercase())
            {
                scored_segments.push((score, segment));
            }
            continue;
        }

        let mut start = 0usize;
        while start < tokens.len() {
            let end = (start + READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_TOKENS).min(tokens.len());
            let segment = tokens[start..end].join(" ");
            let score = structured_metric_window_score(&segment);
            if score >= READ_BLOCK_STRUCTURED_SCRIPT_MIN_SCORE
                && seen.insert(segment.to_ascii_lowercase())
            {
                scored_segments.push((score, segment));
            }
            if end == tokens.len() {
                break;
            }
            start = start.saturating_add(READ_BLOCK_STRUCTURED_SCRIPT_WINDOW_STEP);
        }
    }

    scored_segments.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.len().cmp(&right.1.len()))
    });
    scored_segments
        .into_iter()
        .take(READ_BLOCK_STRUCTURED_SCRIPT_MAX)
        .map(|(_, segment)| segment)
        .collect()
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
    let default_serp_url = build_ddg_serp_url(query);
    let profile = search_backend_profile(query);
    let provider_plan = search_provider_plan(profile);
    let search_started_at_ms = now_ms();
    let mut fallback_notes: Vec<String> = Vec::new();
    let mut challenge_reason: Option<String> = None;
    let mut challenge_url: Option<String> = None;
    let mut sources: Vec<WebSource> = Vec::new();
    let mut backend = "edge:search:empty".to_string();
    let mut source_url = default_serp_url.clone();

    for provider in provider_plan {
        if !sources.is_empty() {
            break;
        }
        if search_budget_exhausted(search_started_at_ms) {
            fallback_notes.push(format!(
                "search_budget_exhausted_ms={}",
                EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
            ));
            break;
        }

        match provider {
            SearchProviderStage::DdgHttp => {
                let serp_url = build_ddg_serp_url(query);
                match fetch_html_http_fallback(&serp_url).await {
                    Ok(html) => {
                        let reason = detect_human_challenge(&serp_url, &html);
                        record_challenge(
                            &mut challenge_reason,
                            &mut challenge_url,
                            &serp_url,
                            reason,
                        );
                        if reason.is_none() {
                            let ddg_sources = parse_ddg_sources_from_html(&html, limit as usize);
                            if !ddg_sources.is_empty() {
                                let filtered_sources =
                                    filter_provider_sources_by_query_anchors(query, ddg_sources);
                                if !filtered_sources.is_empty() {
                                    sources = filtered_sources;
                                    backend = "edge:ddg:http".to_string();
                                    source_url = serp_url;
                                    challenge_reason = None;
                                    challenge_url = None;
                                } else {
                                    fallback_notes.push("ddg_http_anchor_mismatch".to_string());
                                }
                            } else {
                                fallback_notes.push("ddg_http_empty".to_string());
                            }
                        } else if let Some(reason) = reason {
                            fallback_notes.push(format!("ddg_http_challenge={}", reason));
                        }
                    }
                    Err(err) => fallback_notes.push(format!("ddg_http_error={}", err)),
                }
            }
            SearchProviderStage::DdgBrowser => {
                let serp_url = build_ddg_serp_url(query);
                match navigate_browser_retrieval(browser, &serp_url).await {
                    Ok(html) => {
                        let reason = detect_human_challenge(&serp_url, &html);
                        record_challenge(
                            &mut challenge_reason,
                            &mut challenge_url,
                            &serp_url,
                            reason,
                        );
                        if reason.is_none() {
                            let browser_sources =
                                parse_ddg_sources_from_html(&html, limit as usize);
                            if !browser_sources.is_empty() {
                                let filtered_sources = filter_provider_sources_by_query_anchors(
                                    query,
                                    browser_sources,
                                );
                                if !filtered_sources.is_empty() {
                                    sources = filtered_sources;
                                    backend = "edge:ddg:browser".to_string();
                                    source_url = serp_url;
                                    challenge_reason = None;
                                    challenge_url = None;
                                } else {
                                    fallback_notes.push("ddg_browser_anchor_mismatch".to_string());
                                }
                            } else {
                                fallback_notes.push("ddg_browser_empty".to_string());
                            }
                        } else if let Some(reason) = reason {
                            fallback_notes.push(format!("ddg_browser_challenge={}", reason));
                        }
                    }
                    Err(err) => fallback_notes.push(format!("ddg_browser_error={}", err)),
                }
            }
            SearchProviderStage::BingHttp => {
                let bing_url = build_bing_serp_url(query);
                match fetch_html_http_fallback(&bing_url).await {
                    Ok(html) => {
                        let reason = detect_human_challenge(&bing_url, &html);
                        record_challenge(
                            &mut challenge_reason,
                            &mut challenge_url,
                            &bing_url,
                            reason,
                        );
                        if reason.is_none() {
                            let bing_sources = parse_bing_sources_from_html(&html, limit as usize);
                            if !bing_sources.is_empty() {
                                let filtered_sources =
                                    filter_provider_sources_by_query_anchors(query, bing_sources);
                                if !filtered_sources.is_empty() {
                                    sources = filtered_sources;
                                    backend = "edge:bing:http".to_string();
                                    source_url = bing_url;
                                    challenge_reason = None;
                                    challenge_url = None;
                                } else {
                                    fallback_notes.push("bing_anchor_mismatch".to_string());
                                }
                            } else {
                                fallback_notes.push("bing_empty".to_string());
                            }
                        } else if let Some(reason) = reason {
                            fallback_notes.push(format!("bing_challenge={}", reason));
                        }
                    }
                    Err(err) => fallback_notes.push(format!("bing_http_error={}", err)),
                }
            }
            SearchProviderStage::GoogleHttp => {
                let google_url = build_google_serp_url(query);
                match fetch_html_http_fallback(&google_url).await {
                    Ok(html) => {
                        let reason = detect_human_challenge(&google_url, &html);
                        record_challenge(
                            &mut challenge_reason,
                            &mut challenge_url,
                            &google_url,
                            reason,
                        );
                        if reason.is_none() {
                            let google_sources =
                                parse_google_sources_from_html(&html, limit as usize);
                            if !google_sources.is_empty() {
                                let filtered_sources =
                                    filter_provider_sources_by_query_anchors(query, google_sources);
                                if !filtered_sources.is_empty() {
                                    sources = filtered_sources;
                                    backend = "edge:google:http".to_string();
                                    source_url = google_url;
                                    challenge_reason = None;
                                    challenge_url = None;
                                } else {
                                    fallback_notes.push("google_anchor_mismatch".to_string());
                                }
                            } else {
                                fallback_notes.push("google_empty".to_string());
                            }
                        } else if let Some(reason) = reason {
                            fallback_notes.push(format!("google_challenge={}", reason));
                        }
                    }
                    Err(err) => fallback_notes.push(format!("google_http_error={}", err)),
                }
            }
            SearchProviderStage::GoogleNewsRss => {
                match fetch_google_news_rss_sources(query, limit as usize).await {
                    Ok(google_sources) => {
                        if !google_sources.is_empty() {
                            let filtered_sources =
                                filter_provider_sources_by_query_anchors(query, google_sources);
                            if !filtered_sources.is_empty() {
                                sources = filtered_sources;
                                backend = "edge:google-news-rss".to_string();
                                source_url = build_google_news_rss_url(query);
                                challenge_reason = None;
                                challenge_url = None;
                            } else {
                                fallback_notes.push("google_news_rss_anchor_mismatch".to_string());
                            }
                        } else {
                            fallback_notes.push("google_news_rss_empty".to_string());
                        }
                    }
                    Err(err) => fallback_notes.push(format!("google_news_rss_error={}", err)),
                }
            }
        }
    }

    if sources.is_empty() {
        if let Some(reason) = challenge_reason {
            fallback_notes.push(format!("challenge_required={}", reason));
            if let Some(url) = challenge_url {
                fallback_notes.push(format!("challenge_url={}", url));
                source_url = url;
            }
        }
        if !fallback_notes.is_empty() {
            backend = format!("{}:{}", backend, fallback_notes.join("|"));
        }
    }

    Ok(WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: now_ms(),
        tool: "web__search".to_string(),
        backend,
        query: Some(query.trim().to_string()),
        url: Some(source_url),
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
    let mut retrieval_notes: Vec<String> = Vec::new();
    let mut backend = "edge:read:http".to_string();
    let initial_html = match fetch_html_http_fallback(read_url).await {
        Ok(html) => html,
        Err(http_err) => {
            retrieval_notes.push(format!("http_error={}", http_err));
            let browser_html = navigate_browser_retrieval(browser, read_url)
                .await
                .map_err(|browser_err| {
                    anyhow!(
                        "ERROR_CLASS=UnexpectedState web retrieval failed for {}. {} browser_error={}",
                        read_url,
                        retrieval_notes.join("; "),
                        browser_err
                    )
                })?;
            backend = "edge:read:browser".to_string();
            browser_html
        }
    };

    let mut challenge_reason = detect_human_challenge(read_url, &initial_html);
    let (mut title, mut blocks) = extract_read_blocks(&initial_html);

    let low_signal_blocks = blocks.is_empty()
        || blocks
            .iter()
            .map(|block| block.chars().count())
            .sum::<usize>()
            < READ_BLOCK_LOW_SIGNAL_CHAR_THRESHOLD;
    if challenge_reason.is_some() || low_signal_blocks {
        match navigate_browser_retrieval(browser, read_url).await {
            Ok(browser_html) => {
                let browser_challenge = detect_human_challenge(read_url, &browser_html);
                let (browser_title, browser_blocks) = extract_read_blocks(&browser_html);
                if browser_challenge.is_none() && !browser_blocks.is_empty() {
                    challenge_reason = None;
                    title = browser_title;
                    blocks = browser_blocks;
                    backend = "edge:read:browser".to_string();
                } else if challenge_reason.is_none() {
                    challenge_reason = browser_challenge;
                }
            }
            Err(err) => retrieval_notes.push(format!("browser_probe_error={}", err)),
        }
    }

    if let Some(reason) = challenge_reason {
        let suffix = if retrieval_notes.is_empty() {
            String::new()
        } else {
            format!(" fallback={}", retrieval_notes.join("; "))
        };
        return Err(anyhow!(
            "ERROR_CLASS=HumanChallengeRequired {}. Complete the challenge manually, then retry: {}{}",
            reason,
            read_url,
            suffix
        ));
    }

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
        backend,
        query: None,
        url: Some(read_url.to_string()),
        sources: vec![source],
        documents: vec![doc],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
