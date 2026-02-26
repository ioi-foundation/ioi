use crate::agentic::desktop::service::step::signals::analyze_query_facets;
use anyhow::Result;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};
use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;

use super::anchor_policy::{
    filter_provider_sources_by_query_anchors, query_is_generic_headline_lookup,
};
use super::constants::EDGE_WEB_SEARCH_TOTAL_BUDGET_MS;
use super::parsers::{
    fetch_google_news_rss_sources, parse_bing_sources_from_html, parse_ddg_sources_from_html,
    parse_google_sources_from_html,
};
use super::transport::{
    detect_human_challenge, fetch_html_http_fallback, navigate_browser_retrieval, record_challenge,
};
use super::types::{SearchBackendProfile, SearchProviderStage};
use super::urls::{
    build_bing_serp_url, build_ddg_serp_url, build_google_news_rss_url, build_google_serp_url,
};
use super::util::{domain_for_url, normalize_url_for_id, now_ms, source_id_for_url};

pub(crate) fn search_backend_profile(query: &str) -> SearchBackendProfile {
    let facets = analyze_query_facets(query);
    if facets.time_sensitive_public_fact {
        return SearchBackendProfile::ConstraintGroundedTimeSensitive;
    }
    if facets.grounded_external_required {
        return SearchBackendProfile::ConstraintGroundedExternal;
    }
    SearchBackendProfile::General
}

pub(crate) fn search_provider_plan(
    profile: SearchBackendProfile,
) -> &'static [SearchProviderStage] {
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

pub(crate) fn effective_search_provider_plan(query: &str) -> Vec<SearchProviderStage> {
    let profile = search_backend_profile(query);
    let mut plan = search_provider_plan(profile).to_vec();
    if query_is_generic_headline_lookup(query) {
        // Headline retrieval is time-budgeted; prioritize RSS first to maximize
        // early multi-outlet discovery hints before direct provider fallbacks.
        if let Some(idx) = plan
            .iter()
            .position(|stage| *stage == SearchProviderStage::GoogleNewsRss)
        {
            let stage = plan.remove(idx);
            let insert_idx = 0;
            plan.insert(insert_idx, stage);
        } else {
            let insert_idx = 0;
            plan.insert(insert_idx, SearchProviderStage::GoogleNewsRss);
        }
    }
    plan
}

pub(crate) fn search_budget_exhausted(started_at_ms: u64) -> bool {
    now_ms().saturating_sub(started_at_ms) >= EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
}

fn is_news_feed_wrapper_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.to_ascii_lowercase() != "news.google.com" {
        return false;
    }
    let path = parsed.path().to_ascii_lowercase();
    path.starts_with("/rss/articles")
        || path.starts_with("/rss/read")
        || path.starts_with("/rss/topics")
}

fn source_has_headline_news_signal(source: &WebSource) -> bool {
    let title = source.title.as_deref().unwrap_or_default();
    let snippet = source.snippet.as_deref().unwrap_or_default();
    let signal_text = format!(" {} {} {} ", source.url, title, snippet).to_ascii_lowercase();
    let keyword_signal = [
        " news ",
        " headline ",
        " headlines ",
        " breaking ",
        "/article/",
        "/story/",
        "/news/",
        "/world/",
        "/politics/",
        "/business/",
        "/us/",
        "/live/",
    ]
    .iter()
    .any(|marker| signal_text.contains(marker));
    keyword_signal || headline_url_has_article_structure(source.url.as_str())
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn current_utc_year() -> i64 {
    let days_since_epoch = (now_ms() / 86_400_000) as i64;
    let (year, _, _) = civil_date_from_days(days_since_epoch);
    year
}

fn headline_url_has_article_structure(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    let path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if path.is_empty() {
        return false;
    }
    let segments = path
        .split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }

    let taxonomy_markers = [
        "category",
        "categories",
        "topic",
        "topics",
        "tag",
        "tags",
        "section",
        "sections",
        "author",
        "authors",
        "collection",
        "collections",
        "hub",
        "hubs",
        "search",
        "results",
    ];
    if segments.iter().any(|segment| {
        let normalized = segment.replace('-', " ");
        normalized
            .split_whitespace()
            .any(|token| taxonomy_markers.contains(&token))
    }) {
        return false;
    }

    let listing_markers = [
        "news",
        "latest",
        "headlines",
        "headline",
        "home",
        "world",
        "us",
        "politics",
        "business",
        "technology",
        "tech",
        "health",
        "sports",
        "entertainment",
        "video",
        "videos",
        "index",
        "top-stories",
        "top-news",
        "latest-news",
    ];
    if segments.len() <= 2
        && segments.iter().all(|segment| {
            let normalized = segment.replace('-', " ");
            normalized
                .split_whitespace()
                .all(|token| listing_markers.contains(&token))
        })
    {
        return false;
    }

    let has_year_segment = segments.iter().any(|segment| {
        segment.starts_with("20")
            && segment.len() == 4
            && segment
                .chars()
                .skip(2)
                .take(2)
                .all(|ch| ch.is_ascii_digit())
    });
    let has_slug_segment = segments.iter().any(|segment| {
        segment
            .split('-')
            .filter(|token| !token.trim().is_empty() && token.len() >= 3)
            .count()
            >= 3
    });
    let has_alphanumeric_id_segment = segments.iter().any(|segment| {
        segment.len() >= 10
            && segment.chars().any(|ch| ch.is_ascii_alphabetic())
            && segment.chars().any(|ch| ch.is_ascii_digit())
    });
    let terminal = segments.last().copied().unwrap_or_default();
    let terminal_slug_tokens = terminal
        .split('-')
        .filter(|token| !token.trim().is_empty() && token.len() >= 3)
        .count();
    let terminal_has_structure = terminal_slug_tokens >= 3
        || terminal.chars().filter(|ch| ch.is_ascii_digit()).count() >= 4
        || (terminal.len() >= 10
            && terminal.chars().any(|ch| ch.is_ascii_alphabetic())
            && terminal.chars().any(|ch| ch.is_ascii_digit()));
    let has_article_path_keyword = path.contains("/article/")
        || path.contains("/story/")
        || path.contains("/live/")
        || path.contains("/news/")
        || path.contains("/world/")
        || path.contains("/politics/")
        || path.contains("/business/")
        || path.contains("/us/");

    has_alphanumeric_id_segment
        || (has_year_segment && terminal_has_structure)
        || (has_article_path_keyword && terminal_has_structure && segments.len() >= 2)
        || (segments.len() >= 3 && has_slug_segment && terminal_has_structure)
}

fn source_is_likely_headline_article(source: &WebSource) -> bool {
    let url = source.url.trim();
    if url.is_empty() {
        return false;
    }
    if is_news_feed_wrapper_url(url) {
        return false;
    }
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }

    let path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if path.is_empty() {
        return false;
    }
    if headline_url_has_article_structure(url) {
        return true;
    }

    // Keep a metadata fallback for providers that omit useful path detail.
    let has_signal = source_has_headline_news_signal(source);
    if !has_signal {
        return false;
    }
    parsed.path().trim_matches('/').split('/').count() >= 3
}

fn headline_article_like_source_count(sources: &[WebSource]) -> usize {
    sources
        .iter()
        .filter(|source| source_is_likely_headline_article(source))
        .count()
}

fn normalized_domain_key(value: &str) -> String {
    value.trim().trim_start_matches("www.").to_ascii_lowercase()
}

fn source_domain_matches(expected_domain: &str, source: &WebSource) -> bool {
    let expected = normalized_domain_key(expected_domain);
    if expected.is_empty() {
        return false;
    }
    let candidate_domain = canonical_source_domain(source).unwrap_or_default();
    if candidate_domain.is_empty() {
        return false;
    }
    candidate_domain == expected || candidate_domain.ends_with(&format!(".{}", expected))
}

fn resolved_href_with_base(base_url: &str, href: &str) -> Option<String> {
    let trimmed = href.trim();
    if trimmed.is_empty() {
        return None;
    }
    let resolved = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Url::parse(trimmed).ok()?
    } else {
        let base = Url::parse(base_url).ok()?;
        base.join(trimmed).ok()?
    };
    if !matches!(resolved.scheme(), "http" | "https") {
        return None;
    }
    Some(resolved.as_str().to_string())
}

fn extract_domain_article_sources_from_html(
    domain: &str,
    base_url: &str,
    html: &str,
    limit: usize,
) -> Vec<WebSource> {
    if limit == 0 {
        return Vec::new();
    }
    let normalized_domain = normalized_domain_key(domain);
    if normalized_domain.is_empty() {
        return Vec::new();
    }
    let document = Html::parse_document(html);
    let Ok(anchor_selector) = Selector::parse("a[href]") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for anchor in document.select(&anchor_selector) {
        if out.len() >= limit {
            break;
        }
        let Some(href) = anchor.value().attr("href") else {
            continue;
        };
        let Some(resolved_url) = resolved_href_with_base(base_url, href) else {
            continue;
        };
        let Some(candidate_domain) = domain_for_url(&resolved_url) else {
            continue;
        };
        let candidate_domain = normalized_domain_key(&candidate_domain);
        if candidate_domain != normalized_domain
            && !candidate_domain.ends_with(&format!(".{}", normalized_domain))
        {
            continue;
        }
        if !headline_url_has_article_structure(&resolved_url) {
            continue;
        }
        let normalized_url = normalize_url_for_id(&resolved_url);
        if !seen.insert(normalized_url) {
            continue;
        }
        let title_raw = anchor.text().collect::<Vec<_>>().join(" ");
        let title_compact = title_raw
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string();
        out.push(WebSource {
            source_id: source_id_for_url(&resolved_url),
            rank: Some((out.len() as u32) + 1),
            url: resolved_url.clone(),
            title: (!title_compact.is_empty()).then_some(title_compact),
            snippet: None,
            domain: Some(candidate_domain),
        });
    }

    out
}

fn provider_search_query(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if !query_is_generic_headline_lookup(trimmed) {
        return trimmed.to_string();
    }

    let mut tokens = Vec::new();
    let mut seen = HashSet::new();
    for raw in trimmed.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let mut normalized = raw.trim().to_ascii_lowercase();
        if normalized == "todays" {
            normalized = "today".to_string();
        }
        if normalized.len() < 2 {
            continue;
        }
        if matches!(
            normalized.as_str(),
            "tell"
                | "me"
                | "give"
                | "show"
                | "what"
                | "whats"
                | "please"
                | "could"
                | "would"
                | "can"
                | "you"
                | "today"
        ) {
            continue;
        }
        if seen.insert(normalized.clone()) {
            tokens.push(normalized);
        }
    }

    if !tokens.iter().any(|token| token == "news") {
        tokens.push("news".to_string());
    }
    if !tokens
        .iter()
        .any(|token| token == "headline" || token == "headlines")
    {
        tokens.push("headlines".to_string());
    }
    if !tokens
        .iter()
        .any(|token| matches!(token.as_str(), "latest" | "recent" | "breaking"))
    {
        tokens.push("latest".to_string());
    }
    if !tokens
        .iter()
        .any(|token| matches!(token.as_str(), "top" | "latest" | "breaking"))
    {
        tokens.push("top".to_string());
    }

    let priority = ["latest", "breaking", "top", "news", "headlines"];
    let mut ordered = Vec::new();
    let mut included = HashSet::new();
    for wanted in priority {
        if tokens.iter().any(|token| token == wanted) && included.insert(wanted.to_string()) {
            ordered.push(wanted.to_string());
        }
    }
    for token in tokens {
        if included.insert(token.clone()) {
            ordered.push(token);
        }
    }
    if !ordered.iter().any(|token| token == "world") {
        ordered.push("world".to_string());
    }
    let query = ordered.join(" ").trim().to_string();
    if query.is_empty() {
        "latest top news headlines world".to_string()
    } else {
        query
    }
}

fn canonical_source_domain(source: &WebSource) -> Option<String> {
    let from_source = source
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    let domain = from_source
        .or_else(|| domain_for_url(&source.url).map(|value| value.to_ascii_lowercase()))?;
    Some(domain.strip_prefix("www.").unwrap_or(&domain).to_string())
}

fn distinct_source_domain_count(sources: &[WebSource]) -> usize {
    let mut domains = HashSet::new();
    for source in sources {
        if let Some(domain) = canonical_source_domain(source) {
            domains.insert(domain);
        } else {
            domains.insert(normalize_url_for_id(&source.url));
        }
    }
    domains.len()
}

fn append_unique_sources(existing: &mut Vec<WebSource>, incoming: Vec<WebSource>) {
    let mut seen_urls = existing
        .iter()
        .map(|source| normalize_url_for_id(&source.url))
        .collect::<HashSet<_>>();
    for source in incoming {
        let url_key = normalize_url_for_id(&source.url);
        if seen_urls.insert(url_key) {
            existing.push(source);
        }
    }
}

async fn enrich_headline_sources_from_domains(
    query_for_provider: &str,
    sources: &[WebSource],
    required_domain_floor: usize,
) -> Vec<WebSource> {
    if sources.is_empty() || required_domain_floor == 0 {
        return Vec::new();
    }

    let mut domains: Vec<(String, Vec<String>)> = Vec::new();
    let domain_probe_limit = required_domain_floor.saturating_add(6).max(4);
    let enriched_target = required_domain_floor.saturating_add(2).max(3);
    for source in sources {
        let Some(domain) = canonical_source_domain(source) else {
            continue;
        };
        let seed_url = source.url.trim();
        if let Some((_, seed_urls)) = domains.iter_mut().find(|(existing, _)| existing == &domain) {
            if !seed_url.is_empty()
                && !seed_urls
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(seed_url))
            {
                seed_urls.push(seed_url.to_string());
            }
            continue;
        }
        let mut seed_urls = Vec::new();
        if !seed_url.is_empty() {
            seed_urls.push(seed_url.to_string());
        }
        domains.push((domain, seed_urls));
        if domains.len() >= domain_probe_limit {
            break;
        }
    }
    if domains.is_empty() {
        return Vec::new();
    }

    let mut enriched = Vec::new();
    let utc_year = current_utc_year();
    for (domain, seed_urls) in domains {
        let mut resolved_for_domain = false;

        for seed_url in seed_urls.iter().take(2) {
            let Ok(html) = fetch_html_http_fallback(seed_url).await else {
                continue;
            };
            let extracted = extract_domain_article_sources_from_html(&domain, seed_url, &html, 6);
            let Some(best_match) = extracted
                .into_iter()
                .find(|candidate| source_is_likely_headline_article(candidate))
            else {
                continue;
            };
            enriched.push(best_match);
            resolved_for_domain = true;
            break;
        }

        if resolved_for_domain {
            if enriched.len() >= enriched_target {
                break;
            }
            continue;
        }

        let probe_queries = [
            format!("site:{} {} world breaking news", domain, utc_year),
            format!("site:{} {} politics breaking news", domain, utc_year),
            format!("site:{} {} business breaking news", domain, utc_year),
            format!("site:{} {} {}", domain, utc_year, query_for_provider),
        ];
        for probe_query in probe_queries {
            let probe_attempts = [
                (
                    SearchProviderStage::BingHttp,
                    build_bing_serp_url(&probe_query),
                ),
                (
                    SearchProviderStage::GoogleHttp,
                    build_google_serp_url(&probe_query),
                ),
            ];
            for (provider, probe_url) in probe_attempts {
                let Ok(html) = fetch_html_http_fallback(&probe_url).await else {
                    continue;
                };
                let probe_sources = match provider {
                    SearchProviderStage::BingHttp => parse_bing_sources_from_html(&html, 20),
                    SearchProviderStage::GoogleHttp => parse_google_sources_from_html(&html, 20),
                    _ => Vec::new(),
                };
                let Some(best_match) = probe_sources.into_iter().find(|candidate| {
                    source_domain_matches(&domain, candidate)
                        && !is_news_feed_wrapper_url(candidate.url.trim())
                        && source_is_likely_headline_article(candidate)
                }) else {
                    continue;
                };
                enriched.push(best_match);
                resolved_for_domain = true;
                break;
            }
            if resolved_for_domain {
                break;
            }
        }
        if !resolved_for_domain {
            let homepage_candidates = [
                format!("https://{}", domain),
                format!("https://www.{}", domain),
                format!("https://{}/news", domain),
                format!("https://www.{}/news", domain),
                format!("https://{}/world", domain),
                format!("https://www.{}/world", domain),
                format!("https://{}/politics", domain),
                format!("https://www.{}/politics", domain),
                format!("https://{}/business", domain),
                format!("https://www.{}/business", domain),
            ];
            for homepage_url in homepage_candidates {
                let Ok(html) = fetch_html_http_fallback(&homepage_url).await else {
                    continue;
                };
                let fallback_sources =
                    extract_domain_article_sources_from_html(&domain, &homepage_url, &html, 4);
                let Some(best_match) = fallback_sources
                    .into_iter()
                    .find(|candidate| source_is_likely_headline_article(candidate))
                else {
                    continue;
                };
                enriched.push(best_match);
                resolved_for_domain = true;
                break;
            }
        }
        if resolved_for_domain && enriched.len() >= enriched_target {
            break;
        }
    }

    enriched
}

fn diversify_sources_by_domain(sources: Vec<WebSource>, limit: usize) -> Vec<WebSource> {
    if sources.is_empty() || limit == 0 {
        return Vec::new();
    }

    let mut ranked_sources = Vec::new();
    let mut fallback_sources = Vec::new();
    for source in sources {
        if source_is_likely_headline_article(&source) {
            ranked_sources.push(source);
        } else {
            fallback_sources.push(source);
        }
    }
    ranked_sources.extend(fallback_sources);

    let mut unique_domain_first = Vec::new();
    let mut duplicates = Vec::new();
    let mut seen_domains = HashSet::new();
    for source in ranked_sources {
        let domain_key =
            canonical_source_domain(&source).unwrap_or_else(|| normalize_url_for_id(&source.url));
        if seen_domains.insert(domain_key) {
            unique_domain_first.push(source);
        } else {
            duplicates.push(source);
        }
    }

    let mut selected = unique_domain_first;
    selected.extend(duplicates);
    selected.truncate(limit);
    for (idx, source) in selected.iter_mut().enumerate() {
        source.rank = Some((idx + 1) as u32);
    }
    selected
}

pub async fn edge_web_search(
    browser: &BrowserDriver,
    query: &str,
    limit: u32,
) -> Result<WebEvidenceBundle> {
    let effective_query = provider_search_query(query);
    let query_for_provider = if effective_query.trim().is_empty() {
        query.trim()
    } else {
        effective_query.trim()
    };
    let default_serp_url = build_ddg_serp_url(query_for_provider);
    let provider_plan = effective_search_provider_plan(query);
    let search_started_at_ms = now_ms();
    let mut fallback_notes: Vec<String> = Vec::new();
    let mut challenge_reason: Option<String> = None;
    let mut challenge_url: Option<String> = None;
    let mut sources: Vec<WebSource> = Vec::new();
    let mut backend = "edge:search:empty".to_string();
    let mut source_url = default_serp_url.clone();
    let headline_diversification_mode = query_is_generic_headline_lookup(query);
    let headline_domain_floor = (limit.max(1) as usize).min(4);
    let mut headline_backends = Vec::<&str>::new();
    let provider_result_limit = if headline_diversification_mode {
        (limit.max(1) as usize).max(20)
    } else {
        limit as usize
    };

    for provider in provider_plan {
        if search_budget_exhausted(search_started_at_ms) {
            fallback_notes.push(format!(
                "search_budget_exhausted_ms={}",
                EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
            ));
            break;
        }

        match provider {
            SearchProviderStage::DdgHttp => {
                let serp_url = build_ddg_serp_url(query_for_provider);
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
                            let ddg_sources =
                                parse_ddg_sources_from_html(&html, provider_result_limit);
                            if !ddg_sources.is_empty() {
                                let filtered_sources =
                                    filter_provider_sources_by_query_anchors(query, ddg_sources);
                                if !filtered_sources.is_empty() {
                                    if headline_diversification_mode {
                                        if sources.is_empty() {
                                            source_url = serp_url.clone();
                                        }
                                        append_unique_sources(&mut sources, filtered_sources);
                                        if !headline_backends.contains(&"edge:ddg:http") {
                                            headline_backends.push("edge:ddg:http");
                                        }
                                    } else {
                                        sources = filtered_sources;
                                        backend = "edge:ddg:http".to_string();
                                        source_url = serp_url.clone();
                                    }
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
                let serp_url = build_ddg_serp_url(query_for_provider);
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
                                parse_ddg_sources_from_html(&html, provider_result_limit);
                            if !browser_sources.is_empty() {
                                let filtered_sources = filter_provider_sources_by_query_anchors(
                                    query,
                                    browser_sources,
                                );
                                if !filtered_sources.is_empty() {
                                    if headline_diversification_mode {
                                        if sources.is_empty() {
                                            source_url = serp_url.clone();
                                        }
                                        append_unique_sources(&mut sources, filtered_sources);
                                        if !headline_backends.contains(&"edge:ddg:browser") {
                                            headline_backends.push("edge:ddg:browser");
                                        }
                                    } else {
                                        sources = filtered_sources;
                                        backend = "edge:ddg:browser".to_string();
                                        source_url = serp_url.clone();
                                    }
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
                let bing_url = build_bing_serp_url(query_for_provider);
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
                            let bing_sources =
                                parse_bing_sources_from_html(&html, provider_result_limit);
                            if !bing_sources.is_empty() {
                                let filtered_sources =
                                    filter_provider_sources_by_query_anchors(query, bing_sources);
                                if !filtered_sources.is_empty() {
                                    if headline_diversification_mode {
                                        if sources.is_empty() {
                                            source_url = bing_url.clone();
                                        }
                                        append_unique_sources(&mut sources, filtered_sources);
                                        if !headline_backends.contains(&"edge:bing:http") {
                                            headline_backends.push("edge:bing:http");
                                        }
                                    } else {
                                        sources = filtered_sources;
                                        backend = "edge:bing:http".to_string();
                                        source_url = bing_url.clone();
                                    }
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
                let google_url = build_google_serp_url(query_for_provider);
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
                                parse_google_sources_from_html(&html, provider_result_limit);
                            if !google_sources.is_empty() {
                                let filtered_sources =
                                    filter_provider_sources_by_query_anchors(query, google_sources);
                                if !filtered_sources.is_empty() {
                                    if headline_diversification_mode {
                                        if sources.is_empty() {
                                            source_url = google_url.clone();
                                        }
                                        append_unique_sources(&mut sources, filtered_sources);
                                        if !headline_backends.contains(&"edge:google:http") {
                                            headline_backends.push("edge:google:http");
                                        }
                                    } else {
                                        sources = filtered_sources;
                                        backend = "edge:google:http".to_string();
                                        source_url = google_url.clone();
                                    }
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
                match fetch_google_news_rss_sources(query_for_provider, provider_result_limit).await
                {
                    Ok(google_sources) => {
                        if !google_sources.is_empty() {
                            let mut filtered_sources = if headline_diversification_mode {
                                google_sources
                            } else {
                                filter_provider_sources_by_query_anchors(query, google_sources)
                            };
                            if headline_diversification_mode {
                                filtered_sources.retain(|source| {
                                    let url = source.url.trim();
                                    !is_news_feed_wrapper_url(url)
                                        && source_is_likely_headline_article(source)
                                });
                            }
                            if !filtered_sources.is_empty() {
                                let rss_url = build_google_news_rss_url(query_for_provider);
                                if headline_diversification_mode {
                                    if sources.is_empty() {
                                        source_url = rss_url;
                                    }
                                    append_unique_sources(&mut sources, filtered_sources);
                                    if !headline_backends.contains(&"edge:google-news-rss") {
                                        headline_backends.push("edge:google-news-rss");
                                    }
                                } else {
                                    sources = filtered_sources;
                                    backend = "edge:google-news-rss".to_string();
                                    source_url = rss_url;
                                }
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
        if !headline_diversification_mode && !sources.is_empty() {
            break;
        }
        if headline_diversification_mode && !sources.is_empty() {
            let reached_domain_floor =
                distinct_source_domain_count(&sources) >= headline_domain_floor;
            let reached_provider_floor = headline_backends.len() >= 2;
            let article_sources = sources
                .iter()
                .filter(|source| source_is_likely_headline_article(source))
                .cloned()
                .collect::<Vec<_>>();
            let reached_article_floor = !article_sources.is_empty()
                && distinct_source_domain_count(&article_sources) >= headline_domain_floor
                && article_sources.len() >= limit.max(1) as usize;
            if reached_article_floor
                || (reached_domain_floor
                    && reached_provider_floor
                    && sources.len() >= limit.max(1) as usize)
            {
                break;
            }
        }
    }

    if headline_diversification_mode && !sources.is_empty() {
        let article_like_domain_count = distinct_source_domain_count(
            &sources
                .iter()
                .filter(|source| source_is_likely_headline_article(source))
                .cloned()
                .collect::<Vec<_>>(),
        );
        if article_like_domain_count < headline_domain_floor {
            let enriched = enrich_headline_sources_from_domains(
                query_for_provider,
                &sources,
                headline_domain_floor,
            )
            .await;
            if !enriched.is_empty() {
                append_unique_sources(&mut sources, enriched);
            }
        }
        let non_wrapper_count = sources
            .iter()
            .filter(|source| !is_news_feed_wrapper_url(source.url.trim()))
            .count();
        if non_wrapper_count > 0 {
            sources.retain(|source| !is_news_feed_wrapper_url(source.url.trim()));
        }
        let article_sources = sources
            .iter()
            .filter(|source| source_is_likely_headline_article(source))
            .cloned()
            .collect::<Vec<_>>();
        let article_domain_count = distinct_source_domain_count(&article_sources);
        let required_article_floor = headline_domain_floor.max(1);
        if !article_sources.is_empty() {
            if article_domain_count < required_article_floor
                && article_sources.len() < limit.max(1) as usize
            {
                fallback_notes.push(format!(
                    "headline_article_floor_partial={}of{}",
                    article_domain_count, required_article_floor
                ));
            }
            sources = article_sources;
        }
        sources = diversify_sources_by_domain(sources, limit.max(1) as usize);
        backend = if headline_backends.is_empty() {
            "edge:headline-aggregate".to_string()
        } else {
            format!("edge:headline-aggregate:{}", headline_backends.join("+"))
        };
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
        query: Some(query_for_provider.to_string()),
        url: Some(source_url),
        sources,
        documents: vec![],
    })
}
