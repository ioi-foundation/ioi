use crate::agentic::desktop::service::step::signals::analyze_query_facets;
use anyhow::Result;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};
use std::collections::HashSet;

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
use super::util::{domain_for_url, normalize_url_for_id, now_ms};

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
        plan.retain(|stage| *stage != SearchProviderStage::GoogleNewsRss);
        plan.insert(0, SearchProviderStage::GoogleNewsRss);
    }
    plan
}

pub(crate) fn search_budget_exhausted(started_at_ms: u64) -> bool {
    now_ms().saturating_sub(started_at_ms) >= EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
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
        .any(|token| matches!(token.as_str(), "today" | "latest" | "recent" | "breaking"))
    {
        tokens.push("today".to_string());
    }
    if !tokens
        .iter()
        .any(|token| matches!(token.as_str(), "top" | "latest" | "breaking"))
    {
        tokens.push("top".to_string());
    }

    let priority = ["today", "latest", "top", "breaking", "news", "headlines"];
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
    if !ordered.iter().any(|token| token == "us" || token == "u.s") {
        ordered.push("us".to_string());
    }
    if !ordered.iter().any(|token| token == "world") {
        ordered.push("world".to_string());
    }
    for outlet in ["reuters", "ap", "bbc", "npr", "cnn"] {
        if !ordered.iter().any(|token| token == outlet) {
            ordered.push(outlet.to_string());
        }
    }

    let query = ordered.join(" ").trim().to_string();
    if query.is_empty() {
        "today top news headlines".to_string()
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

fn diversify_sources_by_domain(sources: Vec<WebSource>, limit: usize) -> Vec<WebSource> {
    if sources.is_empty() || limit == 0 {
        return Vec::new();
    }

    let mut unique_domain_first = Vec::new();
    let mut duplicates = Vec::new();
    let mut seen_domains = HashSet::new();
    for source in sources {
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
                            let ddg_sources = parse_ddg_sources_from_html(&html, limit as usize);
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
                                parse_ddg_sources_from_html(&html, limit as usize);
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
                            let bing_sources = parse_bing_sources_from_html(&html, limit as usize);
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
                                parse_google_sources_from_html(&html, limit as usize);
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
                match fetch_google_news_rss_sources(query_for_provider, limit as usize).await {
                    Ok(google_sources) => {
                        if !google_sources.is_empty() {
                            let filtered_sources =
                                filter_provider_sources_by_query_anchors(query, google_sources);
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
            if reached_domain_floor
                && reached_provider_floor
                && sources.len() >= limit.max(1) as usize
            {
                break;
            }
        }
    }

    if headline_diversification_mode && !sources.is_empty() {
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
