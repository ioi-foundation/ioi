use crate::agentic::desktop::service::step::signals::analyze_query_facets;
use anyhow::Result;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};

use super::anchor_policy::filter_provider_sources_by_query_anchors;
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
use super::util::now_ms;

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

pub(crate) fn search_budget_exhausted(started_at_ms: u64) -> bool {
    now_ms().saturating_sub(started_at_ms) >= EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
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
