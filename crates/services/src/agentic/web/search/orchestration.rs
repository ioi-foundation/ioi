use super::*;
use crate::agentic::desktop::service::step::queue::web_pipeline::query_is_generic_headline_collection;
use crate::agentic::desktop::service::step::signals::analyze_source_record_signals;

fn reliability_fixture_sources() -> Option<Vec<String>> {
    let raw = std::env::var("IOI_RELIABILITY_WEB_SEARCH_FIXTURE_URLS").ok()?;
    let urls = raw
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect::<Vec<_>>();
    if urls.is_empty() {
        None
    } else {
        Some(urls)
    }
}

fn excluded_hosts_from_query(query: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for token in query.split_whitespace() {
        let normalized = token
            .trim_matches(|ch: char| matches!(ch, ',' | ';' | ')' | '(' | '"' | '\''))
            .to_ascii_lowercase();
        let Some(host_raw) = normalized.strip_prefix("-site:") else {
            continue;
        };
        let host = host_raw
            .trim()
            .trim_start_matches("www.")
            .trim_end_matches('.');
        if host.is_empty() {
            continue;
        }
        out.insert(host.to_string());
    }
    out
}

fn source_matches_excluded_host(source: &WebSource, excluded_hosts: &HashSet<String>) -> bool {
    if excluded_hosts.is_empty() {
        return false;
    }
    canonical_source_domain(source)
        .map(|domain| {
            excluded_hosts
                .iter()
                .any(|excluded| domain == *excluded || domain.ends_with(&format!(".{}", excluded)))
        })
        .unwrap_or(false)
}

fn append_unique_sources(existing: &mut Vec<WebSource>, incoming: Vec<WebSource>) {
    let mut seen = existing
        .iter()
        .map(|source| normalize_url_for_id(&source.url))
        .collect::<HashSet<_>>();
    for source in incoming {
        let key = normalize_url_for_id(&source.url);
        if seen.insert(key) {
            existing.push(source);
        }
    }
}

fn filter_sources_for_query_anchors(
    query: &str,
    sources: Vec<WebSource>,
    enable_anchor_filter: bool,
) -> Vec<WebSource> {
    if enable_anchor_filter {
        filter_provider_sources_by_query_anchors(query, sources)
    } else {
        sources
    }
}

fn reorder_headline_sources_for_truncation(sources: Vec<WebSource>) -> Vec<WebSource> {
    if sources.is_empty() {
        return sources;
    }

    fn source_is_low_priority_headline_surface(source: &WebSource) -> bool {
        let title = source.title.as_deref().unwrap_or_default();
        let snippet = source.snippet.as_deref().unwrap_or_default();
        let signals = analyze_source_record_signals(&source.url, title, snippet);
        signals.low_priority_hits > 0 || signals.low_priority_dominates()
    }

    let mut ranked = sources;
    ranked.sort_by(|left, right| {
        let left_article = looks_like_headline_article_url(&left.url);
        let right_article = looks_like_headline_article_url(&right.url);
        let left_low_priority = source_is_low_priority_headline_surface(left);
        let right_low_priority = source_is_low_priority_headline_surface(right);
        let left_domain_known = canonical_source_domain(left).is_some();
        let right_domain_known = canonical_source_domain(right).is_some();
        right_article
            .cmp(&left_article)
            .then_with(|| left_low_priority.cmp(&right_low_priority))
            .then_with(|| {
                headline_article_path_depth(&right.url).cmp(&headline_article_path_depth(&left.url))
            })
            .then_with(|| right_domain_known.cmp(&left_domain_known))
            .then_with(|| {
                left.rank
                    .unwrap_or(u32::MAX)
                    .cmp(&right.rank.unwrap_or(u32::MAX))
            })
            .then_with(|| left.url.cmp(&right.url))
    });

    let mut reordered = Vec::with_capacity(ranked.len());
    let mut seen_urls = HashSet::new();
    let mut seen_domains = HashSet::new();

    for source in ranked.iter().filter(|source| {
        looks_like_headline_article_url(&source.url)
            && canonical_source_domain(source).is_some()
            && !source_is_low_priority_headline_surface(source)
    }) {
        let url_key = normalize_url_for_id(&source.url);
        let Some(domain_key) = canonical_source_domain(source) else {
            continue;
        };
        if !seen_urls.insert(url_key) || !seen_domains.insert(domain_key) {
            continue;
        }
        reordered.push(source.clone());
    }
    for source in ranked.iter().filter(|source| {
        looks_like_headline_article_url(&source.url)
            && !source_is_low_priority_headline_surface(source)
    }) {
        let url_key = normalize_url_for_id(&source.url);
        if seen_urls.insert(url_key) {
            reordered.push(source.clone());
        }
    }
    for source in ranked {
        let url_key = normalize_url_for_id(&source.url);
        if seen_urls.insert(url_key) {
            reordered.push(source);
        }
    }

    reordered
}

pub async fn edge_web_search(
    browser: &BrowserDriver,
    query: &str,
    limit: u32,
) -> Result<WebEvidenceBundle> {
    if let Some(fixture_urls) = reliability_fixture_sources() {
        let effective_limit = limit.max(1) as usize;
        let sources = fixture_urls
            .into_iter()
            .take(effective_limit)
            .enumerate()
            .map(|(idx, url)| WebSource {
                source_id: source_id_for_url(&url),
                rank: Some((idx + 1) as u32),
                domain: domain_for_url(&url),
                title: Some(format!("Reliability Fixture Source {}", idx + 1)),
                snippet: Some("Deterministic search fixture source".to_string()),
                url,
            })
            .collect::<Vec<_>>();

        let source_url = sources
            .first()
            .map(|source| source.url.clone())
            .unwrap_or_else(|| build_ddg_serp_url(query.trim()));

        return Ok(WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: now_ms(),
            tool: "web__search".to_string(),
            backend: "edge:search:fixture".to_string(),
            query: Some(query.trim().to_string()),
            url: Some(source_url),
            sources,
            documents: vec![],
        });
    }

    let effective_query = provider_search_query(query);
    let query_for_provider = if effective_query.trim().is_empty() {
        query.trim()
    } else {
        effective_query.trim()
    };
    let default_serp_url = build_ddg_serp_url(query_for_provider);
    let provider_plan = effective_search_provider_plan(query);
    let headline_lookup_mode = query_is_generic_headline_collection(query_for_provider);
    let apply_query_anchor_filter = !headline_lookup_mode;
    let excluded_hosts = excluded_hosts_from_query(query_for_provider);
    let search_started_at_ms = now_ms();
    let mut fallback_notes: Vec<String> = Vec::new();
    let mut challenge_reason: Option<String> = None;
    let mut challenge_url: Option<String> = None;
    let mut sources: Vec<WebSource> = Vec::new();
    let mut backend = "edge:search:empty".to_string();
    let mut source_url = default_serp_url.clone();
    let provider_result_limit = limit.max(1) as usize;
    let mut contributing_backends: Vec<&str> = Vec::new();

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
                                let filtered_sources = filter_sources_for_query_anchors(
                                    query,
                                    ddg_sources,
                                    apply_query_anchor_filter,
                                );
                                let mut filtered_sources = filtered_sources;
                                if !excluded_hosts.is_empty() {
                                    filtered_sources.retain(|source| {
                                        !source_matches_excluded_host(source, &excluded_hosts)
                                    });
                                }
                                if !filtered_sources.is_empty() {
                                    if sources.is_empty() {
                                        source_url = serp_url.clone();
                                    }
                                    append_unique_sources(&mut sources, filtered_sources);
                                    contributing_backends.push("edge:ddg:http");
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
                                let filtered_sources = filter_sources_for_query_anchors(
                                    query,
                                    browser_sources,
                                    apply_query_anchor_filter,
                                );
                                let mut filtered_sources = filtered_sources;
                                if !excluded_hosts.is_empty() {
                                    filtered_sources.retain(|source| {
                                        !source_matches_excluded_host(source, &excluded_hosts)
                                    });
                                }
                                if !filtered_sources.is_empty() {
                                    if sources.is_empty() {
                                        source_url = serp_url.clone();
                                    }
                                    append_unique_sources(&mut sources, filtered_sources);
                                    contributing_backends.push("edge:ddg:browser");
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
                                let filtered_sources = filter_sources_for_query_anchors(
                                    query,
                                    bing_sources,
                                    apply_query_anchor_filter,
                                );
                                let mut filtered_sources = filtered_sources;
                                if !excluded_hosts.is_empty() {
                                    filtered_sources.retain(|source| {
                                        !source_matches_excluded_host(source, &excluded_hosts)
                                    });
                                }
                                if !filtered_sources.is_empty() {
                                    if sources.is_empty() {
                                        source_url = bing_url.clone();
                                    }
                                    append_unique_sources(&mut sources, filtered_sources);
                                    contributing_backends.push("edge:bing:http");
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
            SearchProviderStage::BingNewsRss => {
                match fetch_bing_news_rss_sources(query_for_provider, provider_result_limit).await {
                    Ok(mut bing_sources) => {
                        if !excluded_hosts.is_empty() {
                            bing_sources.retain(|source| {
                                !source_matches_excluded_host(source, &excluded_hosts)
                            });
                        }
                        if !bing_sources.is_empty() {
                            let filtered_sources = filter_sources_for_query_anchors(
                                query,
                                bing_sources,
                                apply_query_anchor_filter,
                            );
                            if !filtered_sources.is_empty() {
                                let rss_url = build_bing_news_rss_url(query_for_provider);
                                if sources.is_empty() {
                                    source_url = rss_url;
                                }
                                append_unique_sources(&mut sources, filtered_sources);
                                contributing_backends.push("edge:bing-news-rss");
                                challenge_reason = None;
                                challenge_url = None;
                            } else {
                                fallback_notes.push("bing_news_rss_anchor_mismatch".to_string());
                            }
                        } else {
                            fallback_notes.push("bing_news_rss_empty".to_string());
                        }
                    }
                    Err(err) => fallback_notes.push(format!("bing_news_rss_error={}", err)),
                }
            }
            SearchProviderStage::GoogleHttp => {
                let google_url = if headline_lookup_mode {
                    build_google_news_serp_url(query_for_provider)
                } else {
                    build_google_serp_url(query_for_provider)
                };
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
                                let filtered_sources = filter_sources_for_query_anchors(
                                    query,
                                    google_sources,
                                    apply_query_anchor_filter,
                                );
                                let mut filtered_sources = filtered_sources;
                                if !excluded_hosts.is_empty() {
                                    filtered_sources.retain(|source| {
                                        !source_matches_excluded_host(source, &excluded_hosts)
                                    });
                                }
                                if !filtered_sources.is_empty() {
                                    if sources.is_empty() {
                                        source_url = google_url.clone();
                                    }
                                    append_unique_sources(&mut sources, filtered_sources);
                                    contributing_backends.push("edge:google:http");
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
                    Ok(mut google_sources) => {
                        if !excluded_hosts.is_empty() {
                            google_sources.retain(|source| {
                                !source_matches_excluded_host(source, &excluded_hosts)
                            });
                        }
                        if !google_sources.is_empty() {
                            let filtered_sources = filter_sources_for_query_anchors(
                                query,
                                google_sources,
                                apply_query_anchor_filter,
                            );
                            if !filtered_sources.is_empty() {
                                let rss_url = build_google_news_rss_url(query_for_provider);
                                if sources.is_empty() {
                                    source_url = rss_url;
                                }
                                append_unique_sources(&mut sources, filtered_sources);
                                contributing_backends.push("edge:google-news-rss");
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

    if !sources.is_empty() {
        if headline_lookup_mode {
            sources = reorder_headline_sources_for_truncation(sources);
        }
        sources.truncate(provider_result_limit);
        for (idx, source) in sources.iter_mut().enumerate() {
            source.rank = Some((idx + 1) as u32);
        }
        if let Some(first_backend) = contributing_backends.first() {
            backend = if contributing_backends
                .iter()
                .all(|candidate| candidate == first_backend)
            {
                (*first_backend).to_string()
            } else {
                let unique_backends = contributing_backends.into_iter().fold(
                    Vec::<&str>::new(),
                    |mut acc, backend_name| {
                        if !acc.contains(&backend_name) {
                            acc.push(backend_name);
                        }
                        acc
                    },
                );
                format!("edge:search:aggregate:{}", unique_backends.join("+"))
            };
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
        query: Some(query_for_provider.to_string()),
        url: Some(source_url),
        sources,
        documents: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_source(url: &str, domain: &str) -> WebSource {
        WebSource {
            source_id: source_id_for_url(url),
            rank: Some(1),
            url: url.to_string(),
            title: None,
            snippet: None,
            domain: Some(domain.to_string()),
        }
    }

    #[test]
    fn excluded_hosts_from_query_extracts_site_tokens() {
        let hosts = excluded_hosts_from_query(
            "latest top news headlines -site:www.fifa.com -site:media.fifa.com",
        );
        assert!(hosts.contains("fifa.com"));
        assert!(hosts.contains("media.fifa.com"));
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn source_matches_excluded_host_filters_matching_domains() {
        let mut excluded = HashSet::new();
        excluded.insert("fifa.com".to_string());

        assert!(source_matches_excluded_host(
            &test_source("https://www.fifa.com/en/news/articles/x", "www.fifa.com"),
            &excluded
        ));
        assert!(source_matches_excluded_host(
            &test_source("https://media.fifa.com/en/news/x", "media.fifa.com"),
            &excluded
        ));
        assert!(!source_matches_excluded_host(
            &test_source("https://www.reuters.com/world/example", "www.reuters.com"),
            &excluded
        ));
    }

    #[test]
    fn headline_reorder_prioritizes_article_urls_before_hub_urls() {
        let sources = vec![
            test_source("https://www.nbcnews.com/", "www.nbcnews.com"),
            test_source(
                "https://www.reuters.com/world/europe/example-story-2026-03-01/",
                "www.reuters.com",
            ),
            test_source(
                "https://www.apnews.com/article/sample-story-2026-03-01",
                "www.apnews.com",
            ),
        ];
        let reordered = reorder_headline_sources_for_truncation(sources);
        assert!(looks_like_headline_article_url(&reordered[0].url));
        assert!(looks_like_headline_article_url(&reordered[1].url));
    }
}
