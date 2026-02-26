use super::*;

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
