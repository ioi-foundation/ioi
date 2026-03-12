#[derive(Debug, Clone)]
struct ObservedSearchProviderCandidate {
    descriptor: SearchProviderDescriptor,
    request_url: Option<String>,
    sources: Vec<WebSource>,
    source_observations: Vec<WebSourceObservation>,
    success: bool,
    selected: bool,
    challenge_reason: Option<String>,
    fallback_note: Option<String>,
}

impl ObservedSearchProviderCandidate {
    fn selection_input(&self) -> SearchProviderCandidateSelectionInput<'_> {
        SearchProviderCandidateSelectionInput {
            descriptor: &self.descriptor,
            source_count: self.sources.len(),
            challenge_present: self.challenge_reason.is_some(),
        }
    }

    fn bundle_candidate(&self) -> WebProviderCandidate {
        WebProviderCandidate {
            provider_id: provider_backend_id(self.descriptor.stage).to_string(),
            affordances: self.descriptor.affordances.to_vec(),
            request_url: self.request_url.clone(),
            source_count: self.sources.len() as u32,
            success: self.success,
            selected: self.selected,
            challenge_reason: self.challenge_reason.clone(),
        }
    }
}

fn finalize_provider_sources(
    sources: Vec<WebSource>,
    excluded_hosts: &HashSet<String>,
) -> Vec<WebSource> {
    let mut filtered_sources = sources;
    if !excluded_hosts.is_empty() {
        filtered_sources.retain(|source| !source_matches_excluded_host(source, excluded_hosts));
    }
    filtered_sources
}

fn filter_provider_sources_by_contract(
    sources: Vec<WebSource>,
    query_contract: &str,
    retrieval_contract: &WebRetrievalContract,
) -> Vec<WebSource> {
    if !contract_requires_semantic_source_alignment(retrieval_contract) {
        return sources;
    }

    let aligned_urls =
        match query_matching_source_urls(query_contract, retrieval_contract, &sources) {
            Ok(urls) => urls,
            Err(_) => return Vec::new(),
        };
    if aligned_urls.is_empty() {
        return Vec::new();
    }
    let aligned_keys = aligned_urls
        .into_iter()
        .map(|url| normalize_url_for_id(&url))
        .collect::<HashSet<_>>();
    sources
        .into_iter()
        .filter(|source| aligned_keys.contains(&normalize_url_for_id(&source.url)))
        .collect()
}

async fn probe_search_provider(
    browser: &BrowserDriver,
    descriptor: SearchProviderDescriptor,
    query_for_provider: &str,
    query_contract: &str,
    retrieval_contract: &WebRetrievalContract,
    locality_scope: Option<&str>,
    headline_lookup_mode: bool,
    provider_result_limit: usize,
    _expansion_surface_preferred: bool,
    excluded_hosts: &HashSet<String>,
) -> ObservedSearchProviderCandidate {
    let provider_id = provider_backend_id(descriptor.stage);
    let fallback = |fallback_note: Option<String>,
                    request_url: Option<String>,
                    challenge_reason: Option<String>,
                    success: bool| ObservedSearchProviderCandidate {
        descriptor,
        request_url,
        sources: Vec::new(),
        source_observations: Vec::new(),
        success,
        selected: false,
        challenge_reason,
        fallback_note,
    };
    match descriptor.stage {
        SearchProviderStage::WeatherGovLocalityDetail => {
            let Some(scope) = locality_scope
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return fallback(
                    Some(format!("{}_locality_scope_missing", provider_id)),
                    None,
                    None,
                    false,
                );
            };
            let request_url = build_weather_gov_locality_lookup_url(scope);
            match fetch_structured_detail_http_fallback_browser_ua_with_final_url(&request_url)
                .await
            {
                Ok((final_url, html)) => {
                    let challenge_reason = detect_human_challenge(&final_url, &html)
                        .or_else(|| detect_human_challenge(&request_url, &html))
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let (extracted_title, mut blocks) =
                        extract_read_blocks_for_url(&final_url, &html);
                    if blocks.is_empty() {
                        blocks = extract_non_html_read_blocks(&html);
                    }
                    let sources =
                        best_structured_detail_source(&final_url, &html, extracted_title, &blocks)
                            .into_iter()
                            .collect::<Vec<_>>();
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    let source_observations =
                        source_observations_for_sources(&sources, descriptor.affordances, &[]);
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations,
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::RestaurantJiLocalityDirectory => {
            let Some(scope) = locality_scope
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return fallback(
                    Some(format!("{}_locality_scope_missing", provider_id)),
                    None,
                    None,
                    false,
                );
            };
            let Some(request_url) = build_restaurantji_locality_root_url(scope) else {
                return fallback(
                    Some(format!("{}_locality_scope_invalid", provider_id)),
                    None,
                    None,
                    false,
                );
            };
            match fetch_structured_detail_http_fallback_browser_ua_with_final_url(&request_url)
                .await
            {
                Ok((final_url, html)) => {
                    let challenge_reason = detect_human_challenge(&final_url, &html)
                        .or_else(|| detect_human_challenge(&request_url, &html))
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let category_limit = provider_result_limit.max(8);
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_same_host_child_collection_sources_from_html(
                                &final_url,
                                &html,
                                category_limit,
                            ),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    let source_observations =
                        source_observations_for_sources(&sources, descriptor.affordances, &[]);
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations,
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::BraveHttp => {
            let request_url = build_brave_serp_url(query_for_provider);
            match fetch_structured_detail_http_fallback_browser_ua(&request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_brave_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::DdgHttp => {
            let request_url = build_ddg_serp_url(query_for_provider);
            match fetch_html_http_fallback_browser_ua(&request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_ddg_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::DdgBrowser => {
            let request_url = build_ddg_serp_url(query_for_provider);
            match navigate_browser_retrieval(browser, &request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_ddg_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::BingHttp => {
            let request_url = build_bing_serp_url(query_for_provider);
            match fetch_html_http_fallback_browser_ua(&request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_bing_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::BingNewsRss => {
            let request_url = build_bing_news_rss_url(query_for_provider);
            match fetch_bing_news_rss_sources(query_for_provider, provider_result_limit).await {
                Ok(sources) => {
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::BingSearchRss => {
            let request_url = build_bing_search_rss_url(query_for_provider);
            match fetch_bing_search_rss_sources(query_for_provider, provider_result_limit).await {
                Ok(sources) => {
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::GoogleHttp => {
            let request_url = if headline_lookup_mode {
                build_google_news_serp_url(query_for_provider)
            } else {
                build_google_serp_url(query_for_provider)
            };
            match fetch_html_http_fallback_browser_ua(&request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_google_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::GoogleNewsRss => {
            let request_url = build_google_news_rss_url(query_for_provider);
            match fetch_google_news_rss_sources(query_for_provider, provider_result_limit).await {
                Ok(sources) => {
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::GoogleNewsTopStoriesRss => {
            let request_url = build_google_news_top_stories_rss_url();
            match fetch_google_news_top_stories_rss_sources(provider_result_limit).await {
                Ok(sources) => {
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
    }
}
