fn structural_seed_expansion_from_html(
    seed_url: &str,
    page_url: &str,
    html: &str,
    limit: usize,
) -> Option<(
    ioi_types::app::agentic::WebSourceObservation,
    Vec<WebSource>,
)> {
    let expansion_limit = limit.max(1);
    let json_ld_sources = crate::agentic::web::parse_json_ld_item_list_sources_from_html(
        page_url,
        html,
        expansion_limit,
    );
    let child_link_sources =
        crate::agentic::web::parse_same_host_child_collection_sources_from_html(
            page_url,
            html,
            expansion_limit,
        );
    let mut expansion_affordances = Vec::new();
    let mut expanded_sources = Vec::new();
    let mut seen_urls = std::collections::BTreeSet::new();

    if !json_ld_sources.is_empty() {
        expansion_affordances
            .push(ioi_types::app::agentic::WebSourceExpansionAffordance::JsonLdItemList);
        for source in json_ld_sources {
            let trimmed = source.url.trim();
            if trimmed.is_empty() || !seen_urls.insert(trimmed.to_ascii_lowercase()) {
                continue;
            }
            expanded_sources.push(source);
        }
    }
    if !child_link_sources.is_empty() {
        expansion_affordances
            .push(ioi_types::app::agentic::WebSourceExpansionAffordance::ChildLinkCollection);
        for source in child_link_sources {
            let trimmed = source.url.trim();
            if trimmed.is_empty() || !seen_urls.insert(trimmed.to_ascii_lowercase()) {
                continue;
            }
            expanded_sources.push(source);
        }
    }
    if expansion_affordances.is_empty() {
        return None;
    }

    Some((
        ioi_types::app::agentic::WebSourceObservation {
            url: seed_url.trim().to_string(),
            affordances: vec![
                ioi_types::app::agentic::WebRetrievalAffordance::LinkCollection,
                ioi_types::app::agentic::WebRetrievalAffordance::CanonicalLinkOut,
            ],
            expansion_affordances,
        },
        expanded_sources,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BriefingAuthoritySeedAdmission {
    query_grounded: bool,
    identifier_bearing: bool,
    document_authority: bool,
}

impl BriefingAuthoritySeedAdmission {
    fn admitted(self) -> bool {
        self.query_grounded || self.identifier_bearing || self.document_authority
    }
}

fn briefing_authority_seed_admission(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: usize,
    url: &str,
    title: &str,
    excerpt: &str,
) -> BriefingAuthoritySeedAdmission {
    let query_grounded = crate::agentic::desktop::service::step::queue::support::excerpt_has_query_grounding_signal_with_contract(
        Some(retrieval_contract),
        query_contract,
        min_sources.max(1),
        url,
        title,
        excerpt,
    );
    let identifier_bearing = crate::agentic::desktop::service::step::queue::support::source_has_briefing_standard_identifier_signal(
        query_contract,
        url,
        title,
        excerpt,
    );
    let document_authority =
        crate::agentic::desktop::service::step::queue::support::source_has_document_authority(
            query_contract,
            url,
            title,
            excerpt,
        );

    BriefingAuthoritySeedAdmission {
        query_grounded,
        identifier_bearing,
        document_authority,
    }
}

fn briefing_authority_link_expansion_required(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    discovery_sources: &[WebSource],
    required_url_count: usize,
) -> bool {
    let required_url_count = required_url_count.max(1);
    let authority_expansion_applicable = query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && crate::agentic::desktop::service::step::signals::analyze_query_facets(query_contract)
            .grounded_external_required
        && (retrieval_contract.currentness_required
            || retrieval_contract.source_independence_min > 1);
    if !authority_expansion_applicable {
        return false;
    }
    if discovery_sources.len() < required_url_count {
        return true;
    }

    let discovery_hints = discovery_source_hints(discovery_sources);
    let candidate_urls = discovery_sources
        .iter()
        .map(|source| source.url.clone())
        .collect::<Vec<_>>();
    let deterministic_plan = pre_read_candidate_plan_with_contract(
        Some(retrieval_contract),
        query_contract,
        required_url_count as u32,
        candidate_urls,
        discovery_hints,
        None,
        false,
    );
    let selected_urls = pre_read_batch_urls(&deterministic_plan.candidate_urls, required_url_count);
    if selected_urls.len() < required_url_count {
        return true;
    }

    let selection_quality =
        crate::agentic::desktop::service::step::queue::support::selected_source_quality_observation_with_contract_and_locality_hint(
            Some(retrieval_contract),
            query_contract,
            required_url_count as u32,
            &selected_urls,
            &deterministic_plan.candidate_source_hints,
            None,
        );
    !selection_quality.quality_floor_met
}

fn briefing_authority_link_out_sources_from_html(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    seed_url: &str,
    page_url: &str,
    html: &str,
    min_sources: usize,
    limit: usize,
) -> Vec<WebSource> {
    fn path_depth(parsed: &Url) -> usize {
        parsed
            .path_segments()
            .map(|segments| {
                segments
                    .filter(|segment| !segment.trim().is_empty())
                    .count()
            })
            .unwrap_or(0)
    }

    fn publication_family_root(parsed: &Url) -> Option<Vec<String>> {
        let segments = parsed
            .path_segments()
            .map(|segments| {
                segments
                    .filter(|segment| !segment.trim().is_empty())
                    .map(|segment| segment.to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if segments.len() < 3 {
            return None;
        }
        matches!(
            segments.first().map(String::as_str),
            Some("pubs" | "publications")
        )
        .then(|| segments[..3].to_vec())
    }

    fn same_host_authority_child_allowed(
        page_url: &Url,
        final_url: &Url,
        query_grounded: bool,
        identifier_bearing: bool,
        canonical_publication_artifact: bool,
    ) -> bool {
        let normalized_path = final_url.path().trim_matches('/').to_ascii_lowercase();
        let scoped_authority_surface = normalized_path.starts_with("projects/")
            || normalized_path.starts_with("pubs/")
            || normalized_path.starts_with("publications/")
            || normalized_path.starts_with("news-events/news/");

        path_depth(final_url) > path_depth(page_url)
            || matches!(
                (
                    publication_family_root(page_url),
                    publication_family_root(final_url)
                ),
                (Some(page_root), Some(final_root)) if page_root == final_root
            )
            || (scoped_authority_surface
                && !is_search_hub_url(final_url.as_str())
                && (query_grounded || identifier_bearing || canonical_publication_artifact))
    }

    fn canonical_publication_artifact_signal(parsed_final_url: &Url, title: &str) -> bool {
        let host = parsed_final_url
            .host_str()
            .map(|value| value.trim_start_matches("www.").to_ascii_lowercase())
            .unwrap_or_default();
        let path = parsed_final_url.path().to_ascii_lowercase();
        let title_lower = title.trim().to_ascii_lowercase();

        host == "nvlpubs.nist.gov"
            || (host.ends_with(".nist.gov") && path.ends_with(".pdf"))
            || title_lower.contains("federal information processing standard")
    }

    fn cleaned_external_link_page_context(
        retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
        query_contract: &str,
        min_sources: usize,
        page_context: &str,
    ) -> (String, bool) {
        let mut kept = Vec::new();
        let mut seen = BTreeSet::new();
        let mut rescued = false;
        for segment in page_context.split('|') {
            let normalized = compact_whitespace(segment);
            let trimmed = normalized.trim();
            if trimmed.is_empty() {
                continue;
            }
            let candidate = compact_whitespace(
                &crate::agentic::desktop::service::step::signals::strip_low_priority_leading_marker(
                    trimmed,
                ),
            );
            let trimmed_candidate = candidate.trim();
            let marker_stripped = !trimmed_candidate.eq_ignore_ascii_case(trimmed);
            if trimmed_candidate.is_empty() {
                if marker_stripped {
                    rescued = true;
                }
                continue;
            }
            let signals =
                crate::agentic::desktop::service::step::signals::analyze_source_record_signals(
                    "",
                    "",
                    trimmed_candidate,
                );
            if signals.low_priority_hits > 0 || signals.low_priority_dominates() {
                rescued = true;
                continue;
            }
            let grounded = crate::agentic::desktop::service::step::queue::support::excerpt_has_query_grounding_signal_with_contract(
                Some(retrieval_contract),
                query_contract,
                min_sources.max(1),
                "",
                "",
                trimmed_candidate,
            );
            if grounded || trimmed_candidate.split_whitespace().count() >= 3 {
                if marker_stripped {
                    rescued = true;
                }
                if seen.insert(trimmed_candidate.to_ascii_lowercase()) {
                    kept.push(trimmed_candidate.to_string());
                }
            }
        }

        (kept.join(" | "), rescued)
    }

    #[derive(Debug)]
    struct RankedAuthorityLinkCandidate {
        source: WebSource,
        publication_signal: bool,
        canonical_publication_artifact: bool,
        same_host: bool,
        query_grounded: bool,
        identifier_bearing: bool,
        authority_score: usize,
        path_depth: usize,
        dom_index: usize,
    }

    let Ok(base_url) = Url::parse(page_url.trim()) else {
        return Vec::new();
    };
    let semantic_alignment_required =
        crate::agentic::web::contract_requires_semantic_source_alignment(retrieval_contract);
    let seed_host = base_url
        .host_str()
        .map(|host| host.trim_start_matches("www.").to_ascii_lowercase())
        .unwrap_or_default();
    let document = scraper::Html::parse_document(html);
    let Ok(selector) = scraper::Selector::parse("a[href]") else {
        return Vec::new();
    };
    let page_context = crate::agentic::web::parse_generic_page_source_from_html(page_url, html)
        .map(|source| {
            [source.title, source.snippet]
                .into_iter()
                .flatten()
                .map(|value| compact_whitespace(&value))
                .filter(|value| !value.trim().is_empty())
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_default();
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();

    for (dom_index, anchor) in document.select(&selector).enumerate() {
        let href = anchor.value().attr("href").unwrap_or_default().trim();
        if href.is_empty()
            || href.starts_with('#')
            || href.starts_with("javascript:")
            || href.starts_with("mailto:")
        {
            continue;
        }
        let Ok(final_url) = base_url.join(href) else {
            continue;
        };
        if !matches!(final_url.scheme(), "http" | "https") {
            continue;
        }
        let final_url = final_url.to_string();
        if final_url.eq_ignore_ascii_case(seed_url) || final_url.eq_ignore_ascii_case(page_url) {
            continue;
        }
        let Ok(parsed_final_url) = Url::parse(&final_url) else {
            continue;
        };
        let link_host = parsed_final_url
            .host_str()
            .map(|host| host.trim_start_matches("www.").to_ascii_lowercase())
            .unwrap_or_default();
        if link_host.is_empty() {
            continue;
        }
        let same_host = link_host == seed_host;
        let title_raw = compact_whitespace(&anchor.text().collect::<Vec<_>>().join(" "));
        let title = title_raw.trim();
        if title.is_empty() {
            continue;
        }
        let title_token_count = title
            .split_whitespace()
            .filter(|token| !token.trim().is_empty())
            .count();
        if title_token_count == 0 || title_token_count > 20 {
            continue;
        }
        let (external_page_context, external_page_context_rescued) =
            cleaned_external_link_page_context(
                retrieval_contract,
                query_contract,
                min_sources,
                &page_context,
            );
        let snippet = if same_host || page_context.trim().is_empty() {
            if page_context.trim().is_empty() {
                title.to_string()
            } else {
                format!("{} | linked from {}", title, page_context.trim())
            }
        } else if external_page_context.is_empty() {
            title.to_string()
        } else {
            // Preserve query-grounding context from the seed page, but strip low-priority
            // marketing/opinion rhetoric so independent support candidates stay admissible later.
            format!("{} | linked from {}", title, external_page_context)
        };
        let admission = briefing_authority_seed_admission(
            retrieval_contract,
            query_contract,
            min_sources,
            &final_url,
            title,
            &snippet,
        );
        let canonical_publication_artifact =
            canonical_publication_artifact_signal(&parsed_final_url, title);
        if same_host
            && !same_host_authority_child_allowed(
                &base_url,
                &parsed_final_url,
                admission.query_grounded,
                admission.identifier_bearing,
                canonical_publication_artifact,
            )
        {
            continue;
        }
        if !admission.document_authority {
            continue;
        }
        let external_grounding_surface = if external_page_context_rescued {
            &snippet
        } else {
            title
        };
        let same_host_locally_grounded = same_host
            && crate::agentic::desktop::service::step::queue::support::excerpt_has_query_grounding_signal_with_contract(
                Some(retrieval_contract),
                query_contract,
                min_sources.max(1),
                &final_url,
                title,
                title,
            );
        let external_link_locally_grounded = !same_host
            && crate::agentic::desktop::service::step::queue::support::excerpt_has_query_grounding_signal_with_contract(
                Some(retrieval_contract),
                query_contract,
                min_sources.max(1),
                &final_url,
                title,
                external_grounding_surface,
            );
        let external_link_locally_identifier_bearing = !same_host
            && crate::agentic::desktop::service::step::queue::support::source_has_briefing_standard_identifier_signal(
                query_contract,
                &final_url,
                title,
                external_grounding_surface,
            );
        let external_link_public_authority_title_subject_overlap = !same_host
            && crate::agentic::desktop::service::step::queue::support::source_has_public_authority_host(&final_url)
            && {
                let query_native_tokens =
                    crate::agentic::desktop::service::step::queue::support::document_authority_query_tokens(query_contract);
                let title_tokens =
                    crate::agentic::desktop::service::step::queue::support::normalized_anchor_tokens(title);
                let title_native_overlap = query_native_tokens.intersection(&title_tokens).count();
                title_native_overlap >= 2
                    || (title_native_overlap >= 1
                        && crate::agentic::desktop::service::step::queue::support::source_temporal_recency_score(
                            &final_url,
                            title,
                            external_grounding_surface,
                        ) > 0)
            };
        if !same_host
            && !external_link_locally_grounded
            && !external_link_locally_identifier_bearing
        {
            continue;
        }
        if !same_host
            && crate::agentic::desktop::service::step::queue::support::source_has_public_authority_host(&final_url)
            && !external_link_locally_identifier_bearing
            && !external_link_public_authority_title_subject_overlap
            && !canonical_publication_artifact
        {
            continue;
        }
        let url_key = crate::agentic::web::normalize_url_for_id(&final_url);
        if !seen.insert(url_key) {
            continue;
        }
        let publication_signal = anchor
            .value()
            .attr("data-csrc-pub-link")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
            || parsed_final_url
                .path()
                .to_ascii_lowercase()
                .contains("/pubs/");
        let authority_score =
            crate::agentic::desktop::service::step::queue::support::source_document_authority_score(
                query_contract,
                &final_url,
                title,
                &snippet,
            );
        let candidate_query_grounded = if same_host {
            same_host_locally_grounded
        } else {
            external_link_locally_grounded
        };
        let candidate_identifier_bearing = if same_host {
            admission.identifier_bearing
        } else {
            external_link_locally_identifier_bearing
        };
        if semantic_alignment_required
            && same_host
            && !candidate_query_grounded
            && !candidate_identifier_bearing
            && !canonical_publication_artifact
            && !publication_signal
        {
            continue;
        }
        candidates.push(RankedAuthorityLinkCandidate {
            source: WebSource {
                source_id: crate::agentic::web::source_id_for_url(&final_url),
                rank: None,
                url: final_url.clone(),
                title: Some(title.to_string()),
                snippet: Some(snippet),
                domain: parsed_final_url.host_str().map(|host| host.to_string()),
            },
            publication_signal,
            canonical_publication_artifact,
            same_host,
            query_grounded: candidate_query_grounded,
            identifier_bearing: candidate_identifier_bearing,
            authority_score,
            path_depth: path_depth(&parsed_final_url),
            dom_index,
        });
    }

    candidates.sort_by(|left, right| {
        right
            .publication_signal
            .cmp(&left.publication_signal)
            .then_with(|| {
                right
                    .canonical_publication_artifact
                    .cmp(&left.canonical_publication_artifact)
            })
            .then_with(|| right.identifier_bearing.cmp(&left.identifier_bearing))
            .then_with(|| right.query_grounded.cmp(&left.query_grounded))
            .then_with(|| right.authority_score.cmp(&left.authority_score))
            .then_with(|| right.same_host.cmp(&left.same_host))
            .then_with(|| right.path_depth.cmp(&left.path_depth))
            .then_with(|| left.dom_index.cmp(&right.dom_index))
    });

    let limit = limit.max(1);
    let required_domain_floor =
        retrieval_contract_required_distinct_domain_floor(Some(retrieval_contract), query_contract)
            .min(limit)
            .max(usize::from(limit > 1));
    let mut selected = Vec::new();
    let mut deferred = Vec::new();
    let mut seen_domains = BTreeSet::new();

    for candidate in candidates {
        let domain_key = candidate
            .source
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.trim_start_matches("www.").to_ascii_lowercase())
            .or_else(|| normalized_domain_key(&candidate.source.url));
        let adds_domain = domain_key
            .as_ref()
            .map(|domain| !seen_domains.contains(domain))
            .unwrap_or(false);
        if selected.len() < limit
            && (required_domain_floor <= 1
                || seen_domains.len() >= required_domain_floor
                || adds_domain)
        {
            if let Some(domain) = domain_key {
                seen_domains.insert(domain);
            }
            selected.push(candidate);
        } else {
            deferred.push(candidate);
        }
    }
    for candidate in deferred {
        if selected.len() >= limit {
            break;
        }
        selected.push(candidate);
    }

    selected
        .into_iter()
        .take(limit)
        .enumerate()
        .map(|(idx, mut candidate)| {
            candidate.source.rank = Some(idx as u32 + 1);
            candidate.source
        })
        .collect()
}

async fn expand_briefing_authority_link_out_sources(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    discovery_sources: Vec<WebSource>,
    required_url_count: usize,
    verification_checks: &mut Vec<String>,
) -> Result<Vec<WebSource>, String> {
    let authority_expansion_applicable = briefing_authority_link_expansion_required(
        retrieval_contract,
        query_contract,
        &discovery_sources,
        required_url_count,
    );
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_attempted={}",
        authority_expansion_applicable
    ));
    if !authority_expansion_applicable {
        return Ok(discovery_sources);
    }

    let mut merged_sources = discovery_sources;
    let seed_limit = merged_sources
        .len()
        .min(required_url_count.saturating_mul(3).max(4));
    let expansion_limit = WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT
        .max(required_url_count.saturating_mul(4))
        .max(6);
    let mut seen_urls = merged_sources
        .iter()
        .map(|source| crate::agentic::web::normalize_url_for_id(&source.url))
        .collect::<BTreeSet<_>>();
    let mut candidate_seed_urls = Vec::new();
    let mut admitted_seed_urls = Vec::new();
    let mut query_grounded_seed_urls = Vec::new();
    let mut identifier_seed_urls = Vec::new();
    let mut authority_seed_urls = Vec::new();
    let mut skipped_seed_urls = Vec::new();
    let mut fetched_seed_urls = Vec::new();
    let mut fetch_error_seed_urls = Vec::new();
    let mut challenge_seed_urls = Vec::new();
    let mut zero_candidate_seed_urls = Vec::new();
    let mut expanded_seed_urls = Vec::new();
    let mut expanded_urls = Vec::new();

    for source in merged_sources
        .iter()
        .take(seed_limit)
        .cloned()
        .collect::<Vec<_>>()
    {
        let source_url = source.url.trim();
        if source_url.is_empty() {
            continue;
        }
        candidate_seed_urls.push(source_url.to_string());
        let source_title = source.title.as_deref().unwrap_or_default();
        let source_excerpt = source.snippet.as_deref().unwrap_or_default();
        let seed_admission = briefing_authority_seed_admission(
            retrieval_contract,
            query_contract,
            required_url_count,
            source_url,
            source_title,
            source_excerpt,
        );
        if seed_admission.query_grounded {
            query_grounded_seed_urls.push(source_url.to_string());
        }
        if seed_admission.identifier_bearing {
            identifier_seed_urls.push(source_url.to_string());
        }
        if seed_admission.document_authority {
            authority_seed_urls.push(source_url.to_string());
        }
        if !seed_admission.admitted() {
            skipped_seed_urls.push(source_url.to_string());
            continue;
        }
        admitted_seed_urls.push(source_url.to_string());
        let (final_url, html) = match crate::agentic::web::fetch_structured_detail_http_fallback_browser_ua_with_final_url(source_url).await {
            Ok(result) => result,
            Err(_) => {
                fetch_error_seed_urls.push(source_url.to_string());
                continue;
            }
        };
        if crate::agentic::web::detect_human_challenge(&final_url, &html).is_some() {
            challenge_seed_urls.push(source_url.to_string());
            continue;
        }
        fetched_seed_urls.push(source_url.to_string());
        let expanded_sources = briefing_authority_link_out_sources_from_html(
            retrieval_contract,
            query_contract,
            source_url,
            &final_url,
            &html,
            required_url_count,
            expansion_limit,
        );
        if expanded_sources.is_empty() {
            zero_candidate_seed_urls.push(source_url.to_string());
            continue;
        }
        expanded_seed_urls.push(source_url.to_string());
        for expanded_source in expanded_sources {
            let url_key = crate::agentic::web::normalize_url_for_id(&expanded_source.url);
            if !seen_urls.insert(url_key) {
                continue;
            }
            expanded_urls.push(expanded_source.url.clone());
            merged_sources.push(expanded_source);
        }
    }

    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_candidate_seed_count={}",
        candidate_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_admitted_seed_count={}",
        admitted_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_query_grounded_seed_count={}",
        query_grounded_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_identifier_seed_count={}",
        identifier_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_authority_seed_count={}",
        authority_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_skipped_seed_count={}",
        skipped_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_fetched_seed_count={}",
        fetched_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_fetch_error_seed_count={}",
        fetch_error_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_challenge_seed_count={}",
        challenge_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_zero_candidate_seed_count={}",
        zero_candidate_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_seed_count={}",
        expanded_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_briefing_authority_link_expansion_source_count={}",
        expanded_urls.len()
    ));
    if !expanded_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_seed_url_values={}",
            expanded_seed_urls.join(" | ")
        ));
    }
    if !admitted_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_admitted_seed_url_values={}",
            admitted_seed_urls.join(" | ")
        ));
    }
    if !query_grounded_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_query_grounded_seed_url_values={}",
            query_grounded_seed_urls.join(" | ")
        ));
    }
    if !authority_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_authority_seed_url_values={}",
            authority_seed_urls.join(" | ")
        ));
    }
    if !skipped_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_skipped_seed_url_values={}",
            skipped_seed_urls.join(" | ")
        ));
    }
    if !fetch_error_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_fetch_error_seed_url_values={}",
            fetch_error_seed_urls.join(" | ")
        ));
    }
    if !challenge_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_challenge_seed_url_values={}",
            challenge_seed_urls.join(" | ")
        ));
    }
    if !zero_candidate_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_zero_candidate_seed_url_values={}",
            zero_candidate_seed_urls.join(" | ")
        ));
    }
    if !expanded_urls.is_empty() {
        verification_checks.push(format!(
            "web_briefing_authority_link_expansion_url_values={}",
            expanded_urls.join(" | ")
        ));
    }

    Ok(merged_sources)
}

fn deterministic_local_business_expansion_alignment_urls(
    query_contract: &str,
    locality_hint: Option<&str>,
    expanded_sources: &[WebSource],
    limit: usize,
) -> Vec<String> {
    let expanded_hints = expanded_sources
        .iter()
        .filter_map(|source| {
            let trimmed = source.url.trim();
            (!trimmed.is_empty()).then(|| PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: source
                    .title
                    .clone()
                    .filter(|value| !value.trim().is_empty()),
                excerpt: source
                    .snippet
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            })
        })
        .collect::<Vec<_>>();
    if expanded_hints.is_empty() {
        return Vec::new();
    }

    let target_names = local_business_target_names_from_sources(
        &expanded_hints,
        locality_hint,
        expanded_hints.len(),
    );
    if target_names.is_empty() {
        return Vec::new();
    }

    selected_local_business_target_sources(
        query_contract,
        &target_names,
        &expanded_hints,
        locality_hint,
        limit.max(1),
    )
    .into_iter()
    .map(|source| source.url)
    .collect()
}

async fn observe_geo_scoped_discovery_sources(
    discovery_sources: &[WebSource],
    existing_observations: &[ioi_types::app::agentic::WebSourceObservation],
    required_url_count: usize,
    verification_checks: &mut Vec<String>,
) -> Vec<ioi_types::app::agentic::WebSourceObservation> {
    let mut observed = Vec::new();
    let probe_limit = discovery_sources
        .len()
        .min(required_url_count.saturating_mul(4).max(6));
    let expansion_limit = WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT
        .max(required_url_count.saturating_mul(4))
        .max(6);
    let mut probed_urls = Vec::new();

    for source in discovery_sources.iter().take(probe_limit) {
        let seed_url = source.url.trim();
        if seed_url.is_empty() {
            continue;
        }
        let Ok((final_url, html)) =
            crate::agentic::web::fetch_structured_detail_http_fallback_browser_ua_with_final_url(
                seed_url,
            )
            .await
        else {
            continue;
        };
        if crate::agentic::web::detect_human_challenge(&final_url, &html).is_some() {
            continue;
        }
        let Some((observation, _)) =
            structural_seed_expansion_from_html(seed_url, &final_url, &html, expansion_limit)
        else {
            continue;
        };
        probed_urls.push(seed_url.to_string());
        observed.push(observation);
    }

    verification_checks.push(format!(
        "web_geo_scoped_seed_observation_attempted={}",
        probe_limit > 0
    ));
    verification_checks.push(format!(
        "web_geo_scoped_seed_observation_count={}",
        observed.len()
    ));
    if !probed_urls.is_empty() {
        verification_checks.push(format!(
            "web_geo_scoped_seed_observation_url_values={}",
            probed_urls.join(" | ")
        ));
    }

    merge_source_observations(existing_observations, observed)
}

async fn expand_geo_scoped_discovery_seed_sources(
    service: &DesktopAgentService,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    discovery_sources: Vec<WebSource>,
    source_observations: &[ioi_types::app::agentic::WebSourceObservation],
    required_url_count: usize,
    verification_checks: &mut Vec<String>,
) -> Result<Vec<WebSource>, String> {
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return Ok(discovery_sources);
    }

    let mut expanded_sources = Vec::new();
    let mut seen_urls = std::collections::BTreeSet::new();
    let expansion_seed_limit = discovery_sources
        .len()
        .min(required_url_count.saturating_mul(4).max(6));
    let expansion_limit = WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT
        .max(required_url_count.saturating_mul(4))
        .max(6);
    let mut expanded_seed_urls = Vec::new();
    let locality_hint = explicit_query_scope_hint(query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(Some(retrieval_contract), query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });

    for source in discovery_sources.iter().take(expansion_seed_limit) {
        let source_url = source.url.trim();
        if source_url.is_empty() {
            continue;
        }
        let Some(source_observation) = source_observations.iter().find(|observation| {
            observation.url.eq_ignore_ascii_case(source_url)
                || url_structurally_equivalent(&observation.url, source_url)
        }) else {
            continue;
        };
        let seed_admitted = source_observation
            .affordances
            .contains(&ioi_types::app::agentic::WebRetrievalAffordance::LinkCollection)
            && source_observation
                .affordances
                .contains(&ioi_types::app::agentic::WebRetrievalAffordance::CanonicalLinkOut)
            && source_observation
                .expansion_affordances
                .iter()
                .any(|affordance| {
                    matches!(
                affordance,
                ioi_types::app::agentic::WebSourceExpansionAffordance::JsonLdItemList
                    | ioi_types::app::agentic::WebSourceExpansionAffordance::ChildLinkCollection
            )
                });
        if !seed_admitted {
            continue;
        }
        let (final_url, html) = match crate::agentic::web::fetch_structured_detail_http_fallback_browser_ua_with_final_url(source_url).await {
            Ok(result) => result,
            Err(_) => continue,
        };
        if crate::agentic::web::detect_human_challenge(&final_url, &html).is_some() {
            continue;
        }
        let Some((_, item_sources)) =
            structural_seed_expansion_from_html(source_url, &final_url, &html, expansion_limit)
        else {
            continue;
        };
        expanded_seed_urls.push(source_url.to_string());
        for item_source in item_sources {
            let item_url = item_source.url.trim();
            if item_url.is_empty() {
                continue;
            }
            if !seen_urls.insert(item_url.to_ascii_lowercase()) {
                continue;
            }
            expanded_sources.push(item_source);
        }
    }

    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_attempted={}",
        expansion_seed_limit > 0
    ));
    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_seed_count={}",
        expanded_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_detail_count={}",
        expanded_sources.len()
    ));
    if !expanded_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_geo_scoped_seed_expansion_seed_url_values={}",
            expanded_seed_urls.join(" | ")
        ));
    }

    if expanded_sources.is_empty() {
        return Ok(discovery_sources);
    }

    let mut aligned_expanded_urls = crate::agentic::web::infer_query_matching_source_urls(
        service.fast_inference.clone(),
        query_contract,
        retrieval_contract,
        &expanded_sources,
    )
    .await?;
    let deterministic_expanded_urls = deterministic_local_business_expansion_alignment_urls(
        query_contract,
        locality_hint.as_deref(),
        &expanded_sources,
        expansion_limit,
    );
    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_alignment_deterministic_count={}",
        deterministic_expanded_urls.len()
    ));
    if !deterministic_expanded_urls.is_empty() {
        verification_checks.push(format!(
            "web_geo_scoped_seed_expansion_alignment_deterministic_url_values={}",
            deterministic_expanded_urls.join(" | ")
        ));
    }
    for url in deterministic_expanded_urls {
        if url_in_alignment_set(&url, &aligned_expanded_urls) {
            continue;
        }
        aligned_expanded_urls.push(url);
    }
    if aligned_expanded_urls.is_empty() {
        verification_checks.push("web_geo_scoped_seed_expansion_alignment_matched=0".to_string());
        return Ok(discovery_sources);
    }

    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_alignment_matched={}",
        aligned_expanded_urls.len()
    ));
    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_alignment_url_values={}",
        aligned_expanded_urls.join(" | ")
    ));

    let filtered = expanded_sources
        .into_iter()
        .filter(|source| url_in_alignment_set(&source.url, &aligned_expanded_urls))
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return Ok(discovery_sources);
    }

    let mut combined = filtered;
    for source in discovery_sources {
        let trimmed = source.url.trim();
        if trimmed.is_empty() || !seen_urls.insert(trimmed.to_ascii_lowercase()) {
            continue;
        }
        combined.push(source);
    }

    Ok(combined)
}

#[cfg(test)]
mod discovery_regression_tests {
    use super::*;

    #[test]
    fn authority_link_expansion_prefers_official_publication_artifact_over_stale_news() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let html = r#"
            <html>
              <body>
                <a href="https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms">
                  NIST Announces First Four Quantum-Resistant Cryptographic Algorithms
                </a>
                <a href="https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf">
                  Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process
                </a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
            html,
            2,
            2,
        );

        assert_eq!(sources.len(), 2, "{sources:?}");
        assert_eq!(
            sources[0].url,
            "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
        );
    }

    #[test]
    fn authority_link_expansion_filters_generic_same_host_authority_pages_for_semantic_briefings() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let html = r#"
            <html>
              <head>
                <title>Cybersecurity and privacy | NIST</title>
                <meta
                  name="description"
                  content="NIST develops cybersecurity and privacy standards, guidelines, best practices, and resources."
                />
              </head>
              <body>
                <a href="/about-nist">About NIST</a>
                <a href="/about-nist/work-nist">Work at NIST</a>
                <a href="/publications/search/topic/248731">Publications</a>
                <a href="/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards">
                  NIST Releases First 3 Finalized Post-Quantum Encryption Standards
                </a>
              </body>
            </html>
        "#;

        let sources = briefing_authority_link_out_sources_from_html(
            &retrieval_contract,
            query,
            "https://www.nist.gov/cybersecurity-and-privacy",
            "https://www.nist.gov/cybersecurity-and-privacy",
            html,
            2,
            4,
        );
        let urls = sources.iter().map(|source| source.url.as_str()).collect::<Vec<_>>();

        assert!(
            urls.iter().any(|url| url.eq_ignore_ascii_case(
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            )),
            "{urls:?}"
        );
        assert!(
            urls.iter()
                .all(|url| !url.eq_ignore_ascii_case("https://www.nist.gov/about-nist")),
            "{urls:?}"
        );
        assert!(
            urls.iter().all(|url| !url.eq_ignore_ascii_case(
                "https://www.nist.gov/about-nist/work-nist"
            )),
            "{urls:?}"
        );
    }
}
