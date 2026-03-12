fn best_metric_excerpt(blocks: &[String]) -> Option<String> {
    let mut best = None::<(usize, String)>;
    for start in 0..blocks.len() {
        let mut window = Vec::<String>::new();
        let mut total_chars = 0usize;
        for block in blocks.iter().skip(start).take(4) {
            let compact = compact_ws(block);
            let trimmed = compact.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !window.is_empty() {
                total_chars = total_chars.saturating_add(2);
            }
            total_chars = total_chars.saturating_add(trimmed.chars().count());
            if total_chars > 220 {
                break;
            }
            window.push(trimmed.to_string());
            let excerpt = window.join("; ");
            let schema = analyze_metric_schema(&excerpt);
            let score = usize::from(schema.has_current_observation_payload()) * 8
                + schema.axis_hits.len() * 4
                + schema.timestamp_hits
                + schema.unit_hits
                + schema.numeric_token_hits
                + window.len().saturating_sub(1) * 2;
            if score == 0 {
                continue;
            }
            let candidate = (score, excerpt);
            let replace = best
                .as_ref()
                .map(|current| {
                    candidate.0 > current.0
                        || (candidate.0 == current.0 && candidate.1.len() > current.1.len())
                })
                .unwrap_or(true);
            if replace {
                best = Some(candidate);
            }
        }
    }
    best.map(|(_, excerpt)| excerpt)
}

fn best_structured_detail_source(
    page_url: &str,
    html: &str,
    extracted_title: Option<String>,
    blocks: &[String],
) -> Option<WebSource> {
    let generic_page = parse_generic_page_source_from_html(page_url, html);
    let title = extracted_title
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            generic_page
                .as_ref()
                .and_then(|source| source.title.clone())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        });
    let snippet = best_metric_excerpt(blocks).or_else(|| {
        generic_page
            .as_ref()
            .and_then(|source| source.snippet.clone())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    });
    if title.is_none() && snippet.is_none() {
        return None;
    }

    let canonical_url = generic_page
        .as_ref()
        .map(|source| source.url.as_str())
        .unwrap_or(page_url);

    Some(WebSource {
        source_id: source_id_for_url(canonical_url),
        rank: Some(1),
        domain: domain_for_url(canonical_url),
        title,
        snippet,
        url: canonical_url.to_string(),
    })
}

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

fn append_unique_source_observations(
    existing: &mut Vec<WebSourceObservation>,
    incoming: Vec<WebSourceObservation>,
) {
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

fn source_observations_for_sources(
    sources: &[WebSource],
    affordances: &[SearchStructuralAffordance],
    expansion_affordances: &[WebSourceExpansionAffordance],
) -> Vec<WebSourceObservation> {
    sources
        .iter()
        .map(|source| WebSourceObservation {
            url: source.url.clone(),
            affordances: affordances.to_vec(),
            expansion_affordances: expansion_affordances.to_vec(),
        })
        .collect()
}

fn reorder_headline_sources_for_truncation(sources: Vec<WebSource>) -> Vec<WebSource> {
    if sources.is_empty() {
        return sources;
    }

    let mut ranked = sources;
    ranked.sort_by(|left, right| {
        let left_domain_known = canonical_source_domain(left).is_some();
        let right_domain_known = canonical_source_domain(right).is_some();
        right_domain_known
            .cmp(&left_domain_known)
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

    for source in ranked
        .iter()
        .filter(|source| canonical_source_domain(source).is_some())
    {
        let url_key = normalize_url_for_id(&source.url);
        let Some(domain_key) = canonical_source_domain(source) else {
            continue;
        };
        if !seen_urls.insert(url_key) || !seen_domains.insert(domain_key) {
            continue;
        }
        reordered.push(source.clone());
    }
    for source in ranked {
        let url_key = normalize_url_for_id(&source.url);
        if seen_urls.insert(url_key) {
            reordered.push(source);
        }
    }

    reordered
}

pub(crate) fn aggregated_sources_meet_pre_read_floor(
    retrieval_contract: &WebRetrievalContract,
    query_contract: &str,
    _locality_hint: Option<&str>,
    _discovery_inventory_limit: usize,
    sources: &[WebSource],
) -> bool {
    if sources.is_empty() {
        return false;
    }

    let required_url_count =
        retrieval_contract_min_sources(Some(retrieval_contract), query_contract).max(1);
    let required_source_count = required_url_count as usize;
    let required_domain_floor = if retrieval_contract.entity_diversity_required {
        0
    } else {
        retrieval_contract
            .source_independence_min
            .max(1)
            .min(required_url_count) as usize
    };
    let mut distinct_urls = HashSet::new();
    let mut distinct_domains = HashSet::new();
    for source in sources {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if distinct_urls.insert(normalize_url_for_id(trimmed)) {
            if let Some(domain) = canonical_source_domain(source) {
                distinct_domains.insert(domain);
            }
        }
    }
    distinct_urls.len() >= required_source_count
        && (required_domain_floor == 0 || distinct_domains.len() >= required_domain_floor)
}

fn direct_single_record_snapshot_contract(retrieval_contract: &WebRetrievalContract) -> bool {
    retrieval_contract.entity_cardinality_min <= 1
        && retrieval_contract.structured_record_preferred
        && !retrieval_contract.comparison_required
        && !retrieval_contract.ordered_collection_preferred
        && !retrieval_contract.link_collection_preferred
        && !retrieval_contract.canonical_link_out_preferred
        && !retrieval_contract.discovery_surface_required
}

fn descriptor_supports_direct_snapshot_record(descriptor: &SearchProviderDescriptor) -> bool {
    provider_supports_affordance(descriptor, SearchStructuralAffordance::StructuredRecord)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::GeoScopedRecord)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::DetailDocument)
}

pub(crate) fn should_stop_provider_aggregation(
    retrieval_contract: &WebRetrievalContract,
    query_contract: &str,
    locality_hint: Option<&str>,
    discovery_inventory_limit: usize,
    provider_result_limit: usize,
    aggregated_sources: &[WebSource],
    last_descriptor: Option<&SearchProviderDescriptor>,
    preferred_only_mode: bool,
) -> bool {
    let floor_met = aggregated_sources_meet_pre_read_floor(
        retrieval_contract,
        query_contract,
        locality_hint,
        discovery_inventory_limit,
        aggregated_sources,
    );
    if !floor_met {
        return false;
    }

    if preferred_only_mode && aggregated_sources.len() >= provider_result_limit {
        return true;
    }

    direct_single_record_snapshot_contract(retrieval_contract)
        && last_descriptor
            .map(descriptor_supports_direct_snapshot_record)
            .unwrap_or(false)
}

fn resolved_locality_scope(
    query: &str,
    query_contract: Option<&str>,
    retrieval_contract: &WebRetrievalContract,
) -> Option<String> {
    let query_contract = query_contract
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let query = query.trim();
    query_contract
        .and_then(explicit_query_scope_hint)
        .or_else(|| explicit_query_scope_hint(query))
        .or_else(|| {
            retrieval_contract
                .runtime_locality_required
                .then(|| effective_locality_scope_hint(None))
                .flatten()
        })
}

fn provider_request_query(
    query: &str,
    query_contract: Option<&str>,
    retrieval_contract: &WebRetrievalContract,
    locality_scope: Option<&str>,
) -> String {
    let selection_query_contract = query_contract
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| query.trim());
    if contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        let entity_discovery_query = crate::agentic::desktop::service::step::queue::web_pipeline::local_business_entity_discovery_query_contract(
            selection_query_contract,
            locality_scope,
        );
        if !entity_discovery_query.trim().is_empty() {
            return entity_discovery_query;
        }
    }
    let discovery_query_basis = selection_query_contract;
    let grounded_query = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        discovery_query_basis,
        Some(retrieval_contract),
        retrieval_contract_min_sources(Some(retrieval_contract), selection_query_contract).max(1),
        &[],
        locality_scope,
    );
    let grounded_trimmed = grounded_query.trim();
    if !grounded_trimmed.is_empty() {
        return grounded_trimmed.to_string();
    }

    provider_search_query_with_locality_hint(discovery_query_basis, locality_scope)
}
