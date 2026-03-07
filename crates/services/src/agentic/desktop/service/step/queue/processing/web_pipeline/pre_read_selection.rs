fn pre_read_synthesis_timeout() -> Duration {
    const DEFAULT_TIMEOUT_MS: u64 = 4_000;
    std::env::var("IOI_WEB_PRE_READ_SYNTHESIS_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_TIMEOUT_MS))
}

#[derive(Debug, Clone, Serialize)]
struct PreReadSelectionPayload {
    query_contract: String,
    retrieval_contract: WebRetrievalContract,
    required_url_count: usize,
    constraints: Vec<String>,
    sources: Vec<PreReadDiscoverySource>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PreReadSelectionMode {
    DirectDetail,
    DiscoverySeed,
}

#[derive(Debug, Clone, Deserialize)]
struct PreReadSelectionResponse {
    selection_mode: PreReadSelectionMode,
    urls: Vec<String>,
}

fn pre_read_url_has_allowed_affordance(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    !discovery_source_affordances(
        retrieval_contract,
        query_contract,
        required_url_count,
        source_hints,
        locality_hint,
        url,
        title,
        excerpt,
    )
    .is_empty()
}

fn pre_read_candidate_url_allowed_for_query(
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    projection_candidate_url_allowed_with_projection(
        query_contract,
        &projection,
        url,
        title,
        excerpt,
    )
}

fn selected_url_hint<'a>(
    source_hints: &'a [PendingSearchReadSummary],
    url: &str,
) -> Option<&'a PendingSearchReadSummary> {
    let trimmed = url.trim();
    source_hints.iter().find(|hint| {
        let hint_url = hint.url.trim();
        hint_url.eq_ignore_ascii_case(trimmed)
            || url_structurally_equivalent(hint_url, trimmed)
            || source_url_from_metadata_excerpt(&hint.excerpt)
                .map(|resolved| {
                    resolved.eq_ignore_ascii_case(trimmed)
                        || url_structurally_equivalent(&resolved, trimmed)
                })
                .unwrap_or(false)
    })
}

fn payload_allows_external_article_url(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    discovery_sources: &[WebSource],
    url: &str,
    allowed_hosts: &std::collections::BTreeSet<String>,
) -> bool {
    let trimmed = url.trim();
    let Some(host) = normalized_domain_key(trimmed) else {
        return false;
    };
    if !allowed_hosts.contains(&host) {
        return false;
    }
    let source_hints = discovery_source_hints(discovery_sources);
    let locality_hint =
        if retrieval_contract_requires_runtime_locality(retrieval_contract, query_contract) {
            effective_locality_scope_hint(None)
        } else {
            None
        };
    let Some(matched_hint) = selected_url_hint(&source_hints, trimmed) else {
        return false;
    };
    let hint_url = matched_hint.url.trim();
    if !hint_url.eq_ignore_ascii_case(trimmed) && !url_structurally_equivalent(hint_url, trimmed) {
        return false;
    }
    let title = matched_hint.title.as_deref().unwrap_or_default();
    let excerpt = matched_hint.excerpt.as_str();
    pre_read_candidate_url_allowed_for_query(
        query_contract,
        required_url_count as u32,
        &source_hints,
        locality_hint.as_deref(),
        trimmed,
        title,
        excerpt,
    )
}

fn pre_read_candidate_url_allowed(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && is_citable_web_url(trimmed)
        && !is_search_hub_url(trimmed)
        && !is_multi_item_listing_url(trimmed)
        && looks_like_deep_article_url(trimmed)
}

fn looks_like_deep_article_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    if is_search_hub_url(trimmed) {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.trim().is_empty() {
        return false;
    }

    let normalized_path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if normalized_path.is_empty() {
        return false;
    }
    let segments = normalized_path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }
    if segments
        .iter()
        .any(|segment| segment.contains("menu") || segment.contains("menus"))
    {
        return true;
    }
    if segments.len() <= 2
        && segments
            .first()
            .copied()
            .map(|segment| {
                matches!(
                    segment,
                    "show" | "shows" | "watch" | "video" | "videos" | "live" | "tv"
                )
            })
            .unwrap_or(false)
    {
        return false;
    }

    let path_hub_markers = [
        "news",
        "latest",
        "home",
        "homepage",
        "index",
        "index.html",
        "video",
        "videos",
        "live",
        "world",
        "us",
        "top-stories",
        "top-news",
    ];
    let marker_segment = |segment: &str| {
        if segment.is_empty() {
            return false;
        }
        if path_hub_markers.contains(&segment) {
            return true;
        }
        segment
            .split('-')
            .all(|token| !token.is_empty() && path_hub_markers.contains(&token))
    };
    if path_hub_markers
        .iter()
        .any(|marker| normalized_path == *marker)
    {
        return false;
    }
    if segments
        .last()
        .map(|segment| marker_segment(segment))
        .unwrap_or(false)
    {
        return false;
    }
    if segments
        .last()
        .copied()
        .map(looks_like_placeholder_article_slug_segment)
        .unwrap_or(false)
    {
        return false;
    }
    if segments.len() <= 3
        && segments
            .first()
            .map(|segment| matches!(*segment, "c" | "channel" | "user"))
            .unwrap_or(false)
    {
        return false;
    }

    true
}

fn looks_like_placeholder_article_slug_segment(segment: &str) -> bool {
    let trimmed = segment.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    let tokenized = trimmed
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokenized.is_empty() {
        return false;
    }
    let role_tokens = [
        "article", "story", "news", "headline", "post", "report", "item",
    ];
    let placeholder_tokens = [
        "title",
        "slug",
        "name",
        "text",
        "content",
        "page",
        "link",
        "sample",
        "placeholder",
    ];
    let has_role = tokenized.iter().any(|token| role_tokens.contains(token));
    let has_placeholder = tokenized
        .iter()
        .any(|token| placeholder_tokens.contains(token));
    let all_generic = tokenized
        .iter()
        .all(|token| role_tokens.contains(token) || placeholder_tokens.contains(token));

    tokenized.len() >= 2 && has_role && has_placeholder && all_generic
}

fn lint_pre_read_payload_urls(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    discovery_sources: &[WebSource],
    source_observations: &[WebSourceObservation],
    selection_mode: &PreReadSelectionMode,
    urls: &[String],
    required_count: usize,
) -> Result<Vec<String>, String> {
    if !pre_read_selection_mode_permitted(retrieval_contract, query_contract, selection_mode) {
        return Err(format!(
            "selection mode {:?} is not permitted by the typed retrieval contract",
            selection_mode
        ));
    }

    let mut normalized = Vec::new();
    for url in urls {
        let trimmed = url.trim();
        if trimmed.is_empty()
            || normalized
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(trimmed))
        {
            continue;
        }
        normalized.push(trimmed.to_string());
    }

    let expected_count = match selection_mode {
        PreReadSelectionMode::DirectDetail => required_count,
        PreReadSelectionMode::DiscoverySeed => 1,
    };
    if normalized.len() != expected_count {
        return Err(format!(
            "expected exactly {} URLs but received {}",
            expected_count,
            normalized.len()
        ));
    }

    let source_hints = discovery_source_hints(discovery_sources);
    let entity_diversity_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, query_contract);
    let required_domain_floor = if entity_diversity_required {
        0
    } else {
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
            .min(expected_count)
            .max(usize::from(expected_count > 1))
    };
    let mut distinct_targets = std::collections::BTreeSet::new();
    let mut distinct_domains = std::collections::BTreeSet::new();
    for url in &normalized {
        let trimmed = url.trim();
        let Some(_matched_hint) = selected_url_hint(&source_hints, trimmed) else {
            return Err(format!(
                "selected URL was not present in the discovery payload: {}",
                url
            ));
        };
        if !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
            return Err(format!("selected URL is not a citable source candidate: {}", url));
        }
        if *selection_mode == PreReadSelectionMode::DiscoverySeed {
            let Some(observation) = source_observation_for_url(source_observations, trimmed) else {
                return Err(format!(
                    "selected discovery seed was missing typed source observations: {}",
                    url
                ));
            };
            let seed_admitted = source_observation_supports_discovery_seed(observation);
            if !seed_admitted {
                return Err(format!(
                    "selected discovery seed did not satisfy typed expansion affordances: {}",
                    url
                ));
            }
        }
        distinct_targets.insert(trimmed.to_ascii_lowercase());
        if let Some(domain) = selected_url_domain_key(&source_hints, trimmed) {
            distinct_domains.insert(domain);
        }
    }

    if distinct_targets.len() != normalized.len() {
        return Err(format!(
            "expected {} distinct retrieval targets but received {}",
            normalized.len(),
            distinct_targets.len()
        ));
    }

    if *selection_mode == PreReadSelectionMode::DirectDetail
        && required_domain_floor > 0
        && distinct_domains.len() < required_domain_floor
    {
        return Err(format!(
            "expected at least {} distinct domains but received {}",
            required_domain_floor,
            distinct_domains.len()
        ));
    }

    Ok(normalized)
}

fn ranked_discovery_sources_with_limit(
    bundle: &WebEvidenceBundle,
    limit: usize,
) -> Vec<WebSource> {
    let mut indexed = bundle
        .sources
        .iter()
        .cloned()
        .enumerate()
        .collect::<Vec<_>>();
    indexed.sort_by(|(left_idx, left), (right_idx, right)| {
        left.rank
            .unwrap_or(u32::MAX)
            .cmp(&right.rank.unwrap_or(u32::MAX))
            .then_with(|| left_idx.cmp(right_idx))
            .then_with(|| left.url.cmp(&right.url))
    });

    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (_, source) in indexed {
        let trimmed = source.url.trim();
        if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
            continue;
        }
        out.push(WebSource {
            url: trimmed.to_string(),
            ..source
        });
        if out.len() >= limit {
            break;
        }
    }

    out
}

fn ranked_discovery_sources(bundle: &WebEvidenceBundle) -> Vec<WebSource> {
    ranked_discovery_sources_with_limit(bundle, WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT)
}

fn ordered_discovery_sources(bundle: &WebEvidenceBundle) -> Vec<WebSource> {
    ranked_discovery_sources_with_limit(bundle, usize::MAX)
}

fn source_observation_for_url<'a>(
    source_observations: &'a [WebSourceObservation],
    url: &str,
) -> Option<&'a WebSourceObservation> {
    let trimmed = url.trim();
    source_observations.iter().find(|observation| {
        observation.url.eq_ignore_ascii_case(trimmed)
            || url_structurally_equivalent(&observation.url, trimmed)
    })
}

fn source_observation_supports_discovery_seed(observation: &WebSourceObservation) -> bool {
    observation
        .affordances
        .contains(&WebRetrievalAffordance::LinkCollection)
        && observation
            .affordances
            .contains(&WebRetrievalAffordance::CanonicalLinkOut)
        && observation.expansion_affordances.iter().any(|affordance| {
            matches!(
                affordance,
                WebSourceExpansionAffordance::JsonLdItemList
                    | WebSourceExpansionAffordance::ChildLinkCollection
            )
        })
}

fn build_pre_read_selection_payload(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    discovery_sources: &[WebSource],
    source_observations: &[WebSourceObservation],
) -> PreReadSelectionPayload {
    let retrieval_contract = retrieval_contract.cloned().unwrap_or_default();
    let discovery_seed_permitted = pre_read_selection_mode_permitted(
        Some(&retrieval_contract),
        query_contract,
        &PreReadSelectionMode::DiscoverySeed,
    );
    let payload_sources = discovery_sources
        .iter()
        .map(|source| {
            PreReadDiscoverySource {
                rank: source.rank,
                url: source.url.trim().to_string(),
                domain: source.domain.clone(),
                title: source.title.clone(),
                snippet: source.snippet.clone(),
                affordances: source_observation_for_url(source_observations, &source.url)
                    .map(|observation| observation.affordances.clone())
                    .unwrap_or_default(),
                expansion_affordances: source_observation_for_url(source_observations, &source.url)
                    .map(|observation| observation.expansion_affordances.clone())
                    .unwrap_or_default(),
            }
        })
        .collect::<Vec<_>>();
    let mut constraints = vec![
        "Use only the typed retrieval contract and payload source metadata.".to_string(),
        "Return only URLs present in payload.sources; do not synthesize substitute URLs."
            .to_string(),
        "Use selection_mode=direct_detail when the selected URLs can be read directly as final evidence sources."
            .to_string(),
    ];
    if discovery_seed_permitted {
        constraints.push(
            "Use selection_mode=discovery_seed only when the payload lacks enough direct detail sources but one stronger source can support grounded follow-up expansion."
                .to_string(),
        );
        constraints.push(
            "Return exactly required_url_count URLs for direct_detail or exactly one URL for discovery_seed."
                .to_string(),
        );
    } else {
        constraints.push(
            "Return exactly required_url_count URLs using selection_mode=direct_detail."
                .to_string(),
        );
    }
    if retrieval_contract.source_independence_min > 1 && !retrieval_contract.entity_diversity_required
    {
        constraints.push(
            "When direct_detail is used, prefer independent sources from distinct domains when the payload permits."
                .to_string(),
        );
    }
    if retrieval_contract.entity_diversity_required {
        constraints.push(
            "For multi-entity comparison queries, prefer URLs about distinct answer entities even when domains repeat."
                .to_string(),
        );
    }
    if retrieval_contract.runtime_locality_required {
        constraints.push(
            "Select only sources aligned to the runtime locality already expressed in the query contract."
                .to_string(),
        );
    }
    if discovery_seed_permitted {
        constraints.push(
            "discovery_seed is admissible only for sources whose payload metadata includes link_collection, canonical_link_out, and at least one structural expansion affordance."
                .to_string(),
        );
    } else {
        constraints.push(
            "discovery_seed is not permitted for this payload; selection_mode must be direct_detail."
                .to_string(),
        );
    }
    PreReadSelectionPayload {
        query_contract: query_contract.trim().to_string(),
        retrieval_contract,
        required_url_count,
        constraints,
        sources: payload_sources,
    }
}

fn pre_read_selection_mode_permitted(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    selection_mode: &PreReadSelectionMode,
) -> bool {
    match selection_mode {
        PreReadSelectionMode::DirectDetail => true,
        PreReadSelectionMode::DiscoverySeed => {
            retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
                || crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
                    retrieval_contract.unwrap_or(&WebRetrievalContract::default()),
                )
        }
    }
}

async fn synthesize_pre_read_selection(
    service: &DesktopAgentService,
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    discovery_sources: &[WebSource],
    source_observations: &[WebSourceObservation],
) -> Result<PreReadSelectionResponse, String> {
    let payload = build_pre_read_selection_payload(
        retrieval_contract,
        query_contract,
        required_url_count,
        discovery_sources,
        source_observations,
    );
    let discovery_seed_permitted = pre_read_selection_mode_permitted(
        retrieval_contract,
        query_contract,
        &PreReadSelectionMode::DiscoverySeed,
    );
    let selection_schema = if discovery_seed_permitted {
        "{\"selection_mode\":\"direct_detail|discovery_seed\",\"urls\":[string]}"
    } else {
        "{\"selection_mode\":\"direct_detail\",\"urls\":[string]}"
    };
    let selection_mode_requirement = if discovery_seed_permitted {
        "- `discovery_seed` means the payload lacks enough direct final sources, so exactly one stronger source should be selected for grounded follow-up expansion."
    } else {
        "- `discovery_seed` is not permitted for this payload; `selection_mode` must be `direct_detail`."
    };
    if payload.sources.is_empty() {
        return Err("pre-read selection requires at least one discovered source".to_string());
    }
    let payload_json = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("failed to serialize pre-read selection payload: {}", err))?;
    let timeout = pre_read_synthesis_timeout();
    let mut feedback: Option<String> = None;
    let mut last_error = "pre-read selection failed".to_string();

    for attempt in 1..=WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
        let prompt = if let Some(previous_error) = feedback.as_deref() {
            format!(
                "Return JSON only with schema {}.\n\
                 You are in CEC State 3 (Typed Web Source Selection).\n\
                 Prior output failed lint: {}\n\
                 Re-select URLs using only the typed retrieval contract and payload source metadata.\n\
                 Payload:\n{}",
                selection_schema, previous_error, payload_json
            )
        } else {
            format!(
                "Return JSON only with schema {}.\n\
                 You are in CEC State 3 (Typed Web Source Selection).\n\
                 Select URLs from the payload that best satisfy the typed retrieval contract.\n\
                 Requirements:\n\
                 - Use only payload URLs.\n\
                 - Use only the typed retrieval contract and payload source metadata.\n\
                 - `direct_detail` means the returned URLs can be read directly as final evidence sources.\n\
                 {}\n\
                 - Prefer semantically aligned sources that satisfy locality/currentness constraints already encoded in the query contract.\n\
                 - For multi-entity comparison queries, prefer sources about distinct answer entities.\n\
                 - When source independence matters and entity diversity is not sufficient, prefer distinct domains.\n\
                 - If unclear, exclude the URL.\n\
                 Payload:\n{}",
                selection_schema,
                selection_mode_requirement,
                payload_json
            )
        };
        let options = InferenceOptions {
            tools: vec![],
            temperature: 0.0,
            json_mode: true,
            max_tokens: WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_TOKENS,
        };
        let airlocked_prompt = match service
            .prepare_cloud_inference_input(
                None,
                "desktop_agent",
                "web_pipeline_pre_read_selection",
                prompt.as_bytes(),
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                last_error = format!("pre-read selection airlock failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let raw = match tokio::time::timeout(
            timeout,
            service
                .reasoning_inference
                .execute_inference([0u8; 32], &airlocked_prompt, options),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => {
                last_error = format!("pre-read selection inference failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
            Err(_) => {
                last_error = format!(
                    "pre-read selection timed out after {}ms",
                    timeout.as_millis()
                );
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let text = match String::from_utf8(raw) {
            Ok(text) => text,
            Err(err) => {
                last_error = format!("pre-read selection response was not UTF-8: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let json_text = extract_json_object(&text).unwrap_or(text.as_str());
        let parsed: PreReadSelectionResponse = match serde_json::from_str(json_text) {
            Ok(parsed) => parsed,
            Err(err) => {
                last_error = format!("pre-read selection returned invalid JSON schema: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };

        match lint_pre_read_payload_urls(
            retrieval_contract,
            query_contract,
            discovery_sources,
            source_observations,
            &parsed.selection_mode,
            &parsed.urls,
            payload.required_url_count,
        ) {
            Ok(validated) => {
                return Ok(PreReadSelectionResponse {
                    selection_mode: parsed.selection_mode,
                    urls: validated,
                });
            }
            Err(err) => {
                last_error = err;
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
            }
        }
    }

    Err(last_error)
}

fn selected_source_hints_for_urls(
    bundle: &WebEvidenceBundle,
    selected_urls: &[String],
) -> Vec<PendingSearchReadSummary> {
    let source_hints = candidate_source_hints_from_bundle(bundle);
    selected_urls
        .iter()
        .map(|selected| {
            let selected_trimmed = selected.trim();
            if selected_trimmed.is_empty() {
                return PendingSearchReadSummary::default();
            }
            if let Some(source) = selected_url_hint(&source_hints, selected_trimmed) {
                return PendingSearchReadSummary {
                    url: selected_trimmed.to_string(),
                    title: source.title.clone(),
                    excerpt: source.excerpt.clone(),
                };
            }

            let fallback_source = bundle.sources.iter().find(|source| {
                let source_url = source.url.trim();
                source_url.eq_ignore_ascii_case(selected_trimmed)
                    || url_structurally_equivalent(source_url, selected_trimmed)
            });
            PendingSearchReadSummary {
                url: selected_trimmed.to_string(),
                title: fallback_source.and_then(|source| source.title.clone()),
                excerpt: fallback_source
                    .and_then(|source| source.snippet.clone())
                    .unwrap_or_default(),
            }
        })
        .collect()
}

fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    let marker = "source_url=";
    let lower = excerpt.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    let candidate = excerpt
        .get(start..)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| "|,;:!?)]}\"'".contains(ch))
        .trim();
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn selected_url_domain_key(source_hints: &[PendingSearchReadSummary], url: &str) -> Option<String> {
    let trimmed = url.trim();
    let url_domain = normalized_domain_key(trimmed);
    let hinted_domain = selected_url_hint(source_hints, trimmed)
        .and_then(|hint| source_url_from_metadata_excerpt(&hint.excerpt))
        .and_then(|resolved| normalized_domain_key(&resolved));
    match (url_domain, hinted_domain) {
        (Some(url_domain), Some(hinted_domain)) if url_domain != hinted_domain => {
            Some(hinted_domain)
        }
        (Some(url_domain), _) => Some(url_domain),
        (None, Some(hinted_domain)) => Some(hinted_domain),
        (None, None) => None,
    }
}

fn headline_source_low_priority(url: &str, title: &str, excerpt: &str) -> bool {
    let signals = analyze_source_record_signals(url, title, excerpt);
    signals.low_priority_hits > 0 || signals.low_priority_dominates()
}

pub(super) fn headline_selection_quality_metrics(
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
) -> (usize, usize, usize, Vec<String>) {
    let mut total_sources = 0usize;
    let mut low_priority_sources = 0usize;
    let mut distinct_domains = std::collections::BTreeSet::new();
    let mut low_priority_urls = Vec::new();
    let mut seen_urls = std::collections::BTreeSet::new();

    for selected in selected_urls {
        let selected_trimmed = selected.trim();
        if selected_trimmed.is_empty() {
            continue;
        }
        let dedup_key = selected_trimmed.to_ascii_lowercase();
        if !seen_urls.insert(dedup_key) {
            continue;
        }

        let (title, excerpt) = source_hints
            .iter()
            .find(|hint| {
                let hint_url = hint.url.trim();
                hint_url.eq_ignore_ascii_case(selected_trimmed)
                    || url_structurally_equivalent(hint_url, selected_trimmed)
            })
            .map(|hint| {
                (
                    hint.title.as_deref().unwrap_or_default(),
                    hint.excerpt.as_str(),
                )
            })
            .unwrap_or(("", ""));
        total_sources = total_sources.saturating_add(1);
        if let Some(domain) = selected_url_domain_key(source_hints, selected_trimmed) {
            distinct_domains.insert(domain);
        }
        if headline_source_low_priority(selected_trimmed, title, excerpt) {
            low_priority_sources = low_priority_sources.saturating_add(1);
            low_priority_urls.push(selected_trimmed.to_string());
        }
    }

    (
        total_sources,
        low_priority_sources,
        distinct_domains.len(),
        low_priority_urls,
    )
}

fn resolve_selected_urls_from_hints(
    selected_urls: &mut Vec<String>,
    source_hints: &[PendingSearchReadSummary],
) {
    for selected in selected_urls.iter_mut() {
        let selected_trimmed = selected.trim().to_string();
        if selected_trimmed.is_empty() {
            continue;
        }
        let resolved = source_hints
            .iter()
            .find(|hint| {
                let hint_url = hint.url.trim();
                hint_url.eq_ignore_ascii_case(&selected_trimmed)
                    || url_structurally_equivalent(hint_url, &selected_trimmed)
            })
            .and_then(|hint| source_url_from_metadata_excerpt(&hint.excerpt))
            .filter(|resolved_url| is_citable_web_url(resolved_url) && !is_search_hub_url(resolved_url));
        if let Some(resolved_url) = resolved {
            *selected = resolved_url;
        }
    }

    let mut deduped = Vec::new();
    for selected in selected_urls.iter() {
        let _ = push_unique_selected_url(&mut deduped, selected);
    }
    *selected_urls = deduped;
}

fn merge_source_hints(
    primary: Vec<PendingSearchReadSummary>,
    additional: &[PendingSearchReadSummary],
) -> Vec<PendingSearchReadSummary> {
    let mut merged = Vec::new();

    for source in primary {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if merged.iter().any(|existing: &PendingSearchReadSummary| {
            let existing_url = existing.url.trim();
            existing_url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(existing_url, trimmed)
        }) {
            continue;
        }
        merged.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: source.title,
            excerpt: source.excerpt.trim().to_string(),
        });
    }

    for source in additional {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if merged.iter().any(|existing: &PendingSearchReadSummary| {
            let existing_url = existing.url.trim();
            existing_url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(existing_url, trimmed)
        }) {
            continue;
        }
        merged.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: source.title.clone(),
            excerpt: source.excerpt.trim().to_string(),
        });
    }

    merged
}

fn push_unique_selected_url(selected_urls: &mut Vec<String>, candidate_url: &str) -> bool {
    let trimmed = candidate_url.trim();
    if trimmed.is_empty() {
        return false;
    }
    if selected_urls.iter().any(|existing| {
        existing.eq_ignore_ascii_case(trimmed) || url_structurally_equivalent(existing, trimmed)
    }) {
        return false;
    }
    selected_urls.push(trimmed.to_string());
    true
}
