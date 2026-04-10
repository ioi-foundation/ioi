fn local_business_expansion_timeout() -> Duration {
    const DEFAULT_TIMEOUT_MS: u64 = 4_000;
    std::env::var("IOI_WEB_LOCAL_BUSINESS_EXPANSION_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_TIMEOUT_MS))
}

#[derive(Debug, Clone, Serialize)]
struct PreReadDiscoverySource {
    rank: Option<u32>,
    url: String,
    domain: Option<String>,
    title: Option<String>,
    snippet: Option<String>,
    affordances: Vec<WebRetrievalAffordance>,
    expansion_affordances: Vec<WebSourceExpansionAffordance>,
}

fn filter_local_business_search_bundle_by_entity_anchor(
    bundle: &WebEvidenceBundle,
    retrieval_contract: Option<&WebRetrievalContract>,
    search_query: &str,
    locality_hint: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> WebEvidenceBundle {
    let anchor_preview = local_business_search_entity_anchor_tokens_with_contract(
        search_query,
        retrieval_contract,
        locality_hint,
    );
    if anchor_preview.is_empty() {
        return bundle.clone();
    }

    let mut filtered = bundle.clone();
    let kept_source_ids = filtered
        .sources
        .iter()
        .filter(|source| {
            source_matches_local_business_search_entity_anchor(
                search_query,
                retrieval_contract,
                locality_hint,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                source.snippet.as_deref().unwrap_or_default(),
            )
        })
        .map(|source| source.source_id.clone())
        .collect::<std::collections::BTreeSet<_>>();

    let before_sources = filtered.sources.len();
    let before_documents = filtered.documents.len();
    filtered
        .sources
        .retain(|source| kept_source_ids.contains(&source.source_id));
    filtered.documents.retain(|doc| {
        kept_source_ids.contains(&doc.source_id)
            || source_matches_local_business_search_entity_anchor(
                search_query,
                retrieval_contract,
                locality_hint,
                &doc.url,
                doc.title.as_deref().unwrap_or_default(),
                &doc.content_text,
            )
    });

    verification_checks.push("web_local_business_entity_filter_required=true".to_string());
    verification_checks.push(format!(
        "web_local_business_entity_filter_anchor={}",
        anchor_preview.join(" ")
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_sources_before={}",
        before_sources
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_sources_after={}",
        filtered.sources.len()
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_documents_before={}",
        before_documents
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_documents_after={}",
        filtered.documents.len()
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_satisfied={}",
        !filtered.sources.is_empty() || !filtered.documents.is_empty()
    ));

    filtered
}

fn filter_local_business_search_bundle_by_result_surface(
    bundle: &WebEvidenceBundle,
    query_contract: &str,
    min_sources: u32,
    locality_hint: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> WebEvidenceBundle {
    let retrieval_contract = bundle.retrieval_contract.as_ref();
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        &candidate_source_hints_from_bundle(bundle),
        locality_hint,
    );
    if !retrieval_contract_prefers_multi_item_cardinality(retrieval_contract, query_contract)
        || !retrieval_contract_requests_comparison(retrieval_contract, query_contract)
        || !projection.query_facets.locality_sensitive_public_fact
        || !projection.query_facets.grounded_external_required
    {
        return bundle.clone();
    }

    let mut filtered = bundle.clone();
    for source in &filtered.sources {
        let title = source.title.as_deref().unwrap_or_default();
        verification_checks.push(format!(
            "web_local_business_surface_filter_source_before={} | {}",
            source.url.trim(),
            compact_whitespace(title)
        ));
    }
    let kept_source_ids = filtered
        .sources
        .iter()
        .filter(|source| {
            local_business_discovery_source_allowed_with_projection(
                query_contract,
                &projection,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                source.snippet.as_deref().unwrap_or_default(),
            )
        })
        .map(|source| source.source_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let before_sources = filtered.sources.len();
    let before_documents = filtered.documents.len();

    filtered
        .sources
        .retain(|source| kept_source_ids.contains(&source.source_id));
    for source in &filtered.sources {
        verification_checks.push(format!(
            "web_local_business_surface_filter_source_kept={}",
            source.url.trim()
        ));
    }
    filtered.documents.retain(|doc| {
        kept_source_ids.contains(&doc.source_id)
            || local_business_discovery_source_allowed_with_projection(
                query_contract,
                &projection,
                &doc.url,
                doc.title.as_deref().unwrap_or_default(),
                &doc.content_text,
            )
    });

    verification_checks.push("web_local_business_surface_filter_required=true".to_string());
    verification_checks.push(format!(
        "web_local_business_surface_filter_sources_before={}",
        before_sources
    ));
    verification_checks.push(format!(
        "web_local_business_surface_filter_sources_after={}",
        filtered.sources.len()
    ));
    verification_checks.push(format!(
        "web_local_business_surface_filter_documents_before={}",
        before_documents
    ));
    verification_checks.push(format!(
        "web_local_business_surface_filter_documents_after={}",
        filtered.documents.len()
    ));
    verification_checks.push(format!(
        "web_local_business_surface_filter_satisfied={}",
        !filtered.sources.is_empty() || !filtered.documents.is_empty()
    ));

    filtered
}

fn local_business_expansion_query_contract(
    retrieval_contract: Option<&WebRetrievalContract>,
    _query_contract: &str,
) -> bool {
    retrieval_contract
        .map(|contract| {
            crate::agentic::web::contract_requires_geo_scoped_entity_expansion(contract)
                && contract.comparison_required
                && contract.runtime_locality_required
        })
        .unwrap_or(false)
}

fn local_business_expansion_source_marker(source_url: &str) -> String {
    format!(
        "ioi://local-business-expansion/source/{}",
        source_url.trim()
    )
}

fn local_business_expansion_query_marker(query: &str) -> String {
    format!(
        "{}{}",
        LOCAL_BUSINESS_EXPANSION_QUERY_MARKER_PREFIX,
        query.trim()
    )
}

fn local_business_expansion_done_marker() -> &'static str {
    "ioi://local-business-expansion/done"
}

fn local_business_expansion_target_floor_met(
    existing_targets: &[String],
    new_targets: &[String],
    required_count: usize,
) -> bool {
    merged_local_business_targets(existing_targets, new_targets).len() >= required_count.max(1)
}

fn local_business_expansion_source_excerpt(
    bundle: &WebEvidenceBundle,
    source_id: &str,
    source_url: &str,
    source_text: &str,
) -> String {
    let hinted = bundle.sources.iter().find(|source| {
        source.source_id == source_id
            || source.url.eq_ignore_ascii_case(source_url)
            || url_structurally_equivalent(source.url.as_str(), source_url)
    });
    if let Some(snippet) = hinted
        .and_then(|source| source.snippet.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return snippet.to_string();
    }

    source_text.chars().take(320).collect()
}

fn structured_local_business_target_sources_from_bundle(
    query_contract: &str,
    scope: &str,
    bundle: &WebEvidenceBundle,
    required_count: usize,
) -> Vec<PendingSearchReadSummary> {
    let bundle_source_hints = candidate_source_hints_from_bundle(bundle);
    let bundle_targets = local_business_target_names_from_sources(
        &bundle_source_hints,
        Some(scope),
        required_count.saturating_mul(4),
    );
    if bundle_targets.is_empty() {
        return Vec::new();
    }

    selected_local_business_target_sources(
        query_contract,
        &bundle_targets,
        &bundle_source_hints,
        Some(scope),
        required_count,
    )
}

fn select_local_business_expansion_source(
    query_contract: &str,
    min_sources: u32,
    scope: &str,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    bundle: &WebEvidenceBundle,
) -> Option<(
    String,
    Option<String>,
    String,
    Vec<String>,
    Vec<PendingSearchReadSummary>,
)> {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let required_count = min_sources.max(1) as usize;

    for doc in &bundle.documents {
        let source_url = doc.url.trim();
        let source_text = doc.content_text.trim();
        if source_url.is_empty() || source_text.is_empty() {
            continue;
        }
        let source_title = doc.title.as_deref().or_else(|| {
            bundle
                .sources
                .iter()
                .find(|source| {
                    source.source_id == doc.source_id
                        || source.url.eq_ignore_ascii_case(source_url)
                        || url_structurally_equivalent(source.url.as_str(), source_url)
                })
                .and_then(|source| source.title.as_deref())
        });
        let source_excerpt = local_business_expansion_source_excerpt(
            bundle,
            &doc.source_id,
            source_url,
            source_text,
        );
        let structured_target_sources = structured_local_business_target_sources_from_bundle(
            query_contract,
            scope,
            bundle,
            required_count,
        );
        let mut structured_candidates = structured_target_sources
            .into_iter()
            .filter_map(|source| local_business_detail_display_name(&source, Some(scope)))
            .collect::<Vec<_>>();
        structured_candidates = merged_local_business_targets(
            &structured_candidates,
            &extract_structured_local_business_names(scope, source_text, required_count),
        );
        let guide_detected = structured_candidates.len() >= 2
            || is_multi_item_listing_url(source_url.trim())
            || source_looks_like_multi_item_restaurant_guide(source_url, source_title, source_text);
        if !guide_detected {
            continue;
        }

        if !is_citable_web_url(source_url) || is_search_hub_url(source_url) {
            continue;
        }
        let compatibility_observed_excerpt = compact_whitespace(
            format!(
                "{} {}",
                source_excerpt,
                source_text.chars().take(512).collect::<String>()
            )
            .trim(),
        );
        if source_has_terminal_error_signal(
            source_url,
            source_title.unwrap_or_default(),
            &compatibility_observed_excerpt,
        ) {
            continue;
        }
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            source_url,
            source_title.unwrap_or_default(),
            &compatibility_observed_excerpt,
        );
        if !compatibility_passes_projection(&projection, &compatibility) {
            continue;
        }
        let semantic_query_tokens = projection
            .query_native_tokens
            .iter()
            .filter(|token| !projection.locality_tokens.contains(*token))
            .filter(|token| {
                !LOCAL_BUSINESS_EXPANSION_GENERIC_QUERY_TOKENS.contains(&token.as_str())
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if !semantic_query_tokens.is_empty() {
            let source_tokens = source_anchor_tokens(
                source_url,
                source_title.unwrap_or_default(),
                &compatibility_observed_excerpt,
            );
            let semantic_overlap = semantic_query_tokens
                .iter()
                .filter(|token| source_tokens.contains(*token))
                .count();
            if semantic_overlap == 0 {
                continue;
            }
        }

        return Some((
            source_url.to_string(),
            source_title.map(str::to_string),
            source_text.to_string(),
            structured_candidates,
            structured_local_business_target_sources_from_bundle(
                query_contract,
                scope,
                bundle,
                required_count,
            ),
        ));
    }

    None
}

fn parse_jsonish_string_value(source_text: &str, start_idx: usize) -> Option<(String, usize)> {
    let bytes = source_text.as_bytes();
    if bytes.get(start_idx).copied() != Some(b'"') {
        return None;
    }

    let mut idx = start_idx + 1;
    let mut value = String::new();
    let mut escape = false;
    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        idx += 1;
        if escape {
            match ch {
                '"' | '\\' | '/' => value.push(ch),
                'b' => value.push('\u{0008}'),
                'f' => value.push('\u{000C}'),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                'u' => {
                    if idx + 4 <= bytes.len() {
                        if let Ok(raw) = std::str::from_utf8(&bytes[idx..idx + 4]) {
                            if let Ok(codepoint) = u16::from_str_radix(raw, 16) {
                                if let Some(decoded) = char::from_u32(codepoint as u32) {
                                    value.push(decoded);
                                }
                            }
                        }
                        idx += 4;
                    }
                }
                _ => value.push(ch),
            }
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            return Some((value, idx));
        }
        value.push(ch);
    }
    None
}

fn extract_jsonish_keyed_string_values(source_text: &str, key: &str) -> Vec<(usize, String)> {
    let pattern = format!("\"{}\"", key);
    let mut values = Vec::new();
    let mut cursor = 0usize;

    while let Some(relative_idx) = source_text[cursor..].find(&pattern) {
        let key_start = cursor + relative_idx;
        let after_key = key_start + pattern.len();
        let Some(colon_relative_idx) = source_text[after_key..].find(':') else {
            break;
        };
        let mut value_start = after_key + colon_relative_idx + 1;
        while let Some(ch) = source_text[value_start..].chars().next() {
            if ch.is_whitespace() {
                value_start += ch.len_utf8();
                continue;
            }
            break;
        }
        let Some((value, consumed_idx)) = parse_jsonish_string_value(source_text, value_start)
        else {
            cursor = after_key;
            continue;
        };
        values.push((key_start, value));
        cursor = consumed_idx;
    }

    values
}

fn decode_jsonish_unicode_escapes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = String::with_capacity(input.len());
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] == b'\\' && idx + 5 < bytes.len() && bytes[idx + 1] == b'u' {
            if let Ok(raw) = std::str::from_utf8(&bytes[idx + 2..idx + 6]) {
                if let Ok(codepoint) = u16::from_str_radix(raw, 16) {
                    if let Some(ch) = char::from_u32(codepoint as u32) {
                        decoded.push(ch);
                        idx += 6;
                        continue;
                    }
                }
            }
        }

        decoded.push(bytes[idx] as char);
        idx += 1;
    }

    decoded
}

fn extract_structured_local_business_names(
    scope: &str,
    source_text: &str,
    required_count: usize,
) -> Vec<String> {
    let mut extracted = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut candidate_texts = vec![source_text.to_string()];
    if let Some(normalized) = normalized_jsonish_source_text(source_text) {
        candidate_texts.push(normalized);
    }

    for candidate_text in candidate_texts {
        let source_text_lower = candidate_text.to_ascii_lowercase();

        for (position, raw_name) in extract_jsonish_keyed_string_values(&candidate_text, "name") {
            let Some(name) = normalized_local_business_target_name(&raw_name) else {
                continue;
            };
            if name.eq_ignore_ascii_case(scope) {
                continue;
            }
            if !local_business_entity_name_allowed(&name, Some(scope)) {
                continue;
            }
            let token_count = name
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .filter(|token| !token.trim().is_empty())
                .count();
            if token_count == 0 || token_count > 6 {
                continue;
            }
            let lower_name = name.to_ascii_lowercase();
            if lower_name.contains("infatuation")
                || lower_name.contains("eater")
                || lower_name.contains("new york city")
                || lower_name.contains("restaurant guide")
            {
                continue;
            }
            let window_start = position.saturating_sub(128);
            let window_end = position.saturating_add(384).min(source_text_lower.len());
            let window = &source_text_lower[window_start..window_end];
            let structured_business_markers = window.contains("streetaddress")
                || window.contains("postalcode")
                || window.contains("servescuisine")
                || window.contains("@type\":\"restaurant")
                || window.contains("\"menu\"")
                || window.contains("\"telephone\"");
            if !structured_business_markers {
                continue;
            }
            if !normalized_contains_phrase(&candidate_text, &name) {
                continue;
            }
            let dedup_key = lower_name;
            if !seen.insert(dedup_key) {
                continue;
            }
            extracted.push(name);
            if extracted.len() >= required_count {
                return extracted;
            }
        }
    }

    extracted
}

fn lint_local_business_expansion_restaurants(
    scope: &str,
    source_text: &str,
    restaurants: &[String],
    required_count: usize,
) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for restaurant in restaurants {
        let trimmed = restaurant.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        if trimmed.eq_ignore_ascii_case(scope) {
            continue;
        }
        let token_count = trimmed
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .filter(|token| !token.trim().is_empty())
            .count();
        if token_count == 0 {
            continue;
        }
        if !normalized_contains_phrase(source_text, trimmed) {
            return Err(format!(
                "restaurant '{}' was not grounded in the source text",
                trimmed
            ));
        }
        normalized.push(trimmed.to_string());
        if normalized.len() >= required_count {
            break;
        }
    }

    if normalized.is_empty() {
        return Err("no grounded restaurant names were returned".to_string());
    }
    Ok(normalized)
}

fn local_business_menu_queries(
    query_contract: &str,
    restaurants: &[String],
    scope: &str,
) -> Vec<String> {
    restaurants
        .iter()
        .filter_map(|restaurant| {
            local_business_expansion_query(restaurant, query_contract, Some(scope))
        })
        .collect()
}

async fn synthesize_local_business_expansion_restaurants(
    service: &RuntimeAgentService,
    query_contract: &str,
    scope: &str,
    required_count: usize,
    source_url: &str,
    source_title: Option<&str>,
    source_text: &str,
) -> Result<Vec<String>, String> {
    synthesize_grounded_entity_targets(
        service,
        query_contract,
        scope,
        required_count,
        source_url,
        source_title,
        source_text,
    )
    .await
}

pub(super) async fn maybe_queue_local_business_expansion_searches(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    pending: &mut PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    verification_checks: &mut Vec<String>,
) -> Result<bool, TransactionError> {
    let query_contract = if pending.query_contract.trim().is_empty() {
        pending.query.trim()
    } else {
        pending.query_contract.trim()
    };
    let retrieval_contract = pending.retrieval_contract.as_ref();
    if query_contract.is_empty()
        || !local_business_expansion_query_contract(retrieval_contract, query_contract)
    {
        return Ok(false);
    }

    let locality_hint =
        if retrieval_contract_requires_runtime_locality(retrieval_contract, query_contract) {
            effective_locality_scope_hint(None)
        } else {
            None
        };
    let required_count = pending.min_sources.max(1) as usize;
    let existing_targets = entity_targets_from_attempted_urls(&pending.attempted_urls);
    let existing_matched_targets =
        matched_entity_target_names(&existing_targets, &pending.successful_reads);
    if existing_matched_targets.len() >= required_count {
        return Ok(false);
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        pending.min_sources,
        &pending.successful_reads,
        locality_hint.as_deref(),
    );
    let Some(scope) = projection
        .locality_scope
        .clone()
        .or_else(|| locality_hint.clone())
    else {
        return Ok(false);
    };

    let mut selected_source: Option<(String, Option<String>, String, Vec<String>)> = None;
    for doc in &bundle.documents {
        let source_url = doc.url.trim();
        let source_text = doc.content_text.trim();
        if source_url.is_empty()
            || source_text.is_empty()
            || !is_citable_web_url(source_url)
            || is_search_hub_url(source_url)
        {
            continue;
        }
        let source_title = doc.title.clone().or_else(|| {
            bundle
                .sources
                .iter()
                .find(|source| {
                    source.source_id == doc.source_id
                        || source.url.eq_ignore_ascii_case(source_url)
                        || url_structurally_equivalent(source.url.as_str(), source_url)
                })
                .and_then(|source| source.title.clone())
        });
        if source_has_terminal_error_signal(
            source_url,
            source_title.as_deref().unwrap_or_default(),
            source_text,
        ) {
            continue;
        }
        let source_marker = local_business_expansion_source_marker(source_url);
        if pending
            .attempted_urls
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&source_marker))
        {
            continue;
        }
        let Ok(entities) = synthesize_grounded_entity_targets(
            service,
            query_contract,
            &scope,
            required_count,
            source_url,
            source_title.as_deref(),
            source_text,
        )
        .await
        else {
            continue;
        };
        if entities.is_empty() {
            continue;
        }
        pending.attempted_urls.push(source_marker);
        selected_source = Some((
            source_url.to_string(),
            source_title,
            source_text.to_string(),
            entities,
        ));
        break;
    }

    let Some((source_url, _source_title, _source_text, entities)) = selected_source else {
        verification_checks
            .push("web_local_business_expansion_query_compatible_source=false".to_string());
        return Ok(false);
    };

    verification_checks.push("web_local_business_expansion_required=true".to_string());
    verification_checks
        .push("web_local_business_expansion_query_compatible_source=true".to_string());
    verification_checks.push(format!(
        "web_local_business_expansion_source_url={}",
        source_url
    ));
    verification_checks.push(format!("web_local_business_expansion_scope={}", scope));
    verification_checks.push(format!(
        "web_local_business_expansion_guide_detected={}",
        entities.len() >= 2
    ));
    verification_checks.push(format!(
        "web_local_business_expansion_structured_candidate_count={}",
        entities.len()
    ));
    verification_checks.push(format!(
        "web_local_business_expansion_structured_target_floor_met={}",
        entity_expansion_target_floor_met(&existing_targets, &entities, required_count)
    ));
    let expansion_target_floor_met =
        entity_expansion_target_floor_met(&existing_targets, &entities, required_count);
    let total_targets = merged_entity_targets(&existing_targets, &entities);
    let mut queued = 0usize;
    let search_limit = constraint_grounded_search_limit(query_contract, pending.min_sources);
    for entity in &entities {
        let Some(target_marker) = entity_expansion_target_marker(entity) else {
            continue;
        };
        if pending
            .attempted_urls
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&target_marker))
        {
            continue;
        }
        let Some(search_query) = entity_detail_search_query(entity, query_contract, Some(&scope))
        else {
            continue;
        };
        let Some(query_marker) = entity_expansion_query_marker(&search_query) else {
            continue;
        };
        if pending
            .attempted_urls
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&query_marker))
        {
            continue;
        }
        pending.attempted_urls.push(target_marker);
        pending.attempted_urls.push(query_marker);
        if queue_web_search_from_pipeline(
            agent_state,
            session_id,
            &search_query,
            Some(query_contract),
            pending.retrieval_contract.as_ref(),
            search_limit,
        )? {
            queued = queued.saturating_add(1);
        }
    }
    verification_checks.push(format!(
        "web_local_business_expansion_candidates={}",
        entities.join(" | ")
    ));
    verification_checks.push(format!(
        "web_local_business_expansion_target_total={}",
        total_targets.len()
    ));
    verification_checks.push(format!(
        "web_local_business_expansion_target_floor_met={}",
        expansion_target_floor_met
    ));
    verification_checks.push(format!("web_local_business_expansion_queued={}", queued));
    verification_checks.push(format!(
        "web_local_business_expansion_satisfied={}",
        queued > 0 && expansion_target_floor_met
    ));
    if queued > 0 && expansion_target_floor_met {
        pending
            .attempted_urls
            .push(local_business_expansion_done_marker().to_string());
    }

    Ok(queued > 0)
}
