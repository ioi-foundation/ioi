use super::*;
use ioi_types::app::agentic::{WebDocument, WebRetrievalContract};

const HUMAN_CHALLENGE_DOCUMENT_PROBE_CHARS: usize = 600;
const AUTHORITY_IDENTIFIER_DISCOVERY_CHARS: usize = 2400;

fn preserve_retrieved_excerpt_over_hint(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() || is_low_signal_excerpt(trimmed) {
        return false;
    }

    has_quantitative_metric_payload(trimmed, false)
        || local_business_menu_inventory_excerpt(trimmed, trimmed.chars().count()).is_some()
        || source_has_briefing_standard_identifier_signal(query_contract, url, title, trimmed)
}

fn grounded_document_briefing_source_quality_required(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
) -> bool {
    matches!(
        synthesis_layout_profile(retrieval_contract, query_contract),
        SynthesisLayoutProfile::DocumentBriefing
    ) && !retrieval_contract_requests_comparison(retrieval_contract, query_contract)
        && crate::agentic::runtime::service::step::signals::analyze_query_facets(query_contract)
            .grounded_external_required
}

pub(crate) fn push_pending_web_success(
    pending: &mut PendingSearchCompletion,
    url: &str,
    title: Option<String>,
    excerpt: String,
) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }

    let hint = hint_for_url(pending, trimmed);
    let mut resolved_title = title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    if resolved_title
        .as_deref()
        .map(is_low_signal_title)
        .unwrap_or(true)
    {
        if let Some(hint_title) = hint
            .and_then(|value| value.title.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            resolved_title = Some(hint_title.to_string());
        }
    }

    let hint_excerpt = hint
        .map(|value| value.excerpt.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let mut resolved_excerpt = excerpt.trim().to_string();
    if let Some(hint_excerpt) = hint_excerpt.as_deref() {
        // Keep retrieved page content authoritative. Only backfill from the search
        // snippet when the read itself yielded no excerpt text.
        if resolved_excerpt.is_empty() {
            resolved_excerpt = hint_excerpt.to_string();
        }
    }
    let query_contract = synthesis_query_contract(pending);
    let menu_inventory_grounded_excerpt = local_business_menu_surface_grounded_excerpt(
        pending.retrieval_contract.as_ref(),
        &query_contract,
        trimmed,
        &resolved_excerpt,
    );
    if source_has_human_challenge_signal(
        trimmed,
        resolved_title.as_deref().unwrap_or_default(),
        &resolved_excerpt,
    ) {
        mark_pending_web_blocked(pending, trimmed);
        return;
    }
    if source_has_terminal_error_signal(
        trimmed,
        resolved_title.as_deref().unwrap_or_default(),
        &resolved_excerpt,
    ) {
        return;
    }

    let retrieval_contract = pending.retrieval_contract.as_ref();
    let preserve_retrieved_excerpt = preserve_retrieved_excerpt_over_hint(
        &query_contract,
        trimmed,
        resolved_title.as_deref().unwrap_or_default(),
        &resolved_excerpt,
    );
    let single_snapshot_contract =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract);
    let host_anchored_primary_authority_alignment =
        source_has_host_anchored_primary_authority_snapshot_alignment(
            retrieval_contract,
            &query_contract,
            pending.min_sources as usize,
            trimmed,
            resolved_title.as_deref().unwrap_or_default(),
            &resolved_excerpt,
        );
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let headline_collection_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
    let time_sensitive = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || retrieval_contract
            .map(|contract| contract.currentness_required)
            .unwrap_or(false);
    let reject_search_hub = projection.reject_search_hub_candidates();
    if headline_collection_mode {
        let script_like_excerpt = resolved_excerpt.contains("||")
            && resolved_excerpt.contains("==")
            && resolved_excerpt.to_ascii_lowercase().contains("return");
        if (resolved_excerpt.is_empty()
            || is_low_signal_excerpt(&resolved_excerpt)
            || script_like_excerpt)
            && hint_excerpt.is_some()
        {
            if let Some(hint_excerpt_text) = hint_excerpt.as_deref() {
                resolved_excerpt = hint_excerpt_text.to_string();
            }
        }
        let base_url_allowed = is_citable_web_url(trimmed)
            && !is_search_hub_url(trimmed)
            && !is_multi_item_listing_url(trimmed)
            && !crate::agentic::web::is_google_news_article_wrapper_url(trimmed);
        let resolved_url = if base_url_allowed {
            trimmed.to_string()
        } else {
            source_url_from_metadata_excerpt(&resolved_excerpt)
                .or_else(|| {
                    hint_excerpt
                        .as_deref()
                        .and_then(source_url_from_metadata_excerpt)
                })
                .filter(|candidate_url| {
                    let candidate = candidate_url.trim();
                    is_citable_web_url(candidate)
                        && !is_search_hub_url(candidate)
                        && !is_multi_item_listing_url(candidate)
                        && !crate::agentic::web::is_google_news_article_wrapper_url(candidate)
                })
                .unwrap_or_else(|| trimmed.to_string())
        };
        if headline_source_is_low_quality(
            &resolved_url,
            resolved_title.as_deref().unwrap_or_default(),
            &resolved_excerpt,
        ) {
            return;
        }
        upsert_pending_web_success_record(
            pending,
            &query_contract,
            PendingSearchReadSummary {
                url: resolved_url,
                title: resolved_title,
                excerpt: resolved_excerpt,
            },
        );
        return;
    }
    if reject_search_hub && is_search_hub_url(trimmed) {
        return;
    }
    if let Some(hint_excerpt_text) = hint_excerpt.as_deref() {
        // For grounded reads, retain the stronger same-URL surface between the
        // read excerpt and the search hint so identifier/currentness evidence is
        // not discarded simply because the read returned a weaker snippet.
        if !menu_inventory_grounded_excerpt && !preserve_retrieved_excerpt {
            resolved_excerpt = prefer_excerpt_for_query(
                &query_contract,
                resolved_excerpt,
                hint_excerpt_text.to_string(),
            );
        }
    }
    if projection.query_facets.grounded_external_required || time_sensitive {
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed,
            resolved_title.as_deref().unwrap_or_default(),
            &resolved_excerpt,
        );
        let mut compatibility_passes = compatibility_passes_projection(&projection, &compatibility);
        if !compatibility_passes
            && (menu_inventory_grounded_excerpt || host_anchored_primary_authority_alignment)
        {
            compatibility_passes = true;
        }
        if !compatibility_passes {
            if let Some(hint_entry) = hint {
                let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                let hint_excerpt = hint_entry.excerpt.trim();
                let hint_compatibility = candidate_constraint_compatibility(
                    &projection.constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    trimmed,
                    hint_title,
                    hint_excerpt,
                );
                if compatibility_passes_projection(&projection, &hint_compatibility) {
                    compatibility_passes = true;
                    if resolved_title
                        .as_deref()
                        .map(is_low_signal_title)
                        .unwrap_or(true)
                        && !hint_title.is_empty()
                    {
                        resolved_title = Some(hint_title.to_string());
                    }
                    if !menu_inventory_grounded_excerpt
                        && !preserve_retrieved_excerpt
                        && !hint_excerpt.is_empty()
                    {
                        resolved_excerpt = hint_excerpt.to_string();
                    }
                }
            }
        }
        if !compatibility_passes {
            let has_compatible_alternative =
                pending.candidate_source_hints.iter().any(|candidate| {
                    let candidate_url = candidate.url.trim();
                    if candidate_url.is_empty() || candidate_url.eq_ignore_ascii_case(trimmed) {
                        return false;
                    }
                    if is_search_hub_url(candidate_url) {
                        return false;
                    }
                    let candidate_title = candidate.title.as_deref().unwrap_or_default();
                    let candidate_excerpt = candidate.excerpt.as_str();
                    let candidate_compatibility = candidate_constraint_compatibility(
                        &projection.constraints,
                        &projection.query_facets,
                        &projection.query_native_tokens,
                        &projection.query_tokens,
                        &projection.locality_tokens,
                        projection.locality_scope.is_some(),
                        candidate_url,
                        candidate_title,
                        candidate_excerpt,
                    );
                    compatibility_passes_projection(&projection, &candidate_compatibility)
                });
            let allow_exploratory_first_capture =
                projection.locality_scope_inferred && !projection.locality_tokens.is_empty();
            let allow_exploratory_floor_capture = source_floor_unmet
                && time_sensitive
                && compatibility.locality_compatible
                && !is_search_hub_url(trimmed);
            if (!source_floor_unmet && has_compatible_alternative)
                || (!source_floor_unmet && !pending.successful_reads.is_empty())
                || (!allow_exploratory_first_capture && !allow_exploratory_floor_capture)
            {
                return;
            }
        }

        if grounded_document_briefing_source_quality_required(retrieval_contract, &query_contract)
            && !source_has_briefing_standard_identifier_signal(
                &query_contract,
                trimmed,
                resolved_title.as_deref().unwrap_or_default(),
                &resolved_excerpt,
            )
            && !source_has_document_authority(
                &query_contract,
                trimmed,
                resolved_title.as_deref().unwrap_or_default(),
                &resolved_excerpt,
            )
        {
            return;
        }

        if time_sensitive {
            let mut resolved_payload = candidate_time_sensitive_resolvable_payload(
                trimmed,
                resolved_title.as_deref().unwrap_or_default(),
                &resolved_excerpt,
            );
            if !resolved_payload && host_anchored_primary_authority_alignment {
                resolved_payload = true;
            }
            if !resolved_payload {
                if let Some(hint_entry) = hint {
                    let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                    let hint_excerpt = hint_entry.excerpt.trim();
                    if !hint_excerpt.is_empty()
                        && candidate_time_sensitive_resolvable_payload(
                            trimmed,
                            hint_title,
                            hint_excerpt,
                        )
                    {
                        let hint_compatibility = candidate_constraint_compatibility(
                            &projection.constraints,
                            &projection.query_facets,
                            &projection.query_native_tokens,
                            &projection.query_tokens,
                            &projection.locality_tokens,
                            projection.locality_scope.is_some(),
                            trimmed,
                            hint_title,
                            hint_excerpt,
                        );
                        if compatibility_passes_projection(&projection, &hint_compatibility) {
                            if !hint_title.is_empty() {
                                resolved_title = Some(hint_title.to_string());
                            }
                            resolved_excerpt = hint_excerpt.to_string();
                            resolved_payload = true;
                        }
                    }
                }
            }
            if !resolved_payload {
                let has_resolvable_alternative = pending
                    .candidate_source_hints
                    .iter()
                    .chain(pending.successful_reads.iter())
                    .any(|candidate| {
                        let candidate_url = candidate.url.trim();
                        if candidate_url.is_empty() || is_search_hub_url(candidate_url) {
                            return false;
                        }
                        if candidate_url.eq_ignore_ascii_case(trimmed) {
                            return false;
                        }
                        let candidate_title = candidate.title.as_deref().unwrap_or_default().trim();
                        let candidate_excerpt = candidate.excerpt.trim();
                        if !candidate_time_sensitive_resolvable_payload(
                            candidate_url,
                            candidate_title,
                            candidate_excerpt,
                        ) {
                            return false;
                        }
                        let candidate_compatibility = candidate_constraint_compatibility(
                            &projection.constraints,
                            &projection.query_facets,
                            &projection.query_native_tokens,
                            &projection.query_tokens,
                            &projection.locality_tokens,
                            projection.locality_scope.is_some(),
                            candidate_url,
                            candidate_title,
                            candidate_excerpt,
                        );
                        compatibility_passes_projection(&projection, &candidate_compatibility)
                    });
                if has_resolvable_alternative {
                    if source_floor_unmet {
                        // Floor-recovery mode: retain additional locality-compatible reads even
                        // when stronger resolvable alternatives already exist.
                    } else {
                        return;
                    }
                }
                if single_snapshot_contract {
                    return;
                }
            }
        }
    }

    if single_snapshot_contract || time_sensitive {
        let focused_excerpt = prioritized_success_excerpt_for_query(
            pending,
            trimmed,
            resolved_title.as_deref().unwrap_or_default(),
            &resolved_excerpt,
            WEB_PIPELINE_EXCERPT_CHARS,
        );
        if !focused_excerpt.is_empty() {
            resolved_excerpt = focused_excerpt;
        }
    }

    upsert_pending_web_success_record(
        pending,
        &query_contract,
        PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: resolved_title,
            excerpt: resolved_excerpt,
        },
    );
}

fn local_business_menu_surface_grounded_excerpt(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    url: &str,
    excerpt: &str,
) -> bool {
    let locality_hint = explicit_query_scope_hint(query_contract);
    local_business_menu_surface_url(url)
        && query_requires_local_business_menu_surface(
            query_contract,
            retrieval_contract,
            locality_hint.as_deref(),
        )
        && local_business_menu_inventory_excerpt(excerpt, excerpt.chars().count()).is_some()
}

fn upsert_pending_web_success_record(
    pending: &mut PendingSearchCompletion,
    query_contract: &str,
    incoming: PendingSearchReadSummary,
) {
    let trimmed = incoming.url.trim().to_string();
    if trimmed.is_empty() {
        return;
    }
    let normalized = PendingSearchReadSummary {
        url: trimmed.clone(),
        title: normalize_optional_title(incoming.title),
        excerpt: incoming.excerpt.trim().to_string(),
    };
    if let Some(existing_idx) = pending
        .successful_reads
        .iter()
        .position(|existing| url_structurally_equivalent(existing.url.trim(), &trimmed))
    {
        let merged = merge_pending_source_record_for_query(
            query_contract,
            pending.successful_reads[existing_idx].clone(),
            normalized,
        );
        pending.successful_reads[existing_idx] = merged;
        augment_pending_document_briefing_authority_candidates(pending, query_contract);
        return;
    }

    pending.successful_reads.push(normalized);
    augment_pending_document_briefing_authority_candidates(pending, query_contract);
}

fn augment_pending_document_briefing_authority_candidates(
    pending: &mut PendingSearchCompletion,
    query_contract: &str,
) {
    let retrieval_contract = pending.retrieval_contract.as_ref();
    if !query_prefers_document_briefing_layout(query_contract)
        || query_requests_comparison(query_contract)
        || !analyze_query_facets(query_contract).grounded_external_required
        || !retrieval_contract
            .map(|contract| contract.currentness_required || contract.source_independence_min > 1)
            .unwrap_or(false)
    {
        return;
    }

    let mut synthesized_candidates = Vec::new();
    let mut seen_urls = BTreeSet::new();
    for source in &pending.successful_reads {
        let source_url = source.url.trim();
        if source_url.is_empty() {
            continue;
        }
        let source_title = source.title.as_deref().unwrap_or_default();
        let source_excerpt = source.excerpt.trim();
        if !source_has_document_authority(query_contract, source_url, source_title, source_excerpt)
        {
            continue;
        }
        let Some(host) = source_host(source_url) else {
            continue;
        };
        let normalized_host = host
            .strip_prefix("www.")
            .unwrap_or(&host)
            .to_ascii_lowercase();
        if normalized_host != "nist.gov" && !normalized_host.ends_with(".nist.gov") {
            continue;
        }

        extend_identifier_backed_nist_authority_candidates(
            &mut synthesized_candidates,
            &mut seen_urls,
            query_contract,
            source_url,
            source_title,
            source_excerpt,
            None,
        );
    }

    for candidate in synthesized_candidates {
        if !pending.candidate_urls.iter().any(|existing| {
            existing.eq_ignore_ascii_case(&candidate.url)
                || url_structurally_equivalent(existing, &candidate.url)
        }) {
            pending.candidate_urls.push(candidate.url.clone());
        }
        if let Some(existing) = pending.candidate_source_hints.iter_mut().find(|existing| {
            existing.url.eq_ignore_ascii_case(&candidate.url)
                || url_structurally_equivalent(&existing.url, &candidate.url)
        }) {
            let merged =
                merge_pending_source_record_for_query(query_contract, existing.clone(), candidate);
            *existing = merged;
        } else {
            pending.candidate_source_hints.push(candidate);
        }
    }
}

fn extend_identifier_backed_nist_authority_candidates(
    out: &mut Vec<PendingSearchReadSummary>,
    seen_urls: &mut BTreeSet<String>,
    query_contract: &str,
    source_url: &str,
    source_title: &str,
    source_excerpt: &str,
    extra_surface: Option<&str>,
) {
    let surface = match extra_surface {
        Some(extra) if !extra.trim().is_empty() => {
            format!("{source_url} {source_title} {source_excerpt} {extra}")
        }
        _ => format!("{source_url} {source_title} {source_excerpt}"),
    };
    let authority_surface_excerpt = compact_whitespace(&surface);
    let inferred_labels =
        crate::agentic::runtime::service::step::queue::support::infer_briefing_required_identifier_labels(
            query_contract,
            &[crate::agentic::runtime::service::step::queue::support::BriefingIdentifierObservation {
                url: source_url.trim().to_string(),
                surface: surface.clone(),
                authoritative:
                    crate::agentic::runtime::service::step::queue::support::source_has_document_authority(
                        query_contract,
                        source_url,
                        source_title,
                        &authority_surface_excerpt,
                    ),
            }],
        );
    for label in inferred_labels {
        let Some(url) = identifier_backed_nist_authority_candidate_url(&label) else {
            continue;
        };
        let normalized_url = crate::agentic::web::normalize_url_for_id(&url);
        if !seen_urls.insert(normalized_url) {
            continue;
        }
        let excerpt = if source_excerpt.is_empty() {
            format!(
                "{label} is referenced by an authoritative NIST post-quantum cryptography source."
            )
        } else {
            source_excerpt.to_string()
        };
        out.push(PendingSearchReadSummary {
            url,
            title: Some(format!("Federal Information Processing Standard ({label})")),
            excerpt,
        });
    }
}

fn identifier_backed_nist_authority_candidate_url(label: &str) -> Option<String> {
    let trimmed = label.trim();
    let digits = trimmed
        .strip_prefix("FIPS ")
        .or_else(|| trimmed.strip_prefix("fips "))
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()))?;
    Some(format!(
        "https://csrc.nist.gov/pubs/fips/{}/final",
        digits.to_ascii_lowercase()
    ))
}

fn merge_bundle_source_surface_into_success(
    pending: &mut PendingSearchCompletion,
    query_contract: &str,
    bundle: &WebEvidenceBundle,
    doc: &WebDocument,
) {
    let Some(source) = bundle.sources.iter().find(|source| {
        (!source.source_id.trim().is_empty() && source.source_id == doc.source_id)
            || url_structurally_equivalent(source.url.as_str(), doc.url.as_str())
    }) else {
        return;
    };

    let excerpt = prioritized_success_excerpt_for_query(
        pending,
        source.url.as_str(),
        source.title.as_deref().unwrap_or_default(),
        source.snippet.as_deref().unwrap_or_default(),
        180,
    );
    let title = source
        .title
        .clone()
        .or_else(|| doc.title.clone())
        .filter(|value| !value.trim().is_empty());
    if title.is_none() && excerpt.is_empty() {
        return;
    }

    upsert_pending_web_success_record(
        pending,
        query_contract,
        PendingSearchReadSummary {
            url: doc.url.trim().to_string(),
            title: title.clone(),
            excerpt,
        },
    );

    let doc_surface = compact_excerpt(&doc.content_text, AUTHORITY_IDENTIFIER_DISCOVERY_CHARS);
    let mut synthesized_candidates = Vec::new();
    let mut seen_urls = BTreeSet::new();
    extend_identifier_backed_nist_authority_candidates(
        &mut synthesized_candidates,
        &mut seen_urls,
        query_contract,
        doc.url.trim(),
        title.as_deref().unwrap_or_default(),
        source.snippet.as_deref().unwrap_or_default(),
        Some(&doc_surface),
    );
    for candidate in synthesized_candidates {
        if !pending.candidate_urls.iter().any(|existing| {
            existing.eq_ignore_ascii_case(&candidate.url)
                || url_structurally_equivalent(existing, &candidate.url)
        }) {
            pending.candidate_urls.push(candidate.url.clone());
        }
        if let Some(existing) = pending.candidate_source_hints.iter_mut().find(|existing| {
            existing.url.eq_ignore_ascii_case(&candidate.url)
                || url_structurally_equivalent(&existing.url, &candidate.url)
        }) {
            let merged =
                merge_pending_source_record_for_query(query_contract, existing.clone(), candidate);
            *existing = merged;
        } else {
            pending.candidate_source_hints.push(candidate);
        }
    }
}

fn merge_bundle_source_candidates_into_pending(
    pending: &mut PendingSearchCompletion,
    query_contract: &str,
    bundle: &WebEvidenceBundle,
    primary_source_id: Option<&str>,
) {
    for source in &bundle.sources {
        if primary_source_id.is_some_and(|source_id| source.source_id == source_id) {
            continue;
        }
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let title = source
            .title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let excerpt = source.snippet.as_deref().unwrap_or_default().trim();
        if title.is_none() && excerpt.is_empty() {
            continue;
        }
        if !pending.candidate_urls.iter().any(|existing| {
            existing.eq_ignore_ascii_case(trimmed) || url_structurally_equivalent(existing, trimmed)
        }) {
            pending.candidate_urls.push(trimmed.to_string());
        }
        let incoming = PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: title.map(str::to_string),
            excerpt: excerpt.to_string(),
        };
        if let Some(existing) = pending.candidate_source_hints.iter_mut().find(|existing| {
            existing.url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(&existing.url, trimmed)
        }) {
            let merged =
                merge_pending_source_record_for_query(query_contract, existing.clone(), incoming);
            *existing = merged;
        } else {
            pending.candidate_source_hints.push(incoming);
        }
    }
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

fn excerpt_without_source_url_metadata(excerpt: &str) -> String {
    excerpt
        .split_whitespace()
        .filter(|token| {
            let trimmed = token.trim();
            !trimmed.is_empty()
                && trimmed != "|"
                && !trimmed.to_ascii_lowercase().starts_with("source_url=")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn prioritized_success_excerpt_for_query(
    pending: &PendingSearchCompletion,
    url: &str,
    title: &str,
    input: &str,
    max_chars: usize,
) -> String {
    let query_contract = synthesis_query_contract(pending);
    let grounded = prioritized_query_grounding_excerpt_with_contract(
        pending.retrieval_contract.as_ref(),
        &query_contract,
        pending.min_sources as usize,
        url,
        title,
        input,
        max_chars,
    );
    if !grounded.is_empty() {
        return grounded;
    }

    prioritized_signal_excerpt(input, max_chars)
}

fn prioritized_document_quote_excerpt_for_query(
    pending: &PendingSearchCompletion,
    doc: &WebDocument,
    title: &str,
    max_chars: usize,
) -> String {
    let joined_quotes = doc
        .quote_spans
        .iter()
        .map(|span| span.quote.trim())
        .filter(|quote| !quote.is_empty())
        .take(12)
        .collect::<Vec<_>>()
        .join(" ");
    if !joined_quotes.is_empty() {
        let joined_excerpt = prioritized_success_excerpt_for_query(
            pending,
            doc.url.as_str(),
            title,
            &joined_quotes,
            max_chars,
        );
        if !joined_excerpt.is_empty() {
            return joined_excerpt;
        }
    }

    let query_contract = synthesis_query_contract(pending);
    let mut excerpt = String::new();
    for span in &doc.quote_spans {
        let quote = span.quote.trim();
        if quote.is_empty() {
            continue;
        }
        let candidate = prioritized_success_excerpt_for_query(
            pending,
            doc.url.as_str(),
            title,
            quote,
            max_chars,
        );
        if candidate.is_empty() {
            continue;
        }
        excerpt = prefer_excerpt_for_query(&query_contract, excerpt, candidate);
    }

    excerpt
}

fn supporting_bundle_success_excerpt(
    pending: &PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    primary_source_id: Option<&str>,
    primary_url: &str,
) -> String {
    let query_contract = synthesis_query_contract(pending);
    let mut excerpt = String::new();
    for source in &bundle.sources {
        if primary_source_id.is_some_and(|source_id| source.source_id == source_id) {
            continue;
        }
        if url_structurally_equivalent(source.url.as_str(), primary_url) {
            continue;
        }
        let candidate = prioritized_success_excerpt_for_query(
            pending,
            source.url.as_str(),
            source.title.as_deref().unwrap_or_default(),
            source.snippet.as_deref().unwrap_or_default(),
            WEB_PIPELINE_EXCERPT_CHARS,
        );
        if candidate.is_empty() {
            continue;
        }
        excerpt = prefer_excerpt_for_query(&query_contract, excerpt, candidate);
    }
    excerpt
}

pub(crate) fn append_pending_web_success_fallback(
    pending: &mut PendingSearchCompletion,
    url: &str,
    raw_output: Option<&str>,
) {
    let raw_excerpt = prioritized_success_excerpt_for_query(
        pending,
        url,
        "",
        raw_output.unwrap_or_default(),
        WEB_PIPELINE_EXCERPT_CHARS,
    );
    let excerpt = if raw_excerpt.is_empty()
        || is_low_signal_excerpt(&raw_excerpt)
        || raw_excerpt.contains("Final response emitted via chat__reply")
        || raw_excerpt.starts_with("Recorded challenged source in fixed payload")
        || raw_excerpt.starts_with("Source read failed in fixed payload")
    {
        String::new()
    } else {
        raw_excerpt
    };
    push_pending_web_success(pending, url, None, excerpt);
}

pub(crate) fn append_pending_web_success_from_hint(
    pending: &mut PendingSearchCompletion,
    requested_url: &str,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    if !retrieval_contract_is_generic_headline_collection(
        pending.retrieval_contract.as_ref(),
        &query_contract,
    ) {
        return false;
    }

    let Some(hint) = hint_for_url(pending, requested_url).cloned() else {
        return false;
    };
    let candidate_url = source_url_from_metadata_excerpt(&hint.excerpt)
        .unwrap_or_else(|| hint.url.trim().to_string());
    if candidate_url.trim().is_empty() {
        return false;
    }
    let cleaned_excerpt = excerpt_without_source_url_metadata(&hint.excerpt);
    let excerpt = prioritized_signal_excerpt(&cleaned_excerpt, 180);
    let candidate_source = PendingSearchReadSummary {
        url: candidate_url.clone(),
        title: hint.title.clone(),
        excerpt: excerpt.clone(),
    };
    let candidate_title = canonical_source_title(&candidate_source);
    if is_low_signal_title(&candidate_title)
        || !headline_story_title_has_specificity(&candidate_title)
        || headline_source_is_low_quality(&candidate_url, &candidate_title, &excerpt)
    {
        return false;
    }

    let before = pending.successful_reads.len();
    if !try_append_headline_bundle_success(
        pending,
        requested_url,
        &candidate_url,
        hint.title,
        excerpt,
    ) {
        return false;
    }

    pending.successful_reads.len() > before
}

pub(crate) fn append_pending_web_success_from_bundle(
    pending: &mut PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    fallback_url: &str,
) {
    let blocked_urls = bundle_human_challenge_urls(bundle, fallback_url);
    if !blocked_urls.is_empty() {
        for url in blocked_urls {
            mark_pending_web_blocked(pending, &url);
        }
        return;
    }

    let query_contract = synthesis_query_contract(pending);
    let headline_collection_mode = retrieval_contract_is_generic_headline_collection(
        pending.retrieval_contract.as_ref(),
        &query_contract,
    );
    if headline_collection_mode {
        let fallback_trimmed = fallback_url.trim();
        let mut appended = false;

        for doc in bundle.documents.iter().take(8) {
            let title = doc
                .title
                .clone()
                .or_else(|| {
                    bundle
                        .sources
                        .iter()
                        .find(|source| source.source_id == doc.source_id)
                        .and_then(|source| source.title.clone())
                })
                .filter(|value| !value.trim().is_empty());
            let excerpt = prioritized_success_excerpt_for_query(
                pending,
                doc.url.as_str(),
                title.as_deref().unwrap_or_default(),
                &doc.content_text,
                WEB_PIPELINE_EXCERPT_CHARS,
            );
            if try_append_headline_bundle_success(
                pending,
                fallback_trimmed,
                doc.url.as_str(),
                title,
                excerpt,
            ) {
                appended = true;
                break;
            }
        }

        if !appended {
            for source in bundle.sources.iter().take(8) {
                let excerpt = prioritized_success_excerpt_for_query(
                    pending,
                    source.url.as_str(),
                    source.title.as_deref().unwrap_or_default(),
                    source.snippet.as_deref().unwrap_or_default(),
                    180,
                );
                if try_append_headline_bundle_success(
                    pending,
                    fallback_trimmed,
                    source.url.as_str(),
                    source.title.clone(),
                    excerpt,
                ) {
                    appended = true;
                    break;
                }
            }
        }

        if !appended && !fallback_trimmed.is_empty() {
            append_pending_web_success_fallback(pending, fallback_trimmed, None);
        }
        return;
    }

    if let Some(doc) = bundle.documents.first() {
        let title = doc
            .title
            .clone()
            .or_else(|| {
                bundle
                    .sources
                    .iter()
                    .find(|source| source.source_id == doc.source_id)
                    .and_then(|source| source.title.clone())
            })
            .filter(|value| !value.trim().is_empty());
        let quote_excerpt = prioritized_document_quote_excerpt_for_query(
            pending,
            doc,
            title.as_deref().unwrap_or_default(),
            WEB_PIPELINE_EXCERPT_CHARS,
        );
        let doc_excerpt = prioritized_success_excerpt_for_query(
            pending,
            doc.url.as_str(),
            title.as_deref().unwrap_or_default(),
            &doc.content_text,
            WEB_PIPELINE_EXCERPT_CHARS,
        );
        let supporting_excerpt =
            supporting_bundle_success_excerpt(pending, bundle, Some(&doc.source_id), &doc.url);
        let excerpt = prefer_excerpt_for_query(&query_contract, quote_excerpt, doc_excerpt);
        let excerpt = prefer_excerpt_for_query(&query_contract, excerpt, supporting_excerpt);
        let before = pending.successful_reads.len();
        push_pending_web_success(pending, &doc.url, title.clone(), excerpt.clone());
        if pending.successful_reads.len() > before {
            merge_bundle_source_surface_into_success(pending, &query_contract, bundle, doc);
            merge_bundle_source_candidates_into_pending(
                pending,
                &query_contract,
                bundle,
                Some(&doc.source_id),
            );
            return;
        }
        let fallback_trimmed = fallback_url.trim();
        if !fallback_trimmed.is_empty() && !url_structurally_equivalent(&doc.url, fallback_trimmed)
        {
            push_pending_web_success(pending, fallback_trimmed, title, excerpt);
            if pending.successful_reads.len() > before {
                return;
            }
        } else if pending.successful_reads.len() > before {
            return;
        }
    }

    if let Some(source) = bundle.sources.first() {
        let excerpt = prioritized_success_excerpt_for_query(
            pending,
            source.url.as_str(),
            source.title.as_deref().unwrap_or_default(),
            source.snippet.as_deref().unwrap_or_default(),
            180,
        );
        let before = pending.successful_reads.len();
        push_pending_web_success(pending, &source.url, source.title.clone(), excerpt.clone());
        if pending.successful_reads.len() > before {
            merge_bundle_source_candidates_into_pending(
                pending,
                &query_contract,
                bundle,
                Some(&source.source_id),
            );
            return;
        }
        merge_bundle_source_candidates_into_pending(
            pending,
            &query_contract,
            bundle,
            Some(&source.source_id),
        );
        let fallback_trimmed = fallback_url.trim();
        if !fallback_trimmed.is_empty()
            && !url_structurally_equivalent(&source.url, fallback_trimmed)
        {
            push_pending_web_success(pending, fallback_trimmed, source.title.clone(), excerpt);
            if pending.successful_reads.len() > before {
                return;
            }
        } else if pending.successful_reads.len() > before {
            return;
        }
    }

    append_pending_web_success_fallback(pending, fallback_url, None);
}

fn document_human_challenge_probe_excerpt(content_text: &str) -> String {
    compact_excerpt(content_text, HUMAN_CHALLENGE_DOCUMENT_PROBE_CHARS)
}

fn bundle_human_challenge_urls(bundle: &WebEvidenceBundle, fallback_url: &str) -> Vec<String> {
    let fallback_trimmed = fallback_url.trim();
    let mut blocked = BTreeSet::new();

    for doc in &bundle.documents {
        let probe_excerpt = document_human_challenge_probe_excerpt(&doc.content_text);
        if source_has_human_challenge_signal(
            &doc.url,
            doc.title.as_deref().unwrap_or_default(),
            &probe_excerpt,
        ) {
            if !fallback_trimmed.is_empty() {
                blocked.insert(fallback_trimmed.to_string());
            }
            let trimmed = doc.url.trim();
            if !trimmed.is_empty() {
                blocked.insert(trimmed.to_string());
            }
        }
    }

    for source in &bundle.sources {
        if source_has_human_challenge_signal(
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            source.snippet.as_deref().unwrap_or_default(),
        ) {
            if !fallback_trimmed.is_empty() {
                blocked.insert(fallback_trimmed.to_string());
            }
            let trimmed = source.url.trim();
            if !trimmed.is_empty() {
                blocked.insert(trimmed.to_string());
            }
        }
    }

    blocked.into_iter().collect()
}

fn try_append_headline_bundle_success(
    pending: &mut PendingSearchCompletion,
    requested_url: &str,
    candidate_url: &str,
    title: Option<String>,
    excerpt: String,
) -> bool {
    let candidate_trimmed = candidate_url.trim();
    if candidate_trimmed.is_empty() {
        return false;
    }
    let requested_trimmed = requested_url.trim();
    if !requested_trimmed.is_empty()
        && !headline_bundle_url_matches_requested(candidate_trimmed, requested_trimmed)
    {
        return false;
    }

    let requested_allowed = headline_read_success_url_allowed(requested_trimmed);
    let candidate_allowed = headline_read_success_url_allowed(candidate_trimmed);
    let requested_is_google_news_wrapper =
        crate::agentic::web::is_google_news_article_wrapper_url(requested_trimmed);
    let recorded_url =
        if candidate_allowed && (requested_is_google_news_wrapper || !requested_allowed) {
            candidate_trimmed.to_string()
        } else if requested_allowed {
            requested_trimmed.to_string()
        } else if candidate_allowed {
            candidate_trimmed.to_string()
        } else {
            return false;
        };
    if headline_source_is_low_quality(
        &recorded_url,
        title.as_deref().unwrap_or_default(),
        &excerpt,
    ) {
        return false;
    }
    push_pending_web_success(pending, &recorded_url, title, excerpt);
    true
}

fn headline_bundle_url_matches_requested(candidate_url: &str, requested_url: &str) -> bool {
    if url_structurally_equivalent(candidate_url, requested_url) {
        return true;
    }
    if crate::agentic::web::is_google_news_article_wrapper_url(requested_url)
        && headline_read_success_url_allowed(candidate_url)
    {
        return true;
    }
    let Some(candidate_host) = normalized_source_host(candidate_url) else {
        return false;
    };
    let Some(requested_host) = normalized_source_host(requested_url) else {
        return false;
    };
    candidate_host == requested_host
}

fn normalized_source_host(url: &str) -> Option<String> {
    source_host(url).map(|host| {
        host.strip_prefix("www.")
            .unwrap_or(&host)
            .to_ascii_lowercase()
    })
}

fn headline_read_success_url_allowed(url: &str) -> bool {
    let trimmed = url.trim();
    !trimmed.is_empty() && projection_candidate_url_allowed(trimmed)
}

#[cfg(test)]
#[path = "success/tests.rs"]
mod tests;
