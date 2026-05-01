use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingGroundedCandidateSelection {
    NotApplicable,
    Applicable,
}

#[derive(Debug, Clone)]
struct RankedGroundedPendingCandidate {
    idx: usize,
    url: String,
    domain_key: String,
    grounded_viable: bool,
    briefing_support_viable: bool,
    grounded_external_publication_artifact: bool,
    identifier_priority_viable: bool,
    canonical_publication_detail: bool,
    resolvable_payload: bool,
    blocked_domain_repeat: bool,
    document_authority_score: usize,
    identifier_signal: bool,
    low_priority: bool,
    reuses_authority_family: bool,
    required_identifier_label_count: usize,
    adds_missing_required_identifier_coverage: bool,
    official_status_host_hits: usize,
    primary_status_surface_hits: usize,
    compatibility: CandidateConstraintCompatibility,
    envelope_score: CandidateEvidenceScore,
    relevance_score: usize,
}

fn canonical_publication_detail_candidate(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
    document_authority_score: usize,
    identifier_signal: bool,
) -> bool {
    if document_authority_score == 0 {
        return false;
    }
    let trimmed = url.trim();
    if trimmed.is_empty() || !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
        return false;
    }
    let Ok(parsed) = ::url::Url::parse(trimmed) else {
        return false;
    };
    let host = parsed
        .host_str()
        .map(|value| value.trim_start_matches("www.").to_ascii_lowercase())
        .unwrap_or_default();
    let normalized_path = parsed.path().trim_matches('/').to_ascii_lowercase();
    let title_lower = title.trim().to_ascii_lowercase();
    let authority_publication_artifact = host == "nvlpubs.nist.gov"
        || (host.ends_with(".nist.gov") && normalized_path.ends_with(".pdf"))
        || (!normalized_path.is_empty()
            && normalized_path.starts_with("pubs/")
            && !normalized_path.starts_with("news")
            && !normalized_path.starts_with("news-events"));
    if authority_publication_artifact {
        return true;
    }
    if !identifier_signal {
        return false;
    }
    let observed_labels =
        source_briefing_standard_identifier_labels(query_contract, trimmed, title, excerpt);

    title_lower.contains("federal information processing standard")
        || (!observed_labels.is_empty() && title_lower.starts_with("fips "))
}

fn grounded_external_publication_artifact_candidate(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    url: &str,
) -> bool {
    if !query_prefers_document_briefing_layout(query_contract)
        || query_requests_comparison(query_contract)
        || !crate::agentic::runtime::service::step::signals::analyze_query_facets(query_contract)
            .grounded_external_required
        || !retrieval_contract
            .map(|contract| contract.currentness_required || contract.source_independence_min > 1)
            .unwrap_or(false)
    {
        return false;
    }

    Url::parse(url.trim())
        .ok()
        .map(|parsed| parsed.path().to_ascii_lowercase().ends_with(".pdf"))
        .unwrap_or(false)
}

pub(crate) fn pending_candidate_inventory(pending: &PendingSearchCompletion) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();

    for url in &pending.candidate_urls {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            ordered.push(trimmed.to_string());
        }
    }

    for hint in &pending.candidate_source_hints {
        let trimmed = hint.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            ordered.push(trimmed.to_string());
        }
    }

    ordered
}

fn observed_pending_domain_keys(pending: &PendingSearchCompletion) -> BTreeSet<String> {
    let mut observed_domains = BTreeSet::new();
    for url in pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
    {
        let trimmed = url.trim();
        if trimmed.is_empty() || is_search_hub_url(trimmed) {
            continue;
        }
        let domain_key = source_host(trimmed)
            .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
            .unwrap_or_else(|| trimmed.to_ascii_lowercase());
        observed_domains.insert(domain_key);
    }
    observed_domains
}

fn pending_url_already_observed(pending: &PendingSearchCompletion, url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return true;
    }

    pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .map(|existing| existing.trim())
        .filter(|existing| !existing.is_empty())
        .any(|existing| {
            existing.eq_ignore_ascii_case(trimmed) || url_structurally_equivalent(existing, trimmed)
        })
}

fn observed_source_surface_for_url<'a>(
    pending: &'a PendingSearchCompletion,
    url: &str,
) -> Option<(&'a str, &'a str)> {
    source_hint_for_url(&pending.successful_reads, url)
        .or_else(|| hint_for_url(pending, url))
        .map(|source| {
            (
                source.title.as_deref().unwrap_or_default(),
                source.excerpt.as_str(),
            )
        })
}

fn single_snapshot_current_observation_surface_signal(
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if contains_current_condition_metric_signal(&format!("{title} {excerpt}")) {
        return true;
    }
    if has_subject_currentness_payload(&format!("{title} {excerpt}")) {
        return true;
    }

    let trimmed = url.trim();
    if trimmed.is_empty() || !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
        return false;
    }

    let Ok(parsed) = ::url::Url::parse(trimmed) else {
        return false;
    };
    let path = parsed.path().to_ascii_lowercase();
    let combined = compact_whitespace(&format!("{title} {excerpt}")).to_ascii_lowercase();
    let metric_axis_signal = [
        "temperature",
        "humidity",
        "wind",
        "pressure",
        "visibility",
        "air quality",
        "price",
        "quote",
        "usd",
        "btc",
    ]
    .iter()
    .any(|marker| combined.contains(marker));
    let current_surface_signal = [
        "current weather",
        "current conditions",
        "current weather report",
        "right now",
        "as of ",
        "feels like",
        "current btc quote",
        "current quote",
        "live price",
    ]
    .iter()
    .any(|marker| combined.contains(marker));
    let forecast_heavy = [
        "10-day forecast",
        "12 day forecast",
        "long-range",
        "next 3 days",
        "next three days",
        "weekly forecast",
    ]
    .iter()
    .any(|marker| combined.contains(marker));
    let structural_current_surface = path.contains("/hourly")
        || path.contains("/current-weather")
        || path.contains("/weather/today")
        || path.contains("/price/");

    !forecast_heavy && metric_axis_signal && current_surface_signal && structural_current_surface
}

fn single_snapshot_observed_surface_qualifies_for_grounding(
    pending: &PendingSearchCompletion,
    projection: &QueryConstraintProjection,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let observed_text = format!("{title} {excerpt}");
    if single_snapshot_requires_current_metric_observation_contract(pending) {
        return single_snapshot_current_observation_surface_signal(url, title, excerpt)
            || contains_current_condition_metric_signal(&observed_text);
    }
    if single_snapshot_requires_subject_identity_contract(pending) {
        return first_subject_currentness_sentence(&observed_text).is_some();
    }

    let compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        url,
        title,
        excerpt,
    );
    compatibility_passes_projection(projection, &compatibility)
        || candidate_time_sensitive_resolvable_payload(url, title, excerpt)
}

fn observed_single_snapshot_nonqualifying_count(
    pending: &PendingSearchCompletion,
    projection: &QueryConstraintProjection,
) -> usize {
    pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .map(|url| url.trim())
        .filter(|url| !url.is_empty() && !is_search_hub_url(url))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|url| {
            let Some((title, excerpt)) = observed_source_surface_for_url(pending, url) else {
                return true;
            };
            !single_snapshot_observed_surface_qualifies_for_grounding(
                pending, projection, url, title, excerpt,
            )
        })
        .count()
}

fn next_pending_headline_article_candidate(
    pending: &PendingSearchCompletion,
    attempted: &BTreeSet<String>,
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
) -> Option<String> {
    if !retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract) {
        return None;
    }

    let required_story_floor =
        retrieval_contract_required_story_count(retrieval_contract, query_contract).max(1);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let (actionable_sources_observed, actionable_domains_observed) =
        headline_actionable_source_inventory(&pending.successful_reads);
    if actionable_sources_observed >= required_story_floor
        && actionable_domains_observed >= required_story_floor
    {
        return None;
    }

    let observed_domains = observed_pending_domain_keys(pending);
    let preferred_distinct_domain_floor = required_story_floor.max(min_sources_required);
    let prefer_new_domain = observed_domains.len() < preferred_distinct_domain_floor;
    let mut ranked_candidates = pending_candidate_inventory(pending)
        .iter()
        .enumerate()
        .filter_map(|(idx, candidate)| {
            let trimmed = candidate.trim();
            if trimmed.is_empty()
                || attempted.contains(trimmed)
                || pending_url_already_observed(pending, trimmed)
                || !projection_candidate_url_allowed(trimmed)
                || is_multi_item_listing_url(trimmed)
            {
                return None;
            }

            let hint = hint_for_url(pending, trimmed);
            let fallback_source = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: hint.and_then(|entry| entry.title.clone()),
                excerpt: hint.map(|entry| entry.excerpt.clone()).unwrap_or_default(),
            };
            let title = fallback_source.title.as_deref().unwrap_or_default();
            let excerpt = fallback_source.excerpt.as_str();
            let actionable = headline_source_is_actionable(&fallback_source);
            let low_quality = headline_source_is_low_quality(trimmed, title, excerpt);
            if low_quality && !actionable {
                return None;
            }

            let deep_article = looks_like_deep_article_url(trimmed);
            let title_specific = !title.trim().is_empty()
                && !is_low_signal_title(title)
                && headline_story_title_has_specificity(title)
                && !headline_title_is_multi_story_roundup_surface(title);
            let claim_signal = excerpt_has_claim_signal(title) || excerpt_has_claim_signal(excerpt);
            if !(actionable || deep_article || title_specific || claim_signal) {
                return None;
            }

            let domain_key = source_host(trimmed)
                .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                .unwrap_or_else(|| trimmed.to_ascii_lowercase());
            let adds_new_domain = !observed_domains.contains(&domain_key);

            Some((
                idx,
                trimmed.to_string(),
                actionable,
                prefer_new_domain && adds_new_domain,
                deep_article,
                title_specific,
                claim_signal,
            ))
        })
        .collect::<Vec<_>>();

    ranked_candidates.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| right.4.cmp(&left.4))
            .then_with(|| right.5.cmp(&left.5))
            .then_with(|| right.6.cmp(&left.6))
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });

    ranked_candidates
        .into_iter()
        .map(|(_, candidate, _, _, _, _, _)| candidate)
        .next()
}

fn next_pending_grounded_candidate(
    pending: &PendingSearchCompletion,
    attempted: &BTreeSet<String>,
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
) -> (PendingGroundedCandidateSelection, Option<String>) {
    let projection = build_query_constraint_projection(
        query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let time_sensitive = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || retrieval_contract
            .map(|contract| contract.currentness_required)
            .unwrap_or(false);
    if !projection.query_facets.grounded_external_required && !time_sensitive {
        return (PendingGroundedCandidateSelection::NotApplicable, None);
    }

    let reject_search_hub = projection.reject_search_hub_candidates();
    let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
    let has_constraint_objective = projection.has_constraint_objective();
    let document_briefing_layout = query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract);
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();
    let min_sources_required = pending.min_sources.max(1) as usize;
    let required_distinct_domains =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract);
    let briefing_identifier_observations = pending
        .successful_reads
        .iter()
        .filter_map(|source| {
            let trimmed = source.url.trim();
            let title = source.title.as_deref().unwrap_or_default();
            (!trimmed.is_empty()).then(|| BriefingIdentifierObservation {
                url: trimmed.to_string(),
                surface: format!("{} {} {}", source.url, title, source.excerpt),
                authoritative: source_has_document_authority(
                    query_contract,
                    trimmed,
                    title,
                    &source.excerpt,
                ),
            })
        })
        .collect::<Vec<_>>();
    let required_identifier_labels = infer_briefing_required_identifier_labels(
        query_contract,
        &briefing_identifier_observations,
    );
    let required_identifier_labels_for_surface = |url: &str, title: &str, excerpt: &str| {
        observed_briefing_standard_identifier_labels(
            query_contract,
            &format!("{url} {title} {excerpt}"),
        )
        .into_iter()
        .filter(|label| required_identifier_labels.contains(label))
        .collect::<BTreeSet<_>>()
    };
    let observed_required_identifier_labels = pending
        .successful_reads
        .iter()
        .flat_map(|source| {
            required_identifier_labels_for_surface(
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
            .into_iter()
        })
        .collect::<BTreeSet<_>>();
    let missing_required_identifier_labels = required_identifier_labels
        .difference(&observed_required_identifier_labels)
        .cloned()
        .collect::<BTreeSet<_>>();
    let identifier_priority_required =
        !required_identifier_labels.is_empty() && !missing_required_identifier_labels.is_empty();
    let observed_authority_families = pending
        .successful_reads
        .iter()
        .filter_map(|source| {
            let trimmed = source.url.trim();
            let title = source.title.as_deref().unwrap_or_default();
            source_has_document_authority(query_contract, trimmed, title, &source.excerpt).then(
                || {
                    source_document_authority_family_key(
                        query_contract,
                        trimmed,
                        title,
                        &source.excerpt,
                    )
                    .unwrap_or_else(|| trimmed.to_ascii_lowercase())
                },
            )
        })
        .collect::<BTreeSet<_>>();
    let blocked_domains = pending
        .blocked_urls
        .iter()
        .filter_map(|url| {
            let trimmed = url.trim();
            if trimmed.is_empty() || is_search_hub_url(trimmed) {
                return None;
            }
            source_host(trimmed)
                .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                .or_else(|| Some(trimmed.to_ascii_lowercase()))
        })
        .collect::<BTreeSet<_>>();

    let mut ranked_candidates = pending_candidate_inventory(pending)
        .iter()
        .enumerate()
        .filter_map(|(idx, candidate)| {
            let trimmed = candidate.trim();
            if trimmed.is_empty()
                || attempted.contains(trimmed)
                || pending_url_already_observed(pending, trimmed)
                || !is_citable_web_url(trimmed)
            {
                return None;
            }
            if reject_search_hub && is_search_hub_url(trimmed) {
                return None;
            }

            let hint = hint_for_url(pending, trimmed);
            let title = hint
                .and_then(|entry| entry.title.as_deref())
                .unwrap_or_default();
            let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                title,
                excerpt,
            );
            let compatibility_passes = compatibility_passes_projection(&projection, &compatibility);
            let envelope_score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                excerpt,
            );
            let has_signal = !title.trim().is_empty() || !excerpt.trim().is_empty();
            let resolves_constraint = if has_constraint_objective {
                envelope_score_resolves_constraint(envelope_constraints, &envelope_score)
            } else {
                has_signal
            };
            let signals = analyze_source_record_signals(trimmed, title, excerpt);
            let low_priority = signals.low_priority_hits > 0 || signals.low_priority_dominates();
            let document_authority_score =
                source_document_authority_score(query_contract, trimmed, title, excerpt);
            let identifier_labels =
                source_briefing_standard_identifier_labels(query_contract, trimmed, title, excerpt);
            let required_identifier_hits =
                required_identifier_labels_for_surface(trimmed, title, excerpt);
            let required_identifier_label_count = identifier_labels
                .iter()
                .filter(|label| required_identifier_hits.contains(*label))
                .count();
            let adds_missing_required_identifier_coverage = required_identifier_hits
                .iter()
                .any(|label| missing_required_identifier_labels.contains(label));
            let identifier_signal = !identifier_labels.is_empty();
            let authority_family_key =
                source_document_authority_family_key(query_contract, trimmed, title, excerpt);
            let identifier_priority_viable = identifier_priority_required
                && (adds_missing_required_identifier_coverage
                    || (document_authority_score > 0 && identifier_signal));
            let grounded_external_publication_artifact =
                grounded_external_publication_artifact_candidate(
                    retrieval_contract,
                    query_contract,
                    trimmed,
                );
            let temporal_recency_score = source_temporal_recency_score(trimmed, title, excerpt);
            let source_tokens = source_anchor_tokens(trimmed, title, excerpt);
            let query_native_overlap = projection
                .query_native_tokens
                .intersection(&source_tokens)
                .count();
            let strong_subject_overlap = query_native_overlap >= 3
                || (query_native_overlap >= 2 && temporal_recency_score > 0);
            let query_grounding_signal = excerpt_has_query_grounding_signal_with_contract(
                retrieval_contract,
                query_contract,
                min_sources_required,
                trimmed,
                title,
                excerpt,
            );
            let authoritative_current_briefing_followup =
                query_prefers_document_briefing_layout(query_contract)
                    && retrieval_contract
                        .map(|contract| contract.currentness_required)
                        .unwrap_or(false)
                    && document_authority_score > 0
                    && temporal_recency_score > 0
                    && (query_grounding_signal || strong_subject_overlap);
            let briefing_support_viable = !low_priority
                && (!document_briefing_layout
                    || document_authority_score > 0
                    || identifier_signal
                    || grounded_external_publication_artifact
                    || query_grounding_signal
                    || strong_subject_overlap);
            let grounded_viable = ((!enforce_grounded_compatibility || compatibility_passes)
                && resolves_constraint)
                || authoritative_current_briefing_followup;
            let canonical_publication_detail = canonical_publication_detail_candidate(
                query_contract,
                trimmed,
                title,
                excerpt,
                document_authority_score,
                identifier_signal,
            );

            Some(RankedGroundedPendingCandidate {
                idx,
                url: trimmed.to_string(),
                domain_key: source_host(trimmed)
                    .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                    .unwrap_or_else(|| trimmed.to_ascii_lowercase()),
                grounded_viable: grounded_viable && briefing_support_viable,
                briefing_support_viable,
                grounded_external_publication_artifact,
                identifier_priority_viable,
                canonical_publication_detail,
                resolvable_payload: candidate_time_sensitive_resolvable_payload(
                    trimmed, title, excerpt,
                ),
                blocked_domain_repeat: blocked_domains.contains(
                    &source_host(trimmed)
                        .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                        .unwrap_or_else(|| trimmed.to_ascii_lowercase()),
                ),
                document_authority_score,
                identifier_signal,
                low_priority,
                reuses_authority_family: authority_family_key
                    .as_ref()
                    .is_some_and(|family| observed_authority_families.contains(family)),
                required_identifier_label_count,
                adds_missing_required_identifier_coverage,
                official_status_host_hits: signals.official_status_host_hits,
                primary_status_surface_hits: signals.primary_status_surface_hits,
                compatibility,
                envelope_score,
                relevance_score: signals.relevance_score(false),
            })
        })
        .collect::<Vec<_>>();

    if ranked_candidates.is_empty() {
        return (PendingGroundedCandidateSelection::Applicable, None);
    }

    ranked_candidates.sort_by(|left, right| {
        right
            .identifier_priority_viable
            .cmp(&left.identifier_priority_viable)
            .then_with(|| {
                right
                    .briefing_support_viable
                    .cmp(&left.briefing_support_viable)
            })
            .then_with(|| {
                right
                    .grounded_external_publication_artifact
                    .cmp(&left.grounded_external_publication_artifact)
            })
            .then_with(|| left.low_priority.cmp(&right.low_priority))
            .then_with(|| left.blocked_domain_repeat.cmp(&right.blocked_domain_repeat))
            .then_with(|| {
                right
                    .adds_missing_required_identifier_coverage
                    .cmp(&left.adds_missing_required_identifier_coverage)
            })
            .then_with(|| {
                right
                    .required_identifier_label_count
                    .cmp(&left.required_identifier_label_count)
            })
            .then_with(|| {
                right
                    .canonical_publication_detail
                    .cmp(&left.canonical_publication_detail)
            })
            .then_with(|| {
                (right.document_authority_score > 0).cmp(&(left.document_authority_score > 0))
            })
            .then_with(|| {
                right
                    .document_authority_score
                    .cmp(&left.document_authority_score)
            })
            .then_with(|| right.identifier_signal.cmp(&left.identifier_signal))
            .then_with(|| right.grounded_viable.cmp(&left.grounded_viable))
            .then_with(|| right.resolvable_payload.cmp(&left.resolvable_payload))
            .then_with(|| {
                (right.official_status_host_hits > 0).cmp(&(left.official_status_host_hits > 0))
            })
            .then_with(|| {
                right
                    .official_status_host_hits
                    .cmp(&left.official_status_host_hits)
            })
            .then_with(|| {
                (right.primary_status_surface_hits > 0).cmp(&(left.primary_status_surface_hits > 0))
            })
            .then_with(|| {
                right
                    .primary_status_surface_hits
                    .cmp(&left.primary_status_surface_hits)
            })
            .then_with(|| {
                right
                    .compatibility
                    .compatibility_score
                    .cmp(&left.compatibility.compatibility_score)
            })
            .then_with(|| {
                compare_candidate_evidence_scores_desc(&left.envelope_score, &right.envelope_score)
            })
            .then_with(|| right.relevance_score.cmp(&left.relevance_score))
            .then_with(|| left.idx.cmp(&right.idx))
            .then_with(|| left.url.cmp(&right.url))
    });

    let has_identifier_priority_viable = ranked_candidates
        .iter()
        .any(|entry| entry.identifier_priority_viable);
    let candidate_is_viable = |candidate: &RankedGroundedPendingCandidate| {
        if identifier_priority_required && has_identifier_priority_viable {
            candidate.identifier_priority_viable
        } else {
            candidate.grounded_viable
        }
    };

    let observed_domains = observed_pending_domain_keys(pending);
    let best_viable_unseen_domain = ranked_candidates.iter().find(|candidate| {
        candidate_is_viable(candidate)
            && observed_domains.len() < required_distinct_domains
            && !observed_domains.contains(&candidate.domain_key)
    });
    if let Some(candidate) = best_viable_unseen_domain {
        return (
            PendingGroundedCandidateSelection::Applicable,
            Some(candidate.url.clone()),
        );
    }

    let best_bounded_unseen_domain_probe = ranked_candidates.iter().find(|candidate| {
        observed_domains.len() < required_distinct_domains
            && !observed_domains.contains(&candidate.domain_key)
            && !candidate.blocked_domain_repeat
            && candidate.briefing_support_viable
            && (candidate.grounded_external_publication_artifact
                || candidate.document_authority_score > 0
                || candidate.identifier_signal
                || candidate.resolvable_payload
                || candidate.compatibility.compatibility_score > 0
                || candidate.relevance_score > 0)
    });
    if let Some(candidate) = best_bounded_unseen_domain_probe {
        return (
            PendingGroundedCandidateSelection::Applicable,
            Some(candidate.url.clone()),
        );
    }

    let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
    if !identifier_priority_required && source_floor_unmet {
        if let Some(candidate) = ranked_candidates.iter().find(|candidate| {
            !candidate.reuses_authority_family
                && candidate.briefing_support_viable
                && !candidate.canonical_publication_detail
        }) {
            return (
                PendingGroundedCandidateSelection::Applicable,
                Some(candidate.url.clone()),
            );
        }
    }

    if let Some(candidate) = ranked_candidates
        .iter()
        .find(|candidate| candidate_is_viable(candidate))
    {
        return (
            PendingGroundedCandidateSelection::Applicable,
            Some(candidate.url.clone()),
        );
    }

    let exploratory_allowed = pending.successful_reads.len() < min_sources_required;
    if exploratory_allowed {
        return (
            PendingGroundedCandidateSelection::Applicable,
            ranked_candidates
                .iter()
                .find(|candidate| candidate.briefing_support_viable)
                .or_else(|| ranked_candidates.first())
                .map(|candidate| candidate.url.clone()),
        );
    }

    (PendingGroundedCandidateSelection::Applicable, None)
}

pub(crate) fn next_pending_web_candidate(pending: &PendingSearchCompletion) -> Option<String> {
    let mut attempted = BTreeSet::new();
    for url in &pending.attempted_urls {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            attempted.insert(trimmed.to_string());
        }
    }
    for url in &pending.blocked_urls {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            attempted.insert(trimmed.to_string());
        }
    }

    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let headline_lookup_mode =
        retrieval_or_query_is_generic_headline_collection(retrieval_contract, &query_contract);
    if headline_lookup_mode {
        let observed_domains = observed_pending_domain_keys(pending);
        let preferred_distinct_domain_floor =
            retrieval_contract_required_story_count(retrieval_contract, &query_contract)
                .max(pending.min_sources.max(1) as usize);
        if observed_domains.len() < preferred_distinct_domain_floor {
            let has_new_domain_candidate =
                pending_candidate_inventory(pending)
                    .iter()
                    .any(|candidate| {
                        let trimmed = candidate.trim();
                        if trimmed.is_empty()
                            || attempted.contains(trimmed)
                            || pending_url_already_observed(pending, trimmed)
                            || is_search_hub_url(trimmed)
                        {
                            return false;
                        }
                        let domain_key = source_host(trimmed)
                            .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                            .unwrap_or_else(|| trimmed.to_ascii_lowercase());
                        !observed_domains.contains(&domain_key)
                    });
            if !has_new_domain_candidate {
                return None;
            }
        }
    }
    let prefer_host_diversity =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract);
    if prefer_host_diversity {
        let projection =
            build_query_constraint_projection(&query_contract, 1, &pending.candidate_source_hints);
        let envelope_constraints = &projection.constraints;
        let grounded_anchor_constrained = projection.strict_grounded_compatibility();
        let envelope_policy = ResolutionPolicy::default();
        let candidate_inventory = pending_candidate_inventory(pending);
        let mut ranked_candidates = candidate_inventory
            .iter()
            .enumerate()
            .filter_map(|(idx, candidate)| {
                let trimmed = candidate.trim();
                if trimmed.is_empty()
                    || attempted.contains(trimmed)
                    || pending_url_already_observed(pending, trimmed)
                {
                    return None;
                }
                let hint = hint_for_url(pending, trimmed);
                let title = hint
                    .and_then(|entry| entry.title.as_deref())
                    .unwrap_or_default();
                let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
                let envelope_score = single_snapshot_candidate_envelope_score(
                    envelope_constraints,
                    envelope_policy,
                    trimmed,
                    title,
                    excerpt,
                );
                let compatibility = candidate_constraint_compatibility(
                    envelope_constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    trimmed,
                    title,
                    excerpt,
                );
                let resolvable_payload =
                    candidate_time_sensitive_resolvable_payload(trimmed, title, excerpt);
                let source_relevance_score =
                    analyze_source_record_signals(trimmed, title, excerpt).relevance_score(false);
                Some((
                    idx,
                    trimmed.to_string(),
                    envelope_score,
                    compatibility,
                    resolvable_payload,
                    single_snapshot_current_observation_surface_signal(trimmed, title, excerpt),
                    source_relevance_score,
                ))
            })
            .collect::<Vec<_>>();
        ranked_candidates.sort_by(|left, right| {
            right
                .5
                .cmp(&left.5)
                .then_with(|| right.4.cmp(&left.4))
                .then_with(|| {
                    let right_passes = compatibility_passes_projection(&projection, &right.3);
                    let left_passes = compatibility_passes_projection(&projection, &left.3);
                    right_passes.cmp(&left_passes)
                })
                .then_with(|| right.3.compatibility_score.cmp(&left.3.compatibility_score))
                .then_with(|| compare_candidate_evidence_scores_desc(&left.2, &right.2))
                .then_with(|| right.6.cmp(&left.6))
                .then_with(|| left.0.cmp(&right.0))
                .then_with(|| left.1.cmp(&right.1))
        });
        let has_compatible_candidates =
            ranked_candidates
                .iter()
                .any(|(_, _, _, compatibility, _, _, _)| {
                    compatibility_passes_projection(&projection, compatibility)
                });
        let requires_semantic_locality_alignment = projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            && projection.locality_scope.is_some()
            && projection
                .query_native_tokens
                .iter()
                .any(|token| !projection.locality_tokens.contains(token));
        let exploratory_attempts_without_compatibility =
            observed_single_snapshot_nonqualifying_count(pending, &projection);
        let exploratory_read_cap = SINGLE_SNAPSHOT_MAX_EXPLORATORY_READS_WITHOUT_COMPATIBILITY
            .saturating_add(
                single_snapshot_additional_probe_attempt_count(pending)
                    .min(SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES),
            );
        let can_issue_exploratory_read =
            exploratory_attempts_without_compatibility < exploratory_read_cap;
        if requires_semantic_locality_alignment
            && !has_compatible_candidates
            && !can_issue_exploratory_read
        {
            return None;
        }

        let mut attempted_hosts = BTreeSet::new();
        for url in pending
            .attempted_urls
            .iter()
            .chain(pending.blocked_urls.iter())
            .chain(pending.successful_reads.iter().map(|source| &source.url))
        {
            let trimmed = url.trim();
            if trimmed.is_empty() || is_search_hub_url(trimmed) {
                continue;
            }
            if let Some(host) = source_host(trimmed) {
                attempted_hosts.insert(host);
            }
        }

        for (_, candidate, _, compatibility, _, _, _) in &ranked_candidates {
            if has_compatible_candidates
                && !compatibility_passes_projection(&projection, compatibility)
            {
                continue;
            }
            if let Some(host) = source_host(candidate) {
                if attempted_hosts.contains(&host) {
                    continue;
                }
            }
            return Some(candidate.clone());
        }

        if has_compatible_candidates {
            if let Some((_, candidate, _, _, _, _, _)) =
                ranked_candidates
                    .iter()
                    .find(|(_, _, _, compatibility, _, _, _)| {
                        compatibility_passes_projection(&projection, compatibility)
                    })
            {
                return Some(candidate.clone());
            }
        }

        if grounded_anchor_constrained {
            if !has_compatible_candidates && can_issue_exploratory_read {
                if let Some((_, candidate, _, _, _, _, _)) = ranked_candidates.first() {
                    return Some(candidate.clone());
                }
            }
            return None;
        }

        if let Some((_, candidate, _, _, _, _, _)) = ranked_candidates.first() {
            return Some(candidate.clone());
        }
    }

    match next_pending_grounded_candidate(pending, &attempted, &query_contract, retrieval_contract)
    {
        (_, Some(candidate)) => return Some(candidate),
        (PendingGroundedCandidateSelection::Applicable, None) => {
            if headline_lookup_mode {
                if let Some(candidate) = next_pending_headline_article_candidate(
                    pending,
                    &attempted,
                    &query_contract,
                    retrieval_contract,
                ) {
                    return Some(candidate);
                }
            }
            return None;
        }
        (PendingGroundedCandidateSelection::NotApplicable, None) => {}
    }

    let required_distinct_domains =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, &query_contract);
    let candidate_inventory = pending_candidate_inventory(pending);
    if headline_lookup_mode {
        let observed_domains = observed_pending_domain_keys(pending);
        let preferred_distinct_domain_floor =
            retrieval_contract_required_story_count(retrieval_contract, &query_contract)
                .max(pending.min_sources.max(1) as usize);
        if observed_domains.len() < preferred_distinct_domain_floor {
            let has_new_domain_candidate = candidate_inventory.iter().any(|candidate| {
                let trimmed = candidate.trim();
                if trimmed.is_empty()
                    || attempted.contains(trimmed)
                    || pending_url_already_observed(pending, trimmed)
                    || is_search_hub_url(trimmed)
                {
                    return false;
                }
                let domain_key = source_host(trimmed)
                    .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                    .unwrap_or_else(|| trimmed.to_ascii_lowercase());
                !observed_domains.contains(&domain_key)
            });
            if !has_new_domain_candidate {
                return None;
            }
        }
    }
    if required_distinct_domains > 1 {
        let observed_domains = observed_pending_domain_keys(pending);

        for candidate in &candidate_inventory {
            let trimmed = candidate.trim();
            if trimmed.is_empty()
                || attempted.contains(trimmed)
                || pending_url_already_observed(pending, trimmed)
                || is_search_hub_url(trimmed)
            {
                continue;
            }
            let domain_key = source_host(trimmed)
                .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                .unwrap_or_else(|| trimmed.to_ascii_lowercase());
            if observed_domains.len() < required_distinct_domains
                && observed_domains.contains(&domain_key)
            {
                continue;
            }
            return Some(trimmed.to_string());
        }

        if observed_domains.len() < required_distinct_domains {
            return None;
        }
    }

    for candidate in &candidate_inventory {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        if attempted.contains(trimmed) || pending_url_already_observed(pending, trimmed) {
            continue;
        }
        return Some(trimmed.to_string());
    }

    None
}

pub(crate) fn mark_pending_web_attempted(pending: &mut PendingSearchCompletion, url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .attempted_urls
        .iter()
        .any(|existing| existing.trim() == trimmed)
    {
        return;
    }
    pending.attempted_urls.push(trimmed.to_string());
}

pub(crate) fn mark_pending_web_blocked(pending: &mut PendingSearchCompletion, url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .blocked_urls
        .iter()
        .any(|existing| existing.trim() == trimmed)
    {
        return;
    }
    pending.blocked_urls.push(trimmed.to_string());
}

pub(crate) fn normalize_optional_title(value: Option<String>) -> Option<String> {
    value.and_then(|title| {
        let trimmed = title.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

pub(crate) fn prefer_title(existing: Option<String>, incoming: Option<String>) -> Option<String> {
    let existing = normalize_optional_title(existing);
    let incoming = normalize_optional_title(incoming);
    match (existing, incoming) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => {
            let left_low = is_low_signal_title(&left);
            let right_low = is_low_signal_title(&right);
            if left_low != right_low {
                return if right_low { Some(left) } else { Some(right) };
            }
            if right.chars().count() > left.chars().count() {
                Some(right)
            } else {
                Some(left)
            }
        }
    }
}

pub(crate) fn prefer_excerpt(existing: String, incoming: String) -> String {
    prefer_excerpt_for_query("", existing, incoming)
}

pub(crate) fn prefer_excerpt_for_query(
    query_contract: &str,
    existing: String,
    incoming: String,
) -> String {
    let left = existing.trim().to_string();
    let right = incoming.trim().to_string();
    if left.is_empty() {
        return right;
    }
    if right.is_empty() {
        return left;
    }

    let left_groups = observed_briefing_standard_identifier_groups(query_contract, &left);
    let right_groups = observed_briefing_standard_identifier_groups(query_contract, &right);
    let left_required = left_groups.iter().filter(|group| group.required).count();
    let right_required = right_groups.iter().filter(|group| group.required).count();
    if right_required != left_required {
        return if right_required > left_required {
            right
        } else {
            left
        };
    }
    if right_groups.len() != left_groups.len() {
        return if right_groups.len() > left_groups.len() {
            right
        } else {
            left
        };
    }

    let left_signals = analyze_source_record_signals("", "", &left);
    let right_signals = analyze_source_record_signals("", "", &right);
    let left_low_priority =
        left_signals.low_priority_hits > 0 || left_signals.low_priority_dominates();
    let right_low_priority =
        right_signals.low_priority_hits > 0 || right_signals.low_priority_dominates();
    if right_low_priority != left_low_priority {
        return if right_low_priority { left } else { right };
    }

    let left_structured_noise = looks_like_structured_metadata_noise(&left);
    let right_structured_noise = looks_like_structured_metadata_noise(&right);
    if right_structured_noise != left_structured_noise {
        return if right_structured_noise { left } else { right };
    }

    let left_current = contains_current_condition_metric_signal(&left);
    let right_current = contains_current_condition_metric_signal(&right);
    if right_current != left_current {
        return if right_current { right } else { left };
    }

    let left_metric = contains_metric_signal(&left);
    let right_metric = contains_metric_signal(&right);
    if right_metric != left_metric {
        return if right_metric { right } else { left };
    }

    let left_actionability = excerpt_actionability_score(&left);
    let right_actionability = excerpt_actionability_score(&right);
    if right_actionability != left_actionability {
        return if right_actionability > left_actionability {
            right
        } else {
            left
        };
    }

    let left_low = is_low_signal_excerpt(&left);
    let right_low = is_low_signal_excerpt(&right);
    if right_low != left_low {
        return if right_low { left } else { right };
    }

    if right.chars().count() > left.chars().count() {
        right
    } else {
        left
    }
}

pub(crate) fn merge_pending_source_record(
    existing: PendingSearchReadSummary,
    incoming: PendingSearchReadSummary,
) -> PendingSearchReadSummary {
    merge_pending_source_record_for_query("", existing, incoming)
}

pub(crate) fn merge_pending_source_record_for_query(
    query_contract: &str,
    existing: PendingSearchReadSummary,
    incoming: PendingSearchReadSummary,
) -> PendingSearchReadSummary {
    let url = if existing.url.trim().is_empty() {
        incoming.url.trim().to_string()
    } else {
        existing.url.trim().to_string()
    };
    PendingSearchReadSummary {
        url,
        title: prefer_title(existing.title, incoming.title),
        excerpt: prefer_excerpt_for_query(query_contract, existing.excerpt, incoming.excerpt),
    }
}

pub(crate) fn merge_url_sequence(existing: Vec<String>, incoming: Vec<String>) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();
    for url in existing.into_iter().chain(incoming.into_iter()) {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(trimmed.to_string());
    }
    merged
}

pub(crate) fn merge_pending_search_completion(
    existing: PendingSearchCompletion,
    incoming: PendingSearchCompletion,
) -> PendingSearchCompletion {
    let existing_contract = existing.query_contract.trim();
    let incoming_contract = incoming.query_contract.trim();
    if !existing_contract.is_empty()
        && !incoming_contract.is_empty()
        && !existing_contract.eq_ignore_ascii_case(incoming_contract)
    {
        return incoming;
    }

    let existing_query = existing.query.trim();
    let incoming_query = incoming.query.trim();
    if existing_contract.is_empty()
        && incoming_contract.is_empty()
        && !existing_query.is_empty()
        && !incoming_query.is_empty()
        && !existing_query.eq_ignore_ascii_case(incoming_query)
    {
        return incoming;
    }

    let successful_reads = {
        let merge_query_contract = if existing_contract.is_empty() {
            incoming_contract
        } else {
            existing_contract
        };
        let mut merged_by_url: BTreeMap<String, PendingSearchReadSummary> = BTreeMap::new();
        for source in existing
            .successful_reads
            .into_iter()
            .chain(incoming.successful_reads.into_iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: normalize_optional_title(source.title),
                excerpt: source.excerpt.trim().to_string(),
            };
            if let Some(current) = merged_by_url.get(trimmed) {
                let merged = merge_pending_source_record_for_query(
                    merge_query_contract,
                    current.clone(),
                    normalized,
                );
                merged_by_url.insert(trimmed.to_string(), merged);
            } else {
                merged_by_url.insert(trimmed.to_string(), normalized);
            }
        }
        merged_by_url.into_values().collect::<Vec<_>>()
    };

    let attempted_urls = merge_url_sequence(existing.attempted_urls, incoming.attempted_urls);
    let blocked_urls = merge_url_sequence(existing.blocked_urls, incoming.blocked_urls);

    let mut attempted_or_resolved = BTreeSet::new();
    for url in attempted_urls.iter().chain(blocked_urls.iter()) {
        attempted_or_resolved.insert(url.trim().to_string());
    }
    for source in &successful_reads {
        let trimmed = source.url.trim();
        if !trimmed.is_empty() {
            attempted_or_resolved.insert(trimmed.to_string());
        }
    }

    let candidate_urls = merge_url_sequence(existing.candidate_urls, incoming.candidate_urls)
        .into_iter()
        .filter(|url| !attempted_or_resolved.contains(url))
        .collect::<Vec<_>>();

    let candidate_source_hints = {
        let merge_query_contract = if existing_contract.is_empty() {
            incoming_contract
        } else {
            existing_contract
        };
        let mut merged_by_url: BTreeMap<String, PendingSearchReadSummary> = BTreeMap::new();
        for source in existing
            .candidate_source_hints
            .into_iter()
            .chain(incoming.candidate_source_hints.into_iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: normalize_optional_title(source.title),
                excerpt: source.excerpt.trim().to_string(),
            };
            if let Some(current) = merged_by_url.get(trimmed) {
                let merged = merge_pending_source_record_for_query(
                    merge_query_contract,
                    current.clone(),
                    normalized,
                );
                merged_by_url.insert(trimmed.to_string(), merged);
            } else {
                merged_by_url.insert(trimmed.to_string(), normalized);
            }
        }

        let mut ordered = Vec::new();
        let mut seen = BTreeSet::new();
        for url in &candidate_urls {
            if let Some(source) = merged_by_url.get(url) {
                ordered.push(source.clone());
                seen.insert(url.clone());
            }
        }
        for (url, source) in merged_by_url {
            if seen.insert(url) {
                ordered.push(source);
            }
        }
        ordered
    };

    PendingSearchCompletion {
        query: if incoming_query.is_empty() {
            existing.query
        } else if existing_query.is_empty() || !existing_query.eq_ignore_ascii_case(incoming_query)
        {
            incoming.query
        } else {
            existing.query
        },
        query_contract: if existing_contract.is_empty() {
            incoming.query_contract
        } else {
            existing.query_contract
        },
        retrieval_contract: existing.retrieval_contract.or(incoming.retrieval_contract),
        url: if existing.url.trim().is_empty() {
            incoming.url
        } else {
            existing.url
        },
        started_step: if existing.started_at_ms > 0 || existing.started_step > 0 {
            existing.started_step
        } else {
            incoming.started_step
        },
        started_at_ms: if existing.started_at_ms > 0 {
            existing.started_at_ms
        } else {
            incoming.started_at_ms
        },
        deadline_ms: if existing.deadline_ms > 0 {
            existing.deadline_ms
        } else {
            incoming.deadline_ms
        },
        candidate_urls,
        candidate_source_hints,
        attempted_urls,
        blocked_urls,
        successful_reads,
        min_sources: existing.min_sources.max(incoming.min_sources),
    }
}

#[cfg(test)]
#[path = "pending/tests.rs"]
mod tests;
