use super::*;

pub(crate) fn title_tokens(input: &str) -> BTreeSet<String> {
    input
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter(|token| token.len() > 2)
        .map(|token| token.to_string())
        .collect()
}

pub(crate) fn titles_similar(a: &str, b: &str) -> bool {
    let a_trim = a.trim();
    let b_trim = b.trim();
    if a_trim.is_empty() || b_trim.is_empty() {
        return false;
    }
    if a_trim.eq_ignore_ascii_case(b_trim) {
        return true;
    }
    let a_tokens = title_tokens(a_trim);
    let b_tokens = title_tokens(b_trim);
    if a_tokens.is_empty() || b_tokens.is_empty() {
        return false;
    }
    let overlap = a_tokens.intersection(&b_tokens).count();
    let largest = a_tokens.len().max(b_tokens.len());
    overlap * 2 >= largest
}

pub(crate) fn canonical_source_title(source: &PendingSearchReadSummary) -> String {
    let title = source.title.as_deref().map(str::trim).unwrap_or_default();
    if !title.is_empty() && !is_low_signal_title(title) {
        return title.chars().take(WEB_PIPELINE_STORY_TITLE_CHARS).collect();
    }
    if let Some(from_excerpt) = excerpt_headline(source.excerpt.trim()) {
        return from_excerpt
            .chars()
            .take(WEB_PIPELINE_STORY_TITLE_CHARS)
            .collect();
    }
    format!("Update from {}", source.url)
}

fn successful_source_url_set(pending: &PendingSearchCompletion) -> BTreeSet<String> {
    pending
        .successful_reads
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect()
}

fn blocked_unverified_url_set(
    pending: &PendingSearchCompletion,
    successful_urls: &BTreeSet<String>,
) -> BTreeSet<String> {
    pending
        .blocked_urls
        .iter()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty() && !successful_urls.contains(url))
        .collect()
}

fn is_blocked_unverified_url(url: &str, blocked_unverified_urls: &BTreeSet<String>) -> bool {
    blocked_unverified_urls.contains(url.trim())
}

pub(crate) fn merged_story_sources(
    pending: &PendingSearchCompletion,
) -> Vec<PendingSearchReadSummary> {
    let query_contract = synthesis_query_contract(pending);
    let headline_lookup_mode = query_is_generic_headline_collection(&query_contract);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let enforce_grounded_compatibility =
        projection.enforce_grounded_compatibility() && !headline_lookup_mode;
    let reject_search_hub = projection.reject_search_hub_candidates();
    let source_url_allowed = |url: &str| {
        let trimmed = url.trim();
        !trimmed.is_empty()
            && is_citable_web_url(trimmed)
            && (!reject_search_hub
                || !is_search_hub_url(trimmed)
                || (headline_lookup_mode && is_google_news_rss_wrapper_url(trimmed)))
    };
    let successful_urls = successful_source_url_set(pending);
    let blocked_unverified_urls = blocked_unverified_url_set(pending, &successful_urls);

    let mut merged: Vec<PendingSearchReadSummary> = Vec::new();
    let mut seen = BTreeSet::new();

    for source in &pending.successful_reads {
        let trimmed = source.url.trim();
        if !source_url_allowed(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(source.clone());
    }

    for source in &pending.candidate_source_hints {
        let trimmed = source.url.trim();
        if trimmed.is_empty()
            || !source_url_allowed(trimmed)
            || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
        {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(source.clone());
    }

    for url in &pending.candidate_urls {
        let trimmed = url.trim();
        if trimmed.is_empty()
            || !source_url_allowed(trimmed)
            || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
        {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                "",
                "",
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: None,
            excerpt: String::new(),
        });
    }

    merged.sort_by(|left, right| {
        let left_signals = source_evidence_signals(left);
        let right_signals = source_evidence_signals(right);
        let left_success = successful_urls.contains(left.url.trim());
        let right_success = successful_urls.contains(right.url.trim());
        let left_key = (
            !is_low_priority_coverage_story(left),
            left_signals.official_status_host_hits > 0,
            left_signals.official_status_host_hits,
            left_signals.primary_status_surface_hits > 0,
            left_signals.primary_status_surface_hits,
            left_signals.secondary_coverage_hits == 0,
            left_signals.documentation_surface_hits == 0,
            left_signals.relevance_score(left_success),
            left_signals.provenance_hits,
            left_signals.primary_event_hits,
            left_success,
        );
        let right_key = (
            !is_low_priority_coverage_story(right),
            right_signals.official_status_host_hits > 0,
            right_signals.official_status_host_hits,
            right_signals.primary_status_surface_hits > 0,
            right_signals.primary_status_surface_hits,
            right_signals.secondary_coverage_hits == 0,
            right_signals.documentation_surface_hits == 0,
            right_signals.relevance_score(right_success),
            right_signals.provenance_hits,
            right_signals.primary_event_hits,
            right_success,
        );
        right_key
            .cmp(&left_key)
            .then_with(|| left.url.cmp(&right.url))
    });

    if headline_lookup_mode {
        let filtered = merged
            .iter()
            .filter(|source| !headline_source_is_low_quality(source))
            .cloned()
            .collect::<Vec<_>>();
        if !filtered.is_empty() {
            return filtered;
        }
    }

    merged
}

pub(crate) fn grounded_source_evidence_count(pending: &PendingSearchCompletion) -> usize {
    let query_contract = synthesis_query_contract(pending);
    let headline_lookup_mode = query_is_generic_headline_collection(&query_contract);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let enforce_grounded_compatibility =
        projection.enforce_grounded_compatibility() && !headline_lookup_mode;
    let reject_search_hub = projection.reject_search_hub_candidates();
    let source_url_allowed = |url: &str| {
        let trimmed = url.trim();
        !trimmed.is_empty()
            && is_citable_web_url(trimmed)
            && (!reject_search_hub
                || !is_search_hub_url(trimmed)
                || (headline_lookup_mode && is_google_news_rss_wrapper_url(trimmed)))
    };
    let has_constraint_objective = projection.has_constraint_objective();
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();
    let successful_urls = successful_source_url_set(pending);
    let blocked_unverified_urls = blocked_unverified_url_set(pending, &successful_urls);

    let mut grounded_urls: BTreeSet<String> = BTreeSet::new();

    for source in &pending.successful_reads {
        let trimmed = source.url.trim();
        if !source_url_allowed(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if has_constraint_objective {
            let title = source.title.as_deref().unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                &source.excerpt,
            );
            if !envelope_score_resolves_constraint(envelope_constraints, &score) {
                continue;
            }
        }
        grounded_urls.insert(trimmed.to_string());
    }

    for source in &pending.candidate_source_hints {
        let trimmed = source.url.trim();
        if trimmed.is_empty()
            || !source_url_allowed(trimmed)
            || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
        {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if has_constraint_objective {
            let title = source.title.as_deref().unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                &source.excerpt,
            );
            if !envelope_score_resolves_constraint(envelope_constraints, &score) {
                continue;
            }
        } else {
            let has_signal = !source.excerpt.trim().is_empty()
                || source
                    .title
                    .as_deref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false);
            if !has_signal {
                continue;
            }
        }
        grounded_urls.insert(trimmed.to_string());
    }

    grounded_urls.len()
}

pub(crate) fn is_primary_status_surface_source(source: &PendingSearchReadSummary) -> bool {
    let signals = source_evidence_signals(source);
    has_primary_status_authority(signals) && !signals.low_priority_dominates()
}

pub(crate) fn why_it_matters_from_story(source: &PendingSearchReadSummary) -> String {
    let text = format!(
        "{} {}",
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    )
    .to_ascii_lowercase();
    if text.contains("authentication")
        || text.contains("login")
        || text.contains("identity")
        || text.contains("sso")
    {
        return "User sign-in and account access may fail or degrade for affected tenants."
            .to_string();
    }
    if text.contains("api")
        || text.contains("endpoint")
        || text.contains("request")
        || text.contains("latency")
    {
        return "API-driven workflows may see elevated errors, latency, or timeouts for affected traffic."
            .to_string();
    }
    if text.contains("dashboard")
        || text.contains("console")
        || text.contains("admin")
        || text.contains("portal")
    {
        return "Operator visibility and control-plane actions may be delayed for affected users."
            .to_string();
    }
    "Customer-facing functionality may remain degraded until source updates confirm recovery."
        .to_string()
}

pub(crate) fn user_impact_from_story(source: &PendingSearchReadSummary) -> String {
    why_it_matters_from_story(source)
}

pub(crate) fn workaround_from_story(source: &PendingSearchReadSummary) -> String {
    let signals = source_evidence_signals(source);
    if signals.mitigation_hits > 0 {
        return "Follow mitigation guidance published by the source (retry/failover/alternate path where available).".to_string();
    }
    if signals.primary_event_hits > 0
        || signals.provenance_hits > 0
        || has_primary_status_authority(signals)
    {
        return "No explicit workaround confirmed; monitor official updates and defer non-critical writes until status changes.".to_string();
    }
    "Workaround not explicitly published in retrieved evidence; use standard resilience fallback patterns and continue monitoring updates.".to_string()
}

pub(crate) fn eta_confidence_from_story(
    source: &PendingSearchReadSummary,
    confident_reads: usize,
    citation_count: usize,
    required_citations_per_story: usize,
) -> String {
    let signals = source_evidence_signals(source);
    let explicit_eta = signals.timeline_hits > 0;
    let status_provenance = signals.provenance_hits > 0 || has_primary_status_authority(signals);

    if explicit_eta && confident_reads >= required_citations_per_story {
        return "high".to_string();
    }
    if status_provenance || confident_reads >= 1 || citation_count >= required_citations_per_story {
        return "medium".to_string();
    }
    "low".to_string()
}

pub(crate) fn changed_last_hour_line(
    source: &PendingSearchReadSummary,
    run_timestamp_iso_utc: &str,
) -> String {
    if let Some(excerpt) = actionable_excerpt(source.excerpt.trim()) {
        return format!(
            "As of {}, latest provider update signal: {}",
            run_timestamp_iso_utc, excerpt
        );
    }
    format!(
        "As of {}, the event remains active in retrieved evidence; explicit hour-over-hour deltas were not consistently published.",
        run_timestamp_iso_utc
    )
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

fn headline_low_quality_domain(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    [
        "stackexchange.com",
        "stackoverflow.com",
        "wikipedia.org",
        "reddit.com",
        "quora.com",
        "facebook.com",
        "instagram.com",
        "tiktok.com",
        "youtube.com",
        "pressgazette.co.uk",
    ]
    .iter()
    .any(|domain| lower.contains(domain))
}

fn headline_low_quality_signal(url: &str, title: &str, excerpt: &str) -> bool {
    if headline_low_quality_domain(url) {
        return true;
    }
    let context = format!(" {} {} {} ", title, excerpt, url).to_ascii_lowercase();
    let low_priority_markers = [
        " news websites ",
        " fact sheet ",
        " trust in media ",
        " which news sources ",
        " schedules and results ",
        " watch live ",
        " how to watch ",
        " horoscope ",
        " horoscopes ",
        " social media and news ",
    ];
    if low_priority_markers
        .iter()
        .any(|marker| context.contains(marker))
    {
        return true;
    }
    let signals = analyze_source_record_signals(url, title, excerpt);
    signals.low_priority_dominates() && !has_primary_status_authority(signals)
}

fn headline_source_is_low_quality(source: &PendingSearchReadSummary) -> bool {
    headline_low_quality_signal(
        source.url.as_str(),
        source.title.as_deref().unwrap_or_default(),
        source.excerpt.as_str(),
    )
}

pub(crate) fn build_citation_candidates(
    pending: &PendingSearchCompletion,
    run_timestamp_iso_utc: &str,
) -> Vec<CitationCandidate> {
    let query_contract = synthesis_query_contract(pending);
    let single_snapshot_mode = prefers_single_fact_snapshot(&query_contract);
    let headline_lookup_mode = query_is_generic_headline_collection(&query_contract);
    let citation_usable_url = |url: &str| {
        let trimmed = url.trim();
        !trimmed.is_empty()
            && is_citable_web_url(trimmed)
            && (!is_search_hub_url(trimmed)
                || (headline_lookup_mode && is_google_news_rss_wrapper_url(trimmed)))
    };
    let successful_urls = successful_source_url_set(pending);
    let blocked_unverified_urls = blocked_unverified_url_set(pending, &successful_urls);
    let mut merged = merged_story_sources(pending);
    if single_snapshot_mode && merged.is_empty() {
        let mut seen = BTreeSet::new();
        for source in pending
            .successful_reads
            .iter()
            .chain(pending.candidate_source_hints.iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty()
                || !citation_usable_url(trimmed)
                || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
                || !seen.insert(trimmed.to_string())
            {
                continue;
            }
            merged.push(source.clone());
        }
        for url in pending
            .candidate_urls
            .iter()
            .chain(pending.attempted_urls.iter())
            .chain(std::iter::once(&pending.url))
        {
            let trimmed = url.trim();
            if trimmed.is_empty()
                || !citation_usable_url(trimmed)
                || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
                || !seen.insert(trimmed.to_string())
            {
                continue;
            }
            merged.push(PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: None,
                excerpt: String::new(),
            });
        }
    }

    merged
        .into_iter()
        .filter(|source| {
            let trimmed = source.url.trim();
            citation_usable_url(trimmed)
                && !is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
                && !(headline_lookup_mode && headline_source_is_low_quality(source))
        })
        .enumerate()
        .filter_map(|(idx, source)| {
            let original_url = source.url.trim().to_string();
            let url = if headline_lookup_mode && is_google_news_rss_wrapper_url(&original_url) {
                source_url_from_metadata_excerpt(source.excerpt.as_str()).unwrap_or(original_url)
            } else {
                original_url
            };
            let source_label = canonical_source_title(&source);
            if headline_lookup_mode
                && headline_low_quality_signal(&url, source_label.as_str(), source.excerpt.as_str())
            {
                return None;
            }
            let excerpt = {
                let prioritized = prioritized_signal_excerpt(source.excerpt.as_str(), 180);
                if prioritized.is_empty() || !excerpt_has_claim_signal(&prioritized) {
                    String::new()
                } else {
                    prioritized
                }
            };
            Some(CitationCandidate {
                id: format!("C{}", idx + 1),
                url: url.clone(),
                source_label,
                excerpt,
                timestamp_utc: run_timestamp_iso_utc.to_string(),
                note: "retrieved_utc; source publish/update timestamp unavailable".to_string(),
                from_successful_read: successful_urls.contains(source.url.trim()),
            })
        })
        .collect()
}

pub(crate) fn title_overlap_score(a: &str, b: &str) -> usize {
    let a_tokens = title_tokens(a);
    let b_tokens = title_tokens(b);
    if a_tokens.is_empty() || b_tokens.is_empty() {
        return 0;
    }
    a_tokens.intersection(&b_tokens).count()
}

pub(crate) fn citation_relevance_score(
    source: &PendingSearchReadSummary,
    candidate: &CitationCandidate,
) -> usize {
    let story_title = canonical_source_title(source);
    let story_context = format!("{} {}", story_title, source.excerpt);
    let candidate_context = format!("{} {}", candidate.source_label, candidate.excerpt);
    let candidate_signals =
        analyze_source_record_signals(&candidate.url, &candidate.source_label, &candidate.excerpt);
    let mut score = title_overlap_score(&story_context, &candidate_context)
        + candidate_signals.primary_status_surface_hits * CITATION_PRIMARY_STATUS_BONUS
        + candidate_signals.official_status_host_hits * CITATION_OFFICIAL_STATUS_HOST_BONUS;
    score = score.saturating_sub(
        candidate_signals.secondary_coverage_hits * CITATION_SECONDARY_COVERAGE_PENALTY,
    );
    score = score.saturating_sub(
        candidate_signals.documentation_surface_hits * CITATION_DOCUMENTATION_SURFACE_PENALTY,
    );
    if source.url.trim() == candidate.url.trim() {
        score += CITATION_SOURCE_URL_MATCH_BONUS;
    }
    score
}

pub(crate) fn citation_metric_signal(candidate: &CitationCandidate) -> bool {
    contains_metric_signal(&candidate.excerpt)
        || contains_metric_signal(&format!(
            "{} {} {}",
            candidate.source_label, candidate.excerpt, candidate.url
        ))
}

pub(crate) fn citation_current_condition_metric_signal(candidate: &CitationCandidate) -> bool {
    contains_current_condition_metric_signal(&candidate.excerpt)
        || contains_current_condition_metric_signal(&format!(
            "{} {} {}",
            candidate.source_label, candidate.excerpt, candidate.url
        ))
}

pub(crate) fn citation_single_snapshot_evidence_score(
    candidate: &CitationCandidate,
    envelope_constraints: &ConstraintSet,
    envelope_policy: ResolutionPolicy,
) -> CandidateEvidenceScore {
    single_snapshot_candidate_envelope_score(
        envelope_constraints,
        envelope_policy,
        &candidate.url,
        &candidate.source_label,
        &candidate.excerpt,
    )
}

pub(crate) fn citation_source_signals(candidate: &CitationCandidate) -> SourceSignalProfile {
    analyze_source_record_signals(&candidate.url, &candidate.source_label, &candidate.excerpt)
}

pub(crate) fn is_low_priority_coverage_candidate(candidate: &CitationCandidate) -> bool {
    citation_source_signals(candidate).low_priority_dominates()
}

pub(crate) fn citation_ids_for_story(
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
    used_urls: &mut BTreeSet<String>,
    citations_per_story: usize,
    prefer_host_diversity: bool,
    envelope_constraints: &ConstraintSet,
    envelope_policy: ResolutionPolicy,
) -> Vec<String> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let insights_by_id =
        weighted_insights_for_story(source, candidates, envelope_constraints, envelope_policy)
            .into_iter()
            .map(|insight| (insight.id.clone(), insight))
            .collect::<BTreeMap<_, _>>();
    let policy_flags_by_id = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.id.clone(),
                insight_policy_flags_for_candidate(candidate, &insights_by_id),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let claim_keys_by_id = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.id.clone(),
                insight_claim_key_for_candidate(candidate, &insights_by_id),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut ranked = candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let signals = citation_source_signals(candidate);
            let envelope_score = if prefer_host_diversity {
                citation_single_snapshot_evidence_score(
                    candidate,
                    envelope_constraints,
                    envelope_policy,
                )
            } else {
                CandidateEvidenceScore::default()
            };
            (idx, signals, envelope_score)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(
        |(left_idx, left_signals, left_envelope), (right_idx, right_signals, right_envelope)| {
            let left = &candidates[*left_idx];
            let right = &candidates[*right_idx];
            let insight_order = match (insights_by_id.get(&left.id), insights_by_id.get(&right.id))
            {
                (Some(left_insight), Some(right_insight)) => {
                    compare_weighted_insights_desc(left_insight, right_insight)
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            };
            let envelope_order = if prefer_host_diversity {
                compare_candidate_evidence_scores_desc(left_envelope, right_envelope)
            } else {
                std::cmp::Ordering::Equal
            };
            let left_key = (
                left.from_successful_read,
                prefer_host_diversity
                    && envelope_score_resolves_constraint(envelope_constraints, left_envelope),
                citation_current_condition_metric_signal(left),
                citation_metric_signal(left),
                left_signals.official_status_host_hits > 0,
                left_signals.official_status_host_hits,
                left_signals.primary_status_surface_hits > 0,
                left_signals.primary_status_surface_hits,
                left_signals.secondary_coverage_hits == 0,
                left_signals.documentation_surface_hits == 0,
                citation_relevance_score(source, left),
                !citation_is_low_priority_coverage(left, *left_signals),
            );
            let right_key = (
                right.from_successful_read,
                prefer_host_diversity
                    && envelope_score_resolves_constraint(envelope_constraints, right_envelope),
                citation_current_condition_metric_signal(right),
                citation_metric_signal(right),
                right_signals.official_status_host_hits > 0,
                right_signals.official_status_host_hits,
                right_signals.primary_status_surface_hits > 0,
                right_signals.primary_status_surface_hits,
                right_signals.secondary_coverage_hits == 0,
                right_signals.documentation_surface_hits == 0,
                citation_relevance_score(source, right),
                !citation_is_low_priority_coverage(right, *right_signals),
            );
            insight_order
                .then_with(|| envelope_order)
                .then_with(|| right_key.cmp(&left_key))
        },
    );

    let hard_policy = derive_insight_hard_policy_gates(
        &ranked,
        candidates,
        &policy_flags_by_id,
        used_urls,
        citations_per_story,
        prefer_host_diversity,
        envelope_constraints,
    );
    let host_inventory = ranked
        .iter()
        .filter_map(|(idx, signals, envelope_score)| {
            let candidate = &candidates[*idx];
            if used_urls.contains(&candidate.url) || candidate.url.trim().is_empty() {
                return None;
            }
            let policy_flags = policy_flags_by_id
                .get(&candidate.id)
                .cloned()
                .unwrap_or_else(|| insight_policy_flags_for_candidate(candidate, &insights_by_id));
            if !candidate_passes_insight_hard_policy(
                candidate,
                *signals,
                envelope_score,
                hard_policy,
                envelope_constraints,
                &policy_flags,
            ) {
                return None;
            }
            source_host(&candidate.url)
        })
        .collect::<BTreeSet<_>>();
    let require_host_diversity =
        prefer_host_diversity && host_inventory.len() >= citations_per_story;

    let mut selected_ids = Vec::new();
    let mut selected_urls = BTreeSet::new();
    let mut selected_hosts = BTreeSet::new();
    let mut selected_claim_counts = BTreeMap::<String, usize>::new();

    // Keep story/citation alignment stable by anchoring to the story source URL first
    // when that URL exists in the citation candidate inventory.
    if selected_ids.len() < citations_per_story {
        if let Some(source_anchor_candidate) = candidates.iter().find(|candidate| {
            let candidate_url = candidate.url.trim();
            !candidate_url.is_empty()
                && url_structurally_equivalent(candidate_url, source.url.trim())
                && !selected_ids.iter().any(|id| id == &candidate.id)
        }) {
            selected_ids.push(source_anchor_candidate.id.clone());
            selected_urls.insert(source_anchor_candidate.url.clone());
            used_urls.insert(source_anchor_candidate.url.clone());
            if let Some(host) = source_host(&source_anchor_candidate.url) {
                selected_hosts.insert(host);
            }
            let claim_key =
                insight_claim_key_for_candidate(source_anchor_candidate, &insights_by_id);
            *selected_claim_counts.entry(claim_key).or_insert(0) += 1;
        }
    }

    let prefer_primary_backfill = ranked
        .iter()
        .any(|(idx, signals, _)| has_primary_status_candidate(*signals, &candidates[*idx]));
    run_insight_selection_pass(
        &ranked,
        candidates,
        &policy_flags_by_id,
        &claim_keys_by_id,
        used_urls,
        &mut selected_ids,
        &mut selected_urls,
        &mut selected_hosts,
        &mut selected_claim_counts,
        citations_per_story,
        1,
        require_host_diversity,
        false,
        prefer_primary_backfill,
        hard_policy,
        envelope_constraints,
    );
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            usize::MAX,
            false,
            false,
            false,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            1,
            false,
            false,
            prefer_primary_backfill,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            2,
            false,
            false,
            prefer_primary_backfill,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            usize::MAX,
            false,
            false,
            prefer_primary_backfill,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            usize::MAX,
            false,
            true,
            prefer_primary_backfill,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            usize::MAX,
            false,
            true,
            false,
            hard_policy,
            envelope_constraints,
        );
    }

    selected_ids
}
