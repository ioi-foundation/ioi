use super::*;

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
