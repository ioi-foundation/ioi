use super::*;

mod candidate_build;
mod merge;
mod ranking;
mod selection;
mod shared;

pub(crate) use candidate_build::build_citation_candidates;
pub(crate) use merge::{grounded_source_evidence_count, merged_story_sources};
pub(crate) use ranking::{
    citation_current_condition_metric_signal, citation_metric_signal, citation_relevance_score,
    citation_single_snapshot_evidence_score, citation_source_signals,
    is_low_priority_coverage_candidate,
};
pub(crate) use selection::citation_ids_for_story;
pub(crate) use shared::preferred_citation_excerpt_with_contract;

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

fn canonical_source_title_with_locality_hint(
    source: &PendingSearchReadSummary,
    locality_hint: Option<&str>,
) -> String {
    let title = source.title.as_deref().map(str::trim).unwrap_or_default();
    if !title.is_empty()
        && !is_low_signal_title(title)
        && !local_business_target_matches_source_host(title, &source.url)
    {
        return title.chars().take(WEB_PIPELINE_STORY_TITLE_CHARS).collect();
    }
    if let Some(display_name) = local_business_detail_display_name(source, locality_hint)
        .or_else(|| local_business_detail_display_name(source, None))
    {
        return display_name
            .chars()
            .take(WEB_PIPELINE_STORY_TITLE_CHARS)
            .collect();
    }
    if let Some(from_excerpt) = excerpt_headline(source.excerpt.trim()) {
        return from_excerpt
            .chars()
            .take(WEB_PIPELINE_STORY_TITLE_CHARS)
            .collect();
    }
    format!("Update from {}", source.url)
}

pub(crate) fn canonical_source_title(source: &PendingSearchReadSummary) -> String {
    canonical_source_title_with_locality_hint(source, None)
}

pub(crate) fn canonical_source_title_for_query(
    query_contract: &str,
    source: &PendingSearchReadSummary,
) -> String {
    let locality_scope = explicit_query_scope_hint(query_contract);
    canonical_source_title_with_locality_hint(source, locality_scope.as_deref())
}

pub(crate) fn is_primary_status_surface_source(source: &PendingSearchReadSummary) -> bool {
    let signals = source_evidence_signals(source);
    has_primary_status_authority(signals) && !signals.low_priority_dominates()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_source_title_for_query_uses_query_scoped_local_business_identity() {
        let source = PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurant_Review-g60763-d25369085-Reviews-Marcellino_Restaurant-New_York_City_New_York.html".to_string(),
            title: Some("Tripadvisor".to_string()),
            excerpt: "Marcellino Restaurant: com','cookie':'trip-cookie-payload-12345"
                .to_string(),
        };

        assert_eq!(
            canonical_source_title_for_query(
                "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
                &source,
            ),
            "Marcellino Restaurant"
        );
    }
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
