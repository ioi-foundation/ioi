use super::*;

pub(super) fn successful_source_url_set(pending: &PendingSearchCompletion) -> BTreeSet<String> {
    pending
        .successful_reads
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect()
}

pub(super) fn blocked_unverified_url_set(
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

pub(super) fn is_blocked_unverified_url(
    url: &str,
    blocked_unverified_urls: &BTreeSet<String>,
) -> bool {
    blocked_unverified_urls.contains(url.trim())
}

pub(super) fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
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

pub(super) fn headline_low_quality_signal(url: &str, title: &str, excerpt: &str) -> bool {
    if source_has_human_challenge_signal(url, title, excerpt) {
        return true;
    }
    let signals = analyze_source_record_signals(url, title, excerpt);
    if is_multi_item_listing_url(url) {
        return signals.low_priority_dominates();
    }
    signals.low_priority_dominates() && !has_primary_status_authority(signals)
}

pub(super) fn headline_source_is_low_quality(source: &PendingSearchReadSummary) -> bool {
    headline_low_quality_signal(
        source.url.as_str(),
        source.title.as_deref().unwrap_or_default(),
        source.excerpt.as_str(),
    )
}

fn document_briefing_excerpt_quality_key(
    query_contract: &str,
    url: &str,
    source_label: &str,
    excerpt: &str,
) -> (usize, usize, usize, bool) {
    let required_labels = briefing_standard_identifier_groups_for_query(query_contract)
        .iter()
        .filter(|group| group.required)
        .map(|group| group.primary_label)
        .collect::<BTreeSet<_>>();
    let observed_labels = observed_briefing_standard_identifier_labels(
        query_contract,
        &format!("{} {} {}", url, source_label, excerpt),
    );
    let required_hits = observed_labels
        .iter()
        .filter(|label| required_labels.contains(label.as_str()))
        .count();
    let authority_hits = usize::from(source_has_document_authority(
        query_contract,
        url,
        source_label,
        excerpt,
    ));
    (
        required_hits,
        authority_hits,
        observed_labels.len(),
        !excerpt.trim().is_empty(),
    )
}

pub(crate) fn preferred_citation_excerpt_with_contract(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    url: &str,
    source_label: &str,
    raw_excerpt: &str,
    max_chars: usize,
) -> String {
    let prioritized = prioritized_query_grounding_excerpt_with_contract(
        retrieval_contract,
        query_contract,
        min_sources.max(1),
        url,
        source_label,
        raw_excerpt,
        max_chars,
    );
    let document_briefing_layout = query_prefers_document_briefing_layout(query_contract)
        && !retrieval_contract_requests_comparison(retrieval_contract, query_contract);
    if !document_briefing_layout {
        return prioritized;
    }

    let compact_raw = compact_excerpt(raw_excerpt, max_chars.saturating_mul(2).max(max_chars));
    let prioritized_key =
        document_briefing_excerpt_quality_key(query_contract, url, source_label, &prioritized);
    let raw_key =
        document_briefing_excerpt_quality_key(query_contract, url, source_label, &compact_raw);
    if raw_key > prioritized_key {
        compact_raw
    } else {
        prioritized
    }
}
