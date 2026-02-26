use super::shared::{
    blocked_unverified_url_set, headline_low_quality_signal, headline_source_is_low_quality,
    is_blocked_unverified_url, source_url_from_metadata_excerpt, successful_source_url_set,
};
use super::*;

pub(crate) fn build_citation_candidates(
    pending: &PendingSearchCompletion,
    run_timestamp_iso_utc: &str,
) -> Vec<CitationCandidate> {
    let query_contract = synthesis_query_contract(pending);
    let single_snapshot_mode = prefers_single_fact_snapshot(&query_contract);
    let headline_lookup_mode = query_is_generic_headline_collection(&query_contract);
    let citation_usable_url = |url: &str| {
        let trimmed = url.trim();
        if trimmed.is_empty() || !is_citable_web_url(trimmed) {
            return false;
        }
        if is_search_hub_url(trimmed) {
            return false;
        }
        if headline_lookup_mode
            && (is_news_feed_wrapper_url(trimmed) || is_multi_item_listing_url(trimmed))
        {
            return false;
        }
        true
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

    let mut candidates = merged
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
            let url = if headline_lookup_mode && is_news_feed_wrapper_url(&original_url) {
                source_url_from_metadata_excerpt(source.excerpt.as_str())
                    .filter(|resolved_url| {
                        citation_usable_url(resolved_url)
                            && !is_search_hub_url(resolved_url)
                            && !is_multi_item_listing_url(resolved_url)
                    })
                    .unwrap_or(original_url)
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
        .collect::<Vec<_>>();

    if headline_lookup_mode && candidates.is_empty() {
        let mut fallback_sources = Vec::new();
        let mut seen = BTreeSet::new();

        for source in pending
            .successful_reads
            .iter()
            .chain(pending.candidate_source_hints.iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty()
                || !is_citable_web_url(trimmed)
                || is_search_hub_url(trimmed)
                || (headline_lookup_mode && is_news_feed_wrapper_url(trimmed))
                || (headline_lookup_mode && is_multi_item_listing_url(trimmed))
                || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
                || headline_low_quality_signal(
                    trimmed,
                    source.title.as_deref().unwrap_or_default(),
                    source.excerpt.as_str(),
                )
                || !seen.insert(trimmed.to_string())
            {
                continue;
            }
            fallback_sources.push(PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: source.title.clone(),
                excerpt: source.excerpt.clone(),
            });
        }

        for url in pending
            .candidate_urls
            .iter()
            .chain(pending.attempted_urls.iter())
            .chain(std::iter::once(&pending.url))
        {
            let trimmed = url.trim();
            if trimmed.is_empty()
                || !is_citable_web_url(trimmed)
                || is_search_hub_url(trimmed)
                || (headline_lookup_mode && is_news_feed_wrapper_url(trimmed))
                || (headline_lookup_mode && is_multi_item_listing_url(trimmed))
                || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
                || headline_low_quality_signal(trimmed, "", "")
                || !seen.insert(trimmed.to_string())
            {
                continue;
            }
            fallback_sources.push(PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: None,
                excerpt: String::new(),
            });
        }

        candidates = fallback_sources
            .into_iter()
            .enumerate()
            .map(|(idx, source)| CitationCandidate {
                id: format!("C{}", idx + 1),
                url: source.url.clone(),
                source_label: canonical_source_title(&source),
                excerpt: String::new(),
                timestamp_utc: run_timestamp_iso_utc.to_string(),
                note: "retrieved_utc; fallback citation inventory from constrained source set"
                    .to_string(),
                from_successful_read: successful_urls.contains(source.url.trim()),
            })
            .collect();
    }

    candidates
}
