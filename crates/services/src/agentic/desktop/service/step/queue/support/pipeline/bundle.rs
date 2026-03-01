use super::*;

pub(crate) fn normalize_confidence_label(label: &str) -> String {
    let normalized = label.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "high" | "medium" | "low" => normalized,
        _ => "low".to_string(),
    }
}

pub(crate) fn parse_web_evidence_bundle(raw: &str) -> Option<WebEvidenceBundle> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str::<WebEvidenceBundle>(trimmed).ok()
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

pub(crate) fn candidate_source_hints_from_bundle_ranked(
    bundle: &WebEvidenceBundle,
) -> Vec<PendingSearchReadSummary> {
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();
    let mut sources = bundle.sources.clone();
    sources.sort_by(|left, right| {
        let left_title = left.title.as_deref().unwrap_or_default();
        let right_title = right.title.as_deref().unwrap_or_default();
        let left_excerpt = left.snippet.as_deref().unwrap_or_default();
        let right_excerpt = right.snippet.as_deref().unwrap_or_default();
        let left_signals = analyze_source_record_signals(&left.url, left_title, left_excerpt);
        let right_signals = analyze_source_record_signals(&right.url, right_title, right_excerpt);

        let left_key = (
            left_signals.official_status_host_hits > 0,
            left_signals.official_status_host_hits,
            left_signals.primary_status_surface_hits > 0,
            left_signals.primary_status_surface_hits,
            left_signals.secondary_coverage_hits == 0,
            left_signals.documentation_surface_hits == 0,
            left_signals.relevance_score(false),
            left_signals.provenance_hits,
            left_signals.primary_event_hits,
        );
        let right_key = (
            right_signals.official_status_host_hits > 0,
            right_signals.official_status_host_hits,
            right_signals.primary_status_surface_hits > 0,
            right_signals.primary_status_surface_hits,
            right_signals.secondary_coverage_hits == 0,
            right_signals.documentation_surface_hits == 0,
            right_signals.relevance_score(false),
            right_signals.provenance_hits,
            right_signals.primary_event_hits,
        );

        right_key
            .cmp(&left_key)
            .then_with(|| {
                left.rank
                    .unwrap_or(u32::MAX)
                    .cmp(&right.rank.unwrap_or(u32::MAX))
            })
            .then_with(|| left.url.cmp(&right.url))
    });
    for source in sources {
        let url = source.url.trim();
        if url.is_empty() {
            continue;
        }
        let resolved_url = if is_news_feed_wrapper_url(url) {
            source
                .snippet
                .as_deref()
                .and_then(source_url_from_metadata_excerpt)
                .filter(|candidate| {
                    let trimmed = candidate.trim();
                    is_citable_web_url(trimmed)
                        && !is_news_feed_wrapper_url(trimmed)
                        && !is_search_hub_url(trimmed)
                        && !is_multi_item_listing_url(trimmed)
                })
                .unwrap_or_else(|| url.to_string())
        } else {
            url.to_string()
        };
        if !seen.insert(resolved_url.clone()) {
            continue;
        }
        hints.push(PendingSearchReadSummary {
            url: resolved_url,
            title: source
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
            excerpt: compact_excerpt(source.snippet.as_deref().unwrap_or_default(), 180),
        });
    }
    hints
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::WebSource;

    #[test]
    fn candidate_source_hints_resolve_wrapper_source_url_metadata() {
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "edge:google-news-rss".to_string(),
            query: Some("today top news headlines".to_string()),
            url: Some("https://news.google.com/rss/search?q=today+top+news+headlines".to_string()),
            sources: vec![WebSource {
                source_id: "google-item-1".to_string(),
                rank: Some(1),
                url: "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string(),
                title: Some("Sample Story".to_string()),
                snippet: Some(
                    "Reuters | source_url=https://www.reuters.com/world/europe/example-story-2026-03-01/"
                        .to_string(),
                ),
                domain: Some("reuters.com".to_string()),
            }],
            documents: vec![],
        };

        let hints = candidate_source_hints_from_bundle_ranked(&bundle);
        assert_eq!(hints.len(), 1);
        assert_eq!(
            hints[0].url,
            "https://www.reuters.com/world/europe/example-story-2026-03-01/"
        );
    }
}

pub(crate) fn document_source_hints_from_bundle(
    bundle: &WebEvidenceBundle,
) -> Vec<PendingSearchReadSummary> {
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();
    for doc in &bundle.documents {
        let url = doc.url.trim();
        if url.is_empty() || !seen.insert(url.to_string()) {
            continue;
        }
        hints.push(PendingSearchReadSummary {
            url: url.to_string(),
            title: doc
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
            excerpt: compact_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS),
        });
    }
    hints
}

pub(crate) fn candidate_source_hints_from_bundle(
    bundle: &WebEvidenceBundle,
) -> Vec<PendingSearchReadSummary> {
    candidate_source_hints_from_bundle_ranked(bundle)
}

pub(crate) fn candidate_urls_from_bundle(bundle: &WebEvidenceBundle) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();

    for hint in candidate_source_hints_from_bundle_ranked(bundle) {
        let url = hint.url.trim();
        if !url.is_empty() && seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    for hint in document_source_hints_from_bundle(bundle) {
        let url = hint.url.trim();
        if !url.is_empty() && seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    urls
}

pub(crate) fn constrained_candidate_inventory_from_bundle_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> (Vec<String>, Vec<PendingSearchReadSummary>) {
    let mut candidate_hints = candidate_source_hints_from_bundle_ranked(bundle);
    let mut seen_urls = candidate_hints
        .iter()
        .map(|hint| hint.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>();
    for hint in document_source_hints_from_bundle(bundle) {
        let trimmed = hint.url.trim();
        if trimmed.is_empty() || !seen_urls.insert(trimmed.to_string()) {
            continue;
        }
        candidate_hints.push(hint);
    }

    if candidate_hints.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources,
        &candidate_hints,
        locality_hint,
    );
    let constraints = &projection.constraints;
    let policy = ResolutionPolicy::default();
    let min_required = min_sources.max(1) as usize;

    let mut ranked = candidate_hints
        .into_iter()
        .enumerate()
        .map(|(idx, hint)| {
            let title = hint.title.as_deref().unwrap_or_default();
            let envelope_score = single_snapshot_candidate_envelope_score(
                constraints,
                policy,
                &hint.url,
                title,
                &hint.excerpt,
            );
            let resolves_constraint =
                envelope_score_resolves_constraint(constraints, &envelope_score);
            let compatibility = candidate_constraint_compatibility(
                constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                &hint.url,
                title,
                &hint.excerpt,
            );
            let source_signals = analyze_source_record_signals(&hint.url, title, &hint.excerpt);
            let time_sensitive_resolvable_payload =
                candidate_time_sensitive_resolvable_payload(title, &hint.excerpt);
            RankedAcquisitionCandidate {
                idx,
                hint,
                envelope_score,
                resolves_constraint,
                time_sensitive_resolvable_payload,
                compatibility,
                source_relevance_score: source_signals.relevance_score(false),
            }
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes = compatibility_passes_projection(&projection, &right.compatibility);
        let left_passes = compatibility_passes_projection(&projection, &left.compatibility);
        right
            .time_sensitive_resolvable_payload
            .cmp(&left.time_sensitive_resolvable_payload)
            .then_with(|| right_passes.cmp(&left_passes))
            .then_with(|| right.resolves_constraint.cmp(&left.resolves_constraint))
            .then_with(|| {
                right
                    .compatibility
                    .compatibility_score
                    .cmp(&left.compatibility.compatibility_score)
            })
            .then_with(|| {
                compare_candidate_evidence_scores_desc(&left.envelope_score, &right.envelope_score)
            })
            .then_with(|| {
                right
                    .source_relevance_score
                    .cmp(&left.source_relevance_score)
            })
            .then_with(|| left.idx.cmp(&right.idx))
            .then_with(|| left.hint.url.cmp(&right.hint.url))
    });

    let has_constraint_objective = projection.has_constraint_objective();
    let compatible_candidates = ranked
        .iter()
        .filter(|candidate| compatibility_passes_projection(&projection, &candidate.compatibility))
        .count();
    let should_filter_by_compatibility =
        has_constraint_objective && compatible_candidates >= min_required;

    let mut filtered = ranked.iter().collect::<Vec<_>>();
    if should_filter_by_compatibility {
        filtered.retain(|candidate| {
            compatibility_passes_projection(&projection, &candidate.compatibility)
        });
    }

    let resolvable_candidates = filtered
        .iter()
        .filter(|candidate| candidate.resolves_constraint)
        .count();
    if has_constraint_objective && resolvable_candidates >= min_required {
        filtered.retain(|candidate| candidate.resolves_constraint);
    }

    let selected = if filtered.is_empty() {
        if projection.strict_grounded_compatibility() {
            Vec::new()
        } else {
            ranked.iter().collect::<Vec<_>>()
        }
    } else {
        filtered
    };
    let mut selected_urls = Vec::new();
    let mut selected_hints = Vec::new();
    let mut selected_seen = BTreeSet::new();
    for candidate in selected {
        let url = candidate.hint.url.trim();
        if url.is_empty() || !selected_seen.insert(url.to_string()) {
            continue;
        }
        selected_urls.push(url.to_string());
        selected_hints.push(candidate.hint.clone());
    }

    (selected_urls, selected_hints)
}
