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
        let base_url_allowed =
            is_citable_web_url(url) && !is_search_hub_url(url) && !is_multi_item_listing_url(url);
        let resolved_url = if base_url_allowed {
            url.to_string()
        } else {
            source
                .snippet
                .as_deref()
                .and_then(source_url_from_metadata_excerpt)
                .filter(|candidate| {
                    let trimmed = candidate.trim();
                    is_citable_web_url(trimmed)
                        && !is_search_hub_url(trimmed)
                        && !is_multi_item_listing_url(trimmed)
                })
                .unwrap_or_else(|| url.to_string())
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
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: None,
        };

        let hints = candidate_source_hints_from_bundle_ranked(&bundle);
        assert_eq!(hints.len(), 1);
        assert_eq!(
            hints[0].url,
            "https://www.reuters.com/world/europe/example-story-2026-03-01/"
        );
    }

    #[test]
    fn constrained_inventory_preserves_primary_authority_sources_for_document_briefings() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "edge:bing-search-rss".to_string(),
            query: Some(query.to_string()),
            url: Some(
                "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards&format=rss"
                    .to_string(),
            ),
            sources: vec![
                WebSource {
                    source_id: "secondary-cyberscoop".to_string(),
                    rank: Some(1),
                    url: "https://cyberscoop.com/why-federal-it-leaders-must-act-now-to-deliver-nists-post-quantum-cryptography-transition-op-ed/".to_string(),
                    title: Some(
                        "Why federal IT leaders must act now to deliver NIST's post-quantum cryptography transition".to_string(),
                    ),
                    snippet: Some(
                        "CyberScoop analysis of NIST post-quantum cryptography transition guidance."
                            .to_string(),
                    ),
                    domain: Some("cyberscoop.com".to_string()),
                },
                WebSource {
                    source_id: "official-nist-pqc".to_string(),
                    rank: Some(2),
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    snippet: Some(
                        "December 8, 2025 - These Federal Information Processing Standards (FIPS) are mandatory for federal systems and adopted around the world."
                            .to_string(),
                    ),
                    domain: Some("nist.gov".to_string()),
                },
                WebSource {
                    source_id: "secondary-cybersecuritydive".to_string(),
                    rank: Some(3),
                    url: "https://www.cybersecuritydive.com/news/nist-post-quantum-cryptography-guidance-mapping/760638/".to_string(),
                    title: Some(
                        "NIST expands post-quantum cryptography guidance mapping".to_string(),
                    ),
                    snippet: Some(
                        "Cybersecurity Dive covers NIST post-quantum cryptography transition guidance."
                            .to_string(),
                    ),
                    domain: Some("cybersecuritydive.com".to_string()),
                },
                WebSource {
                    source_id: "official-nist-news".to_string(),
                    rank: Some(4),
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST releases first 3 finalized post-quantum encryption standards"
                            .to_string(),
                    ),
                    snippet: Some(
                        "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                            .to_string(),
                    ),
                    domain: Some("nist.gov".to_string()),
                },
            ],
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: Some(retrieval_contract),
        };

        let (urls, _) =
            constrained_candidate_inventory_from_bundle_with_locality_hint(query, 2, &bundle, None);

        let pqc_idx = urls
            .iter()
            .position(|url| url == "https://www.nist.gov/pqc")
            .expect("nist pqc page retained");
        let news_idx = urls
            .iter()
            .position(|url| {
                url
                    == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            })
            .expect("nist news page retained");
        let cyberscoop_idx = urls
            .iter()
            .position(|url| {
                url
                    == "https://cyberscoop.com/why-federal-it-leaders-must-act-now-to-deliver-nists-post-quantum-cryptography-transition-op-ed/"
            })
            .expect("secondary source retained");

        assert!(pqc_idx < cyberscoop_idx);
        assert!(news_idx < cyberscoop_idx);
    }

    #[test]
    fn constrained_inventory_prioritizes_current_authority_identifier_expansion_sources() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "edge:bing-search-rss".to_string(),
            query: Some(query.to_string()),
            url: Some(
                "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards&format=rss"
                    .to_string(),
            ),
            sources: vec![
                WebSource {
                    source_id: "official-nist-2024".to_string(),
                    rank: Some(1),
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST releases first 3 finalized post-quantum encryption standards"
                            .to_string(),
                    ),
                    snippet: Some(
                        "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                            .to_string(),
                    ),
                    domain: Some("nist.gov".to_string()),
                },
                WebSource {
                    source_id: "official-nist-2025".to_string(),
                    rank: Some(2),
                    url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                            .to_string(),
                    ),
                    snippet: Some(
                        "NIST selected HQC after finalizing FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                    ),
                    domain: Some("nist.gov".to_string()),
                },
                WebSource {
                    source_id: "secondary".to_string(),
                    rank: Some(3),
                    url: "https://example.com/analysis/nist-pqc".to_string(),
                    title: Some("Independent analysis of NIST PQC".to_string()),
                    snippet: Some(
                        "Independent analysis summarizes FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                    ),
                    domain: Some("example.com".to_string()),
                },
            ],
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: Some(retrieval_contract),
        };

        let (urls, _) =
            constrained_candidate_inventory_from_bundle_with_locality_hint(query, 2, &bundle, None);

        assert_eq!(
            urls.first().map(String::as_str),
            Some(
                "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption"
            )
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
    let headline_lookup_mode = retrieval_contract_is_generic_headline_collection(
        bundle.retrieval_contract.as_ref(),
        query_contract,
    );
    let document_briefing_layout = query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract);
    let authority_source_required_for_briefing = document_briefing_layout
        && projection.query_facets.grounded_external_required
        && bundle
            .retrieval_contract
            .as_ref()
            .map(|contract| contract.currentness_required || contract.source_independence_min > 1)
            .unwrap_or(false);
    let constraints = &projection.constraints;
    let policy = ResolutionPolicy::default();
    let min_required = min_sources.max(1) as usize;
    let required_briefing_identifier_labels =
        briefing_standard_identifier_groups_for_query(query_contract)
            .iter()
            .filter(|group| group.required)
            .map(|group| group.primary_label.to_string())
            .collect::<BTreeSet<_>>();
    let optional_briefing_identifier_labels =
        briefing_standard_identifier_groups_for_query(query_contract)
            .iter()
            .filter(|group| !group.required)
            .map(|group| group.primary_label.to_string())
            .collect::<BTreeSet<_>>();

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
                candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt);
            let document_authority_score =
                source_document_authority_score(query_contract, &hint.url, title, &hint.excerpt);
            let observed_identifier_labels = observed_briefing_standard_identifier_labels(
                query_contract,
                &format!("{} {} {}", hint.url, title, hint.excerpt),
            )
            .into_iter()
            .collect::<BTreeSet<_>>();
            let query_grounding_signal = excerpt_has_query_grounding_signal_with_contract(
                bundle.retrieval_contract.as_ref(),
                query_contract,
                min_sources as usize,
                &hint.url,
                title,
                &hint.excerpt,
            );
            let headline_low_quality = headline_lookup_mode
                && headline_source_is_low_quality(&hint.url, title, &hint.excerpt);
            let headline_actionable = headline_lookup_mode && headline_source_is_actionable(&hint);
            RankedAcquisitionCandidate {
                idx,
                hint,
                envelope_score,
                resolves_constraint,
                time_sensitive_resolvable_payload,
                compatibility,
                source_relevance_score: source_signals.relevance_score(false),
                official_status_host_hits: source_signals.official_status_host_hits,
                primary_status_surface_hits: source_signals.primary_status_surface_hits,
                document_authority_score,
                observed_identifier_label_count: observed_identifier_labels.len(),
                required_identifier_label_count: observed_identifier_labels
                    .iter()
                    .filter(|label| required_briefing_identifier_labels.contains(*label))
                    .count(),
                optional_identifier_label_count: observed_identifier_labels
                    .iter()
                    .filter(|label| optional_briefing_identifier_labels.contains(*label))
                    .count(),
                query_grounding_signal,
                headline_low_quality,
                headline_actionable,
            }
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes = compatibility_passes_projection(&projection, &right.compatibility);
        let left_passes = compatibility_passes_projection(&projection, &left.compatibility);
        let briefing_order = if document_briefing_layout {
            (right.document_authority_score > 0)
                .cmp(&(left.document_authority_score > 0))
                .then_with(|| {
                    right
                        .document_authority_score
                        .cmp(&left.document_authority_score)
                })
                .then_with(|| {
                    (right.official_status_host_hits > 0).cmp(&(left.official_status_host_hits > 0))
                })
                .then_with(|| {
                    right
                        .official_status_host_hits
                        .cmp(&left.official_status_host_hits)
                })
                .then_with(|| {
                    right
                        .optional_identifier_label_count
                        .cmp(&left.optional_identifier_label_count)
                })
                .then_with(|| {
                    right
                        .observed_identifier_label_count
                        .cmp(&left.observed_identifier_label_count)
                })
                .then_with(|| {
                    right
                        .required_identifier_label_count
                        .cmp(&left.required_identifier_label_count)
                })
                .then_with(|| {
                    right
                        .query_grounding_signal
                        .cmp(&left.query_grounding_signal)
                })
                .then_with(|| {
                    (right.primary_status_surface_hits > 0)
                        .cmp(&(left.primary_status_surface_hits > 0))
                })
                .then_with(|| {
                    right
                        .primary_status_surface_hits
                        .cmp(&left.primary_status_surface_hits)
                })
                .then_with(|| {
                    right
                        .source_relevance_score
                        .cmp(&left.source_relevance_score)
                })
        } else {
            std::cmp::Ordering::Equal
        };
        right
            .headline_actionable
            .cmp(&left.headline_actionable)
            .then_with(|| left.headline_low_quality.cmp(&right.headline_low_quality))
            .then_with(|| briefing_order)
            .then_with(|| {
                right
                    .time_sensitive_resolvable_payload
                    .cmp(&left.time_sensitive_resolvable_payload)
            })
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
        !headline_lookup_mode && has_constraint_objective && compatible_candidates >= min_required;
    let headline_non_low_quality_candidates = ranked
        .iter()
        .filter(|candidate| !candidate.headline_low_quality)
        .count();
    let authority_candidate_for_briefing = |candidate: &&RankedAcquisitionCandidate| {
        authority_source_required_for_briefing
            && candidate.document_authority_score > 0
            && (candidate.query_grounding_signal
                || candidate.compatibility.compatibility_score > 0
                || candidate.compatibility.is_compatible)
    };

    let mut filtered = ranked.iter().collect::<Vec<_>>();
    if should_filter_by_compatibility {
        filtered.retain(|candidate| {
            compatibility_passes_projection(&projection, &candidate.compatibility)
                || authority_candidate_for_briefing(candidate)
        });
    }
    if headline_lookup_mode && headline_non_low_quality_candidates >= min_required {
        filtered.retain(|candidate| !candidate.headline_low_quality);
    }

    let resolvable_candidates = filtered
        .iter()
        .filter(|candidate| candidate.resolves_constraint)
        .count();
    if !headline_lookup_mode && has_constraint_objective && resolvable_candidates >= min_required {
        filtered.retain(|candidate| {
            candidate.resolves_constraint || authority_candidate_for_briefing(candidate)
        });
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
    if authority_source_required_for_briefing {
        let authority_urls = selected_hints
            .iter()
            .filter(|hint| {
                source_has_document_authority(
                    query_contract,
                    &hint.url,
                    hint.title.as_deref().unwrap_or_default(),
                    &hint.excerpt,
                )
            })
            .map(|hint| hint.url.clone())
            .collect::<BTreeSet<_>>();
        if !authority_urls.is_empty() {
            let mut prioritized_hints = Vec::new();
            let mut secondary_hints = Vec::new();
            for hint in selected_hints {
                if authority_urls.contains(&hint.url) {
                    prioritized_hints.push(hint);
                } else {
                    secondary_hints.push(hint);
                }
            }
            prioritized_hints.extend(secondary_hints);
            selected_urls = prioritized_hints
                .iter()
                .map(|hint| hint.url.clone())
                .collect::<Vec<_>>();
            selected_hints = prioritized_hints;
        }
    }

    (selected_urls, selected_hints)
}
