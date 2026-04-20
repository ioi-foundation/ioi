use super::*;

pub(crate) fn build_deterministic_story_draft(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> SynthesisDraft {
    let run_timestamp_ms = if pending.started_at_ms > 0 {
        pending.started_at_ms
    } else {
        web_pipeline_now_ms()
    };
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);
    let run_date = iso_date_from_unix_ms(run_timestamp_ms);
    let query = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let layout_profile = synthesis_layout_profile(retrieval_contract, &query);
    let single_snapshot_mode =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query);
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query);
    let required_story_count = retrieval_contract_required_story_count(retrieval_contract, &query);
    let required_support_count =
        retrieval_contract_required_support_count(retrieval_contract, &query).max(1);
    let citations_per_story =
        retrieval_contract_required_citations_per_story(retrieval_contract, &query);
    let document_briefing_distinct_domain_floor =
        if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing) {
            retrieval_contract_required_distinct_domain_floor(retrieval_contract, &query)
                .min(required_support_count.max(citations_per_story.max(1)))
        } else {
            0
        };
    let document_briefing_host_diversity_required =
        matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing)
            && document_briefing_distinct_domain_floor > 1;
    let selected_source_target =
        if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing) {
            required_support_count
        } else if single_snapshot_mode {
            required_story_count
                .max(required_support_count)
                .max(citations_per_story.max(1))
        } else {
            required_story_count
        };
    let single_snapshot_policy = ResolutionPolicy::default();
    let completion_reason = completion_reason_line(reason).to_string();
    let min_sources = pending.min_sources.max(1) as usize;
    let required_readable_sources = if headline_lookup_mode && required_story_count > 1 {
        if min_sources <= 1 {
            1
        } else {
            min_sources
                .saturating_sub(pending.blocked_urls.len())
                .clamp(2, min_sources)
        }
    } else {
        min_sources
    };
    let readable_sources = pending.successful_reads.len();
    let blocked_sources = pending.blocked_urls.len();
    let readable_floor_unmet = readable_sources < required_readable_sources;
    let partial_note = readable_floor_unmet.then(|| {
        format!(
            "Partial evidence: verification receipt -> retrieved {} of {} required distinct readable sources ({} blocked by challenge).",
            readable_sources, required_readable_sources, blocked_sources
        )
    });

    let mut candidates = build_citation_candidates(pending, &run_timestamp_iso_utc);
    let mut citations_by_id = BTreeMap::new();
    for candidate in &candidates {
        citations_by_id.insert(candidate.id.clone(), candidate.clone());
    }

    let mut stories = Vec::new();
    let merged_sources = merged_story_sources(pending);
    let successful_urls = pending
        .successful_reads
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>();
    let successful_merged_sources = merged_sources
        .iter()
        .filter(|source| successful_urls.contains(source.url.trim()))
        .cloned()
        .collect::<Vec<_>>();
    let single_snapshot_constraints = single_snapshot_constraint_set_with_hints(
        &query,
        citations_per_story.max(1),
        &merged_sources,
    );
    let primary_status_sources = merged_sources
        .iter()
        .filter(|source| is_primary_status_surface_source(source))
        .cloned()
        .collect::<Vec<_>>();
    let source_pool = if headline_lookup_mode && !successful_merged_sources.is_empty() {
        successful_merged_sources.clone()
    } else if single_snapshot_mode {
        let mut ranked = if !successful_merged_sources.is_empty() {
            successful_merged_sources.clone()
        } else {
            merged_sources.clone()
        };
        ranked.sort_by(|left, right| {
            let left_surface = format!(
                "{} {}",
                left.title.as_deref().unwrap_or_default(),
                left.excerpt
            );
            let right_surface = format!(
                "{} {}",
                right.title.as_deref().unwrap_or_default(),
                right.excerpt
            );
            let left_current_holder = first_current_role_holder_sentence(&left_surface).is_some();
            let right_current_holder = first_current_role_holder_sentence(&right_surface).is_some();
            let left_subject_identity = first_subject_currentness_sentence(&left_surface).is_some();
            let right_subject_identity =
                first_subject_currentness_sentence(&right_surface).is_some();
            let left_current_signal = contains_current_condition_metric_signal(&format!(
                "{} {}",
                left.title.as_deref().unwrap_or_default(),
                left.excerpt
            ));
            let right_current_signal = contains_current_condition_metric_signal(&format!(
                "{} {}",
                right.title.as_deref().unwrap_or_default(),
                right.excerpt
            ));
            right_current_holder
                .cmp(&left_current_holder)
                .then_with(|| right_subject_identity.cmp(&left_subject_identity))
                .then_with(|| right_current_signal.cmp(&left_current_signal))
                .then_with(|| {
                    let left_partial_signal = has_quantitative_metric_payload(
                        &format!(
                            "{} {}",
                            left.title.as_deref().unwrap_or_default(),
                            left.excerpt
                        ),
                        false,
                    );
                    let right_partial_signal = has_quantitative_metric_payload(
                        &format!(
                            "{} {}",
                            right.title.as_deref().unwrap_or_default(),
                            right.excerpt
                        ),
                        false,
                    );
                    right_partial_signal.cmp(&left_partial_signal)
                })
                .then_with(|| {
                    compare_candidate_evidence_scores_desc(
                        &single_snapshot_source_score(
                            left,
                            &single_snapshot_constraints,
                            single_snapshot_policy,
                        ),
                        &single_snapshot_source_score(
                            right,
                            &single_snapshot_constraints,
                            single_snapshot_policy,
                        ),
                    )
                })
                .then_with(|| left.url.cmp(&right.url))
        });
        ranked
    } else if !successful_merged_sources.is_empty() {
        if successful_merged_sources.len() >= required_story_count {
            successful_merged_sources
        } else {
            let mut combined = successful_merged_sources.clone();
            for source in &merged_sources {
                if combined.len() >= required_story_count {
                    break;
                }
                if combined.iter().any(|existing| {
                    existing.url.eq_ignore_ascii_case(source.url.as_str())
                        || url_structurally_equivalent(existing.url.as_str(), source.url.as_str())
                }) {
                    continue;
                }
                combined.push(source.clone());
            }
            combined
        }
    } else if primary_status_sources.len() >= required_story_count {
        primary_status_sources
    } else {
        merged_sources.clone()
    };
    let non_hub_source_pool = source_pool
        .iter()
        .filter(|source| !is_search_hub_url(source.url.trim()))
        .cloned()
        .collect::<Vec<_>>();
    let headline_curated_source_pool = if headline_lookup_mode {
        non_hub_source_pool
            .iter()
            .filter(|source| headline_story_source_is_actionable(source))
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let preferred_source_pool = if headline_lookup_mode
        && !single_snapshot_mode
        && headline_curated_source_pool.len() >= required_story_count
    {
        &headline_curated_source_pool
    } else if !single_snapshot_mode && non_hub_source_pool.len() >= required_story_count {
        &non_hub_source_pool
    } else {
        &source_pool
    };

    let locality_scope = explicit_query_scope_hint(&query).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let local_business_entity_diversity_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, &query);
    let local_business_entity_targets = if local_business_entity_diversity_required {
        merged_local_business_target_names(
            &pending.attempted_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_count,
        )
    } else {
        Vec::new()
    };
    let mut selected_sources = if local_business_entity_targets.is_empty() {
        Vec::new()
    } else {
        let mut selected = selected_local_business_target_sources(
            &query,
            &local_business_entity_targets,
            preferred_source_pool,
            locality_scope.as_deref(),
            selected_source_target,
        );
        for source in selected_local_business_target_sources(
            &query,
            &local_business_entity_targets,
            &source_pool,
            locality_scope.as_deref(),
            selected_source_target,
        ) {
            if selected.len() >= selected_source_target {
                break;
            }
            if selected.iter().any(|existing| {
                existing.url.eq_ignore_ascii_case(source.url.as_str())
                    || url_structurally_equivalent(existing.url.as_str(), source.url.as_str())
            }) {
                continue;
            }
            selected.push(source);
        }
        selected
    };
    let mut selected_story_tokens = Vec::<BTreeSet<String>>::new();
    if !local_business_entity_diversity_required {
        if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing) {
            seed_document_briefing_identifier_coverage_sources(
                &query,
                &candidates,
                preferred_source_pool,
                &mut selected_sources,
                selected_source_target,
            );
            if selected_sources.len() < selected_source_target {
                seed_document_briefing_identifier_coverage_sources(
                    &query,
                    &candidates,
                    &source_pool,
                    &mut selected_sources,
                    selected_source_target,
                );
            }
        }
        for source in preferred_source_pool {
            if selected_sources.len() >= selected_source_target {
                break;
            }
            if !draft_source_is_selectable(source) {
                continue;
            }
            if single_snapshot_mode && is_low_signal_excerpt(source.excerpt.as_str()) {
                continue;
            }
            let title = if local_business_entity_targets.is_empty() {
                canonical_source_title(source)
            } else {
                local_business_display_title(source, locality_scope.as_deref())
            };
            let source_tokens = if headline_lookup_mode {
                Some(headline_story_source_tokens(source))
            } else {
                None
            };
            if selected_sources
                .iter()
                .any(|existing: &PendingSearchReadSummary| {
                    titles_similar(&title, &canonical_source_title(existing))
                })
            {
                continue;
            }
            if let Some(tokens) = source_tokens.as_ref() {
                if selected_story_tokens.iter().any(|existing| {
                    !existing.is_empty() && !tokens.is_empty() && {
                        let overlap = existing.intersection(tokens).count();
                        let smaller = existing.len().min(tokens.len());
                        overlap >= 2 && overlap * 5 >= smaller * 2
                    }
                }) {
                    continue;
                }
            }
            selected_sources.push(source.clone());
            if let Some(tokens) = source_tokens {
                if !tokens.is_empty() {
                    selected_story_tokens.push(tokens);
                }
            }
            if selected_sources.len() >= selected_source_target {
                break;
            }
        }
        if selected_sources.len() < selected_source_target {
            for source in preferred_source_pool {
                if selected_sources.len() >= selected_source_target {
                    break;
                }
                if selected_sources.len() >= selected_source_target {
                    break;
                }
                if !draft_source_is_selectable(source) {
                    continue;
                }
                if selected_sources.iter().any(|existing| {
                    existing.url.eq_ignore_ascii_case(source.url.as_str())
                        || url_structurally_equivalent(existing.url.as_str(), source.url.as_str())
                }) {
                    continue;
                }
                if headline_lookup_mode {
                    let tokens = headline_story_source_tokens(source);
                    if selected_story_tokens.iter().any(|existing| {
                        !existing.is_empty() && !tokens.is_empty() && {
                            let overlap = existing.intersection(&tokens).count();
                            let smaller = existing.len().min(tokens.len());
                            overlap >= 2 && overlap * 5 >= smaller * 2
                        }
                    }) {
                        continue;
                    }
                    if !tokens.is_empty() {
                        selected_story_tokens.push(tokens);
                    }
                }
                selected_sources.push(source.clone());
            }
        }
        if headline_lookup_mode && selected_sources.len() < selected_source_target {
            for source in preferred_source_pool {
                if selected_sources.len() >= selected_source_target {
                    break;
                }
                if selected_sources.len() >= selected_source_target {
                    break;
                }
                if !draft_source_is_selectable(source) {
                    continue;
                }
                if selected_sources.iter().any(|existing| {
                    existing.url.eq_ignore_ascii_case(source.url.as_str())
                        || url_structurally_equivalent(existing.url.as_str(), source.url.as_str())
                }) {
                    continue;
                }
                selected_sources.push(source.clone());
            }
        }
        if headline_lookup_mode && selected_sources.len() < selected_source_target {
            for source in &source_pool {
                if selected_sources.len() >= selected_source_target {
                    break;
                }
                if selected_sources.len() >= selected_source_target {
                    break;
                }
                if !draft_source_is_selectable(source) {
                    continue;
                }
                if selected_sources.iter().any(|existing| {
                    existing.url.eq_ignore_ascii_case(source.url.as_str())
                        || url_structurally_equivalent(existing.url.as_str(), source.url.as_str())
                }) {
                    continue;
                }
                selected_sources.push(source.clone());
            }
        }
    }
    if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing) {
        repair_document_briefing_authority_identifier_coverage(
            &query,
            &candidates,
            &source_pool,
            &mut selected_sources,
            selected_source_target,
        );
        finalize_document_briefing_selected_sources(
            retrieval_contract,
            &query,
            &candidates,
            &source_pool,
            &mut selected_sources,
            selected_source_target,
        );
    }
    if single_snapshot_mode {
        finalize_single_snapshot_selected_sources(
            retrieval_contract,
            &query,
            &source_pool,
            &mut selected_sources,
            selected_source_target,
        );
    }
    if single_snapshot_mode && selected_sources.is_empty() {
        if let Some(source) = source_pool.first() {
            selected_sources.push(source.clone());
        }
    }
    backfill_selected_source_citation_candidates(
        &query,
        retrieval_contract,
        min_sources,
        &selected_sources,
        &run_timestamp_iso_utc,
        &mut candidates,
        &mut citations_by_id,
    );

    let mut used_citation_urls = BTreeSet::new();
    for source in selected_sources.iter().take(selected_source_target) {
        let title = if local_business_entity_targets.is_empty() {
            canonical_source_title(source)
        } else {
            local_business_display_title(source, locality_scope.as_deref())
        };
        let single_snapshot_source = if single_snapshot_mode {
            let focused_excerpt = prioritized_query_grounding_excerpt_with_contract(
                retrieval_contract,
                &query,
                pending.min_sources as usize,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
                WEB_PIPELINE_EXCERPT_CHARS,
            );
            if focused_excerpt.is_empty() {
                source.clone()
            } else {
                PendingSearchReadSummary {
                    url: source.url.clone(),
                    title: source.title.clone(),
                    excerpt: focused_excerpt,
                }
            }
        } else {
            source.clone()
        };
        let what_happened = if single_snapshot_mode {
            single_snapshot_summary_line_with_contract(
                retrieval_contract,
                &query,
                pending.min_sources as usize,
                &single_snapshot_source,
            )
        } else {
            source_bullet_for_query(&query, pending.min_sources as usize, source)
        };
        let why_it_matters = why_it_matters_from_story(source);
        let user_impact = user_impact_from_story(source);
        let workaround = workaround_from_story(source);
        let changed_last_hour = changed_last_hour_line(source, &run_timestamp_iso_utc);
        let citation_ids = citation_ids_for_story(
            source,
            &candidates,
            &mut used_citation_urls,
            citations_per_story,
            single_snapshot_mode || document_briefing_host_diversity_required,
            &single_snapshot_constraints,
            single_snapshot_policy,
        );
        let confident_reads = citation_ids
            .iter()
            .filter_map(|id| citations_by_id.get(id))
            .filter(|candidate| candidate.from_successful_read)
            .count();
        let confidence = if confident_reads >= citations_per_story {
            "high".to_string()
        } else if citation_ids.len() >= citations_per_story {
            "medium".to_string()
        } else {
            "low".to_string()
        };
        let eta_confidence = eta_confidence_from_story(
            source,
            confident_reads,
            citation_ids.len(),
            citations_per_story,
        );
        let caveat = "Timestamps are anchored to UTC retrieval time when source publish/update metadata was unavailable.".to_string();

        stories.push(StoryDraft {
            title,
            what_happened,
            changed_last_hour,
            why_it_matters,
            user_impact,
            workaround,
            eta_confidence,
            citation_ids,
            confidence,
            caveat,
        });
    }

    if single_snapshot_mode && stories.is_empty() {
        let mut fallback_source = if merged_sources.is_empty() {
            PendingSearchReadSummary {
                url: String::new(),
                title: None,
                excerpt: String::new(),
            }
        } else {
            merged_sources[0].clone()
        };
        let mut per_story_used_urls = BTreeSet::new();
        let fallback_ids = citation_ids_for_story(
            &fallback_source,
            &candidates,
            &mut per_story_used_urls,
            citations_per_story,
            true,
            &single_snapshot_constraints,
            single_snapshot_policy,
        );
        if fallback_source.url.trim().is_empty() {
            if let Some(primary_citation) = fallback_ids
                .iter()
                .filter_map(|id| citations_by_id.get(id))
                .next()
            {
                let fallback_excerpt = if primary_citation.excerpt.trim().is_empty() {
                    primary_citation.note.clone()
                } else {
                    primary_citation.excerpt.clone()
                };
                fallback_source = PendingSearchReadSummary {
                    url: primary_citation.url.clone(),
                    title: Some(primary_citation.source_label.clone()),
                    excerpt: fallback_excerpt,
                };
            }
        }
        let fallback_confident_reads = fallback_ids
            .iter()
            .filter_map(|id| citations_by_id.get(id))
            .filter(|candidate| candidate.from_successful_read)
            .count();
        let fallback_confidence = if fallback_confident_reads >= citations_per_story {
            "high".to_string()
        } else if fallback_ids.len() >= citations_per_story {
            "medium".to_string()
        } else {
            "low".to_string()
        };
        let fallback_eta_confidence = eta_confidence_from_story(
            &fallback_source,
            fallback_confident_reads,
            fallback_ids.len(),
            citations_per_story,
        );
        let fallback_single_snapshot_source = {
            let focused_excerpt = prioritized_query_grounding_excerpt_with_contract(
                retrieval_contract,
                &query,
                pending.min_sources as usize,
                &fallback_source.url,
                fallback_source.title.as_deref().unwrap_or_default(),
                &fallback_source.excerpt,
                WEB_PIPELINE_EXCERPT_CHARS,
            );
            if focused_excerpt.is_empty() {
                fallback_source.clone()
            } else {
                PendingSearchReadSummary {
                    url: fallback_source.url.clone(),
                    title: fallback_source.title.clone(),
                    excerpt: focused_excerpt,
                }
            }
        };
        stories.push(StoryDraft {
            title: canonical_source_title(&fallback_source),
            what_happened: single_snapshot_summary_line_with_contract(
                retrieval_contract,
                &query,
                pending.min_sources as usize,
                &fallback_single_snapshot_source,
            ),
            changed_last_hour: changed_last_hour_line(&fallback_source, &run_timestamp_iso_utc),
            why_it_matters: why_it_matters_from_story(&fallback_source),
            user_impact: user_impact_from_story(&fallback_source),
            workaround: workaround_from_story(&fallback_source),
            eta_confidence: fallback_eta_confidence,
            citation_ids: fallback_ids,
            confidence: fallback_confidence,
            caveat: "Evidence quality was limited; sections were composed from available citation metadata where explicit incident updates were sparse.".to_string(),
        });
    }

    if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing) {
        repair_document_briefing_story_citation_coverage(
            retrieval_contract,
            &query,
            &selected_sources,
            &mut stories,
            &candidates,
            &citations_by_id,
            citations_per_story,
        );
        refresh_story_citation_confidence(
            &selected_sources,
            &mut stories,
            &citations_by_id,
            citations_per_story,
        );
    }

    let blocked_urls = if readable_floor_unmet || stories.len() < required_story_count {
        pending
            .blocked_urls
            .iter()
            .map(|url| url.trim().to_string())
            .filter(|url| is_citable_web_url(url) && !successful_urls.contains(url))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    SynthesisDraft {
        query,
        retrieval_contract: pending.retrieval_contract.clone(),
        run_date,
        run_timestamp_ms,
        run_timestamp_iso_utc,
        completion_reason,
        overall_confidence: confidence_tier(pending, reason).to_string(),
        overall_caveat: format!(
            "Ontology={} ranking uses content, provenance, and recency evidence. InsightSelector={} applies relevance/reliability/recency/independence/risk vectors; provider/source timestamps may lag or omit explicit update metadata.",
            WEB_EVIDENCE_SIGNAL_VERSION,
            WEIGHTED_INSIGHT_SIGNAL_VERSION
        ),
        stories,
        citations_by_id,
        blocked_urls,
        partial_note,
    }
}

fn headline_story_topic_tokens(input: &str) -> BTreeSet<String> {
    const STORY_TOPIC_STOPWORDS: &[&str] = &[
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "into",
        "what",
        "happened",
        "story",
        "stories",
        "today",
        "top",
        "news",
        "headline",
        "headlines",
        "breaking",
        "latest",
        "update",
        "updates",
        "report",
        "reports",
        "source",
        "sources",
        "evidence",
        "media",
        "coverage",
        "live",
        "as",
        "of",
        "run",
        "timestamp",
        "utc",
        "us",
        "u",
        "s",
    ];
    input
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter_map(|token| {
            let normalized = token.trim();
            if normalized.len() < 3 {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if STORY_TOPIC_STOPWORDS.contains(&normalized) {
                return None;
            }
            Some(normalized.to_string())
        })
        .collect()
}

fn draft_source_is_selectable(source: &PendingSearchReadSummary) -> bool {
    let title = source.title.as_deref().unwrap_or_default();
    !source_has_human_challenge_signal(&source.url, title, &source.excerpt)
        && !source_has_terminal_error_signal(&source.url, title, &source.excerpt)
}

fn selected_sources_contains_equivalent_source(
    selected_sources: &[PendingSearchReadSummary],
    source: &PendingSearchReadSummary,
) -> bool {
    let title = canonical_source_title(source);
    selected_sources.iter().any(|existing| {
        existing.url.eq_ignore_ascii_case(source.url.as_str())
            || url_structurally_equivalent(existing.url.as_str(), source.url.as_str())
            || titles_similar(&title, &canonical_source_title(existing))
    })
}

fn citation_candidates_contain_equivalent_url(candidates: &[CitationCandidate], url: &str) -> bool {
    existing_citation_candidate_index_for_url(candidates, url).is_some()
}

fn existing_citation_candidate_index_for_url(
    candidates: &[CitationCandidate],
    url: &str,
) -> Option<usize> {
    let trimmed = url.trim();
    (!trimmed.is_empty()).then_some(())?;
    candidates.iter().position(|candidate| {
        let candidate_url = candidate.url.trim();
        !candidate_url.is_empty()
            && (candidate_url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(candidate_url, trimmed))
    })
}

fn citation_surface_quality_key(
    query: &str,
    url: &str,
    source_label: &str,
    excerpt: &str,
) -> (usize, usize, bool) {
    (
        source_briefing_standard_identifier_labels(query, url, source_label, excerpt).len(),
        usize::from(source_has_document_authority(
            query,
            url,
            source_label,
            excerpt,
        )),
        !excerpt.trim().is_empty(),
    )
}

fn backfill_selected_source_citation_candidates(
    query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    min_sources: usize,
    selected_sources: &[PendingSearchReadSummary],
    run_timestamp_iso_utc: &str,
    candidates: &mut Vec<CitationCandidate>,
    citations_by_id: &mut BTreeMap<String, CitationCandidate>,
) {
    let mut next_candidate_num = candidates
        .iter()
        .filter_map(|candidate| candidate.id.strip_prefix('C'))
        .filter_map(|value| value.parse::<usize>().ok())
        .max()
        .unwrap_or(0);

    for source in selected_sources {
        let trimmed_url = source.url.trim();
        if trimmed_url.is_empty()
            || !is_citable_web_url(trimmed_url)
            || is_search_hub_url(trimmed_url)
        {
            continue;
        }

        let source_label = canonical_source_title_for_query(query, source);
        let excerpt = preferred_citation_excerpt_with_contract(
            retrieval_contract,
            query,
            min_sources.max(1),
            trimmed_url,
            source_label.as_str(),
            source.excerpt.as_str(),
            180,
        );
        if let Some(existing_idx) =
            existing_citation_candidate_index_for_url(candidates, trimmed_url)
        {
            let existing = &mut candidates[existing_idx];
            let replace_excerpt =
                citation_surface_quality_key(query, trimmed_url, source_label.as_str(), &excerpt)
                    > citation_surface_quality_key(
                        query,
                        trimmed_url,
                        existing.source_label.as_str(),
                        existing.excerpt.as_str(),
                    );
            let replace_label = existing.source_label.trim().is_empty()
                || (is_low_signal_title(existing.source_label.as_str())
                    && !is_low_signal_title(source_label.as_str()));
            if replace_excerpt {
                existing.excerpt = excerpt.clone();
            }
            if replace_label {
                existing.source_label = source_label.clone();
            }
            if replace_excerpt || replace_label {
                citations_by_id.insert(existing.id.clone(), existing.clone());
            }
            continue;
        }
        next_candidate_num = next_candidate_num.saturating_add(1);
        let candidate = CitationCandidate {
            id: format!("C{}", next_candidate_num),
            url: trimmed_url.to_string(),
            source_label,
            excerpt,
            timestamp_utc: run_timestamp_iso_utc.to_string(),
            note: "retrieved_utc; selected-source citation inventory backfill from successful read"
                .to_string(),
            from_successful_read: true,
        };
        citations_by_id.insert(candidate.id.clone(), candidate.clone());
        candidates.push(candidate);
    }
}

fn document_briefing_sources_share_url_identity(
    left: &PendingSearchReadSummary,
    right: &PendingSearchReadSummary,
) -> bool {
    left.url.eq_ignore_ascii_case(right.url.as_str())
        || url_structurally_equivalent(left.url.as_str(), right.url.as_str())
}

fn document_briefing_domain_key(source: &PendingSearchReadSummary) -> Option<String> {
    let host = source_host(source.url.trim())?;
    let normalized = host.trim().trim_start_matches("www.").to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    let labels = normalized.split('.').collect::<Vec<_>>();
    if labels.len() >= 2 {
        Some(format!(
            "{}.{}",
            labels[labels.len() - 2],
            labels[labels.len() - 1]
        ))
    } else {
        Some(normalized)
    }
}

fn document_briefing_distinct_domain_count(sources: &[PendingSearchReadSummary]) -> usize {
    sources
        .iter()
        .filter_map(document_briefing_domain_key)
        .collect::<BTreeSet<_>>()
        .len()
}

fn document_briefing_identifier_surface_for_source(
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
) -> String {
    let matching_candidates = candidates
        .iter()
        .filter(|candidate| {
            candidate.from_successful_read
                && !candidate.url.trim().is_empty()
                && document_briefing_sources_share_url_identity(
                    source,
                    &PendingSearchReadSummary {
                        url: candidate.url.clone(),
                        title: Some(candidate.source_label.clone()),
                        excerpt: candidate.excerpt.clone(),
                    },
                )
        })
        .collect::<Vec<_>>();
    let mut segments = Vec::new();
    let mut seen_segments = BTreeSet::new();
    let mut push_segment = |segment: &str| {
        let compact = compact_whitespace(segment);
        if compact.is_empty() {
            return;
        }
        let key = compact.to_ascii_lowercase();
        if seen_segments.insert(key) {
            segments.push(compact);
        }
    };
    if let Some(title) = source.title.as_deref().map(str::trim) {
        push_segment(title);
    }
    push_segment(&source.excerpt);
    push_segment(&source.url);
    for candidate in matching_candidates {
        push_segment(&candidate.source_label);
        push_segment(&candidate.excerpt);
        push_segment(&candidate.url);
    }
    compact_whitespace(&segments.join(" "))
}

fn document_briefing_has_document_authority(
    query: &str,
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
) -> bool {
    let title = source.title.as_deref().unwrap_or_default();
    let authority_surface = document_briefing_identifier_surface_for_source(source, candidates);
    source_has_document_authority(query, &source.url, title, &authority_surface)
}

fn document_briefing_document_authority_score(
    query: &str,
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
) -> usize {
    let title = source.title.as_deref().unwrap_or_default();
    let authority_surface = document_briefing_identifier_surface_for_source(source, candidates);
    source_document_authority_score(query, &source.url, title, &authority_surface)
}

fn document_briefing_authoritative_required_identifier_labels_for_source(
    query: &str,
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
    required_labels: &BTreeSet<String>,
) -> BTreeSet<String> {
    if !document_briefing_has_document_authority(query, source, candidates) {
        return BTreeSet::new();
    }
    document_briefing_required_identifier_labels_for_source(
        query,
        source,
        candidates,
        required_labels,
    )
}

fn briefing_identifier_observation_for_source(
    query: &str,
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
) -> Option<BriefingIdentifierObservation> {
    let trimmed_url = source.url.trim();
    (!trimmed_url.is_empty()).then(|| {
        let title = source.title.as_deref().unwrap_or_default();
        let surface = document_briefing_identifier_surface_for_source(source, candidates);
        BriefingIdentifierObservation {
            url: trimmed_url.to_string(),
            authoritative: source_has_document_authority(query, trimmed_url, title, &surface),
            surface,
        }
    })
}

fn required_document_briefing_identifier_labels(
    query: &str,
    sources: &[PendingSearchReadSummary],
    candidates: &[CitationCandidate],
) -> BTreeSet<String> {
    let mut observations = sources
        .iter()
        .filter_map(|source| briefing_identifier_observation_for_source(query, source, candidates))
        .collect::<Vec<_>>();
    let seen_urls = observations
        .iter()
        .map(|observation| observation.url.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    observations.extend(candidates.iter().filter_map(|candidate| {
        let trimmed_url = candidate.url.trim();
        (!trimmed_url.is_empty()
            && !seen_urls.contains(&trimmed_url.to_ascii_lowercase())
            && candidate.from_successful_read)
            .then(|| BriefingIdentifierObservation {
                url: trimmed_url.to_string(),
                authoritative: source_has_document_authority(
                    query,
                    &candidate.url,
                    &candidate.source_label,
                    &candidate.excerpt,
                ),
                surface: format!(
                    "{} {} {}",
                    candidate.url, candidate.source_label, candidate.excerpt
                ),
            })
    }));
    infer_briefing_required_identifier_labels(query, &observations)
}

fn document_briefing_required_identifier_labels_for_source(
    query: &str,
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
    required_labels: &BTreeSet<String>,
) -> BTreeSet<String> {
    let surface = document_briefing_identifier_surface_for_source(source, candidates);
    observed_briefing_standard_identifier_labels(query, &surface)
        .into_iter()
        .filter(|label| required_labels.contains(label))
        .collect()
}

fn seed_document_briefing_identifier_coverage_sources(
    query: &str,
    candidates: &[CitationCandidate],
    source_pool: &[PendingSearchReadSummary],
    selected_sources: &mut Vec<PendingSearchReadSummary>,
    selected_source_target: usize,
) {
    if selected_sources.len() >= selected_source_target {
        return;
    }

    let required_labels =
        required_document_briefing_identifier_labels(query, source_pool, candidates);
    if required_labels.is_empty() {
        return;
    }

    let mut covered_labels = selected_sources
        .iter()
        .flat_map(|source| {
            document_briefing_required_identifier_labels_for_source(
                query,
                source,
                candidates,
                &required_labels,
            )
        })
        .collect::<BTreeSet<_>>();

    while selected_sources.len() < selected_source_target {
        let best_idx = source_pool
            .iter()
            .enumerate()
            .filter_map(|(idx, source)| {
                if !draft_source_is_selectable(source)
                    || selected_sources_contains_equivalent_source(selected_sources, source)
                {
                    return None;
                }

                let required_hits = document_briefing_required_identifier_labels_for_source(
                    query,
                    source,
                    candidates,
                    &required_labels,
                );
                if required_hits.is_empty() {
                    return None;
                }

                let new_required_hits = required_hits.difference(&covered_labels).count();
                if new_required_hits == 0 {
                    return None;
                }

                let authoritative =
                    document_briefing_has_document_authority(query, source, candidates);
                let authority_score =
                    document_briefing_document_authority_score(query, source, candidates);
                Some((
                    idx,
                    (
                        authoritative,
                        new_required_hits,
                        authority_score,
                        required_hits.len(),
                        !is_low_priority_coverage_story(source),
                        !is_low_signal_excerpt(source.excerpt.as_str()),
                    ),
                ))
            })
            .max_by(|(left_idx, left_key), (right_idx, right_key)| {
                left_key
                    .cmp(right_key)
                    .then_with(|| source_pool[*right_idx].url.cmp(&source_pool[*left_idx].url))
            })
            .map(|(idx, _)| idx);

        let Some(best_idx) = best_idx else {
            break;
        };
        let source = source_pool[best_idx].clone();
        covered_labels.extend(document_briefing_required_identifier_labels_for_source(
            query,
            &source,
            candidates,
            &required_labels,
        ));
        selected_sources.push(source);
        if covered_labels.len() >= required_labels.len() {
            break;
        }
    }
}

fn repair_document_briefing_authority_identifier_coverage(
    query: &str,
    candidates: &[CitationCandidate],
    source_pool: &[PendingSearchReadSummary],
    selected_sources: &mut Vec<PendingSearchReadSummary>,
    selected_source_target: usize,
) {
    if selected_source_target == 0 {
        return;
    }

    let required_labels =
        required_document_briefing_identifier_labels(query, source_pool, candidates);
    if required_labels.is_empty() {
        return;
    }
    let required_floor = required_labels.len();

    let selected_authority_label_count = |sources: &[PendingSearchReadSummary]| {
        sources
            .iter()
            .flat_map(|source| {
                document_briefing_authoritative_required_identifier_labels_for_source(
                    query,
                    source,
                    candidates,
                    &required_labels,
                )
            })
            .collect::<BTreeSet<_>>()
            .len()
    };
    let selected_required_label_count = |sources: &[PendingSearchReadSummary]| {
        sources
            .iter()
            .flat_map(|source| {
                document_briefing_required_identifier_labels_for_source(
                    query,
                    source,
                    candidates,
                    &required_labels,
                )
            })
            .collect::<BTreeSet<_>>()
            .len()
    };

    while selected_authority_label_count(selected_sources) < required_floor {
        let authoritative_labels = selected_sources
            .iter()
            .flat_map(|source| {
                document_briefing_authoritative_required_identifier_labels_for_source(
                    query,
                    source,
                    candidates,
                    &required_labels,
                )
            })
            .collect::<BTreeSet<_>>();

        let best_candidate_idx = source_pool
            .iter()
            .enumerate()
            .filter_map(|(idx, source)| {
                if !draft_source_is_selectable(source)
                    || selected_sources_contains_equivalent_source(selected_sources, source)
                {
                    return None;
                }

                if !document_briefing_has_document_authority(query, source, candidates) {
                    return None;
                }

                let required_hits = document_briefing_required_identifier_labels_for_source(
                    query,
                    source,
                    candidates,
                    &required_labels,
                );
                if required_hits.is_empty() {
                    return None;
                }

                let new_authority_hits = required_hits.difference(&authoritative_labels).count();
                if new_authority_hits == 0 {
                    return None;
                }

                let authority_score =
                    document_briefing_document_authority_score(query, source, candidates);
                Some((
                    idx,
                    (
                        new_authority_hits,
                        required_hits.len(),
                        authority_score,
                        !is_low_priority_coverage_story(source),
                        !is_low_signal_excerpt(source.excerpt.as_str()),
                    ),
                ))
            })
            .max_by(|(left_idx, left_key), (right_idx, right_key)| {
                left_key
                    .cmp(right_key)
                    .then_with(|| source_pool[*right_idx].url.cmp(&source_pool[*left_idx].url))
            })
            .map(|(idx, _)| idx);

        let Some(best_candidate_idx) = best_candidate_idx else {
            break;
        };
        let candidate = source_pool[best_candidate_idx].clone();

        if selected_sources.len() < selected_source_target {
            selected_sources.push(candidate);
            continue;
        }

        let replacement_idx = selected_sources
            .iter()
            .enumerate()
            .map(|(idx, source)| {
                let source_required_hits = document_briefing_required_identifier_labels_for_source(
                    query,
                    source,
                    candidates,
                    &required_labels,
                )
                .len();
                let source_authority_hits =
                    document_briefing_authoritative_required_identifier_labels_for_source(
                        query,
                        source,
                        candidates,
                        &required_labels,
                    )
                    .len();
                let remaining_sources = selected_sources
                    .iter()
                    .enumerate()
                    .filter(|(other_idx, _)| *other_idx != idx)
                    .map(|(_, source)| source.clone())
                    .chain(std::iter::once(candidate.clone()))
                    .collect::<Vec<_>>();
                (
                    idx,
                    (
                        selected_authority_label_count(&remaining_sources) < required_floor,
                        selected_required_label_count(&remaining_sources) < required_floor,
                        source_authority_hits,
                        source_required_hits,
                        document_briefing_document_authority_score(query, source, candidates),
                        source.url.clone(),
                    ),
                )
            })
            .min_by(|(_, left_key), (_, right_key)| left_key.cmp(right_key))
            .map(|(idx, _)| idx);

        let Some(replacement_idx) = replacement_idx else {
            break;
        };
        selected_sources[replacement_idx] = candidate;
    }
}

fn finalize_document_briefing_selected_sources(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query: &str,
    candidates: &[CitationCandidate],
    source_pool: &[PendingSearchReadSummary],
    selected_sources: &mut Vec<PendingSearchReadSummary>,
    selected_source_target: usize,
) {
    if selected_source_target == 0 {
        selected_sources.clear();
        return;
    }

    let required_labels =
        required_document_briefing_identifier_labels(query, source_pool, candidates);
    let required_floor = required_labels.len();
    let required_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query)
            .min(selected_source_target);
    let initially_selected_urls = selected_sources
        .iter()
        .map(|source| source.url.trim().to_ascii_lowercase())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>();
    let mut pool = Vec::<PendingSearchReadSummary>::new();
    for source in selected_sources.iter().chain(source_pool.iter()) {
        if !draft_source_is_selectable(source)
            || pool
                .iter()
                .any(|existing| document_briefing_sources_share_url_identity(existing, source))
        {
            continue;
        }
        pool.push(source.clone());
    }
    if pool.is_empty() {
        selected_sources.clear();
        return;
    }

    let enforce_domain_diversity = required_domain_floor > 1
        && document_briefing_distinct_domain_count(&pool) >= required_domain_floor;

    let authoritative_required_available = required_floor > 0
        && pool.iter().any(|source| {
            !document_briefing_authoritative_required_identifier_labels_for_source(
                query,
                source,
                candidates,
                &required_labels,
            )
            .is_empty()
        });
    let mut finalized = Vec::<PendingSearchReadSummary>::new();
    let mut covered_required = BTreeSet::<String>::new();
    let mut covered_authority = BTreeSet::<String>::new();
    let mut covered_domains = BTreeSet::<String>::new();

    while finalized.len() < selected_source_target {
        let identifier_coverage_complete = required_floor == 0
            || (covered_required.len() >= required_floor
                && (!authoritative_required_available
                    || covered_authority.len() >= required_floor));
        let domain_coverage_complete =
            !enforce_domain_diversity || covered_domains.len() >= required_domain_floor;
        let best_idx = pool
            .iter()
            .enumerate()
            .filter(|(_, source)| {
                !finalized
                    .iter()
                    .any(|existing| document_briefing_sources_share_url_identity(existing, source))
            })
            .filter_map(|(idx, source)| {
                let required_hits = document_briefing_required_identifier_labels_for_source(
                    query,
                    source,
                    candidates,
                    &required_labels,
                );
                let authority_hits =
                    document_briefing_authoritative_required_identifier_labels_for_source(
                        query,
                        source,
                        candidates,
                        &required_labels,
                    );
                let new_required_hits = required_hits.difference(&covered_required).count();
                let new_authority_hits = authority_hits.difference(&covered_authority).count();
                let introduces_new_domain = document_briefing_domain_key(source)
                    .map(|domain| !covered_domains.contains(&domain))
                    .unwrap_or(false);
                if !identifier_coverage_complete
                    && new_required_hits == 0
                    && new_authority_hits == 0
                {
                    return None;
                }
                if !domain_coverage_complete
                    && !introduces_new_domain
                    && identifier_coverage_complete
                {
                    return None;
                }
                let title = source.title.as_deref().unwrap_or_default();
                let excerpt = source.excerpt.as_str();
                let authority_score =
                    document_briefing_document_authority_score(query, source, candidates);
                let supports_domain_diversity = new_authority_hits > 0
                    || new_required_hits > 0
                    || source_has_document_briefing_authority_alignment_with_contract(
                        retrieval_contract,
                        query,
                        selected_source_target,
                        &source.url,
                        title,
                        excerpt,
                    );
                if !domain_coverage_complete
                    && introduces_new_domain
                    && identifier_coverage_complete
                    && !supports_domain_diversity
                {
                    return None;
                }
                let initially_selected =
                    initially_selected_urls.contains(&source.url.trim().to_ascii_lowercase());
                Some((
                    idx,
                    (
                        new_authority_hits,
                        new_required_hits,
                        introduces_new_domain,
                        !authority_hits.is_empty(),
                        authority_score,
                        required_hits.len(),
                        initially_selected,
                        !is_low_priority_coverage_story(source),
                        !is_low_signal_excerpt(source.excerpt.as_str()),
                    ),
                ))
            })
            .max_by(|(left_idx, left_key), (right_idx, right_key)| {
                left_key
                    .cmp(right_key)
                    .then_with(|| pool[*right_idx].url.cmp(&pool[*left_idx].url))
            })
            .map(|(idx, _)| idx);
        let Some(best_idx) = best_idx else {
            break;
        };
        let source = pool[best_idx].clone();
        covered_required.extend(document_briefing_required_identifier_labels_for_source(
            query,
            &source,
            candidates,
            &required_labels,
        ));
        covered_authority.extend(
            document_briefing_authoritative_required_identifier_labels_for_source(
                query,
                &source,
                candidates,
                &required_labels,
            ),
        );
        if let Some(domain) = document_briefing_domain_key(&source) {
            covered_domains.insert(domain);
        }
        finalized.push(source);
    }

    if finalized.len() < selected_source_target {
        let finalized_domains = finalized
            .iter()
            .filter_map(document_briefing_domain_key)
            .collect::<BTreeSet<_>>();
        let mut remaining = pool
            .into_iter()
            .filter(|source| {
                !finalized
                    .iter()
                    .any(|existing| document_briefing_sources_share_url_identity(existing, source))
            })
            .collect::<Vec<_>>();
        remaining.sort_by(|left, right| {
            let left_required_hits = document_briefing_required_identifier_labels_for_source(
                query,
                left,
                candidates,
                &required_labels,
            )
            .len();
            let right_required_hits = document_briefing_required_identifier_labels_for_source(
                query,
                right,
                candidates,
                &required_labels,
            )
            .len();
            let left_authority_hits =
                document_briefing_authoritative_required_identifier_labels_for_source(
                    query,
                    left,
                    candidates,
                    &required_labels,
                )
                .len();
            let right_authority_hits =
                document_briefing_authoritative_required_identifier_labels_for_source(
                    query,
                    right,
                    candidates,
                    &required_labels,
                )
                .len();
            let left_authority_score =
                document_briefing_document_authority_score(query, left, candidates);
            let right_authority_score =
                document_briefing_document_authority_score(query, right, candidates);
            let left_initially_selected =
                initially_selected_urls.contains(&left.url.trim().to_ascii_lowercase());
            let right_initially_selected =
                initially_selected_urls.contains(&right.url.trim().to_ascii_lowercase());
            let left_supports_domain_gain = left_authority_hits > 0
                || left_required_hits > 0
                || source_has_document_briefing_authority_alignment_with_contract(
                    retrieval_contract,
                    query,
                    selected_source_target,
                    &left.url,
                    left.title.as_deref().unwrap_or_default(),
                    left.excerpt.as_str(),
                );
            let right_supports_domain_gain = right_authority_hits > 0
                || right_required_hits > 0
                || source_has_document_briefing_authority_alignment_with_contract(
                    retrieval_contract,
                    query,
                    selected_source_target,
                    &right.url,
                    right.title.as_deref().unwrap_or_default(),
                    right.excerpt.as_str(),
                );
            let left_domain_gain = enforce_domain_diversity
                && finalized_domains.len() < required_domain_floor
                && document_briefing_domain_key(left)
                    .map(|domain| !finalized_domains.contains(&domain))
                    .unwrap_or(false)
                && left_supports_domain_gain;
            let right_domain_gain = enforce_domain_diversity
                && finalized_domains.len() < required_domain_floor
                && document_briefing_domain_key(right)
                    .map(|domain| !finalized_domains.contains(&domain))
                    .unwrap_or(false)
                && right_supports_domain_gain;
            (
                right_domain_gain,
                right_authority_hits,
                right_required_hits,
                right_authority_score,
                right_initially_selected,
                !is_low_priority_coverage_story(right),
                !is_low_signal_excerpt(right.excerpt.as_str()),
                &right.url,
            )
                .cmp(&(
                    left_domain_gain,
                    left_authority_hits,
                    left_required_hits,
                    left_authority_score,
                    left_initially_selected,
                    !is_low_priority_coverage_story(left),
                    !is_low_signal_excerpt(left.excerpt.as_str()),
                    &left.url,
                ))
        });
        for source in remaining {
            if finalized.len() >= selected_source_target {
                break;
            }
            finalized.push(source);
        }
    }

    *selected_sources = finalized;
}

fn finalize_single_snapshot_selected_sources(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query: &str,
    source_pool: &[PendingSearchReadSummary],
    selected_sources: &mut Vec<PendingSearchReadSummary>,
    selected_source_target: usize,
) {
    if selected_source_target == 0 {
        selected_sources.clear();
        return;
    }

    let subject_identity_required = query_requires_subject_currentness_identity(query);
    let primary_authority_required =
        crate::agentic::runtime::service::step::queue::support::retrieval_contract_requires_primary_authority_source(
            retrieval_contract,
            query,
        );

    if !primary_authority_required && !subject_identity_required {
        if selected_sources.len() > selected_source_target {
            selected_sources.truncate(selected_source_target);
        }
        return;
    }

    if subject_identity_required {
        let mut identity_pool = selected_sources
            .iter()
            .chain(source_pool.iter())
            .filter(|source| draft_source_is_selectable(source))
            .filter(|source| {
                let surface = format!(
                    "{} {}",
                    source.title.as_deref().unwrap_or_default(),
                    source.excerpt
                );
                first_subject_currentness_sentence(&surface).is_some()
            })
            .cloned()
            .collect::<Vec<_>>();
        identity_pool.dedup_by(|left, right| {
            left.url.eq_ignore_ascii_case(&right.url)
                || url_structurally_equivalent(&left.url, &right.url)
        });

        identity_pool.sort_by(|left, right| {
            let left_surface = format!(
                "{} {}",
                left.title.as_deref().unwrap_or_default(),
                left.excerpt
            );
            let right_surface = format!(
                "{} {}",
                right.title.as_deref().unwrap_or_default(),
                right.excerpt
            );
            let left_key = (
                first_current_role_holder_sentence(&left_surface).is_some(),
                source_counts_as_primary_authority(
                    query,
                    &left.url,
                    left.title.as_deref().unwrap_or_default(),
                    &left.excerpt,
                ),
                source_document_authority_score(
                    query,
                    &left.url,
                    left.title.as_deref().unwrap_or_default(),
                    &left.excerpt,
                ),
                !is_low_signal_excerpt(left.excerpt.as_str()),
            );
            let right_key = (
                first_current_role_holder_sentence(&right_surface).is_some(),
                source_counts_as_primary_authority(
                    query,
                    &right.url,
                    right.title.as_deref().unwrap_or_default(),
                    &right.excerpt,
                ),
                source_document_authority_score(
                    query,
                    &right.url,
                    right.title.as_deref().unwrap_or_default(),
                    &right.excerpt,
                ),
                !is_low_signal_excerpt(right.excerpt.as_str()),
            );
            right_key
                .cmp(&left_key)
                .then_with(|| left.url.cmp(&right.url))
        });

        if let Some(best_identity_source) = identity_pool.into_iter().next() {
            let mut finalized = vec![best_identity_source];
            for source in selected_sources.iter() {
                if finalized.len() >= selected_source_target {
                    break;
                }
                if finalized.iter().any(|existing| {
                    existing.url.eq_ignore_ascii_case(&source.url)
                        || url_structurally_equivalent(&existing.url, &source.url)
                }) {
                    continue;
                }
                finalized.push(source.clone());
            }
            *selected_sources = finalized;
            return;
        }
    }

    let mut authority_pool = selected_sources
        .iter()
        .chain(source_pool.iter())
        .filter(|source| draft_source_is_selectable(source))
        .filter(|source| {
            source_counts_as_primary_authority(
                query,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    authority_pool.dedup_by(|left, right| {
        left.url.eq_ignore_ascii_case(&right.url)
            || url_structurally_equivalent(&left.url, &right.url)
    });

    authority_pool.sort_by(|left, right| {
        let left_surface = format!(
            "{} {}",
            left.title.as_deref().unwrap_or_default(),
            left.excerpt
        );
        let right_surface = format!(
            "{} {}",
            right.title.as_deref().unwrap_or_default(),
            right.excerpt
        );
        let left_key = (
            contains_current_condition_metric_signal(&left_surface),
            has_quantitative_metric_payload(&left_surface, false),
            source_document_authority_score(
                query,
                &left.url,
                left.title.as_deref().unwrap_or_default(),
                &left.excerpt,
            ),
            !is_low_signal_excerpt(left.excerpt.as_str()),
        );
        let right_key = (
            contains_current_condition_metric_signal(&right_surface),
            has_quantitative_metric_payload(&right_surface, false),
            source_document_authority_score(
                query,
                &right.url,
                right.title.as_deref().unwrap_or_default(),
                &right.excerpt,
            ),
            !is_low_signal_excerpt(right.excerpt.as_str()),
        );
        right_key
            .cmp(&left_key)
            .then_with(|| left.url.cmp(&right.url))
    });

    let Some(best_authority_source) = authority_pool.into_iter().next() else {
        if selected_sources.len() > selected_source_target {
            selected_sources.truncate(selected_source_target);
        }
        return;
    };

    let mut finalized = vec![best_authority_source];
    for source in selected_sources.iter() {
        if finalized.len() >= selected_source_target {
            break;
        }
        if finalized.iter().any(|existing| {
            existing.url.eq_ignore_ascii_case(&source.url)
                || url_structurally_equivalent(&existing.url, &source.url)
        }) {
            continue;
        }
        finalized.push(source.clone());
    }
    *selected_sources = finalized;
}

fn document_briefing_candidate_required_identifier_labels(
    query: &str,
    candidate: &CitationCandidate,
    required_labels: &BTreeSet<String>,
) -> BTreeSet<String> {
    if !candidate.from_successful_read {
        return BTreeSet::new();
    }
    observed_briefing_standard_identifier_labels(
        query,
        &format!(
            "{} {} {}",
            candidate.url, candidate.source_label, candidate.excerpt
        ),
    )
    .into_iter()
    .filter(|label| required_labels.contains(label))
    .collect()
}

fn document_briefing_candidate_authoritative_required_identifier_labels(
    query: &str,
    candidate: &CitationCandidate,
    required_labels: &BTreeSet<String>,
) -> BTreeSet<String> {
    if !source_has_document_authority(
        query,
        &candidate.url,
        &candidate.source_label,
        &candidate.excerpt,
    ) {
        return BTreeSet::new();
    }
    document_briefing_candidate_required_identifier_labels(query, candidate, required_labels)
}

fn document_briefing_authority_labels_from_story_citation_ids(
    query: &str,
    story_citation_ids: &[Vec<String>],
    citations_by_id: &BTreeMap<String, CitationCandidate>,
    required_labels: &BTreeSet<String>,
) -> BTreeSet<String> {
    story_citation_ids
        .iter()
        .flat_map(|citation_ids| citation_ids.iter())
        .filter_map(|citation_id| citations_by_id.get(citation_id))
        .flat_map(|candidate| {
            document_briefing_candidate_authoritative_required_identifier_labels(
                query,
                candidate,
                required_labels,
            )
        })
        .collect()
}

fn story_contains_equivalent_citation(
    story: &StoryDraft,
    candidate: &CitationCandidate,
    citations_by_id: &BTreeMap<String, CitationCandidate>,
) -> bool {
    story.citation_ids.iter().any(|citation_id| {
        if citation_id == &candidate.id {
            return true;
        }
        citations_by_id
            .get(citation_id)
            .map(|existing| {
                existing.url.eq_ignore_ascii_case(candidate.url.as_str())
                    || url_structurally_equivalent(existing.url.as_str(), candidate.url.as_str())
            })
            .unwrap_or(false)
    })
}

fn repair_document_briefing_story_citation_coverage(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query: &str,
    story_sources: &[PendingSearchReadSummary],
    stories: &mut [StoryDraft],
    candidates: &[CitationCandidate],
    citations_by_id: &BTreeMap<String, CitationCandidate>,
    citations_per_story: usize,
) {
    if stories.is_empty() || citations_per_story == 0 {
        return;
    }

    let required_labels =
        required_document_briefing_identifier_labels(query, story_sources, candidates);
    if required_labels.is_empty() {
        return;
    }

    let authoritative_candidates = candidates
        .iter()
        .filter(|candidate| {
            candidate.from_successful_read
                && source_has_document_authority(
                    query,
                    &candidate.url,
                    &candidate.source_label,
                    &candidate.excerpt,
                )
        })
        .collect::<Vec<_>>();
    if authoritative_candidates.is_empty() {
        return;
    }

    let story_citation_ids = |stories: &[StoryDraft]| {
        stories
            .iter()
            .map(|story| story.citation_ids.clone())
            .collect::<Vec<_>>()
    };
    let authoritative_identifier_citation_urls = |stories: &[StoryDraft]| {
        story_citation_ids(stories)
            .iter()
            .flat_map(|citation_ids| citation_ids.iter())
            .filter_map(|citation_id| citations_by_id.get(citation_id))
            .filter(|candidate| {
                !document_briefing_candidate_authoritative_required_identifier_labels(
                    query,
                    candidate,
                    &required_labels,
                )
                .is_empty()
            })
            .map(|candidate| candidate.url.trim().to_ascii_lowercase())
            .filter(|url| !url.is_empty())
            .collect::<BTreeSet<_>>()
    };
    let mut current_authority_labels = document_briefing_authority_labels_from_story_citation_ids(
        query,
        &story_citation_ids(stories),
        citations_by_id,
        &required_labels,
    );
    let authoritative_identifier_candidate_count = authoritative_candidates
        .iter()
        .filter(|candidate| {
            !document_briefing_candidate_authoritative_required_identifier_labels(
                query,
                candidate,
                &required_labels,
            )
            .is_empty()
        })
        .map(|candidate| candidate.url.trim().to_ascii_lowercase())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>()
        .len();
    let target_authority_identifier_citation_count =
        crate::agentic::runtime::service::step::queue::support::retrieval_contract_primary_authority_source_slot_cap(
            retrieval_contract,
            query,
            citations_per_story.max(1),
        )
        .min(authoritative_identifier_candidate_count);

    while current_authority_labels.len() < required_labels.len()
        || authoritative_identifier_citation_urls(stories).len()
            < target_authority_identifier_citation_count
    {
        let current_authority_identifier_urls = authoritative_identifier_citation_urls(stories);
        let current_authority_identifier_count = current_authority_identifier_urls.len();
        let best_candidate = authoritative_candidates
            .iter()
            .filter_map(|candidate| {
                let labels = document_briefing_candidate_authoritative_required_identifier_labels(
                    query,
                    candidate,
                    &required_labels,
                );
                let new_hits = labels.difference(&current_authority_labels).count();
                let candidate_url = candidate.url.trim().to_ascii_lowercase();
                let adds_authority_identifier_citation = !candidate_url.is_empty()
                    && !current_authority_identifier_urls.contains(&candidate_url);
                if new_hits == 0 && !adds_authority_identifier_citation {
                    return None;
                }
                Some((
                    *candidate,
                    labels,
                    new_hits,
                    adds_authority_identifier_citation,
                    source_document_authority_score(
                        query,
                        &candidate.url,
                        &candidate.source_label,
                        &candidate.excerpt,
                    ),
                ))
            })
            .max_by(|left, right| {
                (
                    left.2,
                    left.3,
                    left.1.len(),
                    left.4,
                    !left.0.excerpt.trim().is_empty(),
                    &left.0.url,
                )
                    .cmp(&(
                        right.2,
                        right.3,
                        right.1.len(),
                        right.4,
                        !right.0.excerpt.trim().is_empty(),
                        &right.0.url,
                    ))
            });
        let Some((candidate, _, _, _, authority_score)) = best_candidate else {
            break;
        };

        let best_placement = stories
            .iter()
            .enumerate()
            .filter_map(|(story_idx, story)| {
                let source = story_sources.get(story_idx)?;
                if story_contains_equivalent_citation(story, candidate, citations_by_id) {
                    return None;
                }
                let relevance = citation_relevance_score(source, candidate);
                if story.citation_ids.len() < citations_per_story {
                    let mut hypothetical = story_citation_ids(stories);
                    hypothetical[story_idx].push(candidate.id.clone());
                    let hypothetical_labels =
                        document_briefing_authority_labels_from_story_citation_ids(
                            query,
                            &hypothetical,
                            citations_by_id,
                            &required_labels,
                        );
                    let label_gain = hypothetical_labels
                        .len()
                        .saturating_sub(current_authority_labels.len());
                    let hypothetical_authority_identifier_count = hypothetical
                        .iter()
                        .flat_map(|citation_ids| citation_ids.iter())
                        .filter_map(|citation_id| citations_by_id.get(citation_id))
                        .filter(|candidate| {
                            !document_briefing_candidate_authoritative_required_identifier_labels(
                                query,
                                candidate,
                                &required_labels,
                            )
                            .is_empty()
                        })
                        .map(|candidate| candidate.url.trim().to_ascii_lowercase())
                        .filter(|url| !url.is_empty())
                        .collect::<BTreeSet<_>>()
                        .len();
                    let authority_identifier_gain = hypothetical_authority_identifier_count
                        .saturating_sub(current_authority_identifier_count);
                    if label_gain == 0 && authority_identifier_gain == 0 {
                        return None;
                    }
                    return Some((
                        story_idx,
                        None,
                        (
                            true,
                            label_gain,
                            authority_identifier_gain,
                            relevance,
                            authority_score,
                            usize::MAX,
                            &story.title,
                        ),
                    ));
                }

                story
                    .citation_ids
                    .iter()
                    .enumerate()
                    .skip(1)
                    .filter_map(|(replace_idx, citation_id)| {
                        let existing = citations_by_id.get(citation_id)?;
                        let mut hypothetical = story_citation_ids(stories);
                        hypothetical[story_idx][replace_idx] = candidate.id.clone();
                        let hypothetical_labels =
                            document_briefing_authority_labels_from_story_citation_ids(
                                query,
                                &hypothetical,
                                citations_by_id,
                                &required_labels,
                            );
                        let label_gain = hypothetical_labels
                            .len()
                            .saturating_sub(current_authority_labels.len());
                        let hypothetical_authority_identifier_count = hypothetical
                            .iter()
                            .flat_map(|citation_ids| citation_ids.iter())
                            .filter_map(|citation_id| citations_by_id.get(citation_id))
                            .filter(|candidate| {
                                !document_briefing_candidate_authoritative_required_identifier_labels(
                                    query,
                                    candidate,
                                    &required_labels,
                                )
                                .is_empty()
                            })
                            .map(|candidate| candidate.url.trim().to_ascii_lowercase())
                            .filter(|url| !url.is_empty())
                            .collect::<BTreeSet<_>>()
                            .len();
                        let authority_identifier_gain = hypothetical_authority_identifier_count
                            .saturating_sub(current_authority_identifier_count);
                        if label_gain == 0 && authority_identifier_gain == 0 {
                            return None;
                        }
                        let existing_authority_labels =
                            document_briefing_candidate_authoritative_required_identifier_labels(
                                query,
                                existing,
                                &required_labels,
                            )
                            .len();
                        Some((
                            story_idx,
                            Some(replace_idx),
                            (
                                false,
                                label_gain,
                                authority_identifier_gain,
                                relevance,
                                authority_score,
                                usize::MAX.saturating_sub(existing_authority_labels),
                                &story.title,
                            ),
                        ))
                    })
                    .max_by(|(_, _, left_key), (_, _, right_key)| left_key.cmp(right_key))
            })
            .max_by(|(_, _, left_key), (_, _, right_key)| left_key.cmp(right_key));

        let Some((story_idx, replace_idx, _)) = best_placement else {
            break;
        };
        if let Some(replace_idx) = replace_idx {
            stories[story_idx].citation_ids[replace_idx] = candidate.id.clone();
        } else {
            stories[story_idx].citation_ids.push(candidate.id.clone());
        }

        current_authority_labels = document_briefing_authority_labels_from_story_citation_ids(
            query,
            &story_citation_ids(stories),
            citations_by_id,
            &required_labels,
        );
    }
}

fn refresh_story_citation_confidence(
    story_sources: &[PendingSearchReadSummary],
    stories: &mut [StoryDraft],
    citations_by_id: &BTreeMap<String, CitationCandidate>,
    citations_per_story: usize,
) {
    for (story, source) in stories.iter_mut().zip(story_sources.iter()) {
        let confident_reads = story
            .citation_ids
            .iter()
            .filter_map(|citation_id| citations_by_id.get(citation_id))
            .filter(|candidate| candidate.from_successful_read)
            .count();
        story.confidence = if confident_reads >= citations_per_story {
            "high".to_string()
        } else if story.citation_ids.len() >= citations_per_story {
            "medium".to_string()
        } else {
            "low".to_string()
        };
        story.eta_confidence = eta_confidence_from_story(
            source,
            confident_reads,
            story.citation_ids.len(),
            citations_per_story,
        );
    }
}

fn local_business_display_title(
    source: &PendingSearchReadSummary,
    locality_hint: Option<&str>,
) -> String {
    let raw_title = source.title.as_deref().map(str::trim).unwrap_or_default();
    if !raw_title.is_empty()
        && !is_low_signal_title(raw_title)
        && !local_business_target_matches_source_host(raw_title, &source.url)
    {
        return canonical_source_title(source);
    }

    local_business_target_name_from_source(source, locality_hint)
        .unwrap_or_else(|| canonical_source_title(source))
}

fn headline_story_source_tokens(source: &PendingSearchReadSummary) -> BTreeSet<String> {
    let title = canonical_source_title(source);
    let detail = excerpt_headline(source.excerpt.trim())
        .unwrap_or_else(|| compact_excerpt(source.excerpt.as_str(), 220));
    headline_story_topic_tokens(&format!("{} {}", title, detail))
}

fn headline_story_source_is_actionable(source: &PendingSearchReadSummary) -> bool {
    headline_source_is_actionable(source)
}

#[cfg(test)]
#[path = "builder/tests.rs"]
mod tests;
