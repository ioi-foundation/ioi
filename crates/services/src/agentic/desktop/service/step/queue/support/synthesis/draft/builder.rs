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
    let single_snapshot_mode =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query);
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query);
    let required_story_count = retrieval_contract_required_story_count(retrieval_contract, &query);
    let citations_per_story =
        retrieval_contract_required_citations_per_story(retrieval_contract, &query);
    let single_snapshot_policy = ResolutionPolicy::default();
    let completion_reason = completion_reason_line(reason).to_string();
    let min_sources = pending.min_sources.max(1) as usize;
    let required_readable_sources = if headline_lookup_mode && required_story_count > 1 {
        min_sources
            .saturating_sub(pending.blocked_urls.len())
            .clamp(2, min_sources)
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

    let candidates = build_citation_candidates(pending, &run_timestamp_iso_utc);
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
            right_current_signal
                .cmp(&left_current_signal)
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
            required_story_count,
        );
        for source in selected_local_business_target_sources(
            &query,
            &local_business_entity_targets,
            &source_pool,
            locality_scope.as_deref(),
            required_story_count,
        ) {
            if selected.len() >= required_story_count {
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
        for source in preferred_source_pool {
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
            if selected_sources.len() >= required_story_count {
                break;
            }
        }
        if selected_sources.len() < required_story_count {
            for source in preferred_source_pool {
                if selected_sources.len() >= required_story_count {
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
        if headline_lookup_mode && selected_sources.len() < required_story_count {
            for source in preferred_source_pool {
                if selected_sources.len() >= required_story_count {
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
        if headline_lookup_mode && selected_sources.len() < required_story_count {
            for source in &source_pool {
                if selected_sources.len() >= required_story_count {
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
    if single_snapshot_mode && selected_sources.is_empty() {
        if let Some(source) = source_pool.first() {
            selected_sources.push(source.clone());
        }
    }

    let mut used_citation_urls = BTreeSet::new();
    for source in selected_sources.iter().take(required_story_count) {
        let title = if local_business_entity_targets.is_empty() {
            canonical_source_title(source)
        } else {
            local_business_display_title(source, locality_scope.as_deref())
        };
        let what_happened = if single_snapshot_mode {
            single_snapshot_summary_line(source)
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
            single_snapshot_mode,
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
        stories.push(StoryDraft {
            title: canonical_source_title(&fallback_source),
            what_happened: single_snapshot_summary_line(&fallback_source),
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
