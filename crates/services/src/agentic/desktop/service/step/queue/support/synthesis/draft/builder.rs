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
    let single_snapshot_mode = prefers_single_fact_snapshot(&query);
    let headline_lookup_mode = query_is_generic_headline_collection(&query);
    let required_story_count = required_story_count(&query);
    let citations_per_story = required_citations_per_story(&query);
    let single_snapshot_policy = ResolutionPolicy::default();
    let completion_reason = completion_reason_line(reason).to_string();
    let partial_note = {
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
        (readable_sources < required_readable_sources).then(|| {
            format!(
                "Partial evidence: verification receipt -> retrieved {} of {} required distinct readable sources ({} blocked by challenge).",
                readable_sources, required_readable_sources, blocked_sources
            )
        })
    };

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
    let source_pool = if !successful_merged_sources.is_empty() {
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
    } else if single_snapshot_mode {
        let mut ranked = merged_sources.clone();
        ranked.sort_by(|left, right| {
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
            .then_with(|| left.url.cmp(&right.url))
        });
        ranked
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

    let mut selected_sources = Vec::new();
    let mut selected_story_tokens = Vec::<BTreeSet<String>>::new();
    for source in preferred_source_pool {
        if single_snapshot_mode && is_low_signal_excerpt(source.excerpt.as_str()) {
            continue;
        }
        let title = canonical_source_title(source);
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
    if single_snapshot_mode && selected_sources.is_empty() {
        if let Some(source) = source_pool.first() {
            selected_sources.push(source.clone());
        }
    }

    let mut used_citation_urls = BTreeSet::new();
    for source in selected_sources.iter().take(required_story_count) {
        let title = canonical_source_title(source);
        let what_happened = if single_snapshot_mode {
            single_snapshot_summary_line(source)
        } else {
            source_bullet(source)
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

    let blocked_urls = pending
        .blocked_urls
        .iter()
        .map(|url| url.trim().to_string())
        .filter(|url| is_citable_web_url(url) && !successful_urls.contains(url))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    SynthesisDraft {
        query,
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

fn headline_story_source_tokens(source: &PendingSearchReadSummary) -> BTreeSet<String> {
    let title = canonical_source_title(source);
    let detail = excerpt_headline(source.excerpt.trim())
        .unwrap_or_else(|| compact_excerpt(source.excerpt.as_str(), 220));
    headline_story_topic_tokens(&format!("{} {}", title, detail))
}

fn headline_story_title_has_specificity(title: &str) -> bool {
    const GENERIC_TOKENS: &[&str] = &[
        "top",
        "news",
        "headline",
        "headlines",
        "latest",
        "breaking",
        "story",
        "stories",
        "update",
        "updates",
        "today",
        "live",
        "report",
        "reports",
        "listen",
        "watch",
        "now",
    ];
    let tokens = title
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter_map(|token| {
            let normalized = token.trim();
            if normalized.is_empty() {
                None
            } else {
                Some(normalized.to_string())
            }
        })
        .collect::<Vec<_>>();
    if tokens.len() < 2 {
        return false;
    }
    let informative_tokens = tokens
        .iter()
        .filter(|token| token.len() >= 3 && !GENERIC_TOKENS.contains(&token.as_str()))
        .count();
    informative_tokens >= 2
}

fn headline_story_source_is_actionable(source: &PendingSearchReadSummary) -> bool {
    let url = source.url.trim();
    if url.is_empty()
        || is_search_hub_url(url)
        || is_news_feed_wrapper_url(url)
        || is_multi_item_listing_url(url)
    {
        return false;
    }
    let title = canonical_source_title(source);
    if is_low_signal_title(&title) || !headline_story_title_has_specificity(&title) {
        return false;
    }
    let excerpt = source.excerpt.trim();
    if excerpt_has_claim_signal(excerpt) {
        return true;
    }
    let signals = source_evidence_signals(source);
    effective_primary_event_hits(signals) > 0
        || signals.impact_hits > 0
        || signals.mitigation_hits > 0
}
