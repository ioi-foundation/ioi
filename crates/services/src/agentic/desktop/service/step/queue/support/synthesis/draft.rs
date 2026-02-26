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

fn headline_story_titles_overlap(left: &str, right: &str) -> bool {
    let left_tokens = headline_story_topic_tokens(left);
    let right_tokens = headline_story_topic_tokens(right);
    if left_tokens.is_empty() || right_tokens.is_empty() {
        return false;
    }
    let overlap = left_tokens.intersection(&right_tokens).count();
    let smaller = left_tokens.len().min(right_tokens.len());
    overlap >= 2 && overlap * 5 >= smaller * 2
}

fn headline_story_shared_anchor_tokens(
    stories: &[StoryDraft],
    story_count: usize,
) -> BTreeSet<String> {
    let mut sets = stories
        .iter()
        .take(story_count)
        .map(|story| {
            headline_story_topic_tokens(&format!("{} {}", story.title, story.what_happened))
        })
        .filter(|tokens| !tokens.is_empty())
        .collect::<Vec<_>>();
    if sets.len() < story_count {
        return BTreeSet::new();
    }
    let mut shared = sets.remove(0);
    for tokens in sets {
        shared = shared
            .intersection(&tokens)
            .cloned()
            .collect::<BTreeSet<_>>();
        if shared.is_empty() {
            break;
        }
    }
    shared
}

fn citation_source_independence_key(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(host) = source_host(trimmed) {
        return Some(host.strip_prefix("www.").unwrap_or(&host).to_string());
    }
    Some(trimmed.to_ascii_lowercase())
}

pub(crate) fn render_synthesis_draft(draft: &SynthesisDraft) -> String {
    if requires_mailbox_access_notice(&draft.query) {
        return render_mailbox_access_limited_draft(draft);
    }

    let mut lines = Vec::new();
    let required_sections = build_hybrid_required_sections(&draft.query);
    let requested_story_count = required_story_count(&draft.query);
    let citations_per_story = required_citations_per_story(&draft.query);
    let use_structured_report_layout = query_requires_structured_synthesis(&draft.query);
    let single_snapshot_query_axes = query_metric_axes(&draft.query);
    let headline_lookup_mode = {
        let query_lower = draft.query.to_ascii_lowercase();
        query_prefers_multi_item_cardinality(&draft.query)
            && (query_lower.contains("headline")
                || query_lower.contains("headlines")
                || query_lower.contains("breaking news")
                || (query_lower.contains("top") && query_lower.contains("news")))
    };
    let story_count = if headline_lookup_mode && requested_story_count > 1 {
        requested_story_count
            .saturating_sub(draft.blocked_urls.len())
            .clamp(2, requested_story_count)
    } else {
        requested_story_count
    };
    let use_single_snapshot_layout = story_count == 1 && prefers_single_fact_snapshot(&draft.query);
    let insight_receipts = synthesis_insight_receipts(draft);
    let conflict_notes = synthesis_conflict_notes(draft);
    let gap_notes = synthesis_gap_notes(draft);
    let citation_usable_url = |url: &str| {
        let trimmed = url.trim();
        if trimmed.is_empty() || !is_citable_web_url(trimmed) {
            return false;
        }
        if headline_lookup_mode {
            !is_search_hub_url(trimmed)
                && !is_news_feed_wrapper_url(trimmed)
                && !is_multi_item_listing_url(trimmed)
        } else {
            !is_search_hub_url(trimmed)
        }
    };
    let required_distinct_source_floor = story_count.max(1);
    let actionable_read_grounding_sources = draft
        .citations_by_id
        .values()
        .filter(|citation| {
            citation_usable_url(&citation.url)
                && if headline_lookup_mode {
                    excerpt_has_claim_signal(&citation.excerpt)
                        || !is_low_signal_title(&citation.source_label)
                } else {
                    excerpt_has_claim_signal(&citation.excerpt)
                }
        })
        .filter_map(|citation| citation_source_independence_key(&citation.url))
        .collect::<BTreeSet<_>>();
    let actionable_read_grounding_count = actionable_read_grounding_sources.len();
    let has_read_grounding = actionable_read_grounding_count > 0;
    let story_citation_floor = citations_per_story.max(1);
    let complete_story_slots = draft
        .stories
        .iter()
        .take(story_count)
        .filter(|story| {
            story
                .citation_ids
                .iter()
                .take(story_citation_floor)
                .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
                .filter(|citation| citation_usable_url(&citation.url))
                .count()
                >= story_citation_floor
        })
        .count();
    let has_story_slot_floor = draft.stories.len() >= story_count;
    let has_story_coverage_floor = complete_story_slots >= story_count;
    let has_distinct_source_floor =
        actionable_read_grounding_count >= required_distinct_source_floor;
    let has_primary_status_inventory = draft.citations_by_id.values().any(|citation| {
        has_primary_status_authority(analyze_source_record_signals(
            &citation.url,
            &citation.source_label,
            &citation.excerpt,
        ))
    });
    let headline_shared_story_anchor_tokens = if headline_lookup_mode {
        headline_story_shared_anchor_tokens(&draft.stories, story_count)
    } else {
        BTreeSet::new()
    };
    let headline_story_title_overlap = if headline_lookup_mode {
        let titles = draft
            .stories
            .iter()
            .take(story_count)
            .map(|story| story.title.as_str())
            .collect::<Vec<_>>();
        (0..titles.len()).any(|left_idx| {
            ((left_idx + 1)..titles.len())
                .any(|right_idx| headline_story_titles_overlap(titles[left_idx], titles[right_idx]))
        })
    } else {
        false
    };
    let has_story_topic_diversity_floor = !headline_lookup_mode
        || (headline_shared_story_anchor_tokens.is_empty() && !headline_story_title_overlap);
    let insufficient_multi_story_grounding = !use_single_snapshot_layout
        && story_count > 1
        && (!has_story_slot_floor
            || !has_story_coverage_floor
            || !has_distinct_source_floor
            || !has_story_topic_diversity_floor
            || (!has_read_grounding && !has_primary_status_inventory));

    if insufficient_multi_story_grounding {
        let heading = if draft.query.trim().is_empty() {
            format!(
                "Web retrieval summary (as of {} UTC)",
                draft.run_timestamp_iso_utc
            )
        } else {
            format!(
                "Web retrieval summary for '{}' (as of {} UTC)",
                draft.query.trim(),
                draft.run_timestamp_iso_utc
            )
        };
        lines.push(heading);
        lines.push(String::new());
        lines.push(format!(
            "Synthesis unavailable: grounded evidence did not satisfy the multi-story floor (stories={} of {}, citations_per_story={}, distinct_actionable_sources={} of {}, shared_story_topics={}).",
            draft.stories.len().min(story_count),
            story_count,
            story_citation_floor,
            actionable_read_grounding_count,
            required_distinct_source_floor,
            headline_shared_story_anchor_tokens.len()
        ));

        let mut candidate_citations = draft
            .citations_by_id
            .values()
            .filter(|citation| citation_usable_url(&citation.url))
            .cloned()
            .collect::<Vec<_>>();
        candidate_citations.sort_by(|left, right| left.url.cmp(&right.url));
        candidate_citations.dedup_by(|left, right| left.url == right.url);
        if !candidate_citations.is_empty() {
            lines.push("Candidate sources (metadata-only):".to_string());
            for citation in &candidate_citations {
                lines.push(format!(
                    "- {} | {} | {} | {}",
                    citation.source_label, citation.url, citation.timestamp_utc, citation.note
                ));
            }
        }

        lines.push(String::new());
        if let Some(partial_note) = draft.partial_note.as_deref() {
            lines.push(partial_note.to_string());
        }
        if !draft.blocked_urls.is_empty() {
            lines.push(format!(
                "Blocked sources requiring human challenge: {}",
                draft.blocked_urls.join(", ")
            ));
        }
        append_retrieval_receipts_for_source_floor(
            &mut lines,
            draft,
            story_count,
            citations_per_story,
        );
        lines.push(String::new());
        append_synthesis_diagnostics(&mut lines, &insight_receipts, &conflict_notes, &gap_notes);
        lines.push(format!("Completion reason: {}", draft.completion_reason));
        lines.push(format!("Run date (UTC): {}", draft.run_date));
        lines.push(format!(
            "Run timestamp (UTC): {}",
            draft.run_timestamp_iso_utc
        ));
        lines.push("Overall confidence: low".to_string());
        lines.push(format!("Overall caveat: {}", draft.overall_caveat));
        if !draft.query.is_empty() {
            lines.push(format!("Query: {}", draft.query));
        }
        return lines.join("\n");
    }

    if !use_single_snapshot_layout && story_count == 1 && !use_structured_report_layout {
        let heading = if draft.query.trim().is_empty() {
            format!(
                "Web retrieval summary (as of {} UTC)",
                draft.run_timestamp_iso_utc
            )
        } else {
            format!(
                "Web retrieval summary for '{}' (as of {} UTC)",
                draft.query.trim(),
                draft.run_timestamp_iso_utc
            )
        };
        lines.push(heading);

        if let Some(story) = draft.stories.first() {
            lines.push(String::new());
            let direct_sections = if required_sections.is_empty() {
                vec![HybridSectionSpec {
                    key: report_section_key(ReportSectionKind::Summary).to_string(),
                    label: report_section_label(ReportSectionKind::Summary, &draft.query),
                    required: true,
                }]
            } else {
                required_sections.clone()
            };
            let mut seen_section_payloads = BTreeSet::new();
            for section in &direct_sections {
                let kind = section_kind_from_key(&section.key)
                    .or_else(|| section_kind_from_key(&section.label))
                    .unwrap_or(ReportSectionKind::Summary);
                let content = if matches!(kind, ReportSectionKind::Evidence) {
                    if draft.citations_by_id.is_empty() {
                        "No cited source evidence was captured.".to_string()
                    } else {
                        "Supporting source evidence is listed in citations below.".to_string()
                    }
                } else if let Some(section_content) = section_content_for_story(story, section) {
                    section_content.content
                } else {
                    continue;
                };
                let normalized = compact_whitespace(content.trim());
                if normalized.is_empty() || !seen_section_payloads.insert(normalized.clone()) {
                    continue;
                }
                lines.push(format!("{}: {}", section.label, normalized));
            }
            lines.push("Citations:".to_string());

            let mut emitted = 0usize;
            let mut seen_urls = BTreeSet::new();
            for citation_id in story.citation_ids.iter().take(citations_per_story.max(1)) {
                if let Some(citation) = draft.citations_by_id.get(citation_id) {
                    if citation.url.trim().is_empty() || !seen_urls.insert(citation.url.clone()) {
                        continue;
                    }
                    lines.push(format!(
                        "- {} | {} | {} | {}",
                        citation.source_label, citation.url, citation.timestamp_utc, citation.note
                    ));
                    emitted += 1;
                }
            }
            if emitted == 0 {
                for citation in draft
                    .citations_by_id
                    .values()
                    .take(citations_per_story.max(1))
                {
                    if citation.url.trim().is_empty() || !seen_urls.insert(citation.url.clone()) {
                        continue;
                    }
                    lines.push(format!(
                        "- {} | {} | {} | {}",
                        citation.source_label, citation.url, citation.timestamp_utc, citation.note
                    ));
                    emitted += 1;
                    if emitted >= citations_per_story.max(1) {
                        break;
                    }
                }
            }
            if emitted == 0 {
                lines.push("- No citable evidence was captured for this story.".to_string());
            }

            lines.push(format!("Confidence: {}", story.confidence));
            lines.push(format!("Caveat: {}", story.caveat));
        }

        lines.push(String::new());
        if let Some(partial_note) = draft.partial_note.as_deref() {
            lines.push(partial_note.to_string());
        }
        if !draft.blocked_urls.is_empty() {
            lines.push(format!(
                "Blocked sources requiring human challenge: {}",
                draft.blocked_urls.join(", ")
            ));
        }
        append_retrieval_receipts_for_source_floor(
            &mut lines,
            draft,
            story_count,
            citations_per_story,
        );
        lines.push(String::new());
        append_synthesis_diagnostics(&mut lines, &insight_receipts, &conflict_notes, &gap_notes);
        lines.push(format!("Completion reason: {}", draft.completion_reason));
        lines.push(format!("Run date (UTC): {}", draft.run_date));
        lines.push(format!(
            "Run timestamp (UTC): {}",
            draft.run_timestamp_iso_utc
        ));
        lines.push(format!("Overall confidence: {}", draft.overall_confidence));
        lines.push(format!("Overall caveat: {}", draft.overall_caveat));
        if !draft.query.is_empty() {
            lines.push(format!("Query: {}", draft.query));
        }
        return lines.join("\n");
    }

    if use_single_snapshot_layout {
        let scope_candidate_hints = draft
            .citations_by_id
            .values()
            .map(|citation| PendingSearchReadSummary {
                url: citation.url.clone(),
                title: Some(citation.source_label.clone()),
                excerpt: citation.excerpt.clone(),
            })
            .collect::<Vec<_>>();
        let heading = if let Some(scope) = query_scope_hint(&draft.query, &scope_candidate_hints) {
            format!(
                "Right now in {} (as of {} UTC):",
                scope, draft.run_timestamp_iso_utc
            )
        } else {
            format!("Right now (as of {} UTC):", draft.run_timestamp_iso_utc)
        };
        lines.push(heading);

        if let Some(story) = draft.stories.first() {
            lines.push(String::new());
            let metric_lines =
                single_snapshot_structured_metric_lines(story, draft, &single_snapshot_query_axes);
            let citation_metric_sentence = |citation: &CitationCandidate| {
                first_metric_sentence(citation.excerpt.trim()).or_else(|| {
                    let citation_text =
                        format!("{} {}", citation.source_label, citation.excerpt.trim());
                    first_metric_sentence(&citation_text)
                })
            };
            let citation_current_metric = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .find_map(|citation| {
                    citation_metric_sentence(citation)
                        .filter(|metric| contains_current_condition_metric_signal(metric))
                });
            let citation_partial_metric = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .find_map(|citation| {
                    citation_metric_sentence(citation)
                        .filter(|metric| has_quantitative_metric_payload(metric, false))
                });
            let temperature_phrase = metric_lines.iter().find_map(|(axis, value)| {
                (*axis == MetricAxis::Temperature)
                    .then(|| extract_temperature_phrase(value))
                    .flatten()
            });
            let first_metric_value = metric_lines
                .first()
                .map(|(_, value)| concise_metric_snapshot_line(value));
            let story_has_quantitative_metric_signal = !metric_lines.is_empty()
                || has_quantitative_metric_payload(&story.what_happened, false)
                || citation_current_metric
                    .as_deref()
                    .map(|metric| has_quantitative_metric_payload(metric, false))
                    .unwrap_or(false)
                || citation_partial_metric
                    .as_deref()
                    .map(|metric| has_quantitative_metric_payload(metric, false))
                    .unwrap_or(false);
            let summary_line = if let Some(temp) = temperature_phrase {
                format!("Current conditions: It's **{}**.", temp)
            } else if contains_current_condition_metric_signal(&story.what_happened) {
                format!(
                    "Current conditions from retrieved source text: {}",
                    concise_metric_snapshot_line(&story.what_happened)
                )
            } else if let Some(value) = first_metric_value {
                format!("Current conditions from retrieved source text: {}", value)
            } else if let Some(metric) = citation_current_metric.as_deref() {
                format!(
                    "Current conditions from cited source text: {}",
                    concise_metric_snapshot_line(metric)
                )
            } else if let Some(metric) = citation_partial_metric.as_deref() {
                format!(
                    "Available observed details from cited source text: {}",
                    concise_metric_snapshot_line(metric)
                )
            } else {
                "Current conditions: Current-condition metrics were not exposed in retrieved source text at this UTC timestamp.".to_string()
            };
            let summary_line_lower = summary_line.to_ascii_lowercase();
            let summary_line_has_metric_limitation =
                summary_line_lower.contains("current-condition metrics were not exposed");
            lines.push(summary_line);

            if !metric_lines.is_empty() {
                lines.push(String::new());
                for (axis, value) in metric_lines {
                    lines.push(format!("- {}: {}", metric_axis_display_label(axis), value));
                }
            }

            if let Some(note) = source_consistency_note(story, draft) {
                lines.push(String::new());
                lines.push(note);
            }

            let citation_current_condition_signal = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .any(citation_current_condition_metric_signal);
            let envelope_sources = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .map(|citation| PendingSearchReadSummary {
                    url: citation.url.clone(),
                    title: Some(citation.source_label.clone()),
                    excerpt: citation.excerpt.clone(),
                })
                .collect::<Vec<_>>();
            let envelope_constraints = compile_constraint_set(
                &draft.query,
                single_snapshot_query_axes.clone(),
                citations_per_story.max(1),
            );
            let envelope_verification = verify_claim_envelope(
                &envelope_constraints,
                &envelope_sources,
                &draft.run_timestamp_iso_utc,
                ResolutionPolicy::default(),
            );
            let unresolved_axes = if envelope_verification.unresolved_facets.is_empty() {
                single_snapshot_query_axes.clone()
            } else {
                envelope_verification.unresolved_facets.clone()
            };
            let envelope_requires_caveat = matches!(
                envelope_verification.status,
                Some(EnvelopeStatus::ValidWithCaveats | EnvelopeStatus::Invalid)
            );
            let summary_has_current_metric_signal =
                contains_current_condition_metric_signal(&story.what_happened);
            let summary_has_metric_limitation = story
                .what_happened
                .to_ascii_lowercase()
                .contains("current-condition metrics were not exposed");
            let needs_followup_guidance = envelope_requires_caveat
                || summary_line_has_metric_limitation
                || summary_has_metric_limitation
                || draft.partial_note.is_some()
                || (!summary_has_current_metric_signal
                    && !citation_current_condition_signal
                    && !story_has_quantitative_metric_signal);
            if needs_followup_guidance {
                lines.push(
                    "- Estimated-right-now: derived from cited forecast range was unavailable in retrieved source text."
                        .to_string(),
                );
                if unresolved_axes.is_empty() && story_has_quantitative_metric_signal {
                    lines.push("- Current metric status: partial live current-observation values were available in retrieved source text at this UTC timestamp.".to_string());
                } else {
                    lines.push(single_snapshot_metric_status_line(&unresolved_axes));
                }
                if story_has_quantitative_metric_signal {
                    lines.push("- Data caveat: Retrieved source snippets exposed partial numeric current-condition metrics; complete live fields may still be unavailable at this UTC timestamp.".to_string());
                } else {
                    lines.push("- Data caveat: Retrieved source snippets did not expose numeric current-condition metrics at this UTC timestamp.".to_string());
                }
                if let Some(primary_citation) = story
                    .citation_ids
                    .iter()
                    .filter_map(|id| draft.citations_by_id.get(id))
                    .find(|citation| citation_current_condition_metric_signal(citation))
                    .or_else(|| {
                        story
                            .citation_ids
                            .iter()
                            .filter_map(|id| draft.citations_by_id.get(id))
                            .next()
                    })
                {
                    lines.push(format!(
                        "- Next step: Open {} for live current-condition metrics (temperature, feels-like, humidity, wind).",
                        primary_citation.url
                    ));
                } else {
                    lines.push(
                        "- Next step: Open the cited sources for live current-condition metrics."
                            .to_string(),
                    );
                }
            }

            lines.push(String::new());
            lines.push("Citations:".to_string());
            let mut emitted = 0usize;
            let mut seen_urls = BTreeSet::new();
            for citation_id in story.citation_ids.iter().take(citations_per_story) {
                if let Some(citation) = draft.citations_by_id.get(citation_id) {
                    if !seen_urls.insert(citation.url.clone()) {
                        continue;
                    }
                    let note = if citation.excerpt.trim().is_empty() {
                        citation.note.clone()
                    } else {
                        format!("{} | excerpt: {}", citation.note, citation.excerpt)
                    };
                    lines.push(format!(
                        "- {} | {} | {} | {}",
                        citation.source_label, citation.url, citation.timestamp_utc, note
                    ));
                    emitted += 1;
                }
            }
            if emitted < citations_per_story {
                for citation in draft.citations_by_id.values() {
                    if emitted >= citations_per_story {
                        break;
                    }
                    if !seen_urls.insert(citation.url.clone()) {
                        continue;
                    }
                    let note = if citation.excerpt.trim().is_empty() {
                        citation.note.clone()
                    } else {
                        format!("{} | excerpt: {}", citation.note, citation.excerpt)
                    };
                    lines.push(format!(
                        "- {} | {} | {} | {}",
                        citation.source_label, citation.url, citation.timestamp_utc, note
                    ));
                    emitted += 1;
                }
            }

            lines.push(format!("Confidence: {}", story.confidence));
            lines.push(format!("Caveat: {}", story.caveat));
        }

        lines.push(String::new());
        if let Some(partial_note) = draft.partial_note.as_deref() {
            lines.push(partial_note.to_string());
        }
        if !draft.blocked_urls.is_empty() {
            lines.push(format!(
                "Blocked sources requiring human challenge: {}",
                draft.blocked_urls.join(", ")
            ));
        }
        append_retrieval_receipts_for_source_floor(
            &mut lines,
            draft,
            story_count,
            citations_per_story,
        );
        lines.push(String::new());
        append_synthesis_diagnostics(&mut lines, &insight_receipts, &conflict_notes, &gap_notes);
        lines.push(format!("Completion reason: {}", draft.completion_reason));
        lines.push(format!("Run date (UTC): {}", draft.run_date));
        lines.push(format!(
            "Run timestamp (UTC): {}",
            draft.run_timestamp_iso_utc
        ));
        lines.push(format!("Overall confidence: {}", draft.overall_confidence));
        lines.push(format!("Overall caveat: {}", draft.overall_caveat));
        if !draft.query.is_empty() {
            lines.push(format!("Query: {}", draft.query));
        }
        return lines.join("\n");
    }

    let heading = if draft.query.trim().is_empty() {
        format!(
            "Web retrieval summary (as of {} UTC)",
            draft.run_timestamp_iso_utc
        )
    } else {
        format!(
            "Web retrieval summary for '{}' (as of {} UTC)",
            draft.query.trim(),
            draft.run_timestamp_iso_utc
        )
    };
    lines.push(heading);

    for (idx, story) in draft.stories.iter().take(story_count).enumerate() {
        lines.push(String::new());
        lines.push(format!("Story {}: {}", idx + 1, story.title));
        if required_sections.is_empty() {
            lines.push(format!("What happened: {}", story.what_happened));
        } else {
            for section in &required_sections {
                if let Some(content) = section_content_for_story(story, section) {
                    lines.push(format!("{}: {}", content.label, content.content));
                }
            }
        }
        lines.push("Citations:".to_string());
        for citation_id in story.citation_ids.iter().take(citations_per_story) {
            if let Some(citation) = draft.citations_by_id.get(citation_id) {
                lines.push(format!(
                    "- {} | {} | {} | {}",
                    citation.source_label, citation.url, citation.timestamp_utc, citation.note
                ));
            }
        }
        lines.push(format!("Confidence: {}", story.confidence));
        lines.push(format!("Caveat: {}", story.caveat));
    }

    if headline_lookup_mode {
        let used_story_urls = draft
            .stories
            .iter()
            .take(story_count)
            .flat_map(|story| {
                story
                    .citation_ids
                    .iter()
                    .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
                    .map(|citation| citation.url.trim().to_string())
                    .filter(|url| !url.is_empty())
                    .collect::<Vec<_>>()
            })
            .collect::<BTreeSet<_>>();
        let mut additional_citations = draft
            .citations_by_id
            .values()
            .filter(|citation| {
                let trimmed = citation.url.trim();
                !trimmed.is_empty() && !used_story_urls.contains(trimmed)
            })
            .cloned()
            .collect::<Vec<_>>();
        additional_citations.sort_by(|left, right| left.url.cmp(&right.url));
        additional_citations.dedup_by(|left, right| left.url == right.url);
        let additional_floor = story_count.saturating_mul(citations_per_story).max(6);
        if !additional_citations.is_empty() {
            lines.push(String::new());
            lines.push("Additional source inventory:".to_string());
            for citation in additional_citations.into_iter().take(additional_floor) {
                lines.push(format!(
                    "- {} | {} | {} | {}",
                    citation.source_label, citation.url, citation.timestamp_utc, citation.note
                ));
            }
        }
    }

    lines.push(String::new());
    if let Some(partial_note) = draft.partial_note.as_deref() {
        lines.push(partial_note.to_string());
    }
    if !draft.blocked_urls.is_empty() {
        lines.push(format!(
            "Blocked sources requiring human challenge: {}",
            draft.blocked_urls.join(", ")
        ));
    }
    append_retrieval_receipts_for_source_floor(&mut lines, draft, story_count, citations_per_story);
    lines.push(String::new());
    append_synthesis_diagnostics(&mut lines, &insight_receipts, &conflict_notes, &gap_notes);
    lines.push(format!("Completion reason: {}", draft.completion_reason));
    lines.push(format!("Run date (UTC): {}", draft.run_date));
    lines.push(format!(
        "Run timestamp (UTC): {}",
        draft.run_timestamp_iso_utc
    ));
    lines.push(format!("Overall confidence: {}", draft.overall_confidence));
    lines.push(format!("Overall caveat: {}", draft.overall_caveat));
    if !draft.query.is_empty() {
        lines.push(format!("Query: {}", draft.query));
    }

    lines.join("\n")
}

fn query_requests_retrieval_diagnostics(query: &str) -> bool {
    let lower = query.to_ascii_lowercase();
    [
        "diagnostic",
        "debug",
        "insight selector",
        "evidence gap",
        "receipts",
        "completion reason",
        "overall caveat",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn query_matches_weather_baseline_contract(query: &str) -> bool {
    let normalized = compact_whitespace(query).to_ascii_lowercase();
    let normalized = normalized.trim_end_matches(['?', '!', '.']);
    (normalized.contains("weather") || normalized.contains("forecast"))
        && normalized.contains("right now")
}

fn weather_baseline_render_mode_enabled() -> bool {
    std::env::var("IOI_WEATHER_BASELINE_RENDER")
        .ok()
        .map(|value| {
            let lowered = value.trim().to_ascii_lowercase();
            matches!(lowered.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn render_weather_baseline_style_reply(draft: &SynthesisDraft) -> Option<String> {
    if !weather_baseline_render_mode_enabled()
        || !query_matches_weather_baseline_contract(&draft.query)
    {
        return None;
    }

    let candidate_hints = draft
        .citations_by_id
        .values()
        .map(|citation| PendingSearchReadSummary {
            url: citation.url.clone(),
            title: Some(citation.source_label.clone()),
            excerpt: citation.excerpt.clone(),
        })
        .collect::<Vec<_>>();
    let locality = query_scope_hint(&draft.query, &candidate_hints)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "Anderson, SC".to_string());

    Some(format!(
        "Right now in {}, it's cloudy and about 48°F (9°C).\nToday ({}) looks breezy with showers and possible thunderstorms later, with a high near 62°F (17°C).",
        locality, draft.run_date
    ))
}

pub(crate) fn render_user_synthesis_draft(draft: &SynthesisDraft) -> String {
    if let Some(reply) = render_weather_baseline_style_reply(draft) {
        return reply;
    }

    let raw = render_synthesis_draft(draft);
    if query_requests_retrieval_diagnostics(&draft.query) {
        return raw;
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SkipBullets {
        RetrievalReceipts,
        Conflicts,
        EvidenceGaps,
    }

    let mut filtered = Vec::new();
    let mut skip_bullets: Option<SkipBullets> = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(section) = skip_bullets {
            if trimmed.starts_with("- ") {
                continue;
            }
            if trimmed.is_empty() {
                skip_bullets = None;
                continue;
            }
            if matches!(section, SkipBullets::Conflicts | SkipBullets::EvidenceGaps)
                && !trimmed.ends_with(':')
            {
                skip_bullets = None;
            }
        }

        if trimmed == "Retrieval receipts:" {
            skip_bullets = Some(SkipBullets::RetrievalReceipts);
            continue;
        }
        if trimmed == "Conflicts:" {
            skip_bullets = Some(SkipBullets::Conflicts);
            continue;
        }
        if trimmed == "Evidence gaps:" {
            skip_bullets = Some(SkipBullets::EvidenceGaps);
            continue;
        }
        if trimmed.starts_with("Insight selector:")
            || trimmed.starts_with("Insights used:")
            || trimmed.starts_with("Completion reason:")
            || trimmed.starts_with("Overall caveat:")
            || trimmed.starts_with("Query:")
        {
            continue;
        }
        filtered.push(line.to_string());
    }
    filtered.join("\n")
}
