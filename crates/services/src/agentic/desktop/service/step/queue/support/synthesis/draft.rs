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
    let required_story_count = required_story_count(&query);
    let citations_per_story = required_citations_per_story(&query);
    let single_snapshot_policy = ResolutionPolicy::default();
    let completion_reason = completion_reason_line(reason).to_string();
    let partial_note = {
        let min_sources = pending.min_sources.max(1) as usize;
        let grounded_sources = grounded_source_evidence_count(pending);
        (pending.successful_reads.len() < min_sources && grounded_sources < min_sources).then(
            || {
                format!(
                    "Partial evidence: confirmed readable sources={} while floor={}.",
                    pending.successful_reads.len(),
                    min_sources
                )
            },
        )
    };

    let candidates = build_citation_candidates(pending, &run_timestamp_iso_utc);
    let mut citations_by_id = BTreeMap::new();
    for candidate in &candidates {
        citations_by_id.insert(candidate.id.clone(), candidate.clone());
    }

    let mut stories = Vec::new();
    let merged_sources = merged_story_sources(pending);
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
    let source_pool = if single_snapshot_mode {
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
    let mut selected_sources = Vec::new();
    for source in &source_pool {
        if single_snapshot_mode && is_low_signal_excerpt(source.excerpt.as_str()) {
            continue;
        }
        let title = canonical_source_title(source);
        if selected_sources
            .iter()
            .any(|existing: &PendingSearchReadSummary| {
                titles_similar(&title, &canonical_source_title(existing))
            })
        {
            continue;
        }
        selected_sources.push(source.clone());
        if selected_sources.len() >= required_story_count {
            break;
        }
    }
    while selected_sources.len() < required_story_count && !source_pool.is_empty() {
        selected_sources.push(source_pool[selected_sources.len() % source_pool.len()].clone());
    }

    let mut used_urls = BTreeSet::new();
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
            &mut used_urls,
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

    while stories.len() < required_story_count {
        let mut fallback_source = if merged_sources.is_empty() {
            PendingSearchReadSummary {
                url: String::new(),
                title: None,
                excerpt: String::new(),
            }
        } else {
            merged_sources[stories.len() % merged_sources.len()].clone()
        };
        let fallback_ids = citation_ids_for_story(
            &fallback_source,
            &candidates,
            &mut used_urls,
            citations_per_story,
            single_snapshot_mode,
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
        let fallback_title = if fallback_source.url.trim().is_empty() {
            format!("Story {}", stories.len() + 1)
        } else {
            canonical_source_title(&fallback_source)
        };
        let fallback_what_happened = if single_snapshot_mode {
            single_snapshot_summary_line(&fallback_source)
        } else {
            source_bullet(&fallback_source)
        };
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
        let fallback_caveat = if fallback_source.url.trim().is_empty() {
            "Evidence quality was limited for this slot.".to_string()
        } else {
            "Evidence quality was limited; sections were composed from available citation metadata where explicit incident updates were sparse.".to_string()
        };
        stories.push(StoryDraft {
            title: fallback_title,
            what_happened: fallback_what_happened,
            changed_last_hour: changed_last_hour_line(&fallback_source, &run_timestamp_iso_utc),
            why_it_matters: why_it_matters_from_story(&fallback_source),
            user_impact: user_impact_from_story(&fallback_source),
            workaround: workaround_from_story(&fallback_source),
            eta_confidence: fallback_eta_confidence,
            citation_ids: fallback_ids,
            confidence: fallback_confidence,
            caveat: fallback_caveat,
        });
    }

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
        blocked_urls: pending.blocked_urls.clone(),
        partial_note,
    }
}

pub(crate) fn render_synthesis_draft(draft: &SynthesisDraft) -> String {
    if requires_mailbox_access_notice(&draft.query) {
        return render_mailbox_access_limited_draft(draft);
    }

    let mut lines = Vec::new();
    let required_sections = build_hybrid_required_sections(&draft.query);
    let story_count = required_story_count(&draft.query);
    let citations_per_story = required_citations_per_story(&draft.query);
    let use_single_snapshot_layout = story_count == 1 && prefers_single_fact_snapshot(&draft.query);
    let single_snapshot_query_axes = query_metric_axes(&draft.query);
    let insight_receipts = synthesis_insight_receipts(draft);
    let conflict_notes = synthesis_conflict_notes(draft);
    let gap_notes = synthesis_gap_notes(draft);

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
            let citation_current_metric = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .find_map(|citation| {
                    let citation_text =
                        format!("{} {}", citation.source_label, citation.excerpt.trim());
                    first_metric_sentence(&citation_text)
                        .filter(|metric| contains_current_condition_metric_signal(metric))
                });
            let citation_partial_metric = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .find_map(|citation| {
                    let citation_text =
                        format!("{} {}", citation.source_label, citation.excerpt.trim());
                    first_metric_sentence(&citation_text)
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
                    .next()
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
