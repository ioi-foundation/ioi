use super::*;

pub(super) fn render_single_snapshot_layout(
    draft: &SynthesisDraft,
    story_count: usize,
    citations_per_story: usize,
    single_snapshot_query_axes: &BTreeSet<MetricAxis>,
    insight_receipts: &[String],
    conflict_notes: &[String],
    gap_notes: &[String],
) -> String {
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

    let mut lines = vec![heading];

    if let Some(story) = draft.stories.first() {
        lines.push(String::new());
        let metric_lines =
            single_snapshot_structured_metric_lines(story, draft, single_snapshot_query_axes);
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

    append_common_postamble(
        &mut lines,
        draft,
        story_count,
        citations_per_story,
        insight_receipts,
        conflict_notes,
        gap_notes,
        None,
    );
    lines.join("\n")
}
