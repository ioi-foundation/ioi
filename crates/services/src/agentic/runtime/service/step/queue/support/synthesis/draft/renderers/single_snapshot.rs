use super::*;

fn followup_metric_details_label(unresolved_axes: &BTreeSet<MetricAxis>) -> Option<String> {
    let labels = unresolved_axes
        .iter()
        .copied()
        .map(metric_axis_display_label)
        .take(4)
        .collect::<Vec<_>>();
    if labels.is_empty() {
        None
    } else {
        Some(labels.join(", "))
    }
}

fn single_snapshot_primary_story<'a>(
    draft: &'a SynthesisDraft,
    single_snapshot_query_axes: &BTreeSet<MetricAxis>,
) -> Option<&'a StoryDraft> {
    let mut best = None::<(&StoryDraft, usize, usize, usize, usize)>;
    for story in &draft.stories {
        let metric_lines =
            single_snapshot_structured_metric_lines(story, draft, single_snapshot_query_axes);
        let successful_read_count = story
            .citation_ids
            .iter()
            .filter_map(|id| draft.citations_by_id.get(id))
            .filter(|citation| citation.from_successful_read)
            .count();
        let current_condition_score = usize::from(
            contains_current_condition_metric_signal(&story.what_happened)
                || story
                    .citation_ids
                    .iter()
                    .filter_map(|id| draft.citations_by_id.get(id))
                    .any(citation_current_condition_metric_signal),
        );
        let direct_fact_score =
            usize::from(single_snapshot_has_direct_fact_line(&story.what_happened));
        let candidate = (
            story,
            current_condition_score,
            direct_fact_score,
            metric_lines.len(),
            successful_read_count,
        );
        match best {
            Some((_, best_current, best_direct_fact, best_metric_lines, best_reads))
                if current_condition_score < best_current
                    || (current_condition_score == best_current
                        && direct_fact_score < best_direct_fact)
                    || (current_condition_score == best_current
                        && direct_fact_score == best_direct_fact
                        && metric_lines.len() < best_metric_lines)
                    || (current_condition_score == best_current
                        && direct_fact_score == best_direct_fact
                        && metric_lines.len() == best_metric_lines
                        && successful_read_count <= best_reads) => {}
            _ => best = Some(candidate),
        }
    }
    best.map(|(story, _, _, _, _)| story)
}

fn single_snapshot_aggregated_citation_ids(
    draft: &SynthesisDraft,
    primary_story: &StoryDraft,
    citations_per_story: usize,
) -> Vec<String> {
    let mut ordered_story_ids = primary_story
        .citation_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    for story in &draft.stories {
        for citation_id in &story.citation_ids {
            ordered_story_ids.push(citation_id.clone());
        }
    }

    let mut selected = Vec::new();
    let mut seen_urls = BTreeSet::new();
    for citation_id in ordered_story_ids {
        if selected.len() >= citations_per_story {
            break;
        }
        let Some(citation) = draft.citations_by_id.get(&citation_id) else {
            continue;
        };
        if !citation.from_successful_read || !seen_urls.insert(citation.url.clone()) {
            continue;
        }
        selected.push(citation_id);
    }

    if selected.len() < citations_per_story {
        for citation in draft.citations_by_id.values() {
            if selected.len() >= citations_per_story {
                break;
            }
            if !citation.from_successful_read || !seen_urls.insert(citation.url.clone()) {
                continue;
            }
            selected.push(citation.id.clone());
        }
    }

    selected
}

pub(super) fn render_single_snapshot_layout(
    draft: &SynthesisDraft,
    story_count: usize,
    citations_per_story: usize,
    single_snapshot_query_axes: &BTreeSet<MetricAxis>,
    insight_receipts: &[String],
    conflict_notes: &[String],
    gap_notes: &[String],
) -> String {
    let direct_fact_snapshot = single_snapshot_query_axes.is_empty()
        && draft
            .stories
            .iter()
            .any(|story| single_snapshot_has_direct_fact_line(&story.what_happened));
    let scope_candidate_hints = draft
        .citations_by_id
        .values()
        .map(|citation| PendingSearchReadSummary {
            url: citation.url.clone(),
            title: Some(citation.source_label.clone()),
            excerpt: citation.excerpt.clone(),
        })
        .collect::<Vec<_>>();
    let heading = if direct_fact_snapshot {
        format!(
            "Current snapshot (as of {} UTC):",
            draft.run_timestamp_iso_utc
        )
    } else if let Some(scope) = query_scope_hint(&draft.query, &scope_candidate_hints) {
        format!(
            "Right now in {} (as of {} UTC):",
            scope, draft.run_timestamp_iso_utc
        )
    } else {
        format!("Right now (as of {} UTC):", draft.run_timestamp_iso_utc)
    };

    let mut lines = vec![heading];

    if let Some(story) = single_snapshot_primary_story(draft, single_snapshot_query_axes) {
        lines.push(String::new());
        let aggregated_citation_ids =
            single_snapshot_aggregated_citation_ids(draft, story, citations_per_story.max(1));
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
            .chain(aggregated_citation_ids.iter())
            .filter_map(|id| draft.citations_by_id.get(id))
            .find_map(|citation| {
                citation_metric_sentence(citation)
                    .filter(|metric| contains_current_condition_metric_signal(metric))
            });
        let citation_partial_metric = story
            .citation_ids
            .iter()
            .chain(aggregated_citation_ids.iter())
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
        let summary_line = if single_snapshot_has_direct_fact_line(&story.what_happened) {
            format!(
                "Current answer: {}",
                strip_single_snapshot_direct_fact_prefix(&story.what_happened)
            )
        } else if let Some(temp) = temperature_phrase {
            format!("Current conditions: It's **{}**.", temp)
        } else if contains_current_condition_metric_signal(&story.what_happened) {
            format!(
                "{} {}",
                single_snapshot_current_metric_prefix(&draft.query, &story.what_happened, false),
                concise_metric_snapshot_line(&story.what_happened)
            )
        } else if let Some(value) = first_metric_value {
            format!(
                "{} {}",
                single_snapshot_current_metric_prefix(&draft.query, &value, false),
                value
            )
        } else if let Some(metric) = citation_current_metric.as_deref() {
            format!(
                "{} {}",
                single_snapshot_current_metric_prefix(&draft.query, metric, true),
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
        let summary_line_has_direct_fact_signal = summary_line_lower.starts_with("current answer:");
        let citation_current_condition_signal = story
            .citation_ids
            .iter()
            .chain(aggregated_citation_ids.iter())
            .filter_map(|id| draft.citations_by_id.get(id))
            .any(citation_current_condition_metric_signal);
        let strong_current_price_snapshot =
            single_snapshot_prefers_price_summary_label(&draft.query, &story.what_happened)
                || metric_lines.iter().any(|(_, value)| {
                    single_snapshot_prefers_price_summary_label(&draft.query, value)
                })
                || citation_current_metric
                    .as_deref()
                    .map(|metric| single_snapshot_prefers_price_summary_label(&draft.query, metric))
                    .unwrap_or(false)
                || citation_partial_metric
                    .as_deref()
                    .map(|metric| single_snapshot_prefers_price_summary_label(&draft.query, metric))
                    .unwrap_or(false);
        let strong_current_price_snapshot = strong_current_price_snapshot
            && (contains_current_condition_metric_signal(&story.what_happened)
                || citation_current_condition_signal);
        lines.push(summary_line);

        if !metric_lines.is_empty() && !strong_current_price_snapshot {
            lines.push(String::new());
            for (axis, value) in metric_lines {
                lines.push(format!("- {}: {}", metric_axis_display_label(axis), value));
            }
        }

        if !strong_current_price_snapshot {
            if let Some(note) = source_consistency_note(story, draft) {
                lines.push(String::new());
                lines.push(note);
            }
        }

        let envelope_sources = aggregated_citation_ids
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
        let metric_followup_applicable = !direct_fact_snapshot;
        let summary_has_metric_limitation = story
            .what_happened
            .to_ascii_lowercase()
            .contains("current-condition metrics were not exposed");
        let needs_followup_guidance = metric_followup_applicable
            && !strong_current_price_snapshot
            && (envelope_requires_caveat
                || summary_line_has_metric_limitation
                || summary_has_metric_limitation
                || draft.partial_note.is_some()
                || (!summary_has_current_metric_signal
                    && !citation_current_condition_signal
                    && !story_has_quantitative_metric_signal
                    && !summary_line_has_direct_fact_signal));
        if needs_followup_guidance {
            lines.push(String::new());
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
                if let Some(metric_labels) = followup_metric_details_label(&unresolved_axes) {
                    lines.push(format!(
                        "- Next step: Open {} for live metric details ({}).",
                        primary_citation.url, metric_labels
                    ));
                } else {
                    lines.push(format!(
                        "- Next step: Open {} for live metric details.",
                        primary_citation.url
                    ));
                }
            } else {
                lines.push(
                    "- Next step: Open the cited sources for live metric details.".to_string(),
                );
            }
        }

        lines.push(String::new());
        lines.push("Citations:".to_string());
        let mut emitted = 0usize;
        let mut seen_urls = BTreeSet::new();
        for citation_id in aggregated_citation_ids.iter() {
            if let Some(citation) = draft.citations_by_id.get(citation_id) {
                if !citation.from_successful_read {
                    continue;
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
        if emitted < citations_per_story {
            for citation in draft.citations_by_id.values() {
                if emitted >= citations_per_story {
                    break;
                }
                if !citation.from_successful_read {
                    continue;
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

#[cfg(test)]
mod tests {
    use ioi_types::app::agentic::WebRetrievalContract;

    use super::*;

    #[test]
    fn render_single_snapshot_layout_omits_unread_citations() {
        let mut citations_by_id = BTreeMap::new();
        citations_by_id.insert(
            "c1".to_string(),
            CitationCandidate {
                id: "c1".to_string(),
                url: "https://www.worldcoinindex.com/coin/bitcoin".to_string(),
                source_label: "Bitcoin price | index, chart and news | WorldCoinIndex".to_string(),
                excerpt: "Bitcoin price right now: $86,743.63 USD.".to_string(),
                timestamp_utc: "2026-03-11T13:42:57Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
        citations_by_id.insert(
            "c2".to_string(),
            CitationCandidate {
                id: "c2".to_string(),
                url: "https://crypto.com/us/price/bitcoin".to_string(),
                source_label: "Bitcoin price - Crypto.com".to_string(),
                excerpt: "BTC price now: $86,744 USD.".to_string(),
                timestamp_utc: "2026-03-11T13:42:57Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: false,
            },
        );

        let draft = SynthesisDraft {
            query: "What's the current price of Bitcoin?".to_string(),
            retrieval_contract: Some(WebRetrievalContract {
                contract_version: "test.v1".to_string(),
                entity_cardinality_min: 1,
                comparison_required: false,
                currentness_required: true,
                runtime_locality_required: false,
                source_independence_min: 1,
                citation_count_min: 2,
                structured_record_preferred: true,
                ordered_collection_preferred: false,
                link_collection_preferred: false,
                canonical_link_out_preferred: false,
                geo_scoped_detail_required: false,
                discovery_surface_required: false,
                entity_diversity_required: false,
                scalar_measure_required: true,
                browser_fallback_allowed: true,
            }),
            run_date: "2026-03-11".to_string(),
            run_timestamp_ms: 1_773_236_577_000,
            run_timestamp_iso_utc: "2026-03-11T13:42:57Z".to_string(),
            completion_reason: "min_sources_reached".to_string(),
            overall_confidence: "high".to_string(),
            overall_caveat: "retrieval receipts available".to_string(),
            stories: vec![StoryDraft {
                title: "Bitcoin".to_string(),
                what_happened: "Bitcoin price right now: $86,743.63 USD.".to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c1".to_string(), "c2".to_string()],
                confidence: "high".to_string(),
                caveat: "timestamps may reflect retrieval time".to_string(),
            }],
            citations_by_id,
            blocked_urls: Vec::new(),
            partial_note: None,
        };

        let rendered = render_single_snapshot_layout(&draft, 1, 2, &BTreeSet::new(), &[], &[], &[]);

        assert!(rendered.contains("https://www.worldcoinindex.com/coin/bitcoin"));
        assert!(!rendered.contains("https://crypto.com/us/price/bitcoin"));
    }

    #[test]
    fn render_single_snapshot_layout_aggregates_read_backed_citations_across_stories() {
        let mut citations_by_id = BTreeMap::new();
        citations_by_id.insert(
            "c1".to_string(),
            CitationCandidate {
                id: "c1".to_string(),
                url: "https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC&site=GSP&textField1=34.5186&textField2=-82.6458&e=0".to_string(),
                source_label: "National Weather Service".to_string(),
                excerpt: "Current conditions as of 8:56 am EDT: temperature 65°F, humidity 93%, wind SW 3 mph.".to_string(),
                timestamp_utc: "2026-03-11T13:19:18Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
        citations_by_id.insert(
            "c2".to_string(),
            CitationCandidate {
                id: "c2".to_string(),
                url: "https://www.timeanddate.com/weather/usa/anderson".to_string(),
                source_label: "Weather for Anderson, South Carolina, USA".to_string(),
                excerpt: "Current weather: 64°F, fair, wind 4 mph.".to_string(),
                timestamp_utc: "2026-03-11T13:19:18Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );

        let draft = SynthesisDraft {
            query: "What's the weather like right now in Anderson, SC?".to_string(),
            retrieval_contract: Some(WebRetrievalContract {
                contract_version: "test.v1".to_string(),
                entity_cardinality_min: 1,
                comparison_required: false,
                currentness_required: true,
                runtime_locality_required: true,
                source_independence_min: 2,
                citation_count_min: 2,
                structured_record_preferred: true,
                ordered_collection_preferred: false,
                link_collection_preferred: false,
                canonical_link_out_preferred: false,
                geo_scoped_detail_required: true,
                discovery_surface_required: false,
                entity_diversity_required: false,
                scalar_measure_required: true,
                browser_fallback_allowed: true,
            }),
            run_date: "2026-03-11".to_string(),
            run_timestamp_ms: 1_773_236_577_000,
            run_timestamp_iso_utc: "2026-03-11T13:19:18Z".to_string(),
            completion_reason: "min_sources_reached".to_string(),
            overall_confidence: "high".to_string(),
            overall_caveat: "retrieval receipts available".to_string(),
            stories: vec![
                StoryDraft {
                    title: "National Weather Service".to_string(),
                    what_happened:
                        "Current conditions from retrieved source text: temperature 65°F, humidity 93%, wind SW 3 mph."
                            .to_string(),
                    changed_last_hour: String::new(),
                    why_it_matters: String::new(),
                    user_impact: String::new(),
                    workaround: String::new(),
                    eta_confidence: "high".to_string(),
                    citation_ids: vec!["c1".to_string()],
                    confidence: "high".to_string(),
                    caveat: "retrieved_utc".to_string(),
                },
                StoryDraft {
                    title: "Time and Date".to_string(),
                    what_happened:
                        "Current conditions from retrieved source text: 64°F, fair, wind 4 mph."
                            .to_string(),
                    changed_last_hour: String::new(),
                    why_it_matters: String::new(),
                    user_impact: String::new(),
                    workaround: String::new(),
                    eta_confidence: "high".to_string(),
                    citation_ids: vec!["c2".to_string()],
                    confidence: "high".to_string(),
                    caveat: "retrieved_utc".to_string(),
                },
            ],
            citations_by_id,
            blocked_urls: Vec::new(),
            partial_note: None,
        };

        let rendered = render_single_snapshot_layout(
            &draft,
            1,
            2,
            &query_metric_axes(&draft.query),
            &[],
            &[],
            &[],
        );

        assert!(rendered.contains("https://forecast.weather.gov/MapClick.php"));
        assert!(rendered.contains("https://www.timeanddate.com/weather/usa/anderson"));
    }

    #[test]
    fn render_single_snapshot_layout_surfaces_direct_current_fact_without_metric_caveats() {
        let mut citations_by_id = BTreeMap::new();
        citations_by_id.insert(
            "c1".to_string(),
            CitationCandidate {
                id: "c1".to_string(),
                url: "https://ask.un.org/faq/14625".to_string(),
                source_label:
                    "UN Ask DAG ask.un.org \u{203a} faq \u{203a} 14625 Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                        .to_string(),
                excerpt:
                    "Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                        .to_string(),
                timestamp_utc: "2026-04-14T21:08:14Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );

        let draft = SynthesisDraft {
            query: "Who is the current Secretary-General of the UN?".to_string(),
            retrieval_contract: Some(WebRetrievalContract {
                contract_version: "test.v1".to_string(),
                entity_cardinality_min: 1,
                comparison_required: false,
                currentness_required: true,
                runtime_locality_required: false,
                source_independence_min: 1,
                citation_count_min: 1,
                structured_record_preferred: true,
                ordered_collection_preferred: false,
                link_collection_preferred: false,
                canonical_link_out_preferred: false,
                geo_scoped_detail_required: false,
                discovery_surface_required: false,
                entity_diversity_required: false,
                scalar_measure_required: false,
                browser_fallback_allowed: true,
            }),
            run_date: "2026-04-14".to_string(),
            run_timestamp_ms: 1_776_200_894_000,
            run_timestamp_iso_utc: "2026-04-14T21:08:14Z".to_string(),
            completion_reason: "min_sources_reached".to_string(),
            overall_confidence: "high".to_string(),
            overall_caveat: "retrieval receipts available".to_string(),
            stories: vec![StoryDraft {
                title: "United Nations".to_string(),
                what_happened:
                    "Current answer from retrieved source text: Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c1".to_string()],
                confidence: "high".to_string(),
                caveat: "retrieved_utc".to_string(),
            }],
            citations_by_id,
            blocked_urls: Vec::new(),
            partial_note: None,
        };

        let rendered = render_single_snapshot_layout(&draft, 1, 1, &BTreeSet::new(), &[], &[], &[]);

        assert!(rendered.contains("Current snapshot (as of 2026-04-14T21:08:14Z UTC):"));
        assert!(rendered.contains(
            "Current answer: Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
        ));
        assert!(!rendered.contains("Current metric status:"));
        assert!(!rendered.contains("Data caveat: Retrieved source snippets did not expose numeric current-condition metrics"));
    }

    #[test]
    fn render_single_snapshot_layout_keeps_strong_price_snapshot_concise() {
        let mut citations_by_id = BTreeMap::new();
        citations_by_id.insert(
            "c1".to_string(),
            CitationCandidate {
                id: "c1".to_string(),
                url: "https://openai.com/api/pricing/".to_string(),
                source_label: "OpenAI API Pricing | OpenAI".to_string(),
                excerpt: "Pricing: Audio: $32.00 for inputs $0.40 for cached inputs $64.00 for outputs Text: $4.00 for inputs $0.40 for cached inputs $16.00 for outputs".to_string(),
                timestamp_utc: "2026-04-15T06:04:04Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );

        let draft = SynthesisDraft {
            query: "What is the latest OpenAI API pricing?".to_string(),
            retrieval_contract: Some(WebRetrievalContract {
                contract_version: "test.v1".to_string(),
                entity_cardinality_min: 1,
                comparison_required: false,
                currentness_required: true,
                runtime_locality_required: false,
                source_independence_min: 1,
                citation_count_min: 1,
                structured_record_preferred: true,
                ordered_collection_preferred: false,
                link_collection_preferred: false,
                canonical_link_out_preferred: false,
                geo_scoped_detail_required: false,
                discovery_surface_required: false,
                entity_diversity_required: false,
                scalar_measure_required: true,
                browser_fallback_allowed: true,
            }),
            run_date: "2026-04-15".to_string(),
            run_timestamp_ms: 1_776_233_044_000,
            run_timestamp_iso_utc: "2026-04-15T06:04:04Z".to_string(),
            completion_reason: "min_sources_reached".to_string(),
            overall_confidence: "high".to_string(),
            overall_caveat: "retrieval receipts available".to_string(),
            stories: vec![StoryDraft {
                title: "OpenAI API Pricing".to_string(),
                what_happened: "Current pricing from retrieved source text: Pricing: Audio: $32.00 for inputs $0.40 for cached inputs $64.00 for outputs Text: $4.00 for inputs $0.40 for cached inputs $16.00 for outputs".to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c1".to_string()],
                confidence: "high".to_string(),
                caveat: "retrieved_utc".to_string(),
            }],
            citations_by_id,
            blocked_urls: Vec::new(),
            partial_note: None,
        };

        let rendered = render_single_snapshot_layout(
            &draft,
            1,
            1,
            &query_metric_axes(&draft.query),
            &[],
            &[],
            &[],
        );

        assert!(rendered.contains("Current pricing from retrieved source text:"));
        assert!(rendered.contains("Audio: $32.00 input, $0.40 cached input, $64.00 output"));
        assert!(rendered.contains("Text: $4.00 input, $0.40 cached input, $16.00 output"));
        assert!(!rendered.contains("Estimated-right-now:"));
        assert!(!rendered.contains("Current metric status:"));
        assert!(!rendered.contains("Data caveat:"));
        assert!(!rendered.contains("(From OpenAI API Pricing"));
    }
}
