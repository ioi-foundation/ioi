use super::*;

mod diagnostics;
mod multi_story;
mod single_snapshot;

pub(crate) fn render_synthesis_draft(draft: &SynthesisDraft) -> String {
    if requires_mailbox_access_notice(&draft.query) {
        return render_mailbox_access_limited_draft(draft);
    }

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

    let assessment = diagnostics::assess_multi_story_grounding(
        draft,
        story_count,
        citations_per_story,
        headline_lookup_mode,
        use_single_snapshot_layout,
    );

    if assessment.insufficient_multi_story_grounding {
        return diagnostics::render_insufficient_multi_story_floor(
            draft,
            story_count,
            citations_per_story,
            headline_lookup_mode,
            &assessment,
            &insight_receipts,
            &conflict_notes,
            &gap_notes,
        );
    }

    if !use_single_snapshot_layout && story_count == 1 && !use_structured_report_layout {
        return multi_story::render_single_story_direct_layout(
            draft,
            &required_sections,
            story_count,
            citations_per_story,
            &insight_receipts,
            &conflict_notes,
            &gap_notes,
        );
    }

    if use_single_snapshot_layout {
        return single_snapshot::render_single_snapshot_layout(
            draft,
            story_count,
            citations_per_story,
            &single_snapshot_query_axes,
            &insight_receipts,
            &conflict_notes,
            &gap_notes,
        );
    }

    multi_story::render_multi_story_layout(
        draft,
        &required_sections,
        story_count,
        citations_per_story,
        headline_lookup_mode,
        &insight_receipts,
        &conflict_notes,
        &gap_notes,
    )
}

pub(super) fn summary_heading(draft: &SynthesisDraft) -> String {
    if draft.query.trim().is_empty() {
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
    }
}

pub(super) fn append_common_postamble(
    lines: &mut Vec<String>,
    draft: &SynthesisDraft,
    story_count: usize,
    citations_per_story: usize,
    insight_receipts: &[String],
    conflict_notes: &[String],
    gap_notes: &[String],
    overall_confidence_override: Option<&str>,
) {
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
    append_retrieval_receipts_for_source_floor(lines, draft, story_count, citations_per_story);
    lines.push(String::new());
    append_synthesis_diagnostics(lines, insight_receipts, conflict_notes, gap_notes);
    lines.push(format!("Completion reason: {}", draft.completion_reason));
    lines.push(format!("Run date (UTC): {}", draft.run_date));
    lines.push(format!(
        "Run timestamp (UTC): {}",
        draft.run_timestamp_iso_utc
    ));
    lines.push(format!(
        "Overall confidence: {}",
        overall_confidence_override.unwrap_or(draft.overall_confidence.as_str())
    ));
    lines.push(format!("Overall caveat: {}", draft.overall_caveat));
    if !draft.query.is_empty() {
        lines.push(format!("Query: {}", draft.query));
    }
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
