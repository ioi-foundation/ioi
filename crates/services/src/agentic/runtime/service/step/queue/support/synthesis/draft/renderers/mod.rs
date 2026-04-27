use super::*;

mod diagnostics;
mod multi_story;
mod single_snapshot;

pub(crate) use multi_story::document_briefing_render_facts;
pub(crate) fn render_synthesis_draft(draft: &SynthesisDraft) -> String {
    if requires_mailbox_access_notice(&draft.query) {
        return render_mailbox_access_limited_draft(draft);
    }

    let retrieval_contract = draft.retrieval_contract.as_ref();
    let required_sections = build_hybrid_required_sections(&draft.query);
    let requested_story_count =
        retrieval_contract_required_story_count(retrieval_contract, &draft.query);
    let briefing_support_count =
        retrieval_contract_required_support_count(retrieval_contract, &draft.query);
    let briefing_citation_count = retrieval_contract_required_document_briefing_citation_count(
        retrieval_contract,
        &draft.query,
    );
    let citations_per_story =
        retrieval_contract_required_citations_per_story(retrieval_contract, &draft.query);
    let use_structured_report_layout = query_requires_structured_synthesis(&draft.query);
    let layout_profile = synthesis_layout_profile(retrieval_contract, &draft.query);
    let single_snapshot_query_axes = query_metric_axes(&draft.query);
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &draft.query);
    let story_count = if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing) {
        briefing_support_count
    } else {
        requested_story_count
    };
    let use_single_snapshot_layout =
        matches!(layout_profile, SynthesisLayoutProfile::SingleSnapshot) && story_count == 1;
    let insight_receipts = synthesis_insight_receipts(draft);
    let conflict_notes = synthesis_conflict_notes(draft);
    let gap_notes = synthesis_gap_notes(draft);

    if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing) {
        return multi_story::render_document_briefing_layout(
            draft,
            &required_sections,
            briefing_support_count,
            briefing_citation_count,
            &insight_receipts,
            &conflict_notes,
            &gap_notes,
        );
    }

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
        "evidence",
        "completion reason",
        "overall caveat",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

pub(crate) fn render_user_synthesis_draft(draft: &SynthesisDraft) -> String {
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

        if trimmed == "Retrieval evidence:" {
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
            || trimmed.starts_with("Confidence:")
            || trimmed.starts_with("Caveat:")
            || trimmed.starts_with("Overall caveat:")
            || trimmed.starts_with("Query:")
        {
            continue;
        }
        filtered.push(line.to_string());
    }
    filtered.join("\n")
}
