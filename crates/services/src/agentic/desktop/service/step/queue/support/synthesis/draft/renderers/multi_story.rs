use super::*;

pub(super) fn render_single_story_direct_layout(
    draft: &SynthesisDraft,
    required_sections: &[HybridSectionSpec],
    story_count: usize,
    citations_per_story: usize,
    insight_receipts: &[String],
    conflict_notes: &[String],
    gap_notes: &[String],
) -> String {
    let mut lines = vec![summary_heading(draft)];

    if let Some(story) = draft.stories.first() {
        lines.push(String::new());
        let direct_sections = if required_sections.is_empty() {
            vec![HybridSectionSpec {
                key: report_section_key(ReportSectionKind::Summary).to_string(),
                label: report_section_label(ReportSectionKind::Summary, &draft.query),
                required: true,
            }]
        } else {
            required_sections.to_vec()
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

pub(super) fn render_multi_story_layout(
    draft: &SynthesisDraft,
    required_sections: &[HybridSectionSpec],
    story_count: usize,
    citations_per_story: usize,
    headline_lookup_mode: bool,
    insight_receipts: &[String],
    conflict_notes: &[String],
    gap_notes: &[String],
) -> String {
    let mut lines = vec![summary_heading(draft)];

    for (idx, story) in draft.stories.iter().take(story_count).enumerate() {
        lines.push(String::new());
        lines.push(format!("Story {}: {}", idx + 1, story.title));
        if required_sections.is_empty() {
            lines.push(format!("What happened: {}", story.what_happened));
        } else {
            for section in required_sections {
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
