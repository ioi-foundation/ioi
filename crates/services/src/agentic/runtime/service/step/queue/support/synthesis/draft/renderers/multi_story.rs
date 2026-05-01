use super::*;

#[derive(Debug, Clone, Default)]
pub(crate) struct DocumentBriefingRenderFacts {
    pub required_section_count: usize,
    pub rendered_required_section_count: usize,
    pub query_grounded_required_section_count: usize,
    pub required_narrative_sections: usize,
    pub rendered_single_block_narrative_sections: usize,
    pub required_evidence_sections: usize,
    pub rendered_evidence_block_count: usize,
    pub qualifying_evidence_sections: usize,
    pub required_supporting_fragment_floor: usize,
    pub qualifying_aggregated_narrative_sections: usize,
    pub standard_identifiers: Vec<String>,
    pub required_standard_identifier_count: usize,
    pub standard_identifier_group_floor: usize,
    pub authority_standard_identifiers: Vec<String>,
    pub required_authority_standard_identifier_count: usize,
    pub summary_inventory_identifiers: Vec<String>,
    pub summary_inventory_required_identifier_count: usize,
    pub summary_inventory_optional_identifier_count: usize,
    pub summary_inventory_authority_identifier_count: usize,
    pub standard_identifier_authority_source_count: usize,
    pub available_standard_identifier_authority_source_count: usize,
    pub required_section_floor_met: bool,
    pub query_grounding_floor_met: bool,
    pub standard_identifier_floor_met: bool,
    pub authority_standard_identifier_floor_met: bool,
    pub summary_inventory_floor_met: bool,
    pub narrative_aggregation_floor_met: bool,
    pub evidence_block_floor_met: bool,
}

#[derive(Debug, Clone)]
struct DocumentBriefingSupport {
    source_label: String,
    url: String,
    fragment: String,
    standard_identifiers: Vec<String>,
    authoritative: bool,
    from_successful_read: bool,
}

fn strip_repeated_source_prefix(fragment: &str, source_label: &str) -> String {
    let mut trimmed = compact_whitespace(fragment);
    let normalized_label = normalize_section_key(source_label);
    for separator in [": ", " - ", " | "] {
        let Some((head, tail)) = trimmed.split_once(separator) else {
            continue;
        };
        if tail.trim().is_empty() {
            continue;
        }
        let normalized_head = normalize_section_key(head);
        if normalized_head == normalized_label || titles_similar(head, source_label) {
            trimmed = compact_whitespace(tail);
            break;
        }
    }
    trimmed
}

fn lowercase_attribution_clause_start(input: &str) -> String {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let second = chars.next();
    if first.is_ascii_uppercase() && second.is_some_and(|value| value.is_ascii_lowercase()) {
        let mut out = first.to_ascii_lowercase().to_string();
        if let Some(value) = second {
            out.push(value);
        }
        out.push_str(chars.as_str());
        return out;
    }
    input.to_string()
}

fn ensure_terminal_sentence(input: &str) -> String {
    let trimmed = input
        .trim()
        .trim_matches(|ch: char| matches!(ch, ':' | ';' | '|' | '-'));
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?') {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    }
}

fn cited_briefing_sources(
    draft: &SynthesisDraft,
    story_count: usize,
) -> Vec<DocumentBriefingSupport> {
    let mut seen_urls = BTreeSet::new();
    let mut cited = Vec::new();
    for story in draft.stories.iter().take(story_count.max(1)) {
        for citation_id in &story.citation_ids {
            let Some(citation) = draft.citations_by_id.get(citation_id) else {
                continue;
            };
            if !citation.from_successful_read {
                continue;
            }
            let trimmed_url = citation.url.trim();
            if trimmed_url.is_empty() || !seen_urls.insert(trimmed_url.to_string()) {
                continue;
            }
            cited.push(DocumentBriefingSupport {
                source_label: compact_source_label(&citation.source_label),
                url: trimmed_url.to_string(),
                fragment: {
                    let compact = compact_whitespace(&citation.excerpt);
                    if compact.is_empty() {
                        compact_source_label(&citation.source_label)
                    } else {
                        compact
                    }
                },
                standard_identifiers:
                    observed_briefing_standard_identifier_labels_with_compressed_fips(
                        &draft.query,
                        &preferred_source_briefing_identifier_surface(
                            &draft.query,
                            &citation.url,
                            &citation.source_label,
                            &citation.excerpt,
                        ),
                    ),
                authoritative: source_has_document_authority(
                    &draft.query,
                    &citation.url,
                    &citation.source_label,
                    &citation.excerpt,
                ),
                from_successful_read: citation.from_successful_read,
            });
        }
    }
    cited
}

fn briefing_identifier_observations_for_draft(
    draft: &SynthesisDraft,
) -> Vec<BriefingIdentifierObservation> {
    draft
        .citations_by_id
        .values()
        .filter(|citation| citation.from_successful_read)
        .filter_map(|citation| {
            let trimmed_url = citation.url.trim();
            (!trimmed_url.is_empty()).then(|| BriefingIdentifierObservation {
                url: trimmed_url.to_string(),
                surface: preferred_source_briefing_identifier_surface(
                    &draft.query,
                    &citation.url,
                    &citation.source_label,
                    &citation.excerpt,
                ),
                authoritative: source_has_document_authority(
                    &draft.query,
                    &citation.url,
                    &citation.source_label,
                    &citation.excerpt,
                ),
            })
        })
        .collect()
}

fn required_briefing_identifier_labels(draft: &SynthesisDraft) -> BTreeSet<String> {
    infer_briefing_required_identifier_labels(
        &draft.query,
        &briefing_identifier_observations_for_draft(draft),
    )
}

fn document_briefing_summary_inventory_identifiers(
    draft: &SynthesisDraft,
    authority_standard_identifiers: &[String],
    standard_identifiers: &[String],
) -> Vec<String> {
    let observations = briefing_identifier_observations_for_draft(draft);
    let required_labels = required_briefing_identifier_labels(draft);
    let authority_required = authority_standard_identifiers
        .iter()
        .filter(|label| required_labels.contains(*label))
        .cloned()
        .collect::<Vec<_>>();
    if !authority_required.is_empty() {
        return preferred_briefing_identifier_display_labels(authority_required, &observations);
    }
    let standard_required = standard_identifiers
        .iter()
        .filter(|label| required_labels.contains(*label))
        .cloned()
        .collect::<Vec<_>>();
    preferred_briefing_identifier_display_labels(standard_required, &observations)
}

fn document_briefing_identifier_support_candidates(
    draft: &SynthesisDraft,
) -> Vec<DocumentBriefingSupport> {
    let mut candidates = draft
        .citations_by_id
        .values()
        .filter_map(|citation| {
            if !citation.from_successful_read {
                return None;
            }
            let trimmed_url = citation.url.trim();
            if trimmed_url.is_empty() {
                return None;
            }
            let standard_identifiers = source_briefing_standard_identifier_labels(
                &draft.query,
                &citation.url,
                &citation.source_label,
                &citation.excerpt,
            )
            .into_iter()
            .collect::<Vec<_>>();
            if standard_identifiers.is_empty() {
                return None;
            }
            let fragment = compact_whitespace(&citation.excerpt);
            Some(DocumentBriefingSupport {
                source_label: compact_source_label(&citation.source_label),
                url: trimmed_url.to_string(),
                fragment: if fragment.is_empty() {
                    compact_source_label(&citation.source_label)
                } else {
                    fragment
                },
                standard_identifiers,
                authoritative: source_has_document_authority(
                    &draft.query,
                    &citation.url,
                    &citation.source_label,
                    &citation.excerpt,
                ),
                from_successful_read: citation.from_successful_read,
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        let left_required_hits = left
            .standard_identifiers
            .iter()
            .filter(|label| required_briefing_identifier_labels(draft).contains(*label))
            .count();
        let right_required_hits = right
            .standard_identifiers
            .iter()
            .filter(|label| required_briefing_identifier_labels(draft).contains(*label))
            .count();
        (
            right.authoritative,
            right_required_hits,
            right.standard_identifiers.len(),
            !right.fragment.is_empty(),
            &right.url,
        )
            .cmp(&(
                left.authoritative,
                left_required_hits,
                left.standard_identifiers.len(),
                !left.fragment.is_empty(),
                &left.url,
            ))
    });
    candidates.dedup_by(|left, right| left.url.eq_ignore_ascii_case(&right.url));
    candidates
}

fn document_briefing_priority_cited_sources(
    draft: &SynthesisDraft,
    story_count: usize,
) -> Vec<DocumentBriefingSupport> {
    let required_identifier_labels = required_briefing_identifier_labels(draft);
    let required_identifier_floor = required_identifier_labels.len();
    let authoritative_identifier_support_available =
        available_briefing_identifier_authority_source_count(draft) > 0;
    let mut supports = cited_briefing_sources(draft, story_count);
    let mut seen_urls = supports
        .iter()
        .map(|support| support.url.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut observed_required_labels = supports
        .iter()
        .flat_map(|support| support.standard_identifiers.iter().cloned())
        .filter(|label| required_identifier_labels.contains(label))
        .collect::<BTreeSet<_>>();
    let mut authority_identifier_urls = supports
        .iter()
        .filter(|support| support.authoritative && !support.standard_identifiers.is_empty())
        .map(|support| support.url.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut observed_authority_required_labels = supports
        .iter()
        .filter(|support| support.authoritative)
        .flat_map(|support| support.standard_identifiers.iter().cloned())
        .filter(|label| required_identifier_labels.contains(label))
        .collect::<BTreeSet<_>>();

    for support in document_briefing_identifier_support_candidates(draft) {
        let lower_url = support.url.to_ascii_lowercase();
        let support_required_labels = support
            .standard_identifiers
            .iter()
            .filter(|label| required_identifier_labels.contains(*label))
            .cloned()
            .collect::<BTreeSet<_>>();
        let adds_required_identifier = support_required_labels
            .iter()
            .any(|label| !observed_required_labels.contains(label));
        let adds_authority_required_identifier = support.authoritative
            && support_required_labels
                .iter()
                .any(|label| !observed_authority_required_labels.contains(label));
        let adds_identifier_authority = support.authoritative
            && !support.standard_identifiers.is_empty()
            && !authority_identifier_urls.contains(&lower_url);
        if !adds_required_identifier
            && !adds_authority_required_identifier
            && !adds_identifier_authority
        {
            continue;
        }
        if !seen_urls.insert(lower_url.clone()) {
            continue;
        }
        observed_required_labels.extend(support_required_labels.iter().cloned());
        if support.authoritative && !support.standard_identifiers.is_empty() {
            observed_authority_required_labels.extend(support_required_labels.iter().cloned());
            authority_identifier_urls.insert(lower_url);
        }
        supports.push(support);
        let authority_identifier_floor_met = !authoritative_identifier_support_available
            || observed_authority_required_labels.len() >= required_identifier_floor;
        if observed_required_labels.len() >= required_identifier_floor
            && authority_identifier_floor_met
        {
            break;
        }
    }

    supports.sort_by(|left, right| {
        let left_required_hits = left
            .standard_identifiers
            .iter()
            .filter(|label| required_identifier_labels.contains(*label))
            .count();
        let right_required_hits = right
            .standard_identifiers
            .iter()
            .filter(|label| required_identifier_labels.contains(*label))
            .count();
        (
            right.authoritative,
            right_required_hits,
            right.standard_identifiers.len(),
            !right.fragment.is_empty(),
            &right.url,
        )
            .cmp(&(
                left.authoritative,
                left_required_hits,
                left.standard_identifiers.len(),
                !left.fragment.is_empty(),
                &left.url,
            ))
    });

    supports
}

fn query_grounded_briefing_supports(
    draft: &SynthesisDraft,
    section: &HybridSectionSpec,
    story_count: usize,
) -> Vec<DocumentBriefingSupport> {
    let kind = section_kind_from_key(&section.key)
        .or_else(|| section_kind_from_key(&section.label))
        .unwrap_or(ReportSectionKind::Summary);
    if matches!(kind, ReportSectionKind::Evidence) {
        return document_briefing_priority_cited_sources(draft, story_count);
    }

    let retrieval_contract = draft.retrieval_contract.as_ref();
    let min_sources = story_count.max(1);
    let mut cited_supports = Vec::new();
    for support in document_briefing_priority_cited_sources(draft, story_count) {
        let prioritized = prioritized_query_grounding_excerpt_with_contract(
            retrieval_contract,
            &draft.query,
            min_sources,
            &support.url,
            &support.source_label,
            &support.fragment,
            220,
        );
        let cleaned = ensure_terminal_sentence(&strip_repeated_source_prefix(
            &prioritized,
            &support.source_label,
        ));
        if cleaned.is_empty() {
            continue;
        }
        cited_supports.push(DocumentBriefingSupport {
            source_label: support.source_label,
            url: support.url,
            fragment: cleaned,
            standard_identifiers: support.standard_identifiers,
            authoritative: support.authoritative,
            from_successful_read: support.from_successful_read,
        });
    }
    if !cited_supports.is_empty() {
        return cited_supports;
    }

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for story in draft.stories.iter().take(story_count.max(1)) {
        let Some(content) = section_content_for_story(story, section) else {
            continue;
        };
        let normalized = prioritized_query_grounding_excerpt_with_contract(
            retrieval_contract,
            &draft.query,
            min_sources,
            "",
            &story.title,
            content.content.trim(),
            220,
        );
        let cleaned =
            ensure_terminal_sentence(&strip_repeated_source_prefix(&normalized, &story.title));
        if cleaned.is_empty() || !seen.insert(cleaned.clone()) {
            continue;
        }
        out.push(DocumentBriefingSupport {
            source_label: compact_source_label(&story.title),
            url: String::new(),
            fragment: cleaned,
            standard_identifiers: observed_briefing_standard_identifier_labels_with_compressed_fips(
                &draft.query,
                &normalized,
            ),
            authoritative: false,
            from_successful_read: false,
        });
    }
    out
}

fn document_briefing_standard_identifiers(
    draft: &SynthesisDraft,
    story_count: usize,
) -> Vec<String> {
    document_briefing_standard_identifiers_with_filter(draft, story_count, |_| true)
}

fn document_briefing_authority_standard_identifiers(
    draft: &SynthesisDraft,
    story_count: usize,
) -> Vec<String> {
    document_briefing_standard_identifiers_with_filter(draft, story_count, |support| {
        support.authoritative
    })
}

fn document_briefing_standard_identifiers_with_filter<F>(
    draft: &SynthesisDraft,
    story_count: usize,
    mut include_support: F,
) -> Vec<String>
where
    F: FnMut(&DocumentBriefingSupport) -> bool,
{
    let required_labels = required_briefing_identifier_labels(draft);
    if required_labels.is_empty() {
        return Vec::new();
    }
    let mut labels = Vec::new();
    let mut seen = BTreeSet::new();
    for support in document_briefing_priority_cited_sources(draft, story_count) {
        if !include_support(&support) {
            continue;
        }
        for label in support.standard_identifiers {
            if required_labels.contains(&label) && seen.insert(label.clone()) {
                labels.push(label);
            }
        }
    }
    labels
}

fn document_briefing_identifier_authority_source_count(
    draft: &SynthesisDraft,
    story_count: usize,
) -> usize {
    document_briefing_priority_cited_sources(draft, story_count)
        .iter()
        .filter(|support| support.authoritative && !support.standard_identifiers.is_empty())
        .map(|support| support.url.to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len()
}

fn available_briefing_identifier_authority_source_count(draft: &SynthesisDraft) -> usize {
    document_briefing_identifier_support_candidates(draft)
        .iter()
        .filter(|support| support.authoritative)
        .map(|support| support.url.to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len()
}

fn citation_candidate_for_url<'a>(
    draft: &'a SynthesisDraft,
    url: &str,
) -> Option<&'a CitationCandidate> {
    draft
        .citations_by_id
        .values()
        .find(|citation| citation.url.eq_ignore_ascii_case(url))
}

fn document_briefing_sections(
    draft: &SynthesisDraft,
    required_sections: &[HybridSectionSpec],
) -> Vec<HybridSectionSpec> {
    if required_sections.is_empty() {
        vec![
            HybridSectionSpec {
                key: report_section_key(ReportSectionKind::Summary).to_string(),
                label: report_section_label(ReportSectionKind::Summary, &draft.query),
                required: true,
            },
            HybridSectionSpec {
                key: report_section_key(ReportSectionKind::Evidence).to_string(),
                label: report_section_label(ReportSectionKind::Evidence, &draft.query),
                required: true,
            },
        ]
    } else {
        required_sections.to_vec()
    }
}

fn join_natural_language(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        2 => format!("{} and {}", items[0], items[1]),
        _ => {
            let mut out = items[..items.len() - 1].join(", ");
            out.push_str(", and ");
            if let Some(last) = items.last() {
                out.push_str(last);
            }
            out
        }
    }
}

fn document_briefing_summary_inventory_intro(run_date: &str, labels: &[String]) -> String {
    if labels.is_empty() {
        return format!(
            "As of {}, retrieved sources align on the current picture.",
            run_date
        );
    }

    let inventory = join_natural_language(labels);
    if labels
        .iter()
        .all(|label| label.to_ascii_lowercase().starts_with("fips "))
    {
        return format!(
            "As of {}, retrieved authoritative sources identify the currently published standards as {}.",
            run_date, inventory
        );
    }

    format!(
        "As of {}, retrieved authoritative sources identify the current authoritative publications as {}.",
        run_date, inventory
    )
}

fn attributed_briefing_sentence(source_label: &str, fragment: &str) -> String {
    let cleaned = ensure_terminal_sentence(&strip_repeated_source_prefix(fragment, source_label));
    if cleaned.is_empty() {
        return String::new();
    }
    if cleaned.to_ascii_lowercase().starts_with("according to ") {
        return cleaned;
    }
    let label = compact_source_label(source_label);
    if label.is_empty() {
        return cleaned;
    }
    ensure_terminal_sentence(&format!(
        "According to {}, {}",
        label,
        lowercase_attribution_clause_start(&cleaned)
    ))
}

fn rendered_document_briefing_section_blocks(
    draft: &SynthesisDraft,
    section: &HybridSectionSpec,
    story_count: usize,
) -> Vec<String> {
    let kind = section_kind_from_key(&section.key)
        .or_else(|| section_kind_from_key(&section.label))
        .unwrap_or(ReportSectionKind::Summary);
    let supports = query_grounded_briefing_supports(draft, section, story_count);
    if supports.is_empty() {
        return Vec::new();
    }
    if matches!(kind, ReportSectionKind::Evidence) {
        let retrieval_contract = draft.retrieval_contract.as_ref();
        let min_sources = story_count.max(1);
        let mut lines = Vec::new();
        let mut seen = BTreeSet::new();
        for support in supports {
            let prioritized = prioritized_query_grounding_excerpt_with_contract(
                retrieval_contract,
                &draft.query,
                min_sources,
                &support.url,
                &support.source_label,
                &support.fragment,
                220,
            );
            let evidence_fragment = if prioritized.is_empty() {
                support.fragment.clone()
            } else {
                prioritized
            };
            let attributed =
                attributed_briefing_sentence(&support.source_label, &evidence_fragment);
            if attributed.is_empty() {
                continue;
            }
            let key = normalize_section_key(&attributed);
            if key.is_empty() || !seen.insert(key) {
                continue;
            }
            lines.push(attributed);
        }
        return lines;
    }

    let attributed = supports
        .iter()
        .map(|support| attributed_briefing_sentence(&support.source_label, &support.fragment))
        .filter(|sentence| !sentence.is_empty())
        .collect::<Vec<_>>();
    if attributed.is_empty() {
        return Vec::new();
    }

    let mut lines = Vec::new();
    if matches!(kind, ReportSectionKind::Summary) {
        let standard_identifiers = document_briefing_standard_identifiers(draft, story_count);
        let authority_standard_identifiers =
            document_briefing_authority_standard_identifiers(draft, story_count);
        let summary_inventory_identifiers = document_briefing_summary_inventory_identifiers(
            draft,
            &authority_standard_identifiers,
            &standard_identifiers,
        );
        let intro = document_briefing_summary_inventory_intro(
            &draft.run_date,
            &summary_inventory_identifiers,
        );
        lines.push(intro);
    }
    lines.extend(attributed);
    vec![lines.join(" ")]
}

pub(crate) fn document_briefing_render_facts(
    draft: &SynthesisDraft,
    required_sections: &[HybridSectionSpec],
    support_count: usize,
) -> DocumentBriefingRenderFacts {
    let direct_sections = document_briefing_sections(draft, required_sections);
    let required_supporting_fragment_floor = support_count.min(2).max(1);
    let required_section_count = direct_sections.len();
    let mut rendered_required_section_count = 0usize;
    let mut query_grounded_required_section_count = 0usize;
    let mut required_narrative_sections = 0usize;
    let mut rendered_single_block_narrative_sections = 0usize;
    let mut required_evidence_sections = 0usize;
    let mut rendered_evidence_block_count = 0usize;
    let mut qualifying_evidence_sections = 0usize;
    let mut qualifying_aggregated_narrative_sections = 0usize;
    let standard_identifiers = document_briefing_standard_identifiers(draft, support_count);
    let authority_standard_identifiers =
        document_briefing_authority_standard_identifiers(draft, support_count);
    let summary_inventory_identifiers = document_briefing_summary_inventory_identifiers(
        draft,
        &authority_standard_identifiers,
        &standard_identifiers,
    );
    let required_identifier_labels = required_briefing_identifier_labels(draft);
    let authority_standard_identifier_set = authority_standard_identifiers
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required_standard_identifier_count = standard_identifiers
        .iter()
        .filter(|label| required_identifier_labels.contains(*label))
        .count();
    let required_authority_standard_identifier_count = authority_standard_identifiers
        .iter()
        .filter(|label| required_identifier_labels.contains(*label))
        .count();
    let standard_identifier_group_floor = required_identifier_labels.len();
    let summary_inventory_required_identifier_count = summary_inventory_identifiers
        .iter()
        .filter(|label| required_identifier_labels.contains(*label))
        .count();
    let summary_inventory_optional_identifier_count = summary_inventory_identifiers
        .len()
        .saturating_sub(summary_inventory_required_identifier_count);
    let summary_inventory_authority_identifier_count = summary_inventory_identifiers
        .iter()
        .filter(|label| authority_standard_identifier_set.contains(*label))
        .count();
    let standard_identifier_authority_source_count =
        document_briefing_identifier_authority_source_count(draft, support_count);
    let available_standard_identifier_authority_source_count =
        available_briefing_identifier_authority_source_count(draft);

    for section in &direct_sections {
        let kind = section_kind_from_key(&section.key)
            .or_else(|| section_kind_from_key(&section.label))
            .unwrap_or(ReportSectionKind::Summary);
        let rendered_blocks =
            rendered_document_briefing_section_blocks(draft, section, support_count);
        if rendered_blocks.is_empty() {
            continue;
        }
        rendered_required_section_count = rendered_required_section_count.saturating_add(1);
        let supports = query_grounded_briefing_supports(draft, section, support_count);
        if matches!(kind, ReportSectionKind::Evidence) {
            required_evidence_sections = required_evidence_sections.saturating_add(1);
            rendered_evidence_block_count =
                rendered_evidence_block_count.saturating_add(rendered_blocks.len());
            if supports.len() >= required_supporting_fragment_floor
                && rendered_blocks.len() >= required_supporting_fragment_floor
            {
                query_grounded_required_section_count =
                    query_grounded_required_section_count.saturating_add(1);
                qualifying_evidence_sections = qualifying_evidence_sections.saturating_add(1);
            }
            continue;
        }
        required_narrative_sections = required_narrative_sections.saturating_add(1);
        if supports.len() >= required_supporting_fragment_floor {
            query_grounded_required_section_count =
                query_grounded_required_section_count.saturating_add(1);
        }
        if rendered_blocks.len() == 1 {
            rendered_single_block_narrative_sections =
                rendered_single_block_narrative_sections.saturating_add(1);
        }
        if supports.len() >= required_supporting_fragment_floor && rendered_blocks.len() == 1 {
            qualifying_aggregated_narrative_sections =
                qualifying_aggregated_narrative_sections.saturating_add(1);
        }
    }

    let required_section_floor_met =
        required_section_count == 0 || rendered_required_section_count >= required_section_count;
    let query_grounding_floor_met = required_section_count == 0
        || query_grounded_required_section_count >= required_section_count;
    let standard_identifier_floor_met = standard_identifier_group_floor == 0
        || (required_standard_identifier_count >= standard_identifier_group_floor
            && (available_standard_identifier_authority_source_count == 0
                || standard_identifier_authority_source_count > 0));
    let authority_standard_identifier_floor_met = standard_identifier_group_floor == 0
        || available_standard_identifier_authority_source_count == 0
        || required_authority_standard_identifier_count >= standard_identifier_group_floor;
    let summary_inventory_authority_only_floor_met = summary_inventory_required_identifier_count
        == 0
        && summary_inventory_optional_identifier_count > standard_identifier_group_floor
        && summary_inventory_authority_identifier_count
            == summary_inventory_optional_identifier_count
        && required_authority_standard_identifier_count >= standard_identifier_group_floor;
    let summary_inventory_floor_met = standard_identifier_group_floor == 0
        || (summary_inventory_required_identifier_count >= standard_identifier_group_floor
            && summary_inventory_optional_identifier_count == 0
            && (available_standard_identifier_authority_source_count == 0
                || summary_inventory_authority_identifier_count
                    >= standard_identifier_group_floor))
        || summary_inventory_authority_only_floor_met;
    let narrative_aggregation_floor_met = required_narrative_sections == 0
        || qualifying_aggregated_narrative_sections >= required_narrative_sections;
    let evidence_block_floor_met = required_evidence_sections == 0
        || qualifying_evidence_sections >= required_evidence_sections;

    DocumentBriefingRenderFacts {
        required_section_count,
        rendered_required_section_count,
        query_grounded_required_section_count,
        required_narrative_sections,
        rendered_single_block_narrative_sections,
        required_evidence_sections,
        rendered_evidence_block_count,
        qualifying_evidence_sections,
        required_supporting_fragment_floor,
        qualifying_aggregated_narrative_sections,
        standard_identifiers,
        required_standard_identifier_count,
        standard_identifier_group_floor,
        authority_standard_identifiers,
        required_authority_standard_identifier_count,
        summary_inventory_identifiers,
        summary_inventory_required_identifier_count,
        summary_inventory_optional_identifier_count,
        summary_inventory_authority_identifier_count,
        standard_identifier_authority_source_count,
        available_standard_identifier_authority_source_count,
        required_section_floor_met,
        query_grounding_floor_met,
        standard_identifier_floor_met,
        authority_standard_identifier_floor_met,
        summary_inventory_floor_met,
        narrative_aggregation_floor_met,
        evidence_block_floor_met,
    }
}

pub(super) fn render_document_briefing_layout(
    draft: &SynthesisDraft,
    required_sections: &[HybridSectionSpec],
    support_count: usize,
    citation_count: usize,
    insight_receipts: &[String],
    conflict_notes: &[String],
    gap_notes: &[String],
) -> String {
    let heading = if draft.query.trim().is_empty() {
        format!("Web briefing (as of {} UTC)", draft.run_timestamp_iso_utc)
    } else {
        format!(
            "Briefing for '{}' (as of {} UTC)",
            draft.query.trim(),
            draft.run_timestamp_iso_utc
        )
    };
    let mut lines = vec![heading];
    let direct_sections = document_briefing_sections(draft, required_sections);

    for section in &direct_sections {
        let rendered_blocks =
            rendered_document_briefing_section_blocks(draft, section, support_count);
        if rendered_blocks.is_empty() {
            continue;
        }
        lines.push(String::new());
        if rendered_blocks.len() == 1 {
            lines.push(format!("{}: {}", section.label, rendered_blocks[0]));
        } else {
            lines.push(format!("{}:", section.label));
            for block in rendered_blocks {
                lines.push(format!("- {}", block));
            }
        }
    }

    lines.push(String::new());
    lines.push("Citations:".to_string());
    let prioritized_citations = document_briefing_priority_cited_sources(draft, support_count);
    let citation_target = support_count.max(citation_count.max(1));
    let mut emitted = 0usize;
    let mut seen_urls = BTreeSet::new();
    for support in &prioritized_citations {
        let Some(citation) = citation_candidate_for_url(draft, &support.url) else {
            continue;
        };
        if citation.url.trim().is_empty() || !seen_urls.insert(citation.url.clone()) {
            continue;
        }
        lines.push(format!(
            "- {} | {} | {} | {}",
            citation.source_label, citation.url, citation.timestamp_utc, citation.note
        ));
        emitted += 1;
    }
    for story in draft.stories.iter().take(support_count.max(1)) {
        for citation_id in &story.citation_ids {
            let Some(citation) = draft.citations_by_id.get(citation_id) else {
                continue;
            };
            if !citation.from_successful_read {
                continue;
            }
            if citation.url.trim().is_empty() || !seen_urls.insert(citation.url.clone()) {
                continue;
            }
            lines.push(format!(
                "- {} | {} | {} | {}",
                citation.source_label, citation.url, citation.timestamp_utc, citation.note
            ));
            emitted += 1;
            if emitted >= citation_target {
                break;
            }
        }
        if emitted >= citation_target {
            break;
        }
    }
    if emitted == 0 {
        lines.push("- No citable evidence was captured for this briefing.".to_string());
    }

    append_common_postamble(
        &mut lines,
        draft,
        support_count,
        citation_count,
        insight_receipts,
        conflict_notes,
        gap_notes,
        None,
    );
    lines.join("\n")
}

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

    if retrieval_or_query_requests_comparison(draft.retrieval_contract.as_ref(), &draft.query)
        && story_count > 1
    {
        lines.push(String::new());
        lines.push("Comparison:".to_string());
        for story in draft.stories.iter().take(story_count) {
            let summary = compact_whitespace(&story.what_happened);
            let summary = if summary.is_empty() {
                story.title.clone()
            } else if summary.chars().count() <= 160 {
                summary
            } else {
                format!("{}...", summary.chars().take(160).collect::<String>())
            };
            lines.push(format!("- {}: {}", story.title, summary));
        }
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

#[cfg(test)]
#[path = "multi_story/tests.rs"]
mod tests;
