use super::*;

#[derive(Debug, Clone, Default)]
struct RenderedBriefingShapeFacts {
    heading_present: bool,
    rendered_required_section_label_count: usize,
    rendered_required_section_label_floor_met: bool,
    story_header_count: usize,
    comparison_label_count: usize,
    single_snapshot_heading_present: bool,
    single_snapshot_metric_line_count: usize,
    single_snapshot_support_url_count: usize,
    single_snapshot_temporal_signal_present: bool,
}

#[derive(Debug, Clone, Default)]
struct RenderedBriefingContractFacts {
    rendered_required_section_count: usize,
    query_grounded_required_section_count: usize,
    required_narrative_sections: usize,
    rendered_single_block_narrative_sections: usize,
    required_evidence_sections: usize,
    rendered_evidence_block_count: usize,
    qualifying_evidence_sections: usize,
    qualifying_aggregated_narrative_sections: usize,
    standard_identifier_count: usize,
    required_standard_identifier_count: usize,
    standard_identifier_group_floor: usize,
    authority_standard_identifier_count: usize,
    required_authority_standard_identifier_count: usize,
    summary_inventory_identifier_count: usize,
    summary_inventory_required_identifier_count: usize,
    summary_inventory_optional_identifier_count: usize,
    summary_inventory_authority_identifier_count: usize,
    standard_identifier_authority_source_count: usize,
    available_standard_identifier_authority_source_count: usize,
    primary_authority_source_count: usize,
    required_primary_authority_source_count: usize,
    citation_urls: Vec<String>,
    successful_citation_url_count: usize,
    unread_citation_url_count: usize,
    run_date: Option<String>,
    run_timestamp_iso_utc: Option<String>,
    overall_confidence: Option<String>,
    required_section_floor_met: bool,
    query_grounding_floor_met: bool,
    standard_identifier_floor_met: bool,
    authority_standard_identifier_floor_met: bool,
    summary_inventory_floor_met: bool,
    narrative_aggregation_floor_met: bool,
    evidence_block_floor_met: bool,
    primary_authority_source_floor_met: bool,
    citation_read_backing_floor_met: bool,
    temporal_anchor_floor_met: bool,
    postamble_floor_met: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenderedSummaryLayoutProfile {
    DocumentBriefing,
    SingleSnapshot,
    StoryCollection,
    Other,
}

impl RenderedSummaryLayoutProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::DocumentBriefing => "document_briefing",
            Self::SingleSnapshot => "single_snapshot",
            Self::StoryCollection => "story_collection",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FinalWebCompletionFacts {
    pub selected_source_urls: Vec<String>,
    pub briefing_selected_source_total: usize,
    pub briefing_selected_source_compatible: usize,
    pub briefing_selected_source_quality_floor_met: bool,
    pub briefing_selected_source_identifier_coverage_floor_met: bool,
    pub selected_primary_authority_source_count: usize,
    pub available_primary_authority_source_count: usize,
    pub attempted_primary_authority_source_count: usize,
    pub local_business_targets: Vec<String>,
    pub matched_local_business_targets: Vec<String>,
    pub local_business_source_urls: Vec<String>,
    pub local_business_menu_surface_required: bool,
    pub local_business_menu_surface_source_urls: Vec<String>,
    pub local_business_menu_surface_floor_met: bool,
    pub local_business_menu_inventory_source_urls: Vec<String>,
    pub local_business_menu_inventory_items: Vec<String>,
    pub local_business_menu_inventory_total_item_count: usize,
    pub local_business_menu_inventory_floor_met: bool,
    pub required_story_floor: usize,
    pub required_citations_per_story: usize,
    pub briefing_required_sections: Vec<String>,
    pub briefing_required_section_count: usize,
    pub briefing_rendered_required_section_count: usize,
    pub briefing_query_grounded_required_section_count: usize,
    pub briefing_required_narrative_sections: usize,
    pub briefing_single_block_narrative_sections: usize,
    pub briefing_required_evidence_sections: usize,
    pub briefing_rendered_evidence_block_count: usize,
    pub briefing_qualifying_evidence_sections: usize,
    pub briefing_required_supporting_fragment_floor: usize,
    pub briefing_aggregated_narrative_sections: usize,
    pub briefing_standard_identifier_count: usize,
    pub briefing_required_standard_identifier_count: usize,
    pub briefing_standard_identifier_group_floor: usize,
    pub briefing_authority_standard_identifier_count: usize,
    pub briefing_required_authority_standard_identifier_count: usize,
    pub briefing_summary_inventory_identifier_count: usize,
    pub briefing_summary_inventory_required_identifier_count: usize,
    pub briefing_summary_inventory_optional_identifier_count: usize,
    pub briefing_summary_inventory_authority_identifier_count: usize,
    pub briefing_standard_identifier_authority_source_count: usize,
    pub briefing_available_standard_identifier_authority_source_count: usize,
    pub briefing_required_primary_authority_source_count: usize,
    pub briefing_successful_citation_url_count: usize,
    pub briefing_unread_citation_url_count: usize,
    pub briefing_run_date: String,
    pub briefing_run_timestamp_iso_utc: String,
    pub briefing_overall_confidence: String,
    pub briefing_query_layout_expected: bool,
    pub briefing_layout_profile: String,
    pub briefing_rendered_layout_profile: String,
    pub briefing_render_heading_floor_met: bool,
    pub briefing_rendered_required_section_label_count: usize,
    pub briefing_rendered_required_section_label_floor_met: bool,
    pub briefing_story_header_count: usize,
    pub briefing_comparison_label_count: usize,
    pub observed_story_slots: usize,
    pub story_slot_floor_met: bool,
    pub story_citation_floor_met: bool,
    pub comparison_required: bool,
    pub comparison_ready: bool,
    pub briefing_document_layout_met: bool,
    pub briefing_story_headers_absent: bool,
    pub briefing_comparison_absent: bool,
    pub briefing_required_section_floor_met: bool,
    pub briefing_query_grounding_floor_met: bool,
    pub briefing_standard_identifier_floor_met: bool,
    pub briefing_authority_standard_identifier_floor_met: bool,
    pub briefing_summary_inventory_floor_met: bool,
    pub briefing_narrative_aggregation_floor_met: bool,
    pub briefing_evidence_block_floor_met: bool,
    pub briefing_primary_authority_source_floor_met: bool,
    pub briefing_citation_read_backing_floor_met: bool,
    pub briefing_temporal_anchor_floor_met: bool,
    pub briefing_postamble_floor_met: bool,
    pub single_snapshot_metric_grounding: bool,
    pub single_snapshot_required_citation_count: usize,
    pub single_snapshot_rendered_layout_met: bool,
    pub single_snapshot_rendered_metric_line_count: usize,
    pub single_snapshot_rendered_metric_line_floor_met: bool,
    pub single_snapshot_rendered_support_url_count: usize,
    pub single_snapshot_rendered_support_url_floor_met: bool,
    pub single_snapshot_rendered_read_backed_url_count: usize,
    pub single_snapshot_rendered_read_backed_url_floor_met: bool,
    pub single_snapshot_rendered_temporal_signal_present: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalWebSummaryCandidate {
    pub provider: &'static str,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalWebSummaryCandidateEvaluation {
    pub provider: &'static str,
    pub contract_ready: bool,
    pub facts: FinalWebCompletionFacts,
}

#[derive(Debug, Clone)]
pub(crate) struct FinalWebSummarySelection {
    pub provider: &'static str,
    pub summary: String,
    pub contract_ready: bool,
    pub facts: FinalWebCompletionFacts,
    pub evaluations: Vec<FinalWebSummaryCandidateEvaluation>,
}

fn final_web_summary_fallback_score(
    facts: &FinalWebCompletionFacts,
) -> (bool, usize, usize, usize) {
    let contract_quality_count = [
        facts.briefing_selected_source_quality_floor_met,
        facts.briefing_selected_source_identifier_coverage_floor_met,
        facts.briefing_document_layout_met,
        facts.briefing_render_heading_floor_met,
        facts.briefing_rendered_required_section_label_floor_met,
        facts.briefing_story_headers_absent,
        facts.briefing_comparison_absent,
        facts.briefing_required_section_floor_met,
        facts.briefing_query_grounding_floor_met,
        facts.briefing_standard_identifier_floor_met,
        facts.briefing_authority_standard_identifier_floor_met,
        facts.briefing_summary_inventory_floor_met,
        facts.briefing_narrative_aggregation_floor_met,
        facts.briefing_evidence_block_floor_met,
        facts.briefing_primary_authority_source_floor_met,
        facts.briefing_citation_read_backing_floor_met,
        facts.briefing_temporal_anchor_floor_met,
        facts.briefing_postamble_floor_met,
        facts.single_snapshot_rendered_layout_met,
        facts.single_snapshot_rendered_metric_line_floor_met,
        facts.single_snapshot_rendered_support_url_floor_met,
        facts.single_snapshot_rendered_read_backed_url_floor_met,
        facts.single_snapshot_rendered_temporal_signal_present,
        facts.story_slot_floor_met,
        facts.story_citation_floor_met,
        facts.comparison_ready,
        facts.local_business_menu_surface_floor_met,
        facts.local_business_menu_inventory_floor_met,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();

    (
        facts.briefing_query_layout_expected == facts.briefing_document_layout_met,
        contract_quality_count,
        facts.selected_source_urls.len(),
        facts.briefing_successful_citation_url_count,
    )
}

fn rendered_briefing_shape_facts(
    rendered_summary: &str,
    required_sections: &[HybridSectionSpec],
) -> RenderedBriefingShapeFacts {
    let lines = rendered_summary
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let heading_present = lines.first().is_some_and(|line| {
        line.starts_with("Briefing for '") || line.starts_with("Web briefing (as of ")
    });
    let story_header_count = lines
        .iter()
        .filter(|line| rendered_summary_line_is_story_header(line))
        .count();
    let comparison_label_count = lines
        .iter()
        .filter(|line| line.eq_ignore_ascii_case("Comparison:"))
        .count();
    let single_snapshot_heading_present = lines.first().is_some_and(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("right now")
            || (lower.contains("current")
                && (lower.ends_with(':')
                    || lower.contains(" as of ")
                    || lower.contains("right now")))
    });
    let single_snapshot_metric_line_count = lines
        .iter()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.eq_ignore_ascii_case("Citations:")
                || trimmed.starts_with("Run date (UTC):")
                || trimmed.starts_with("Run timestamp (UTC):")
                || trimmed.starts_with("Overall confidence:")
            {
                return false;
            }
            let metric_candidate = trimmed.trim_start_matches("- ").trim();
            if metric_candidate.contains("http://") || metric_candidate.contains("https://") {
                return false;
            }
            let lower = metric_candidate.to_ascii_lowercase();
            (trimmed.starts_with("- ")
                || lower.starts_with("current conditions:")
                || lower.starts_with("available observed details")
                || lower.starts_with("the current "))
                && has_quantitative_metric_payload(metric_candidate, false)
        })
        .count();
    let single_snapshot_support_url_count = rendered_summary
        .lines()
        .flat_map(|line| extract_urls(line, 8))
        .collect::<BTreeSet<_>>()
        .len();
    let single_snapshot_temporal_signal_present = lines.iter().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("latest update")
            || lower.contains(" as of ")
            || lower.starts_with("run date (utc):")
            || lower.starts_with("run timestamp (utc):")
    });
    let rendered_required_section_label_count = required_sections
        .iter()
        .filter(|section| {
            let prefix = format!("{}:", section.label.trim());
            lines.iter().any(|line| line.starts_with(&prefix))
        })
        .count();
    let rendered_required_section_label_floor_met = required_sections.is_empty()
        || rendered_required_section_label_count >= required_sections.len();

    RenderedBriefingShapeFacts {
        heading_present,
        rendered_required_section_label_count,
        rendered_required_section_label_floor_met,
        story_header_count,
        comparison_label_count,
        single_snapshot_heading_present,
        single_snapshot_metric_line_count,
        single_snapshot_support_url_count,
        single_snapshot_temporal_signal_present,
    }
}

fn rendered_summary_layout_profile(
    shape_facts: &RenderedBriefingShapeFacts,
) -> RenderedSummaryLayoutProfile {
    if shape_facts.heading_present
        && shape_facts.rendered_required_section_label_floor_met
        && shape_facts.story_header_count == 0
        && shape_facts.comparison_label_count == 0
    {
        return RenderedSummaryLayoutProfile::DocumentBriefing;
    }
    if shape_facts.story_header_count > 0 || shape_facts.comparison_label_count > 0 {
        return RenderedSummaryLayoutProfile::StoryCollection;
    }
    if shape_facts.single_snapshot_heading_present
        && shape_facts.single_snapshot_metric_line_count > 0
        && shape_facts.single_snapshot_support_url_count > 0
        && shape_facts.single_snapshot_temporal_signal_present
    {
        return RenderedSummaryLayoutProfile::SingleSnapshot;
    }
    RenderedSummaryLayoutProfile::Other
}

fn rendered_summary_structured_field(rendered_summary: &str, marker: &str) -> Option<String> {
    rendered_summary.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix(marker)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn rendered_summary_line_is_story_header(line: &str) -> bool {
    line.trim()
        .strip_prefix("Story ")
        .and_then(|rest| rest.split_once(':'))
        .is_some()
}

fn rendered_summary_starts_structured_postamble(line: &str) -> bool {
    [
        "Citations:",
        "Blocked sources requiring human challenge:",
        "Partial evidence:",
        "Retrieval receipts:",
        "Completion reason:",
        "Run date (UTC):",
        "Run timestamp (UTC):",
        "Overall confidence:",
        "Overall caveat:",
        "Query:",
        "Insight selector:",
        "Insights used:",
        "Conflicts:",
        "Evidence gaps:",
    ]
    .iter()
    .any(|marker| line.eq_ignore_ascii_case(marker) || line.starts_with(marker))
}

fn rendered_summary_starts_required_section(
    line: &str,
    required_sections: &[HybridSectionSpec],
) -> bool {
    required_sections
        .iter()
        .any(|section| line.starts_with(format!("{}:", section.label.trim()).as_str()))
}

pub(super) fn rendered_summary_citation_urls(
    rendered_summary: &str,
    required_sections: &[HybridSectionSpec],
) -> Vec<String> {
    let mut citation_urls = BTreeSet::new();
    let mut in_citation_block = false;

    for line in rendered_summary.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("Citations:") {
            in_citation_block = true;
            continue;
        }
        if !in_citation_block {
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if rendered_summary_starts_structured_postamble(trimmed)
            || rendered_summary_line_is_story_header(trimmed)
            || trimmed.eq_ignore_ascii_case("Comparison:")
            || rendered_summary_starts_required_section(trimmed, required_sections)
        {
            in_citation_block = false;
            continue;
        }
        citation_urls.extend(extract_urls(trimmed, 8));
    }

    citation_urls.into_iter().collect()
}

fn rendered_summary_section_blocks(
    rendered_summary: &str,
    required_sections: &[HybridSectionSpec],
) -> BTreeMap<String, Vec<String>> {
    let mut sections = BTreeMap::<String, Vec<String>>::new();
    let prefixes = required_sections
        .iter()
        .map(|section| (section.key.clone(), format!("{}:", section.label.trim())))
        .collect::<Vec<_>>();
    let mut current_key = None::<String>;

    for line in rendered_summary.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if rendered_summary_starts_structured_postamble(trimmed) {
            current_key = None;
            continue;
        }
        if let Some((key, prefix)) = prefixes
            .iter()
            .find(|(_, prefix)| trimmed.starts_with(prefix.as_str()))
        {
            current_key = Some(key.clone());
            let remainder = trimmed[prefix.len()..].trim();
            if !remainder.is_empty() {
                sections
                    .entry(key.clone())
                    .or_default()
                    .push(compact_whitespace(remainder));
                current_key = None;
            }
            continue;
        }
        let Some(key) = current_key.clone() else {
            continue;
        };
        let block = if let Some(rest) = trimmed.strip_prefix("- ") {
            compact_whitespace(rest)
        } else {
            compact_whitespace(trimmed)
        };
        if block.is_empty() {
            continue;
        }
        sections.entry(key).or_default().push(block);
        if !trimmed.starts_with("- ") {
            current_key = None;
        }
    }

    sections
}

fn rendered_summary_inventory_surface(blocks: &[String]) -> String {
    let Some(first_block) = blocks.first() else {
        return String::new();
    };
    let compact = compact_whitespace(first_block);
    if compact.is_empty() {
        return String::new();
    }
    if let Some((prefix, _)) = compact.split_once(" According to ") {
        return prefix.trim().to_string();
    }
    compact
}

fn successful_read_for_url<'a>(
    pending: &'a PendingSearchCompletion,
    url: &str,
) -> Option<&'a PendingSearchReadSummary> {
    source_hint_for_url(&pending.successful_reads, url)
}

fn normalize_menu_inventory_item(raw: &str) -> Option<String> {
    let compact = compact_whitespace(raw);
    let trimmed = compact
        .trim()
        .trim_matches(|ch: char| matches!(ch, ':' | ';' | '|' | ',' | '-' | '.'))
        .trim();
    if trimmed.is_empty()
        || trimmed.chars().count() < 4
        || trimmed.chars().count() > 96
        || !trimmed.chars().any(|ch| ch.is_ascii_alphabetic())
    {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if [
        "customers' favorites",
        "customer favorites",
        "menu",
        "menu photo gallery",
        "photo gallery",
        "photo credit",
        "upload menu",
        "upload image",
        "view photo",
        "hours",
        "phone number",
        "address",
        "map",
    ]
    .iter()
    .any(|marker| lower == *marker || lower.contains(marker))
    {
        return None;
    }

    Some(trimmed.to_string())
}

fn split_menu_inventory_clause(clause: &str) -> Vec<String> {
    let normalized = clause.replace(", and ", ", ");
    normalized
        .split([',', ';'])
        .filter_map(normalize_menu_inventory_item)
        .collect::<Vec<_>>()
}

pub(super) fn local_business_menu_inventory_items_from_excerpt(excerpt: &str) -> Vec<String> {
    let raw_trimmed = excerpt.trim();
    if raw_trimmed.is_empty() {
        return Vec::new();
    }
    let compact = compact_whitespace(raw_trimmed);
    let trimmed = compact.trim();

    let lower = trimmed.to_ascii_lowercase();
    let mut items = Vec::new();
    if let Some(idx) = lower.find("item inventory includes ") {
        let rest = trimmed[idx + "item inventory includes ".len()..]
            .split('.')
            .next()
            .unwrap_or_default();
        items.extend(split_menu_inventory_clause(rest));
    } else if let Some(idx) = lower.find("menu inventory items include ") {
        let rest = trimmed[idx + "menu inventory items include ".len()..]
            .split('.')
            .next()
            .unwrap_or_default();
        items.extend(split_menu_inventory_clause(rest));
    } else if let Some(idx) = lower.find("customers' favorites include ") {
        let rest = trimmed[idx + "customers' favorites include ".len()..]
            .split('.')
            .next()
            .unwrap_or_default();
        items.extend(split_menu_inventory_clause(rest));
    } else if let Some(idx) = lower.find("customer favorites include ") {
        let rest = trimmed[idx + "customer favorites include ".len()..]
            .split('.')
            .next()
            .unwrap_or_default();
        items.extend(split_menu_inventory_clause(rest));
    } else if let Some(idx) = lower.find("menu highlights include ") {
        let rest = trimmed[idx + "menu highlights include ".len()..]
            .split('.')
            .next()
            .unwrap_or_default();
        items.extend(split_menu_inventory_clause(rest));
    } else if let Some(idx) = lower.find("menu items include ") {
        let rest = trimmed[idx + "menu items include ".len()..]
            .split('.')
            .next()
            .unwrap_or_default();
        items.extend(split_menu_inventory_clause(rest));
    }

    if items.is_empty() {
        items.extend(local_business_menu_inventory_items(raw_trimmed, 12));
    }

    if items.is_empty() {
        for segment in trimmed.split(['.', ';', '\n']) {
            if let Some(item) = normalize_menu_inventory_item(segment) {
                items.push(item);
            }
        }
    }

    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    for item in items {
        let normalized = item.to_ascii_lowercase();
        if seen.insert(normalized) {
            deduped.push(item);
        }
    }
    deduped
}

fn local_business_menu_inventory_evidence(
    pending: &PendingSearchCompletion,
    selected_source_urls: &[String],
    required_story_floor: usize,
    min_sources_required: usize,
) -> (Vec<String>, Vec<String>, usize, bool) {
    let required_source_floor = required_story_floor.max(min_sources_required).max(1);
    let required_items_per_source = 2usize;
    let mut qualifying_source_urls = Vec::new();
    let mut total_items = Vec::new();
    let mut seen_total_items = BTreeSet::new();
    let mut seen_source_urls = BTreeSet::new();

    for selected_url in selected_source_urls.iter().filter(|url| {
        let trimmed = url.trim();
        !trimmed.is_empty() && local_business_menu_surface_url(trimmed)
    }) {
        let Some(source) = successful_read_for_url(pending, selected_url) else {
            continue;
        };
        let normalized_source_url = source.url.trim().to_string();
        if !seen_source_urls.insert(normalized_source_url.clone()) {
            continue;
        }
        let items = local_business_menu_inventory_items_from_excerpt(&source.excerpt);
        if items.len() < required_items_per_source {
            continue;
        }
        qualifying_source_urls.push(normalized_source_url);
        for item in items {
            let normalized = item.to_ascii_lowercase();
            if seen_total_items.insert(normalized) {
                total_items.push(item);
            }
        }
    }

    let floor_met = qualifying_source_urls.len() >= required_source_floor
        && total_items.len() >= required_source_floor.saturating_mul(required_items_per_source);

    (
        qualifying_source_urls,
        total_items.clone(),
        total_items.len(),
        floor_met,
    )
}

fn rendered_briefing_contract_facts(
    pending: &PendingSearchCompletion,
    query_contract: &str,
    rendered_summary: &str,
    required_sections: &[HybridSectionSpec],
    required_supporting_fragment_floor: usize,
    required_primary_authority_source_count: usize,
) -> RenderedBriefingContractFacts {
    let section_blocks = rendered_summary_section_blocks(rendered_summary, required_sections);
    let direct_sections = required_sections
        .iter()
        .filter(|section| section.required)
        .cloned()
        .collect::<Vec<_>>();
    let required_section_count = direct_sections.len();
    let query_anchor_tokens = query_semantic_anchor_tokens(query_contract)
        .into_iter()
        .filter(|token| token.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS)
        .filter(|token| !is_query_stopword(token))
        .collect::<BTreeSet<_>>();
    let full_surface = compact_whitespace(rendered_summary).to_ascii_lowercase();
    let successful_read_observations = pending
        .successful_reads
        .iter()
        .filter_map(|source| {
            let trimmed = source.url.trim();
            let title = source.title.as_deref().unwrap_or_default();
            (!trimmed.is_empty()).then(|| BriefingIdentifierObservation {
                url: trimmed.to_string(),
                surface: preferred_source_briefing_identifier_surface(
                    query_contract,
                    &source.url,
                    title,
                    &source.excerpt,
                ),
                authoritative: source_has_document_authority(
                    query_contract,
                    trimmed,
                    title,
                    &source.excerpt,
                ),
            })
        })
        .collect::<Vec<_>>();
    let required_identifier_labels =
        infer_briefing_required_identifier_labels(query_contract, &successful_read_observations);
    let observed_identifier_labels =
        observed_briefing_standard_identifier_labels(query_contract, &full_surface);
    let standard_identifier_count = observed_identifier_labels.len();
    let required_standard_identifier_count = observed_identifier_labels
        .iter()
        .filter(|label| required_identifier_labels.contains(*label))
        .count();
    let standard_identifier_group_floor = required_identifier_labels.len();
    let citation_urls = rendered_summary_citation_urls(rendered_summary, required_sections);
    let successful_citation_sources = citation_urls
        .iter()
        .filter_map(|url| successful_read_for_url(pending, url).map(|source| (url, source)))
        .collect::<Vec<_>>();
    let successful_citation_url_count = successful_citation_sources
        .iter()
        .map(|(url, _)| url.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len();
    let unread_citation_url_count = citation_urls
        .len()
        .saturating_sub(successful_citation_url_count);
    let primary_authority_source_count = successful_citation_sources
        .iter()
        .filter(|(_, source)| {
            source_has_document_authority(
                query_contract,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
        })
        .map(|(url, _)| url.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len();
    let mut authority_standard_identifiers = BTreeSet::new();
    let mut required_authority_standard_identifiers = BTreeSet::new();
    let mut standard_identifier_authority_source_urls = BTreeSet::new();
    for (_, source) in &successful_citation_sources {
        let title = source.title.as_deref().unwrap_or_default();
        let identifiers = source_briefing_standard_identifier_labels(
            query_contract,
            &source.url,
            title,
            &source.excerpt,
        );
        if identifiers.is_empty() {
            continue;
        }
        if !source_has_document_authority(query_contract, &source.url, title, &source.excerpt) {
            continue;
        }
        standard_identifier_authority_source_urls.insert(source.url.trim().to_ascii_lowercase());
        for label in identifiers {
            if required_identifier_labels.contains(&label) {
                required_authority_standard_identifiers.insert(label.clone());
            }
            authority_standard_identifiers.insert(label);
        }
    }
    let available_standard_identifier_authority_source_count = pending
        .successful_reads
        .iter()
        .filter(|source| {
            let title = source.title.as_deref().unwrap_or_default();
            source_has_document_authority(query_contract, &source.url, title, &source.excerpt)
                && !source_briefing_standard_identifier_labels(
                    query_contract,
                    &source.url,
                    title,
                    &source.excerpt,
                )
                .is_empty()
        })
        .map(|source| source.url.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len();
    let mut summary_inventory_identifier_count = 0usize;
    let mut summary_inventory_required_identifier_count = 0usize;
    let mut summary_inventory_optional_identifier_count = 0usize;
    let mut summary_inventory_authority_identifier_count = 0usize;
    let mut rendered_required_section_count = 0usize;
    let mut query_grounded_required_section_count = 0usize;
    let mut required_narrative_sections = 0usize;
    let mut rendered_single_block_narrative_sections = 0usize;
    let mut required_evidence_sections = 0usize;
    let mut rendered_evidence_block_count = 0usize;
    let mut qualifying_evidence_sections = 0usize;
    let mut qualifying_aggregated_narrative_sections = 0usize;

    for section in &direct_sections {
        let Some(blocks) = section_blocks.get(&section.key) else {
            continue;
        };
        if blocks.is_empty() {
            continue;
        }
        rendered_required_section_count = rendered_required_section_count.saturating_add(1);
        let joined = compact_whitespace(&blocks.join(" ")).to_ascii_lowercase();
        let kind = section_kind_from_key(&section.key)
            .or_else(|| section_kind_from_key(&section.label))
            .unwrap_or(ReportSectionKind::Summary);
        if matches!(kind, ReportSectionKind::Summary) {
            let inventory_surface = rendered_summary_inventory_surface(blocks);
            let inventory_identifiers =
                observed_briefing_standard_identifier_labels(query_contract, &inventory_surface);
            summary_inventory_identifier_count = inventory_identifiers.len();
            summary_inventory_required_identifier_count = inventory_identifiers
                .iter()
                .filter(|label| required_identifier_labels.contains(*label))
                .count();
            summary_inventory_optional_identifier_count = inventory_identifiers
                .len()
                .saturating_sub(summary_inventory_required_identifier_count);
            summary_inventory_authority_identifier_count = inventory_identifiers
                .iter()
                .filter(|label| authority_standard_identifiers.contains(*label))
                .count();
        }
        let grounded = if matches!(kind, ReportSectionKind::Evidence) {
            required_evidence_sections = required_evidence_sections.saturating_add(1);
            rendered_evidence_block_count =
                rendered_evidence_block_count.saturating_add(blocks.len());
            let evidence_grounded = citation_urls.len()
                >= required_supporting_fragment_floor.max(1)
                && blocks.len() >= required_supporting_fragment_floor.max(1);
            if evidence_grounded {
                qualifying_evidence_sections = qualifying_evidence_sections.saturating_add(1);
            }
            evidence_grounded
        } else {
            let matched_anchor_count = query_anchor_tokens
                .iter()
                .filter(|token| joined.contains(token.as_str()))
                .count();
            matched_anchor_count >= 2
                || (matched_anchor_count >= 1 && required_standard_identifier_count > 0)
        };
        if grounded {
            query_grounded_required_section_count =
                query_grounded_required_section_count.saturating_add(1);
        }
        if !matches!(kind, ReportSectionKind::Evidence) {
            required_narrative_sections = required_narrative_sections.saturating_add(1);
            if blocks.len() == 1 {
                rendered_single_block_narrative_sections =
                    rendered_single_block_narrative_sections.saturating_add(1);
            }
            if grounded && blocks.len() == 1 {
                qualifying_aggregated_narrative_sections =
                    qualifying_aggregated_narrative_sections.saturating_add(1);
            }
        }
    }

    let required_section_floor_met =
        required_section_count == 0 || rendered_required_section_count >= required_section_count;
    let query_grounding_floor_met = required_section_count == 0
        || query_grounded_required_section_count >= required_section_count;
    let standard_identifier_floor_met = standard_identifier_group_floor == 0
        || required_standard_identifier_count >= standard_identifier_group_floor;
    let authority_standard_identifier_floor_met = standard_identifier_group_floor == 0
        || available_standard_identifier_authority_source_count == 0
        || required_authority_standard_identifiers.len() >= standard_identifier_group_floor;
    let summary_inventory_authority_only_floor_met = summary_inventory_required_identifier_count
        == 0
        && summary_inventory_optional_identifier_count > standard_identifier_group_floor
        && summary_inventory_authority_identifier_count
            == summary_inventory_optional_identifier_count
        && required_authority_standard_identifiers.len() >= standard_identifier_group_floor;
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
    let citation_read_backing_floor_met = unread_citation_url_count == 0
        && successful_citation_url_count >= required_supporting_fragment_floor.max(1);
    let temporal_anchor_floor_met =
        rendered_summary_structured_field(rendered_summary, "Run date (UTC):")
            .filter(|value| !value.trim().is_empty())
            .is_some()
            && rendered_summary_structured_field(rendered_summary, "Run timestamp (UTC):")
                .as_deref()
                .is_some_and(|value| is_iso_utc_datetime(value.trim()));
    let overall_confidence =
        rendered_summary_structured_field(rendered_summary, "Overall confidence:")
            .map(|value| normalize_confidence_label(&value));
    let postamble_floor_met = temporal_anchor_floor_met
        && overall_confidence
            .as_deref()
            .is_some_and(|value| matches!(value, "high" | "medium" | "low"));

    RenderedBriefingContractFacts {
        rendered_required_section_count,
        query_grounded_required_section_count,
        required_narrative_sections,
        rendered_single_block_narrative_sections,
        required_evidence_sections,
        rendered_evidence_block_count,
        qualifying_evidence_sections,
        qualifying_aggregated_narrative_sections,
        standard_identifier_count,
        required_standard_identifier_count,
        standard_identifier_group_floor,
        authority_standard_identifier_count: authority_standard_identifiers.len(),
        required_authority_standard_identifier_count: required_authority_standard_identifiers.len(),
        summary_inventory_identifier_count,
        summary_inventory_required_identifier_count,
        summary_inventory_optional_identifier_count,
        summary_inventory_authority_identifier_count,
        standard_identifier_authority_source_count: standard_identifier_authority_source_urls.len(),
        available_standard_identifier_authority_source_count,
        primary_authority_source_count,
        required_primary_authority_source_count,
        citation_urls,
        successful_citation_url_count,
        unread_citation_url_count,
        run_date: rendered_summary_structured_field(rendered_summary, "Run date (UTC):"),
        run_timestamp_iso_utc: rendered_summary_structured_field(
            rendered_summary,
            "Run timestamp (UTC):",
        ),
        overall_confidence,
        required_section_floor_met,
        query_grounding_floor_met,
        standard_identifier_floor_met,
        authority_standard_identifier_floor_met,
        summary_inventory_floor_met,
        narrative_aggregation_floor_met,
        evidence_block_floor_met,
        primary_authority_source_floor_met: required_primary_authority_source_count == 0
            || primary_authority_source_count >= required_primary_authority_source_count,
        citation_read_backing_floor_met,
        temporal_anchor_floor_met,
        postamble_floor_met,
    }
}

pub(crate) fn final_web_completion_facts(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> FinalWebCompletionFacts {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let locality_scope = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let headline_collection_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let required_story_floor =
        retrieval_contract_required_story_count(retrieval_contract, &query_contract).max(1);
    let briefing_support_floor =
        retrieval_contract_required_support_count(retrieval_contract, &query_contract).max(1);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let local_business_entity_floor_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, &query_contract);
    let local_business_targets = if local_business_entity_floor_required {
        merged_local_business_target_names(
            &pending.attempted_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_floor.max(min_sources_required),
        )
    } else {
        Vec::new()
    };
    let matched_local_business_targets = if local_business_targets.is_empty() {
        Vec::new()
    } else {
        matched_local_business_target_names(
            &local_business_targets,
            &pending.successful_reads,
            locality_scope.as_deref(),
        )
    };
    let local_business_selected_sources = if local_business_targets.is_empty() {
        Vec::new()
    } else {
        selected_local_business_target_sources(
            &query_contract,
            &local_business_targets,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_floor.max(min_sources_required),
        )
    };
    let selected_sources =
        if local_business_entity_floor_required && local_business_selected_sources.is_empty() {
            Vec::new()
        } else if local_business_selected_sources.is_empty() {
            if headline_collection_mode {
                pending
                    .successful_reads
                    .iter()
                    .filter(|source| headline_source_is_actionable(source))
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                pending.successful_reads.clone()
            }
        } else {
            local_business_selected_sources.clone()
        };
    let final_draft = build_deterministic_story_draft(pending, reason);
    let rendered_selected_citations = final_draft
        .stories
        .iter()
        .flat_map(|story| story.citation_ids.iter())
        .filter_map(|citation_id| final_draft.citations_by_id.get(citation_id))
        .cloned()
        .collect::<Vec<_>>();
    let selected_source_urls = if rendered_selected_citations.is_empty() {
        selected_sources
            .iter()
            .map(|source| source.url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        rendered_selected_citations
            .iter()
            .map(|citation| citation.url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    let selected_source_observation =
        selected_source_quality_observation_with_contract_and_locality_hint(
            retrieval_contract,
            &query_contract,
            pending.min_sources,
            &selected_source_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
        );
    let local_business_menu_surface_required = query_requires_local_business_menu_surface(
        &query_contract,
        retrieval_contract,
        locality_scope.as_deref(),
    );
    let local_business_menu_surface_source_urls = selected_source_urls
        .iter()
        .filter(|url| local_business_menu_surface_url(url))
        .cloned()
        .collect::<Vec<_>>();
    let local_business_menu_surface_floor_met = !local_business_menu_surface_required
        || local_business_menu_surface_source_urls.len()
            >= required_story_floor.max(min_sources_required);
    let (
        local_business_menu_inventory_source_urls,
        local_business_menu_inventory_items,
        local_business_menu_inventory_total_item_count,
        local_business_menu_inventory_floor_met,
    ) = if local_business_menu_surface_required {
        local_business_menu_inventory_evidence(
            pending,
            &selected_source_urls,
            required_story_floor,
            min_sources_required,
        )
    } else {
        (Vec::new(), Vec::new(), 0, true)
    };
    let briefing_successful_citation_url_count = if rendered_selected_citations.is_empty() {
        selected_source_urls.len()
    } else {
        rendered_selected_citations
            .iter()
            .filter(|citation| citation.from_successful_read)
            .map(|citation| citation.url.trim().to_ascii_lowercase())
            .filter(|url| !url.is_empty())
            .collect::<BTreeSet<_>>()
            .len()
    };
    let briefing_unread_citation_url_count = selected_source_urls
        .len()
        .saturating_sub(briefing_successful_citation_url_count);
    let selected_primary_authority_source_count = if rendered_selected_citations.is_empty() {
        selected_sources
            .iter()
            .filter(|source| is_document_authority_source(&query_contract, source))
            .count()
    } else {
        rendered_selected_citations
            .iter()
            .filter(|citation| citation.from_successful_read)
            .filter(|citation| {
                source_has_document_authority(
                    &query_contract,
                    &citation.url,
                    &citation.source_label,
                    &citation.excerpt,
                )
            })
            .map(|citation| citation.url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect::<BTreeSet<_>>()
            .len()
    };
    let required_citations =
        retrieval_contract_required_citations_per_story(retrieval_contract, &query_contract).max(1);
    let briefing_required_section_specs = build_hybrid_required_sections(&query_contract);
    let briefing_required_sections = briefing_required_section_specs
        .iter()
        .map(|section| section.key.clone())
        .collect::<Vec<_>>();
    let briefing_query_layout_expected = query_prefers_document_briefing_layout(&query_contract)
        && !query_requests_comparison(&query_contract);
    let layout_profile = synthesis_layout_profile(retrieval_contract, &query_contract);
    let briefing_render_facts = document_briefing_render_facts(
        &final_draft,
        &briefing_required_section_specs,
        briefing_support_floor,
    );
    let (headline_actionable_sources_observed, headline_actionable_domains_observed) =
        if headline_collection_mode {
            headline_actionable_source_inventory(&pending.successful_reads)
        } else {
            (0, 0)
        };
    let observed_story_slots = if headline_collection_mode {
        headline_actionable_sources_observed.min(required_story_floor)
    } else {
        final_draft.stories.len().min(required_story_floor)
    };
    let story_slot_floor_met = if headline_collection_mode {
        headline_actionable_sources_observed >= required_story_floor
            && headline_actionable_domains_observed >= required_story_floor
    } else {
        observed_story_slots >= required_story_floor
    };
    let story_citation_floor_met =
        final_draft
            .stories
            .iter()
            .take(required_story_floor)
            .all(|story| {
                story
                    .citation_ids
                    .iter()
                    .filter_map(|citation_id| final_draft.citations_by_id.get(citation_id))
                    .filter(|citation| citation.from_successful_read)
                    .map(|citation| citation.url.trim())
                    .filter(|url: &&str| !url.is_empty())
                    .collect::<BTreeSet<_>>()
                    .len()
                    >= required_citations
            });
    let comparison_required =
        retrieval_contract_requests_comparison(retrieval_contract, &query_contract)
            && required_story_floor > 1;
    let comparison_ready = !comparison_required || story_slot_floor_met;
    let briefing_document_layout_met =
        matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing);
    let briefing_story_headers_absent = briefing_document_layout_met;
    let briefing_comparison_absent = briefing_document_layout_met && !comparison_required;
    let briefing_required_section_floor_met = briefing_render_facts.required_section_floor_met;
    let briefing_query_grounding_floor_met = briefing_render_facts.query_grounding_floor_met;
    let briefing_standard_identifier_floor_met =
        briefing_render_facts.standard_identifier_floor_met;
    let briefing_citation_read_backing_floor_met = briefing_unread_citation_url_count == 0
        && briefing_successful_citation_url_count
            >= briefing_render_facts
                .required_supporting_fragment_floor
                .max(required_citations);
    let briefing_temporal_anchor_floor_met = !final_draft.run_date.trim().is_empty()
        && final_draft.run_timestamp_ms > 0
        && is_iso_utc_datetime(final_draft.run_timestamp_iso_utc.trim());
    let query_facets = analyze_query_facets(&query_contract);
    let attempted_primary_authority_source_count = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .map(|url| url.trim())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|url| {
            let hint = hint_for_url(pending, url);
            source_has_document_authority(
                &query_contract,
                url,
                hint.and_then(|value| value.title.as_deref())
                    .unwrap_or_default(),
                hint.map(|value| value.excerpt.as_str()).unwrap_or_default(),
            )
        })
        .count();
    let available_primary_authority_source_count = merged_story_sources(pending)
        .iter()
        .filter(|source| is_document_authority_source(&query_contract, source))
        .count();
    let briefing_primary_authority_source_floor_applicable = briefing_document_layout_met
        && !comparison_required
        && query_facets.grounded_external_required
        && retrieval_contract
            .map(|contract| contract.currentness_required || contract.source_independence_min > 1)
            .unwrap_or(false);
    let briefing_required_primary_authority_source_count =
        if briefing_primary_authority_source_floor_applicable {
            available_primary_authority_source_count.min(
                crate::agentic::runtime::service::step::queue::support::retrieval_contract_primary_authority_source_slot_cap(
                    retrieval_contract,
                    &query_contract,
                    required_citations.max(1),
                ),
            )
        } else {
            0
        };
    let briefing_primary_authority_source_floor_met =
        !briefing_primary_authority_source_floor_applicable
            || (briefing_required_primary_authority_source_count == 0
                && available_primary_authority_source_count == 0
                && attempted_primary_authority_source_count == 0)
            || selected_primary_authority_source_count
                >= briefing_required_primary_authority_source_count.max(1);
    let overall_confidence = normalize_confidence_label(&final_draft.overall_confidence);
    let briefing_postamble_floor_met = briefing_temporal_anchor_floor_met
        && !final_draft.completion_reason.trim().is_empty()
        && matches!(overall_confidence.as_str(), "high" | "medium" | "low");
    let single_snapshot_metric_grounding =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract)
            && single_snapshot_has_metric_grounding(pending);

    FinalWebCompletionFacts {
        selected_source_urls,
        briefing_selected_source_total: selected_source_observation.total_sources,
        briefing_selected_source_compatible: selected_source_observation.compatible_sources,
        briefing_selected_source_quality_floor_met: selected_source_observation.quality_floor_met,
        briefing_selected_source_identifier_coverage_floor_met: selected_source_observation
            .identifier_coverage_floor_met,
        selected_primary_authority_source_count,
        available_primary_authority_source_count,
        attempted_primary_authority_source_count,
        local_business_targets,
        matched_local_business_targets,
        local_business_source_urls: local_business_selected_sources
            .iter()
            .map(|source| source.url.clone())
            .collect(),
        local_business_menu_surface_required,
        local_business_menu_surface_source_urls,
        local_business_menu_surface_floor_met,
        local_business_menu_inventory_source_urls,
        local_business_menu_inventory_items,
        local_business_menu_inventory_total_item_count,
        local_business_menu_inventory_floor_met,
        required_story_floor,
        required_citations_per_story: required_citations,
        briefing_required_sections,
        briefing_required_section_count: briefing_render_facts.required_section_count,
        briefing_rendered_required_section_count: briefing_render_facts
            .rendered_required_section_count,
        briefing_query_grounded_required_section_count: briefing_render_facts
            .query_grounded_required_section_count,
        briefing_required_narrative_sections: briefing_render_facts.required_narrative_sections,
        briefing_single_block_narrative_sections: briefing_render_facts
            .rendered_single_block_narrative_sections,
        briefing_required_evidence_sections: briefing_render_facts.required_evidence_sections,
        briefing_rendered_evidence_block_count: briefing_render_facts.rendered_evidence_block_count,
        briefing_qualifying_evidence_sections: briefing_render_facts.qualifying_evidence_sections,
        briefing_required_supporting_fragment_floor: briefing_render_facts
            .required_supporting_fragment_floor,
        briefing_aggregated_narrative_sections: briefing_render_facts
            .qualifying_aggregated_narrative_sections,
        briefing_standard_identifier_count: briefing_render_facts.standard_identifiers.len(),
        briefing_required_standard_identifier_count: briefing_render_facts
            .required_standard_identifier_count,
        briefing_standard_identifier_group_floor: briefing_render_facts
            .standard_identifier_group_floor,
        briefing_authority_standard_identifier_count: briefing_render_facts
            .authority_standard_identifiers
            .len(),
        briefing_required_authority_standard_identifier_count: briefing_render_facts
            .required_authority_standard_identifier_count,
        briefing_summary_inventory_identifier_count: briefing_render_facts
            .summary_inventory_identifiers
            .len(),
        briefing_summary_inventory_required_identifier_count: briefing_render_facts
            .summary_inventory_required_identifier_count,
        briefing_summary_inventory_optional_identifier_count: briefing_render_facts
            .summary_inventory_optional_identifier_count,
        briefing_summary_inventory_authority_identifier_count: briefing_render_facts
            .summary_inventory_authority_identifier_count,
        briefing_standard_identifier_authority_source_count: briefing_render_facts
            .standard_identifier_authority_source_count,
        briefing_available_standard_identifier_authority_source_count: briefing_render_facts
            .available_standard_identifier_authority_source_count,
        briefing_required_primary_authority_source_count,
        briefing_successful_citation_url_count,
        briefing_unread_citation_url_count,
        briefing_run_date: final_draft.run_date,
        briefing_run_timestamp_iso_utc: final_draft.run_timestamp_iso_utc,
        briefing_overall_confidence: overall_confidence,
        briefing_query_layout_expected,
        briefing_layout_profile: match layout_profile {
            SynthesisLayoutProfile::SingleSnapshot => "single_snapshot".to_string(),
            SynthesisLayoutProfile::DocumentBriefing => "document_briefing".to_string(),
            SynthesisLayoutProfile::MultiStoryCollection => "multi_story_collection".to_string(),
        },
        briefing_rendered_layout_profile: "unobserved".to_string(),
        briefing_render_heading_floor_met: briefing_document_layout_met,
        briefing_rendered_required_section_label_count: briefing_render_facts
            .rendered_required_section_count,
        briefing_rendered_required_section_label_floor_met: briefing_render_facts
            .required_section_floor_met,
        briefing_story_header_count: usize::from(!briefing_story_headers_absent),
        briefing_comparison_label_count: usize::from(!briefing_comparison_absent),
        observed_story_slots,
        story_slot_floor_met,
        story_citation_floor_met,
        comparison_required,
        comparison_ready,
        briefing_document_layout_met,
        briefing_story_headers_absent,
        briefing_comparison_absent,
        briefing_required_section_floor_met,
        briefing_query_grounding_floor_met,
        briefing_standard_identifier_floor_met,
        briefing_authority_standard_identifier_floor_met: briefing_render_facts
            .authority_standard_identifier_floor_met,
        briefing_summary_inventory_floor_met: briefing_render_facts.summary_inventory_floor_met,
        briefing_narrative_aggregation_floor_met: briefing_render_facts
            .narrative_aggregation_floor_met,
        briefing_evidence_block_floor_met: briefing_render_facts.evidence_block_floor_met,
        briefing_primary_authority_source_floor_met,
        briefing_citation_read_backing_floor_met,
        briefing_temporal_anchor_floor_met,
        briefing_postamble_floor_met,
        single_snapshot_metric_grounding,
        single_snapshot_required_citation_count: required_citations,
        single_snapshot_rendered_layout_met: false,
        single_snapshot_rendered_metric_line_count: 0,
        single_snapshot_rendered_metric_line_floor_met: false,
        single_snapshot_rendered_support_url_count: 0,
        single_snapshot_rendered_support_url_floor_met: false,
        single_snapshot_rendered_read_backed_url_count: 0,
        single_snapshot_rendered_read_backed_url_floor_met: false,
        single_snapshot_rendered_temporal_signal_present: false,
    }
}

pub(crate) fn final_web_completion_facts_with_rendered_summary(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    rendered_summary: &str,
) -> FinalWebCompletionFacts {
    let mut facts = final_web_completion_facts(pending, reason);
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let locality_scope = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let required_sections = build_hybrid_required_sections(&query_contract);
    let shape_facts = rendered_briefing_shape_facts(rendered_summary, &required_sections);
    let rendered_layout_profile = rendered_summary_layout_profile(&shape_facts);
    let rendered_contract_facts = rendered_briefing_contract_facts(
        pending,
        &query_contract,
        rendered_summary,
        &required_sections,
        facts.briefing_required_supporting_fragment_floor,
        facts.briefing_required_primary_authority_source_count,
    );
    facts.briefing_render_heading_floor_met = shape_facts.heading_present;
    facts.briefing_rendered_required_section_label_count =
        shape_facts.rendered_required_section_label_count;
    facts.briefing_rendered_required_section_label_floor_met =
        shape_facts.rendered_required_section_label_floor_met;
    facts.briefing_story_header_count = shape_facts.story_header_count;
    facts.briefing_comparison_label_count = shape_facts.comparison_label_count;
    facts.briefing_story_headers_absent = shape_facts.story_header_count == 0;
    facts.briefing_comparison_absent = shape_facts.comparison_label_count == 0;
    facts.briefing_rendered_layout_profile = rendered_layout_profile.as_str().to_string();
    facts.single_snapshot_rendered_metric_line_count =
        shape_facts.single_snapshot_metric_line_count;
    facts.single_snapshot_rendered_metric_line_floor_met =
        shape_facts.single_snapshot_metric_line_count > 0;
    facts.single_snapshot_rendered_support_url_count =
        shape_facts.single_snapshot_support_url_count;
    facts.single_snapshot_rendered_support_url_floor_met = shape_facts
        .single_snapshot_support_url_count
        >= facts.single_snapshot_required_citation_count;
    facts.single_snapshot_rendered_read_backed_url_count = rendered_summary
        .lines()
        .flat_map(|line| extract_urls(line, 8))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|url| successful_read_for_url(pending, url).is_some())
        .count();
    facts.single_snapshot_rendered_read_backed_url_floor_met = facts
        .single_snapshot_rendered_support_url_floor_met
        && facts.single_snapshot_rendered_read_backed_url_count
            >= facts.single_snapshot_required_citation_count
        && facts.single_snapshot_rendered_read_backed_url_count
            == facts.single_snapshot_rendered_support_url_count;
    facts.single_snapshot_rendered_temporal_signal_present =
        shape_facts.single_snapshot_temporal_signal_present;
    facts.single_snapshot_rendered_layout_met = matches!(
        rendered_layout_profile,
        RenderedSummaryLayoutProfile::SingleSnapshot
    );
    if !rendered_contract_facts.citation_urls.is_empty() {
        facts.selected_source_urls = rendered_contract_facts.citation_urls.clone();
        facts.selected_primary_authority_source_count =
            rendered_contract_facts.primary_authority_source_count;
    }
    let selected_source_observation =
        selected_source_quality_observation_with_contract_and_locality_hint(
            retrieval_contract,
            &query_contract,
            pending.min_sources,
            &facts.selected_source_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
        );
    facts.briefing_selected_source_total = selected_source_observation.total_sources;
    facts.briefing_selected_source_compatible = selected_source_observation.compatible_sources;
    facts.briefing_selected_source_quality_floor_met =
        selected_source_observation.quality_floor_met;
    facts.briefing_selected_source_identifier_coverage_floor_met =
        selected_source_observation.identifier_coverage_floor_met;
    if let Some(run_date) = rendered_contract_facts.run_date.as_ref() {
        facts.briefing_run_date = run_date.clone();
    }
    if let Some(run_timestamp_iso_utc) = rendered_contract_facts.run_timestamp_iso_utc.as_ref() {
        facts.briefing_run_timestamp_iso_utc = run_timestamp_iso_utc.clone();
    }
    if let Some(overall_confidence) = rendered_contract_facts.overall_confidence.as_ref() {
        facts.briefing_overall_confidence = overall_confidence.clone();
    }
    facts.briefing_document_layout_met = facts.briefing_query_layout_expected
        && matches!(
            rendered_layout_profile,
            RenderedSummaryLayoutProfile::DocumentBriefing
        );
    facts.briefing_rendered_required_section_count =
        rendered_contract_facts.rendered_required_section_count;
    facts.briefing_query_grounded_required_section_count =
        rendered_contract_facts.query_grounded_required_section_count;
    facts.briefing_required_narrative_sections =
        rendered_contract_facts.required_narrative_sections;
    facts.briefing_single_block_narrative_sections =
        rendered_contract_facts.rendered_single_block_narrative_sections;
    facts.briefing_required_evidence_sections = rendered_contract_facts.required_evidence_sections;
    facts.briefing_rendered_evidence_block_count =
        rendered_contract_facts.rendered_evidence_block_count;
    facts.briefing_qualifying_evidence_sections =
        rendered_contract_facts.qualifying_evidence_sections;
    facts.briefing_aggregated_narrative_sections =
        rendered_contract_facts.qualifying_aggregated_narrative_sections;
    facts.briefing_standard_identifier_count = rendered_contract_facts.standard_identifier_count;
    facts.briefing_required_standard_identifier_count =
        rendered_contract_facts.required_standard_identifier_count;
    facts.briefing_standard_identifier_group_floor =
        rendered_contract_facts.standard_identifier_group_floor;
    facts.briefing_authority_standard_identifier_count =
        rendered_contract_facts.authority_standard_identifier_count;
    facts.briefing_required_authority_standard_identifier_count =
        rendered_contract_facts.required_authority_standard_identifier_count;
    facts.briefing_summary_inventory_identifier_count =
        rendered_contract_facts.summary_inventory_identifier_count;
    facts.briefing_summary_inventory_required_identifier_count =
        rendered_contract_facts.summary_inventory_required_identifier_count;
    facts.briefing_summary_inventory_optional_identifier_count =
        rendered_contract_facts.summary_inventory_optional_identifier_count;
    facts.briefing_summary_inventory_authority_identifier_count =
        rendered_contract_facts.summary_inventory_authority_identifier_count;
    facts.briefing_standard_identifier_authority_source_count =
        rendered_contract_facts.standard_identifier_authority_source_count;
    facts.briefing_available_standard_identifier_authority_source_count =
        rendered_contract_facts.available_standard_identifier_authority_source_count;
    facts.briefing_required_primary_authority_source_count =
        rendered_contract_facts.required_primary_authority_source_count;
    facts.briefing_successful_citation_url_count =
        rendered_contract_facts.successful_citation_url_count;
    facts.briefing_unread_citation_url_count = rendered_contract_facts.unread_citation_url_count;
    facts.briefing_required_section_floor_met =
        facts.briefing_document_layout_met && rendered_contract_facts.required_section_floor_met;
    facts.briefing_query_grounding_floor_met =
        facts.briefing_document_layout_met && rendered_contract_facts.query_grounding_floor_met;
    facts.briefing_standard_identifier_floor_met =
        facts.briefing_document_layout_met && rendered_contract_facts.standard_identifier_floor_met;
    facts.briefing_authority_standard_identifier_floor_met = facts.briefing_document_layout_met
        && rendered_contract_facts.authority_standard_identifier_floor_met;
    facts.briefing_summary_inventory_floor_met =
        facts.briefing_document_layout_met && rendered_contract_facts.summary_inventory_floor_met;
    facts.briefing_narrative_aggregation_floor_met = facts.briefing_document_layout_met
        && rendered_contract_facts.narrative_aggregation_floor_met;
    facts.briefing_evidence_block_floor_met =
        facts.briefing_document_layout_met && rendered_contract_facts.evidence_block_floor_met;
    facts.briefing_primary_authority_source_floor_met = if facts.briefing_document_layout_met {
        rendered_contract_facts.primary_authority_source_floor_met
    } else {
        facts.briefing_primary_authority_source_floor_met
    };
    facts.briefing_citation_read_backing_floor_met = facts.briefing_document_layout_met
        && rendered_contract_facts.citation_read_backing_floor_met;
    facts.briefing_temporal_anchor_floor_met = rendered_contract_facts.temporal_anchor_floor_met;
    facts.briefing_postamble_floor_met = rendered_contract_facts.postamble_floor_met;
    facts
}

pub(crate) fn final_web_completion_contract_ready(facts: &FinalWebCompletionFacts) -> bool {
    if facts.briefing_query_layout_expected {
        return facts.briefing_selected_source_quality_floor_met
            && facts.briefing_selected_source_identifier_coverage_floor_met
            && facts.briefing_document_layout_met
            && facts.briefing_render_heading_floor_met
            && facts.briefing_rendered_required_section_label_floor_met
            && facts.briefing_story_headers_absent
            && facts.briefing_comparison_absent
            && facts.briefing_required_section_floor_met
            && facts.briefing_query_grounding_floor_met
            && facts.briefing_standard_identifier_floor_met
            && facts.briefing_authority_standard_identifier_floor_met
            && facts.briefing_summary_inventory_floor_met
            && facts.briefing_narrative_aggregation_floor_met
            && facts.briefing_evidence_block_floor_met
            && facts.briefing_primary_authority_source_floor_met
            && facts.briefing_citation_read_backing_floor_met
            && facts.briefing_temporal_anchor_floor_met
            && facts.briefing_postamble_floor_met
            && (!facts.comparison_required || facts.comparison_ready);
    }
    if facts.briefing_layout_profile == "single_snapshot" {
        return facts.single_snapshot_metric_grounding
            && facts.single_snapshot_rendered_layout_met
            && facts.single_snapshot_rendered_metric_line_floor_met
            && facts.single_snapshot_rendered_support_url_floor_met
            && facts.single_snapshot_rendered_read_backed_url_floor_met
            && facts.single_snapshot_rendered_temporal_signal_present
            && facts.briefing_story_headers_absent
            && facts.briefing_comparison_absent
            && !facts.selected_source_urls.is_empty()
            && (!facts.comparison_required || facts.comparison_ready);
    }
    if facts.briefing_document_layout_met {
        return facts.briefing_selected_source_quality_floor_met
            && facts.briefing_selected_source_identifier_coverage_floor_met
            && facts.briefing_required_section_floor_met
            && facts.briefing_query_grounding_floor_met
            && facts.briefing_standard_identifier_floor_met
            && facts.briefing_authority_standard_identifier_floor_met
            && facts.briefing_summary_inventory_floor_met
            && facts.briefing_narrative_aggregation_floor_met
            && facts.briefing_evidence_block_floor_met
            && facts.briefing_primary_authority_source_floor_met
            && facts.briefing_citation_read_backing_floor_met
            && facts.briefing_temporal_anchor_floor_met
            && facts.briefing_postamble_floor_met
            && (!facts.comparison_required || facts.comparison_ready);
    }
    facts.story_slot_floor_met
        && facts.story_citation_floor_met
        && facts.local_business_menu_surface_floor_met
        && facts.local_business_menu_inventory_floor_met
        && facts.observed_story_slots >= facts.required_story_floor
        && (!facts.comparison_required || facts.comparison_ready)
}

pub(crate) fn select_final_web_summary_from_candidates<I>(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    candidates: I,
) -> Option<FinalWebSummarySelection>
where
    I: IntoIterator<Item = FinalWebSummaryCandidate>,
{
    let mut evaluations = Vec::new();
    let mut fallback = None::<FinalWebSummarySelection>;
    let mut fallback_score = None::<(bool, usize, usize, usize)>;
    for candidate in candidates {
        let facts =
            final_web_completion_facts_with_rendered_summary(pending, reason, &candidate.summary);
        let contract_ready = final_web_completion_contract_ready(&facts);
        evaluations.push(FinalWebSummaryCandidateEvaluation {
            provider: candidate.provider,
            contract_ready,
            facts: facts.clone(),
        });
        let selection = FinalWebSummarySelection {
            provider: candidate.provider,
            summary: candidate.summary,
            contract_ready,
            facts,
            evaluations: Vec::new(),
        };
        if selection.contract_ready {
            let mut selected = selection;
            selected.evaluations = evaluations;
            return Some(selected);
        }
        let selection_score = final_web_summary_fallback_score(&selection.facts);
        if fallback_score
            .as_ref()
            .is_none_or(|existing| selection_score > *existing)
        {
            fallback_score = Some(selection_score);
            fallback = Some(selection);
        }
    }

    fallback.map(|mut selection| {
        selection.evaluations = evaluations;
        selection
    })
}
