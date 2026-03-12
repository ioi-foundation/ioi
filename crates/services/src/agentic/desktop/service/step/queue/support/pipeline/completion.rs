use super::*;
use crate::agentic::desktop::service::step::action::emit_execution_contract_receipt_event_with_observation;
use crate::agentic::desktop::service::DesktopAgentService;

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

fn rendered_summary_citation_urls(
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

fn local_business_menu_inventory_items_from_excerpt(excerpt: &str) -> Vec<String> {
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
    let observed_identifier_groups =
        observed_briefing_standard_identifier_groups(query_contract, &full_surface);
    let standard_identifier_count = observed_identifier_groups.len();
    let required_standard_identifier_count = observed_identifier_groups
        .iter()
        .filter(|group| group.required)
        .count();
    let standard_identifier_group_floor = briefing_standard_identifier_group_floor(query_contract);
    let citation_urls = rendered_summary_citation_urls(rendered_summary, required_sections);
    let required_identifier_labels = briefing_standard_identifier_groups_for_query(query_contract)
        .iter()
        .filter(|group| group.required)
        .map(|group| group.primary_label.to_string())
        .collect::<BTreeSet<_>>();
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
        let identifiers = observed_briefing_standard_identifier_labels(
            query_contract,
            &format!("{} {} {}", title, source.excerpt, source.url),
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
                && !observed_briefing_standard_identifier_labels(
                    query_contract,
                    &format!("{} {} {}", title, source.excerpt, source.url),
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
    let summary_inventory_floor_met = standard_identifier_group_floor == 0
        || (summary_inventory_required_identifier_count >= standard_identifier_group_floor
            && summary_inventory_optional_identifier_count == 0
            && (available_standard_identifier_authority_source_count == 0
                || summary_inventory_authority_identifier_count
                    >= standard_identifier_group_floor));
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
            available_primary_authority_source_count.min(required_citations.max(1))
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

fn append_final_web_completion_receipts_from_facts(
    facts: &FinalWebCompletionFacts,
    verification_checks: &mut Vec<String>,
) {
    verification_checks.push(format!(
        "web_final_output_contract_ready={}",
        final_web_completion_contract_ready(facts)
    ));
    if !facts.selected_source_urls.is_empty() {
        verification_checks.push(format!(
            "web_final_selected_source_url_values={}",
            facts.selected_source_urls.join(" | ")
        ));
    }
    verification_checks.push(format!(
        "web_final_selected_source_total={}",
        facts.briefing_selected_source_total
    ));
    verification_checks.push(format!(
        "web_final_selected_source_compatible={}",
        facts.briefing_selected_source_compatible
    ));
    verification_checks.push(format!(
        "web_final_selected_source_quality_floor_met={}",
        facts.briefing_selected_source_quality_floor_met
    ));
    verification_checks.push(format!(
        "web_final_selected_source_identifier_coverage_floor_met={}",
        facts.briefing_selected_source_identifier_coverage_floor_met
    ));
    if !facts.local_business_targets.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_entity_targets={}",
            facts.local_business_targets.join(" | ")
        ));
    }
    if !facts.matched_local_business_targets.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_entity_matched={}",
            facts.matched_local_business_targets.join(" | ")
        ));
    }
    if !facts.local_business_source_urls.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_entity_source_values={}",
            facts.local_business_source_urls.join(" | ")
        ));
    }
    verification_checks.push(format!(
        "web_final_local_business_menu_surface_required={}",
        facts.local_business_menu_surface_required
    ));
    verification_checks.push(format!(
        "web_final_local_business_menu_surface_floor_met={}",
        facts.local_business_menu_surface_floor_met
    ));
    if !facts.local_business_menu_surface_source_urls.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_menu_surface_source_values={}",
            facts.local_business_menu_surface_source_urls.join(" | ")
        ));
    }
    verification_checks.push(format!(
        "web_final_local_business_menu_inventory_total_item_count={}",
        facts.local_business_menu_inventory_total_item_count
    ));
    verification_checks.push(format!(
        "web_final_local_business_menu_inventory_floor_met={}",
        facts.local_business_menu_inventory_floor_met
    ));
    if !facts.local_business_menu_inventory_source_urls.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_menu_inventory_source_values={}",
            facts.local_business_menu_inventory_source_urls.join(" | ")
        ));
    }
    if !facts.local_business_menu_inventory_items.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_menu_inventory_item_values={}",
            facts.local_business_menu_inventory_items.join(" | ")
        ));
    }
    if !facts.briefing_required_sections.is_empty() {
        verification_checks.push(format!(
            "web_final_briefing_required_section_keys={}",
            facts.briefing_required_sections.join(" | ")
        ));
    }
    if !facts.briefing_document_layout_met {
        verification_checks.push(format!(
            "web_final_story_slots_observed={}",
            facts.observed_story_slots
        ));
        verification_checks.push(format!(
            "web_final_story_slot_floor_met={}",
            facts.story_slot_floor_met
        ));
        verification_checks.push(format!(
            "web_final_story_citation_floor_met={}",
            facts.story_citation_floor_met
        ));
    }
    verification_checks.push(format!(
        "web_final_comparison_required={}",
        facts.comparison_required
    ));
    verification_checks.push(format!(
        "web_final_comparison_ready={}",
        facts.comparison_ready
    ));
    verification_checks.push(format!(
        "web_final_briefing_layout_profile={}",
        facts.briefing_layout_profile
    ));
    verification_checks.push(format!(
        "web_final_briefing_query_layout_expected={}",
        facts.briefing_query_layout_expected
    ));
    verification_checks.push(format!(
        "web_final_briefing_rendered_layout_profile={}",
        facts.briefing_rendered_layout_profile
    ));
    verification_checks.push(format!(
        "web_final_briefing_document_layout_met={}",
        facts.briefing_document_layout_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_render_heading_floor_met={}",
        facts.briefing_render_heading_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_rendered_required_section_label_count={}",
        facts.briefing_rendered_required_section_label_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_rendered_required_section_label_floor_met={}",
        facts.briefing_rendered_required_section_label_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_story_header_count={}",
        facts.briefing_story_header_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_story_headers_absent={}",
        facts.briefing_story_headers_absent
    ));
    verification_checks.push(format!(
        "web_final_briefing_comparison_label_count={}",
        facts.briefing_comparison_label_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_comparison_absent={}",
        facts.briefing_comparison_absent
    ));
    verification_checks.push(format!(
        "web_final_briefing_required_section_count={}",
        facts.briefing_required_section_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_rendered_required_section_count={}",
        facts.briefing_rendered_required_section_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_required_narrative_sections={}",
        facts.briefing_required_narrative_sections
    ));
    verification_checks.push(format!(
        "web_final_briefing_single_block_narrative_sections={}",
        facts.briefing_single_block_narrative_sections
    ));
    verification_checks.push(format!(
        "web_final_briefing_required_evidence_sections={}",
        facts.briefing_required_evidence_sections
    ));
    verification_checks.push(format!(
        "web_final_briefing_rendered_evidence_block_count={}",
        facts.briefing_rendered_evidence_block_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_qualifying_evidence_sections={}",
        facts.briefing_qualifying_evidence_sections
    ));
    verification_checks.push(format!(
        "web_final_briefing_required_supporting_fragment_floor={}",
        facts.briefing_required_supporting_fragment_floor
    ));
    verification_checks.push(format!(
        "web_final_briefing_aggregated_narrative_sections={}",
        facts.briefing_aggregated_narrative_sections
    ));
    verification_checks.push(format!(
        "web_final_briefing_query_grounded_required_section_count={}",
        facts.briefing_query_grounded_required_section_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_standard_identifier_count={}",
        facts.briefing_standard_identifier_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_required_standard_identifier_count={}",
        facts.briefing_required_standard_identifier_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_standard_identifier_group_floor={}",
        facts.briefing_standard_identifier_group_floor
    ));
    verification_checks.push(format!(
        "web_final_briefing_authority_standard_identifier_count={}",
        facts.briefing_authority_standard_identifier_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_required_authority_standard_identifier_count={}",
        facts.briefing_required_authority_standard_identifier_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_summary_inventory_identifier_count={}",
        facts.briefing_summary_inventory_identifier_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_summary_inventory_required_identifier_count={}",
        facts.briefing_summary_inventory_required_identifier_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_summary_inventory_optional_identifier_count={}",
        facts.briefing_summary_inventory_optional_identifier_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_summary_inventory_authority_identifier_count={}",
        facts.briefing_summary_inventory_authority_identifier_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_required_section_floor_met={}",
        facts.briefing_required_section_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_query_grounding_floor_met={}",
        facts.briefing_query_grounding_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_standard_identifier_floor_met={}",
        facts.briefing_standard_identifier_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_authority_standard_identifier_floor_met={}",
        facts.briefing_authority_standard_identifier_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_summary_inventory_floor_met={}",
        facts.briefing_summary_inventory_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_narrative_aggregation_floor_met={}",
        facts.briefing_narrative_aggregation_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_evidence_block_floor_met={}",
        facts.briefing_evidence_block_floor_met
    ));
    verification_checks.push(format!(
        "web_final_selected_primary_authority_source_count={}",
        facts.selected_primary_authority_source_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_standard_identifier_authority_source_count={}",
        facts.briefing_standard_identifier_authority_source_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_successful_citation_url_count={}",
        facts.briefing_successful_citation_url_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_unread_citation_url_count={}",
        facts.briefing_unread_citation_url_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_citation_read_backing_floor_met={}",
        facts.briefing_citation_read_backing_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_available_standard_identifier_authority_source_count={}",
        facts.briefing_available_standard_identifier_authority_source_count
    ));
    verification_checks.push(format!(
        "web_final_available_primary_authority_source_count={}",
        facts.available_primary_authority_source_count
    ));
    verification_checks.push(format!(
        "web_final_attempted_primary_authority_source_count={}",
        facts.attempted_primary_authority_source_count
    ));
    verification_checks.push(format!(
        "web_final_briefing_primary_authority_source_floor_met={}",
        facts.briefing_primary_authority_source_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_temporal_anchor_floor_met={}",
        facts.briefing_temporal_anchor_floor_met
    ));
    verification_checks.push(format!(
        "web_final_briefing_postamble_floor_met={}",
        facts.briefing_postamble_floor_met
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_metric_grounding={}",
        facts.single_snapshot_metric_grounding
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_required_citation_count={}",
        facts.single_snapshot_required_citation_count
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_rendered_layout_met={}",
        facts.single_snapshot_rendered_layout_met
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_rendered_metric_line_count={}",
        facts.single_snapshot_rendered_metric_line_count
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_rendered_metric_line_floor_met={}",
        facts.single_snapshot_rendered_metric_line_floor_met
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_rendered_support_url_count={}",
        facts.single_snapshot_rendered_support_url_count
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_rendered_support_url_floor_met={}",
        facts.single_snapshot_rendered_support_url_floor_met
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_rendered_read_backed_url_count={}",
        facts.single_snapshot_rendered_read_backed_url_count
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_rendered_read_backed_url_floor_met={}",
        facts.single_snapshot_rendered_read_backed_url_floor_met
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_rendered_temporal_signal_present={}",
        facts.single_snapshot_rendered_temporal_signal_present
    ));
}

pub(crate) fn append_final_web_completion_receipts(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    verification_checks: &mut Vec<String>,
) {
    let facts = final_web_completion_facts(pending, reason);
    append_final_web_completion_receipts_from_facts(&facts, verification_checks);
}

pub(crate) fn append_final_web_completion_receipts_with_rendered_summary(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    rendered_summary: &str,
    verification_checks: &mut Vec<String>,
) {
    let facts = final_web_completion_facts_with_rendered_summary(pending, reason, rendered_summary);
    append_final_web_completion_receipts_from_facts(&facts, verification_checks);
}

pub(crate) fn emit_final_web_completion_contract_receipts(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    facts: &FinalWebCompletionFacts,
) {
    let emit_receipt = |key: &str,
                        satisfied: bool,
                        probe_source: &str,
                        observed_value: &str,
                        evidence_type: &str| {
        let evidence_material = format!(
            "probe_source={};observed_value={};evidence_type={}",
            probe_source, observed_value, evidence_type
        );
        emit_execution_contract_receipt_event_with_observation(
            service,
            session_id,
            step_index,
            intent_id,
            "verification",
            key,
            satisfied,
            &evidence_material,
            Some(probe_source),
            Some(observed_value),
            Some(evidence_type),
            None,
            None,
            None,
        );
    };
    let emit_unique_string_receipts =
        |key: &str, probe_source: &str, evidence_type: &str, values: &[String]| {
            let mut seen = BTreeSet::new();
            for value in values
                .iter()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
            {
                if !seen.insert(value.to_string()) {
                    continue;
                }
                emit_receipt(key, true, probe_source, value, evidence_type);
            }
        };

    if !facts.briefing_document_layout_met {
        emit_receipt(
            "story_slots_observed",
            true,
            "web.pipeline.completion.story_slots_observed.v1",
            &facts.observed_story_slots.to_string(),
            "scalar",
        );
        emit_receipt(
            "story_slot_floor",
            facts.story_slot_floor_met,
            "web.pipeline.completion.story_slots.v1",
            &facts.observed_story_slots.to_string(),
            "scalar",
        );
        emit_receipt(
            "story_citation_floor",
            facts.story_citation_floor_met,
            "web.pipeline.completion.story_citations.v1",
            &facts.observed_story_slots.to_string(),
            "scalar",
        );
    }
    emit_receipt(
        "local_business_menu_surface_required",
        true,
        "web.pipeline.completion.local_business_menu_surface_required.v1",
        &facts.local_business_menu_surface_required.to_string(),
        "scalar",
    );
    emit_receipt(
        "local_business_menu_surface_floor",
        facts.local_business_menu_surface_floor_met,
        "web.pipeline.completion.local_business_menu_surface.v1",
        &format!(
            "required={};selected_menu_surface_sources={};required_story_floor={}",
            facts.local_business_menu_surface_required,
            facts.local_business_menu_surface_source_urls.len(),
            facts.required_story_floor
        ),
        "summary",
    );
    emit_unique_string_receipts(
        "local_business_menu_surface_source_url",
        "web.pipeline.completion.local_business_menu_surface_sources.v1",
        "url",
        &facts.local_business_menu_surface_source_urls,
    );
    emit_receipt(
        "local_business_menu_inventory_floor",
        facts.local_business_menu_inventory_floor_met,
        "web.pipeline.completion.local_business_menu_inventory.v1",
        &format!(
            "selected_menu_inventory_sources={};total_menu_inventory_items={};required_story_floor={};required_items_per_source={}",
            facts.local_business_menu_inventory_source_urls.len(),
            facts.local_business_menu_inventory_total_item_count,
            facts.required_story_floor,
            2
        ),
        "summary",
    );
    emit_receipt(
        "local_business_menu_inventory_total_item_count",
        true,
        "web.pipeline.completion.local_business_menu_inventory_total.v1",
        &facts
            .local_business_menu_inventory_total_item_count
            .to_string(),
        "scalar",
    );
    emit_unique_string_receipts(
        "local_business_menu_inventory_source_url",
        "web.pipeline.completion.local_business_menu_inventory_sources.v1",
        "url",
        &facts.local_business_menu_inventory_source_urls,
    );
    emit_unique_string_receipts(
        "local_business_menu_inventory_item",
        "web.pipeline.completion.local_business_menu_inventory_items.v1",
        "label",
        &facts.local_business_menu_inventory_items,
    );
    emit_receipt(
        "final_output_contract_ready",
        final_web_completion_contract_ready(facts),
        "web.pipeline.completion.final_output.v1",
        &format!(
            "query_requires_document_briefing={};rendered_layout={};document_layout_met={};required_section_floor_met={};query_grounding_floor_met={};standard_identifier_floor_met={};authority_standard_identifier_floor_met={};summary_inventory_floor_met={};evidence_block_floor_met={};citation_read_backing_floor_met={};standard_identifier_count={};required_standard_identifier_count={};required_standard_identifier_group_floor={};authority_standard_identifier_count={};required_authority_standard_identifier_count={};summary_inventory_identifier_count={};summary_inventory_required_identifier_count={};summary_inventory_optional_identifier_count={};summary_inventory_authority_identifier_count={};rendered_evidence_block_count={};required_evidence_sections={};standard_identifier_authority_source_count={};successful_citation_url_count={};unread_citation_url_count={};narrative_aggregation_floor_met={};primary_authority_source_floor_met={};temporal_anchor_floor_met={};postamble_floor_met={};story_slot_floor_met={};story_citation_floor_met={};local_business_menu_surface_floor_met={};local_business_menu_inventory_floor_met={};local_business_menu_inventory_total_item_count={};single_snapshot_required_citation_count={};single_snapshot_rendered_support_url_count={};single_snapshot_rendered_read_backed_url_count={}",
            facts.briefing_query_layout_expected,
            facts.briefing_rendered_layout_profile,
            facts.briefing_document_layout_met,
            facts.briefing_required_section_floor_met,
            facts.briefing_query_grounding_floor_met,
            facts.briefing_standard_identifier_floor_met,
            facts.briefing_authority_standard_identifier_floor_met,
            facts.briefing_summary_inventory_floor_met,
            facts.briefing_evidence_block_floor_met,
            facts.briefing_citation_read_backing_floor_met,
            facts.briefing_standard_identifier_count,
            facts.briefing_required_standard_identifier_count,
            facts.briefing_standard_identifier_group_floor,
            facts.briefing_authority_standard_identifier_count,
            facts.briefing_required_authority_standard_identifier_count,
            facts.briefing_summary_inventory_identifier_count,
            facts.briefing_summary_inventory_required_identifier_count,
            facts.briefing_summary_inventory_optional_identifier_count,
            facts.briefing_summary_inventory_authority_identifier_count,
            facts.briefing_rendered_evidence_block_count,
            facts.briefing_required_evidence_sections,
            facts.briefing_standard_identifier_authority_source_count,
            facts.briefing_successful_citation_url_count,
            facts.briefing_unread_citation_url_count,
            facts.briefing_narrative_aggregation_floor_met,
            facts.briefing_primary_authority_source_floor_met,
            facts.briefing_temporal_anchor_floor_met,
            facts.briefing_postamble_floor_met,
            facts.story_slot_floor_met,
            facts.story_citation_floor_met,
            facts.local_business_menu_surface_floor_met,
            facts.local_business_menu_inventory_floor_met,
            facts.local_business_menu_inventory_total_item_count,
            facts.single_snapshot_required_citation_count,
            facts.single_snapshot_rendered_support_url_count,
            facts.single_snapshot_rendered_read_backed_url_count
        ),
        "summary",
    );
    emit_receipt(
        "comparison_ready",
        facts.comparison_ready,
        "web.pipeline.completion.comparison.v1",
        &format!("comparison_required={}", facts.comparison_required),
        "summary",
    );
    emit_receipt(
        "briefing_document_layout",
        facts.briefing_document_layout_met,
        "web.pipeline.completion.briefing.layout.v1",
        &format!(
            "query_requires_document_briefing={};contract_layout={};rendered_layout={};heading_present={};rendered_required_section_label_count={};story_header_count={};comparison_label_count={}",
            facts.briefing_query_layout_expected,
            facts.briefing_layout_profile,
            facts.briefing_rendered_layout_profile,
            facts.briefing_render_heading_floor_met,
            facts.briefing_rendered_required_section_label_count,
            facts.briefing_story_header_count,
            facts.briefing_comparison_label_count
        ),
        "summary",
    );
    emit_receipt(
        "briefing_render_heading_floor",
        facts.briefing_render_heading_floor_met,
        "web.pipeline.completion.briefing.heading.v1",
        &format!(
            "contract_layout={};rendered_layout={};heading_present={}",
            facts.briefing_layout_profile,
            facts.briefing_rendered_layout_profile,
            facts.briefing_render_heading_floor_met
        ),
        "summary",
    );
    emit_receipt(
        "briefing_rendered_required_section_label_floor",
        facts.briefing_rendered_required_section_label_floor_met,
        "web.pipeline.completion.briefing.rendered_sections.v1",
        &format!(
            "rendered_required_section_label_count={};required_section_count={}",
            facts.briefing_rendered_required_section_label_count,
            facts.briefing_required_section_count
        ),
        "summary",
    );
    emit_receipt(
        "briefing_story_headers_absent",
        facts.briefing_story_headers_absent,
        "web.pipeline.completion.briefing.story_headers.v1",
        &format!(
            "contract_layout={};rendered_layout={};story_headers_rendered={};story_header_count={}",
            facts.briefing_layout_profile,
            facts.briefing_rendered_layout_profile,
            !facts.briefing_story_headers_absent,
            facts.briefing_story_header_count
        ),
        "summary",
    );
    emit_receipt(
        "briefing_comparison_absent",
        facts.briefing_comparison_absent,
        "web.pipeline.completion.briefing.comparison.v1",
        &format!(
            "contract_layout={};rendered_layout={};comparison_required={};comparison_rendered={};comparison_label_count={}",
            facts.briefing_layout_profile,
            facts.briefing_rendered_layout_profile,
            facts.comparison_required,
            !facts.briefing_comparison_absent,
            facts.briefing_comparison_label_count
        ),
        "summary",
    );
    emit_receipt(
        "briefing_required_section_floor",
        facts.briefing_required_section_floor_met,
        "web.pipeline.completion.briefing.sections.v2",
        &format!(
            "rendered_required_sections={};required_section_count={};required_sections={}",
            facts.briefing_rendered_required_section_count,
            facts.briefing_required_section_count,
            facts.briefing_required_sections.join("|")
        ),
        "summary",
    );
    emit_receipt(
        "briefing_query_grounding_floor",
        facts.briefing_query_grounding_floor_met,
        "web.pipeline.completion.briefing.query_grounding.v1",
        &format!(
            "grounded_required_sections={};required_section_count={}",
            facts.briefing_query_grounded_required_section_count,
            facts.briefing_required_section_count
        ),
        "summary",
    );
    emit_receipt(
        "briefing_standard_identifier_floor",
        facts.briefing_standard_identifier_floor_met,
        "web.pipeline.completion.briefing.standard_identifiers.v1",
        &format!(
            "standard_identifier_count={};required_standard_identifier_count={};required_standard_identifier_group_floor={};standard_identifier_authority_source_count={};available_standard_identifier_authority_source_count={}",
            facts.briefing_standard_identifier_count,
            facts.briefing_required_standard_identifier_count,
            facts.briefing_standard_identifier_group_floor,
            facts.briefing_standard_identifier_authority_source_count,
            facts.briefing_available_standard_identifier_authority_source_count
        ),
        "summary",
    );
    emit_receipt(
        "briefing_authority_standard_identifier_floor",
        facts.briefing_authority_standard_identifier_floor_met,
        "web.pipeline.completion.briefing.authority_standard_identifiers.v1",
        &format!(
            "authority_standard_identifier_count={};required_authority_standard_identifier_count={};required_standard_identifier_group_floor={};standard_identifier_authority_source_count={};available_standard_identifier_authority_source_count={}",
            facts.briefing_authority_standard_identifier_count,
            facts.briefing_required_authority_standard_identifier_count,
            facts.briefing_standard_identifier_group_floor,
            facts.briefing_standard_identifier_authority_source_count,
            facts.briefing_available_standard_identifier_authority_source_count
        ),
        "summary",
    );
    emit_receipt(
        "briefing_summary_inventory_floor",
        facts.briefing_summary_inventory_floor_met,
        "web.pipeline.completion.briefing.summary_inventory.v1",
        &format!(
            "summary_inventory_identifier_count={};summary_inventory_required_identifier_count={};summary_inventory_optional_identifier_count={};summary_inventory_authority_identifier_count={};required_standard_identifier_group_floor={}",
            facts.briefing_summary_inventory_identifier_count,
            facts.briefing_summary_inventory_required_identifier_count,
            facts.briefing_summary_inventory_optional_identifier_count,
            facts.briefing_summary_inventory_authority_identifier_count,
            facts.briefing_standard_identifier_group_floor
        ),
        "summary",
    );
    emit_receipt(
        "briefing_narrative_aggregation_floor",
        facts.briefing_narrative_aggregation_floor_met,
        "web.pipeline.completion.briefing.narrative_aggregation.v1",
        &format!(
            "required_narrative_sections={};single_block_narrative_sections={};aggregated_narrative_sections={};required_supporting_fragment_floor={}",
            facts.briefing_required_narrative_sections,
            facts.briefing_single_block_narrative_sections,
            facts.briefing_aggregated_narrative_sections,
            facts.briefing_required_supporting_fragment_floor
        ),
        "summary",
    );
    emit_receipt(
        "briefing_evidence_block_floor",
        facts.briefing_evidence_block_floor_met,
        "web.pipeline.completion.briefing.evidence_blocks.v1",
        &format!(
            "rendered_evidence_block_count={};required_supporting_fragment_floor={};required_evidence_sections={};qualifying_evidence_sections={}",
            facts.briefing_rendered_evidence_block_count,
            facts.briefing_required_supporting_fragment_floor,
            facts.briefing_required_evidence_sections,
            facts.briefing_qualifying_evidence_sections
        ),
        "summary",
    );
    emit_receipt(
        "briefing_primary_authority_source_floor",
        facts.briefing_primary_authority_source_floor_met,
        "web.pipeline.completion.briefing.primary_authority.v1",
        &format!(
            "selected_primary_authority_sources={};required_primary_authority_sources={};available_primary_authority_sources={};attempted_primary_authority_sources={}",
            facts.selected_primary_authority_source_count,
            facts.briefing_required_primary_authority_source_count,
            facts.available_primary_authority_source_count,
            facts.attempted_primary_authority_source_count
        ),
        "summary",
    );
    emit_receipt(
        "briefing_citation_read_backing_floor",
        facts.briefing_citation_read_backing_floor_met,
        "web.pipeline.completion.briefing.citation_backing.v1",
        &format!(
            "successful_citation_url_count={};unread_citation_url_count={};required_supporting_fragment_floor={}",
            facts.briefing_successful_citation_url_count,
            facts.briefing_unread_citation_url_count,
            facts.briefing_required_supporting_fragment_floor
        ),
        "summary",
    );
    emit_receipt(
        "briefing_temporal_anchor_floor",
        facts.briefing_temporal_anchor_floor_met,
        "web.pipeline.completion.briefing.temporal_anchor.v1",
        &format!(
            "run_date={};run_timestamp_iso_utc={}",
            facts.briefing_run_date, facts.briefing_run_timestamp_iso_utc
        ),
        "summary",
    );
    emit_receipt(
        "briefing_postamble_floor",
        facts.briefing_postamble_floor_met,
        "web.pipeline.completion.briefing.postamble.v1",
        &format!(
            "temporal_anchor={};overall_confidence={};required_citations_per_story={}",
            facts.briefing_temporal_anchor_floor_met,
            facts.briefing_overall_confidence,
            facts.required_citations_per_story
        ),
        "summary",
    );
    emit_receipt(
        "single_snapshot_metric_grounding",
        facts.single_snapshot_metric_grounding,
        "web.pipeline.completion.single_snapshot_metric.v1",
        &facts.single_snapshot_metric_grounding.to_string(),
        "bool",
    );
    emit_receipt(
        "single_snapshot_rendered_layout",
        facts.single_snapshot_rendered_layout_met,
        "web.pipeline.completion.single_snapshot.layout.v1",
        &format!(
            "rendered_layout={};story_header_count={};comparison_label_count={}",
            facts.briefing_rendered_layout_profile,
            facts.briefing_story_header_count,
            facts.briefing_comparison_label_count
        ),
        "summary",
    );
    emit_receipt(
        "single_snapshot_metric_line_floor",
        facts.single_snapshot_rendered_metric_line_floor_met,
        "web.pipeline.completion.single_snapshot.metric_lines.v1",
        &facts.single_snapshot_rendered_metric_line_count.to_string(),
        "scalar",
    );
    emit_receipt(
        "single_snapshot_support_url_floor",
        facts.single_snapshot_rendered_support_url_floor_met,
        "web.pipeline.completion.single_snapshot.support_urls.v1",
        &format!(
            "rendered_support_urls={};required_support_urls={}",
            facts.single_snapshot_rendered_support_url_count,
            facts.single_snapshot_required_citation_count
        ),
        "summary",
    );
    emit_receipt(
        "single_snapshot_read_backed_url_floor",
        facts.single_snapshot_rendered_read_backed_url_floor_met,
        "web.pipeline.completion.single_snapshot.read_backed_urls.v1",
        &format!(
            "read_backed_urls={};rendered_support_urls={};required_support_urls={}",
            facts.single_snapshot_rendered_read_backed_url_count,
            facts.single_snapshot_rendered_support_url_count,
            facts.single_snapshot_required_citation_count
        ),
        "summary",
    );
    emit_receipt(
        "single_snapshot_temporal_signal",
        facts.single_snapshot_rendered_temporal_signal_present,
        "web.pipeline.completion.single_snapshot.temporal_signal.v1",
        &facts
            .single_snapshot_rendered_temporal_signal_present
            .to_string(),
        "bool",
    );
    emit_unique_string_receipts(
        "selected_source_url",
        "web.pipeline.completion.selected_sources.v1",
        "url",
        &facts.selected_source_urls,
    );
    emit_unique_string_receipts(
        "local_business_entity_name",
        "web.pipeline.completion.local_business_entities.v1",
        "entity_name",
        &facts.matched_local_business_targets,
    );
    emit_unique_string_receipts(
        "local_business_entity_source_url",
        "web.pipeline.completion.local_business_entity_sources.v1",
        "url",
        &facts.local_business_source_urls,
    );
}

pub(crate) fn remaining_pending_web_candidates(pending: &PendingSearchCompletion) -> usize {
    let attempted: BTreeSet<String> = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    pending_candidate_inventory(pending)
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && !attempted.contains(*value))
        .count()
}

pub(crate) fn single_snapshot_has_metric_grounding(pending: &PendingSearchCompletion) -> bool {
    pending.successful_reads.iter().any(|source| {
        let observed_text = format!(
            "{} {}",
            source.title.as_deref().unwrap_or_default(),
            source.excerpt
        );
        contains_current_condition_metric_signal(&observed_text)
    })
}

pub(crate) fn single_snapshot_has_viable_followup_candidate(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> bool {
    let projection =
        build_query_constraint_projection(query_contract, 1, &pending.candidate_source_hints);
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();
    let attempted_urls = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();

    pending_candidate_inventory(pending)
        .iter()
        .any(|candidate| {
            let trimmed = candidate.trim();
            if trimmed.is_empty() || attempted_urls.contains(trimmed) {
                return false;
            }
            let hint = hint_for_url(pending, trimmed);
            let title = hint
                .and_then(|entry| entry.title.as_deref())
                .unwrap_or_default();
            let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
            let compatibility = candidate_constraint_compatibility(
                envelope_constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                title,
                excerpt,
            );
            if projection.enforce_grounded_compatibility()
                && !compatibility_passes_projection(&projection, &compatibility)
            {
                return false;
            }
            if title.trim().is_empty() && excerpt.trim().is_empty() {
                return false;
            }
            let envelope_score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                excerpt,
            );
            let resolves_constraint =
                envelope_score_resolves_constraint(envelope_constraints, &envelope_score);
            if projection.has_constraint_objective() {
                resolves_constraint
            } else {
                resolves_constraint || compatibility_passes_projection(&projection, &compatibility)
            }
        })
}

pub(crate) fn single_snapshot_probe_budget_allows_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if pending.deadline_ms == 0 {
        return true;
    }
    pending.deadline_ms.saturating_sub(now_ms) >= SINGLE_SNAPSHOT_MIN_REMAINING_BUDGET_MS_FOR_PROBE
}

pub(crate) fn single_snapshot_additional_probe_attempt_count(
    pending: &PendingSearchCompletion,
) -> usize {
    let observed_search_attempts = pending
        .attempted_urls
        .iter()
        .filter(|url| {
            let trimmed = url.trim();
            !trimmed.is_empty() && is_search_hub_url(trimmed)
        })
        .count();
    let baseline_search_attempt_missing_from_attempts = if is_search_hub_url(&pending.url) {
        let pending_search_url = pending.url.trim();
        !pending_search_url.is_empty()
            && !pending.attempted_urls.iter().any(|url| {
                let trimmed = url.trim();
                !trimmed.is_empty() && url_structurally_equivalent(trimmed, pending_search_url)
            })
    } else {
        false
    };
    let total_search_attempts = observed_search_attempts
        .saturating_add(usize::from(baseline_search_attempt_missing_from_attempts));
    let probe_query_delta = usize::from({
        let query = pending.query.trim();
        let query_contract = pending.query_contract.trim();
        total_search_attempts == 0
            && !query.is_empty()
            && !query_contract.is_empty()
            && !query.eq_ignore_ascii_case(query_contract)
    });
    total_search_attempts
        .saturating_sub(1)
        .saturating_add(probe_query_delta)
}

pub(crate) fn web_pipeline_grounded_probe_attempt_limit(
    pending: &PendingSearchCompletion,
) -> usize {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let required_distinct_source_floor =
        retrieval_contract_required_distinct_citations(retrieval_contract, &query_contract);
    required_distinct_source_floor
        .max(pending.min_sources.max(1) as usize)
        .max(1)
        .saturating_sub(1)
        .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX as usize)
}

pub(crate) fn web_pipeline_grounded_probe_attempt_available(
    pending: &PendingSearchCompletion,
) -> bool {
    single_snapshot_additional_probe_attempt_count(pending)
        < web_pipeline_grounded_probe_attempt_limit(pending)
}

fn grounded_probe_query_available(
    pending: &PendingSearchCompletion,
    locality_scope: Option<&str>,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    let prior_query = if pending.query.trim().is_empty() {
        query_contract.trim()
    } else {
        pending.query.trim()
    };
    constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        &query_contract,
        pending.retrieval_contract.as_ref(),
        pending.min_sources,
        &pending.candidate_source_hints,
        prior_query,
        locality_scope,
    )
    .is_some()
}

pub(crate) fn single_snapshot_requires_current_metric_observation_contract(
    pending: &PendingSearchCompletion,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    if !retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract) {
        return false;
    }
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources.max(1),
        &pending.candidate_source_hints,
    );
    let has_metric_objective = !projection.constraints.required_facets.is_empty()
        || !projection.query_facets.metric_schema.axis_hits.is_empty()
        || (projection.query_facets.time_sensitive_public_fact
            && projection.query_facets.locality_sensitive_public_fact);
    let requires_current_observation = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || projection.query_facets.time_sensitive_public_fact
        || retrieval_contract
            .map(|contract| contract.currentness_required)
            .unwrap_or(false);
    has_metric_objective && requires_current_observation
}

pub(crate) fn web_pipeline_requires_metric_probe_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if !single_snapshot_requires_current_metric_observation_contract(pending) {
        return false;
    }
    let query_contract = synthesis_query_contract(pending);
    let min_sources = pending.min_sources.max(1) as usize;
    if pending.successful_reads.len() < min_sources {
        return false;
    }
    if single_snapshot_has_metric_grounding(pending) {
        return false;
    }
    if single_snapshot_additional_probe_attempt_count(pending)
        >= SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES
    {
        return false;
    }
    if !single_snapshot_probe_budget_allows_followup(pending, now_ms) {
        return false;
    }
    if single_snapshot_has_viable_followup_candidate(pending, &query_contract) {
        return true;
    }
    // Pre-emit quality gate: allow one deterministic recovery probe even when
    // candidate inventory is exhausted, so the pipeline can self-correct
    // missing current-observation metrics before final reply emission.
    true
}

pub(crate) fn story_completion_contract_ready(
    pending: &PendingSearchCompletion,
    required_story_floor: usize,
) -> bool {
    if required_story_floor == 0 {
        return true;
    }
    let facts = final_web_completion_facts(pending, WebPipelineCompletionReason::MinSourcesReached);
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
        && facts.observed_story_slots >= required_story_floor
        && (!facts.comparison_required || facts.comparison_ready)
}

pub(crate) fn web_pipeline_completion_terminalization_allowed(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    queued_web_reads: usize,
) -> bool {
    if queued_web_reads == 0 || !matches!(reason, WebPipelineCompletionReason::MinSourcesReached) {
        return true;
    }

    let query_contract = synthesis_query_contract(pending);
    let locality_hint = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(
            pending.retrieval_contract.as_ref(),
            &query_contract,
        )
        .then(|| effective_locality_scope_hint(None))
        .flatten()
    });
    if query_requires_local_business_menu_surface(
        &query_contract,
        pending.retrieval_contract.as_ref(),
        locality_hint.as_deref(),
    ) {
        return false;
    }
    !matches!(
        synthesis_layout_profile(pending.retrieval_contract.as_ref(), &query_contract),
        SynthesisLayoutProfile::DocumentBriefing
    )
}

pub(crate) fn web_pipeline_completion_reason(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> Option<WebPipelineCompletionReason> {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let required_distinct_source_floor =
        retrieval_contract_required_distinct_citations(retrieval_contract, &query_contract);

    let single_snapshot_mode =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract);
    let headline_collection_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let layout_profile = synthesis_layout_profile(retrieval_contract, &query_contract);
    let required_story_floor =
        retrieval_contract_required_story_count(retrieval_contract, &query_contract).max(1);
    let (headline_actionable_sources_observed, headline_actionable_domains_observed) =
        if headline_collection_mode {
            headline_actionable_source_inventory(&pending.successful_reads)
        } else {
            (0, 0)
        };
    let story_floor_met = !headline_collection_mode
        || (headline_actionable_sources_observed >= required_story_floor
            && headline_actionable_domains_observed >= required_story_floor);
    let query_facets = analyze_query_facets(&query_contract);
    let remaining_candidates = remaining_pending_web_candidates(pending);
    let has_viable_followup_candidate =
        single_snapshot_has_viable_followup_candidate(pending, &query_contract);
    let next_viable_candidate_available = next_pending_web_candidate(pending).is_some();
    let candidate_inventory_exhausted =
        remaining_candidates == 0 || !next_viable_candidate_available;
    let min_sources = pending.min_sources.max(1) as usize;
    let locality_scope = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let grounded_probe_query_available =
        grounded_probe_query_available(pending, locality_scope.as_deref());
    let local_business_entity_floor_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, &query_contract);
    let local_business_targets = if local_business_entity_floor_required {
        merged_local_business_target_names(
            &pending.attempted_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_floor.max(min_sources),
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
    let local_business_entity_floor_met = !local_business_entity_floor_required
        || (!local_business_targets.is_empty()
            && matched_local_business_targets.len() >= required_story_floor.max(min_sources));
    let grounded_sources = grounded_source_evidence_count(pending);
    let required_grounded_source_floor = required_distinct_source_floor.max(min_sources);
    let grounded_floor_met = if headline_collection_mode {
        headline_actionable_sources_observed >= min_sources
            && headline_actionable_domains_observed >= min_sources
    } else if single_snapshot_mode || !query_facets.grounded_external_required {
        pending.successful_reads.len() >= min_sources
    } else {
        grounded_sources >= required_grounded_source_floor && local_business_entity_floor_met
    };

    if single_snapshot_mode
        && pending.successful_reads.len() >= 1
        && pending.successful_reads.len() < min_sources
        && grounded_floor_met
        && !single_snapshot_has_metric_grounding(pending)
        && !has_viable_followup_candidate
    {
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }

    if grounded_floor_met {
        if headline_collection_mode && !story_floor_met {
            let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
                true
            } else {
                pending.deadline_ms.saturating_sub(now_ms)
                    >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
            };
            if web_pipeline_grounded_probe_attempt_available(pending)
                && grounded_probe_budget_allows
                && grounded_probe_query_available
            {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing)
            && !story_completion_contract_ready(pending, required_story_floor)
        {
            let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
                true
            } else {
                pending.deadline_ms.saturating_sub(now_ms)
                    >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
            };
            if web_pipeline_grounded_probe_attempt_available(pending)
                && grounded_probe_budget_allows
                && grounded_probe_query_available
            {
                return None;
            }
            if !candidate_inventory_exhausted {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        if single_snapshot_mode && web_pipeline_requires_metric_probe_followup(pending, now_ms) {
            return None;
        }
        if single_snapshot_mode && !single_snapshot_has_metric_grounding(pending) {
            let post_probe_attempt_available =
                single_snapshot_additional_probe_attempt_count(pending) > 0;
            if post_probe_attempt_available
                && remaining_candidates > 0
                && next_pending_web_candidate(pending).is_some()
            {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        if single_snapshot_mode {
            let snapshot_facts =
                final_web_completion_facts(pending, WebPipelineCompletionReason::MinSourcesReached);
            if !snapshot_facts.story_citation_floor_met {
                let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
                    true
                } else {
                    pending.deadline_ms.saturating_sub(now_ms)
                        >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
                };
                if !candidate_inventory_exhausted {
                    return None;
                }
                if web_pipeline_grounded_probe_attempt_available(pending)
                    && grounded_probe_budget_allows
                    && grounded_probe_query_available
                {
                    return None;
                }
                return Some(WebPipelineCompletionReason::ExhaustedCandidates);
            }
        }
        return Some(WebPipelineCompletionReason::MinSourcesReached);
    }
    if !single_snapshot_mode
        && pending.successful_reads.len() >= min_sources
        && story_completion_contract_ready(pending, required_story_floor)
    {
        return Some(WebPipelineCompletionReason::MinSourcesReached);
    }
    if pending.deadline_ms > 0 && now_ms >= pending.deadline_ms {
        return Some(WebPipelineCompletionReason::DeadlineReached);
    }
    if candidate_inventory_exhausted {
        let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
            true
        } else {
            pending.deadline_ms.saturating_sub(now_ms)
                >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
        };
        let grounded_probe_recovery = !single_snapshot_mode
            && query_facets.grounded_external_required
            && !grounded_floor_met
            && web_pipeline_grounded_probe_attempt_available(pending)
            && grounded_probe_budget_allows
            && grounded_probe_query_available;
        if grounded_probe_recovery {
            return None;
        }
        // Keep the loop alive for one bounded probe when the citation/source floor
        // is still unmet in single-snapshot mode and budget allows recovery.
        if single_snapshot_mode
            && !grounded_floor_met
            && single_snapshot_additional_probe_attempt_count(pending)
                < SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES
            && single_snapshot_probe_budget_allows_followup(pending, now_ms)
        {
            return None;
        }
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }
    None
}

pub(crate) fn queue_web_read_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    url: &str,
    allow_browser_fallback: bool,
) -> Result<bool, TransactionError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    if agent_state
        .pending_search_completion
        .as_ref()
        .map(|pending| {
            pending.attempted_urls.iter().any(|existing| {
                existing.eq_ignore_ascii_case(trimmed)
                    || url_structurally_equivalent(existing, trimmed)
            }) || pending.successful_reads.iter().any(|existing| {
                existing.url.eq_ignore_ascii_case(trimmed)
                    || url_structurally_equivalent(&existing.url, trimmed)
            }) || pending.blocked_urls.iter().any(|existing| {
                existing.eq_ignore_ascii_case(trimmed)
                    || url_structurally_equivalent(existing, trimmed)
            })
        })
        .unwrap_or(false)
    {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({
        "url": trimmed,
        "allow_browser_fallback": allow_browser_fallback,
    }))
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };

    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.insert(0, request);
    Ok(true)
}

pub(crate) fn queue_web_search_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    query: &str,
    query_contract: Option<&str>,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    limit: u32,
) -> Result<bool, TransactionError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({
        "query": trimmed,
        "query_contract": query_contract
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        "retrieval_contract": retrieval_contract,
        "limit": limit.max(1),
    }))
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };
    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }
    agent_state.execution_queue.insert(0, request);
    Ok(true)
}

pub(crate) fn is_human_challenge_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("error_class=humanchallengerequired")
        || lower.contains("recaptcha")
        || lower.contains("human verification")
        || lower.contains("verify you are human")
        || lower.contains("i'm not a robot")
        || lower.contains("i am not a robot")
}

#[cfg(test)]
mod tests {
    use ioi_types::app::agentic::WebRetrievalContract;

    use super::*;

    fn nist_briefing_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
            None,
        )
        .expect("retrieval contract")
    }

    fn weather_snapshot_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(
            "What's the weather like right now in Anderson, SC?",
            None,
        )
        .expect("retrieval contract")
    }

    fn weather_snapshot_pending() -> PendingSearchCompletion {
        PendingSearchCompletion {
            query: "What's the weather like right now in Anderson, SC?".to_string(),
            query_contract: "What's the weather like right now in Anderson, SC?".to_string(),
            retrieval_contract: Some(weather_snapshot_contract()),
            url: "https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical".to_string(),
            started_step: 1,
            started_at_ms: 1_773_235_143_000,
            deadline_ms: 1_773_235_203_000,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical".to_string(),
                title: Some(
                    "Anderson, Anderson County Airport (KAND) current conditions".to_string(),
                ),
                excerpt: "Current conditions at Anderson, Anderson County Airport (KAND); Fair; temperature 65°F (18°C); Humidity 93%; Wind Speed SW 3 mph; Barometer 30.06 in (1017.2 mb); Visibility 10.00 mi; Last update 11 Mar 8:56 am EDT.".to_string(),
            }],
            min_sources: 1,
        }
    }

    #[test]
    fn grounded_probe_query_availability_detects_non_recoverable_latest_nist_briefing_loop() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: Vec::new(),
            candidate_source_hints: Vec::new(),
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
            ],
            blocked_urls: Vec::new(),
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt:
                        "NIST directs organizations to migrate to post-quantum encryption standards now."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };

        assert!(!grounded_probe_query_available(&pending, None));
        assert_eq!(
            web_pipeline_completion_reason(&pending, 1_773_117_280_000),
            Some(WebPipelineCompletionReason::ExhaustedCandidates)
        );
    }

    #[test]
    fn story_contract_ready_terminalizes_latest_nist_briefing_when_grounded_sources_are_merged() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some(
                        "Federal Information Processing Standard (FIPS) 204".to_string(),
                    ),
                    excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                        .to_string(),
                },
            ],
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
            ],
            blocked_urls: vec![
                "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans"
                    .to_string(),
            ],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some(
                        "Federal Information Processing Standard (FIPS) 204".to_string(),
                    ),
                    excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                        .to_string(),
                },
            ],
            min_sources: 3,
        };

        let summary =
            synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            &summary,
        );
        assert!(facts
            .briefing_required_sections
            .iter()
            .any(|section| section == "what_happened"));
        assert!(facts
            .briefing_required_sections
            .iter()
            .any(|section| section == "key_evidence"));
        assert_eq!(facts.briefing_layout_profile, "document_briefing");
        assert!(facts.briefing_document_layout_met);
        assert!(facts.briefing_render_heading_floor_met);
        assert!(facts.briefing_rendered_required_section_label_floor_met);
        assert_eq!(facts.briefing_story_header_count, 0);
        assert!(facts.briefing_story_headers_absent);
        assert_eq!(facts.briefing_comparison_label_count, 0);
        assert!(facts.briefing_comparison_absent);
        assert!(facts.briefing_required_section_floor_met);
        assert!(facts.briefing_query_grounding_floor_met);
        assert!(facts.briefing_standard_identifier_floor_met);
        assert!(facts.briefing_authority_standard_identifier_floor_met);
        assert!(facts.briefing_summary_inventory_floor_met);
        assert!(facts.briefing_evidence_block_floor_met);
        assert!(facts.briefing_temporal_anchor_floor_met);
        assert!(facts.briefing_postamble_floor_met);
        assert!(story_completion_contract_ready(&pending, 3));
        assert_eq!(
            web_pipeline_completion_reason(&pending, 1_773_117_280_000),
            Some(WebPipelineCompletionReason::MinSourcesReached)
        );
    }

    #[test]
    fn story_contract_ready_requires_primary_authority_source_when_available_for_document_briefing()
    {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/pqc".to_string(),
                "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
                },
            ],
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.digicert.com/blog/nist-standards-for-quantum-safe-cryptography"
                        .to_string(),
                    title: Some("NIST standards for quantum-safe cryptography".to_string()),
                    excerpt: "DigiCert explains the latest NIST standards for quantum-safe cryptography.".to_string(),
                },
            ],
            min_sources: 2,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
        assert_eq!(facts.available_primary_authority_source_count, 1);
        assert_eq!(facts.selected_primary_authority_source_count, 0);
        assert!(!facts.briefing_primary_authority_source_floor_met);
        assert!(!story_completion_contract_ready(&pending, 1));
    }

    #[test]
    fn story_contract_ready_requires_menu_surface_sources_for_restaurant_menu_comparison() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Brothers Italian Cuisine",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Coach House Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Dolce Vita Italian Bistro and Pizzeria",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                        .to_string(),
                    title: Some(
                        "Brothers Italian Cuisine, Anderson - Menu, Reviews (226), Photos (25) - Restaurantji"
                            .to_string(),
                    ),
                    excerpt: "Italian restaurant in Anderson, SC serving pizza, pasta and subs."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                        .to_string(),
                    title: Some(
                        "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                            .to_string(),
                    ),
                    excerpt:
                        "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/"
                        .to_string(),
                    title: Some(
                        "Dolce Vita Italian Bistro and Pizzeria, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                            .to_string(),
                    ),
                    excerpt:
                        "Italian bistro in Anderson, SC with pizza, pasta, calzones and dessert."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert!(facts.local_business_menu_surface_required);
        assert!(facts.local_business_menu_surface_source_urls.is_empty());
        assert!(!facts.local_business_menu_surface_floor_met);
        assert!(!story_completion_contract_ready(&pending, 3));
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn story_contract_ready_accepts_menu_surface_sources_for_restaurant_menu_comparison() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Brothers Italian Cuisine",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Coach House Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Dolce Vita Italian Bistro and Pizzeria",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "Customers' favorites include Brothers Special Shrimp Pasta, Chef Salad, Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone. Menu photo gallery available with 6 images."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "Customers' favorites include Assorted Home Made Cakes, Chicken and Dumplings, Chicken Fried Steak, Baked Greek Chicken, and Roast Beef Sandwich. Menu photo gallery available with 19 images."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "Customers' favorites include Margherita Pizza, Baked Ziti, Chicken Alfredo, Calzone, and Cannoli. Menu photo gallery available with 7 images."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert!(facts.local_business_menu_surface_required);
        assert_eq!(facts.local_business_menu_surface_source_urls.len(), 3);
        assert!(facts.local_business_menu_surface_floor_met);
        assert_eq!(facts.local_business_menu_inventory_source_urls.len(), 3);
        assert!(facts.local_business_menu_inventory_total_item_count >= 6);
        assert!(facts.local_business_menu_inventory_floor_met);
        assert!(story_completion_contract_ready(&pending, 3));
        assert!(final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn story_contract_ready_requires_menu_inventory_for_restaurant_menu_comparison() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Brothers Italian Cuisine",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Coach House Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Dolce Vita Italian Bistro and Pizzeria",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "View the menu, hours, phone number, address and map for Brothers Italian Cuisine."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "View the menu, hours, phone number, address and map for Coach House Restaurant."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "View the menu, hours, phone number, address and map for Dolce Vita Italian Bistro and Pizzeria."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert!(facts.local_business_menu_surface_required);
        assert_eq!(facts.local_business_menu_surface_source_urls.len(), 3);
        assert!(facts.local_business_menu_surface_floor_met);
        assert!(facts.local_business_menu_inventory_source_urls.is_empty());
        assert_eq!(facts.local_business_menu_inventory_total_item_count, 0);
        assert!(!facts.local_business_menu_inventory_floor_met);
        assert!(!story_completion_contract_ready(&pending, 3));
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn menu_inventory_parser_accepts_canonical_inventory_intro() {
        let items = local_business_menu_inventory_items_from_excerpt(
            "Item inventory includes Organic Smoked Ham Hero Sandwich, Meatball Hero Sandwich, Gourmet Chicken Hero Sandwich, and Philly Steak & Cheese Hero Sandwich.",
        );

        assert_eq!(
            items,
            vec![
                "Organic Smoked Ham Hero Sandwich".to_string(),
                "Meatball Hero Sandwich".to_string(),
                "Gourmet Chicken Hero Sandwich".to_string(),
                "Philly Steak & Cheese Hero Sandwich".to_string(),
            ]
        );
    }

    #[test]
    fn story_contract_ready_requires_authority_identifier_coverage_for_document_briefing() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            ],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                            .to_string(),
                    ),
                    excerpt: "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                    title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                    excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum cryptography standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some(
                        "Federal Information Processing Standard (FIPS) 204".to_string(),
                    ),
                    excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                        .to_string(),
                },
            ],
            min_sources: 3,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
        assert!(facts.briefing_standard_identifier_floor_met);
        assert!(!facts.briefing_authority_standard_identifier_floor_met);
        assert!(!story_completion_contract_ready(&pending, 1));
    }

    #[test]
    fn story_contract_ready_requires_primary_authority_source_when_authority_read_was_attempted() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
            }],
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
                "https://www.nist.gov/pqc".to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://cyberscoop.com/why-federal-it-leaders-must-act-now-to-deliver-nists-post-quantum-cryptography-transition-op-ed/".to_string(),
                    title: Some(
                        "Why federal IT leaders must act now to deliver NIST’s post-quantum cryptography transition"
                            .to_string(),
                    ),
                    excerpt: "CyberScoop covers federal post-quantum cryptography transition planning.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.cybersecuritydive.com/news/nist-post-quantum-cryptography-guidance-mapping/760638/".to_string(),
                    title: Some(
                        "NIST explains how post-quantum cryptography push overlaps with existing security guidance"
                            .to_string(),
                    ),
                    excerpt: "Cybersecurity Dive covers NIST post-quantum cryptography guidance mapping.".to_string(),
                },
            ],
            min_sources: 2,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
        assert_eq!(facts.available_primary_authority_source_count, 0);
        assert_eq!(facts.attempted_primary_authority_source_count, 1);
        assert_eq!(facts.selected_primary_authority_source_count, 0);
        assert!(!facts.briefing_primary_authority_source_floor_met);
        assert!(!story_completion_contract_ready(&pending, 1));
    }

    #[test]
    fn rendered_document_briefing_requires_all_available_authority_sources_up_to_citation_floor() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards&format=rss"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption"
                    .to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                            .to_string(),
                    ),
                    excerpt: "NIST selected HQC in 2025 after finalizing FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                            .to_string(),
                    ),
                    excerpt: "NIST finalized FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                    title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                    excerpt: "Independent analysis summarized the finalized standards set."
                        .to_string(),
                },
            ],
            min_sources: 2,
        };

        let summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T23:36:24Z UTC)\n\nWhat happened: As of 2026-03-10, retrieved authoritative sources identify the current standards as FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST, NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n- Independent analysis corroborated the finalized standards set.\n\nCitations:\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | 2026-03-10T23:36:24Z | retrieved_utc\n- Diving Into NIST’s New Post-Quantum Standards | https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/ | 2026-03-10T23:36:24Z | retrieved_utc\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T23:36:24Z\nOverall confidence: medium";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            summary,
        );

        assert_eq!(facts.available_primary_authority_source_count, 2);
        assert_eq!(facts.briefing_required_primary_authority_source_count, 2);
        assert_eq!(facts.selected_primary_authority_source_count, 1);
        assert!(!facts.briefing_primary_authority_source_floor_met);
    }

    #[test]
    fn document_briefing_min_sources_completion_waits_for_queued_reads() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/pqc".to_string(),
                "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
                },
            ],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
                },
            ],
            min_sources: 2,
        };

        assert!(!web_pipeline_completion_terminalization_allowed(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            1,
        ));
        assert!(web_pipeline_completion_terminalization_allowed(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            0,
        ));
    }

    #[test]
    fn rendered_summary_shape_facts_fail_for_story_collection_output_on_document_briefing_queries()
    {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt:
                        "NIST says now is the time to migrate to post-quantum encryption standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204, and FIPS 205.".to_string(),
                },
            ],
            min_sources: 2,
        };
        let bad_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            bad_summary,
        );

        assert!(!facts.briefing_document_layout_met);
        assert!(facts.briefing_query_layout_expected);
        assert_eq!(facts.briefing_rendered_layout_profile, "story_collection");
        assert!(!facts.briefing_render_heading_floor_met);
        assert!(!facts.briefing_rendered_required_section_label_floor_met);
        assert_eq!(facts.briefing_story_header_count, 1);
        assert!(!facts.briefing_story_headers_absent);
        assert_eq!(facts.briefing_comparison_label_count, 1);
        assert!(!facts.briefing_comparison_absent);
        assert!(!facts.briefing_required_section_floor_met);
        assert!(!facts.briefing_query_grounding_floor_met);
        assert!(!facts.briefing_standard_identifier_floor_met);
        assert!(!facts.briefing_narrative_aggregation_floor_met);
        assert!(!facts.briefing_temporal_anchor_floor_met);
        assert!(!facts.briefing_postamble_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_summary_requires_read_backed_citations_for_document_briefing() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.cyberark.com/resources/blog/nist-s-new-timeline-for-post-quantum-encryption"
                    .to_string(),
            ],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                        .to_string(),
                ),
                excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                    .to_string(),
            }],
            min_sources: 2,
        };
        let rendered_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T20:58:06Z UTC)\n\nWhat happened: As of 2026-03-10, retrieved sources identify the current standards set as FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence: Supporting evidence is drawn from cited sources.\n\nCitations:\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | 2026-03-10T20:58:06Z | retrieved_utc\n- NIST's new timeline for post-quantum encryption | https://www.cyberark.com/resources/blog/nist-s-new-timeline-for-post-quantum-encryption | 2026-03-10T20:58:06Z | retrieved_utc\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T20:58:06Z\nOverall confidence: high";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_successful_citation_url_count, 1);
        assert_eq!(facts.briefing_unread_citation_url_count, 1);
        assert!(!facts.briefing_citation_read_backing_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_summary_requires_quality_of_cited_sources_for_document_briefing() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_217_927_000,
            deadline_ms: 1_773_217_987_000,
            candidate_urls: vec![
                "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                "https://webbook.nist.gov/chemistry/".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
            ],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                    title: Some("Cybersecurity and privacy | NIST".to_string()),
                    excerpt: "NIST develops cybersecurity and privacy standards, guidelines, best practices, and resources."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://webbook.nist.gov/chemistry/".to_string(),
                    title: Some("NIST Chemistry WebBook".to_string()),
                    excerpt: "The NIST site provides chemical and physical property data for over 40,000 compounds."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as its first three finalized post-quantum encryption standards."
                        .to_string(),
                },
            ],
            min_sources: 2,
        };
        let rendered_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-11T22:52:07Z UTC)\n\nWhat happened: As of 2026-03-11, retrieved authoritative sources identify the currently published standards as FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards, FIPS 205 is designed for digital signatures. According to Cybersecurity and privacy, NIST develops cybersecurity and privacy standards, guidelines, best practices, and resources. According to NIST Chemistry WebBook, NIST provides chemical and physical property data for over 40,000 compounds.\n\nKey evidence:\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards, NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n- According to Cybersecurity and privacy, NIST develops cybersecurity and privacy standards, guidelines, best practices, and resources.\n- According to NIST Chemistry WebBook, NIST provides chemical and physical property data for over 40,000 compounds.\n\nCitations:\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | 2026-03-11T22:52:07Z | retrieved_utc\n- Cybersecurity and privacy | NIST | https://www.nist.gov/cybersecurity-and-privacy | 2026-03-11T22:52:07Z | retrieved_utc\n- NIST Chemistry WebBook | https://webbook.nist.gov/chemistry/ | 2026-03-11T22:52:07Z | retrieved_utc\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T22:52:07Z\nOverall confidence: medium";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::ExhaustedCandidates,
            rendered_summary,
        );

        assert_eq!(facts.briefing_selected_source_total, 3);
        assert_eq!(facts.briefing_selected_source_compatible, 3);
        assert!(!facts.briefing_selected_source_quality_floor_met);
        assert!(!facts.briefing_selected_source_identifier_coverage_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_summary_rejects_inline_evidence_and_optional_identifier_inventory() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                            .to_string(),
                    ),
                    excerpt: "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms, while HQC was selected as an additional algorithm."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                    title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                    excerpt: "FIPS 203, FIPS 204, and FIPS 205 are the three finalized post-quantum cryptography standards."
                        .to_string(),
                },
            ],
            min_sources: 2,
        };
        let rendered_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T23:36:24Z UTC)\n\nWhat happened: As of 2026-03-10, retrieved sources identify the current standards set as FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), HQC, and FIPS 203 (ML-KEM). According to NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption, FIPS 204 and FIPS 205 contain digital signature algorithms while HQC was selected as an additional algorithm. According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards, NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards.\n\nKey evidence: As of 2026-03-10, retrieved sources identify the current standards set as FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), HQC, and FIPS 203 (ML-KEM). According to NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption, FIPS 204 and FIPS 205 contain digital signature algorithms while HQC was selected as an additional algorithm. According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards, NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards.\n\nCitations:\n- NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption | 2026-03-10T23:36:24Z | retrieved_utc\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | 2026-03-10T23:36:24Z | retrieved_utc\n- Diving Into NIST’s New Post-Quantum Standards | https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/ | 2026-03-10T23:36:24Z | retrieved_utc\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T23:36:24Z\nOverall confidence: high";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert!(!facts.briefing_summary_inventory_floor_met);
        assert_eq!(
            facts.briefing_summary_inventory_optional_identifier_count,
            1
        );
        assert!(!facts.briefing_evidence_block_floor_met);
        assert_eq!(facts.briefing_rendered_evidence_block_count, 1);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_summary_shape_facts_observe_story_collection_output_even_when_contract_drifts() {
        let mut drifted_contract = nist_briefing_contract();
        drifted_contract.source_independence_min = 1;
        drifted_contract.structured_record_preferred = true;
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(drifted_contract),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt:
                        "NIST says now is the time to migrate to post-quantum encryption standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204, and FIPS 205.".to_string(),
                },
            ],
            min_sources: 1,
        };
        let bad_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            bad_summary,
        );

        assert!(facts.briefing_query_layout_expected);
        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.briefing_rendered_layout_profile, "story_collection");
        assert!(!facts.briefing_document_layout_met);
        assert_eq!(facts.briefing_story_header_count, 1);
        assert!(!facts.briefing_story_headers_absent);
    }

    #[test]
    fn rendered_summary_citation_urls_collect_all_story_collection_blocks() {
        let required_sections = vec![
            HybridSectionSpec {
                key: "what_happened".to_string(),
                label: "What happened".to_string(),
                required: true,
            },
            HybridSectionSpec {
                key: "key_evidence".to_string(),
                label: "Key evidence".to_string(),
                required: true,
            },
        ];
        let rendered_summary = "Web retrieval summary for 'Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.'\n\nStory 1: Brothers Italian Cuisine\nWhat happened: Example.\nKey evidence: Example.\nCitations:\n- Menu | https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nConfidence: high\n\nStory 2: Coach House Restaurant\nWhat happened: Example.\nKey evidence: Example.\nCitations:\n- Menu | https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nConfidence: high\n\nStory 3: Red Tomato and Wine Restaurant\nWhat happened: Example.\nKey evidence: Example.\nCitations:\n- Menu | https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nComparison:\n- Example.\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T19:58:57Z\nOverall confidence: high";

        assert_eq!(
            rendered_summary_citation_urls(rendered_summary, &required_sections),
            vec![
                "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                    .to_string(),
                "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                    .to_string(),
                "https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn rendered_live_weather_snapshot_reply_satisfies_single_snapshot_contract() {
        let pending = weather_snapshot_pending();
        let rendered_summary = "The current weather in Anderson, SC, is as follows:\n\n- Condition: Fair\n- Temperature: 65°F (18°C)\n- Humidity: 93%\n- Wind Speed: SW 3 mph\n- Barometer: 30.06 in (1017.2 mb)\n- Visibility: 10.00 miles\n\nThis information is based on the latest update from the Anderson County Airport (KAND) as of 8:56 am EDT on March 11th. For more details, visit https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:19:18Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.briefing_rendered_layout_profile, "single_snapshot");
        assert!(facts.single_snapshot_rendered_layout_met);
        assert_eq!(facts.single_snapshot_required_citation_count, 1);
        assert!(facts.single_snapshot_rendered_metric_line_floor_met);
        assert_eq!(facts.single_snapshot_rendered_support_url_count, 1);
        assert!(facts.single_snapshot_rendered_support_url_floor_met);
        assert_eq!(facts.single_snapshot_rendered_read_backed_url_count, 1);
        assert!(facts.single_snapshot_rendered_read_backed_url_floor_met);
        assert!(facts.single_snapshot_rendered_temporal_signal_present);
        assert!(facts.single_snapshot_metric_grounding);
        assert!(final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_single_snapshot_reply_requires_all_required_citations_to_be_read_backed() {
        let pending = PendingSearchCompletion {
            query: "What's the current price of Bitcoin?".to_string(),
            query_contract: "What's the current price of Bitcoin?".to_string(),
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
            url: "https://search.brave.com/search?q=current+bitcoin+price".to_string(),
            started_step: 1,
            started_at_ms: 1_773_236_577_000,
            deadline_ms: 1_773_236_637_000,
            candidate_urls: vec!["https://crypto.com/us/price/bitcoin".to_string()],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://www.worldcoinindex.com/coin/bitcoin".to_string(),
                title: Some("Bitcoin price | index, chart and news | WorldCoinIndex".to_string()),
                excerpt: "Bitcoin price right now: $86,743.63 USD.".to_string(),
            }],
            min_sources: 2,
        };
        let rendered_summary = "Right now (as of 2026-03-11T13:42:57Z UTC):\n\nCurrent conditions from cited source text: Bitcoin price right now: $86,743.63 USD.\n\nCitations:\n- Bitcoin price | index, chart and news | WorldCoinIndex | https://www.worldcoinindex.com/coin/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n- Bitcoin price - Crypto.com | https://crypto.com/us/price/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:42:57Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.single_snapshot_required_citation_count, 2);
        assert_eq!(facts.single_snapshot_rendered_support_url_count, 2);
        assert_eq!(facts.single_snapshot_rendered_read_backed_url_count, 1);
        assert!(facts.single_snapshot_rendered_support_url_floor_met);
        assert!(!facts.single_snapshot_rendered_read_backed_url_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn story_collection_output_fails_single_snapshot_contract() {
        let pending = weather_snapshot_pending();
        let rendered_summary = "Web retrieval summary for 'What's the weather like right now in Anderson, SC?'\n\nStory 1: Anderson weather\nWhat happened: Current conditions are fair and 65°F.\nKey evidence: https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:19:18Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.briefing_rendered_layout_profile, "story_collection");
        assert!(!facts.single_snapshot_rendered_layout_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_story_collection_menu_comparison_binds_all_cited_menu_sources() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Brothers Italian Cuisine",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Coach House Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Red Tomato and Wine Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                        .to_string(),
                    title: Some("Menu for Brothers Italian Cuisine, Anderson, SC - Restaurantji".to_string()),
                    excerpt:
                        "Item inventory includes Brothers Sepcial Shrimp Pasta, 2 Plates of 1 2 a Chef Salad, 1 2 an Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                        .to_string(),
                    title: Some("Menu for Coach House Restaurant, Anderson, SC - Restaurantji".to_string()),
                    excerpt:
                        "Item inventory includes Served with Sauteed Onions and Brown Gravy, Tuesday Dinner Special Chopped Steak, Broccoli Stuffed Chicken Breast, Country Fried Steak Sandwich, and Assorted Home Made Cakes."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/"
                        .to_string(),
                    title: Some("Menu for Red Tomato and Wine Restaurant, Anderson, SC - Restaurantji".to_string()),
                    excerpt:
                        "Item inventory includes Ziti with Meat and Rose Sauce, Hummus with Grilled Pita Bread, Fettuccine Alfredo with Shrimp, Spaghetti with Meat Sauce, and Three Cheese Manicotti."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };
        let rendered_summary = "Web retrieval summary for 'Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.' (as of 2026-03-11T19:58:57Z UTC)\n\nStory 1: Brothers Italian Cuisine\nWhat happened: Brothers Italian Cuisine remains one of the better-reviewed Italian options in Anderson.\nKey evidence: Item inventory includes Brothers Sepcial Shrimp Pasta, 2 Plates of 1 2 a Chef Salad, 1 2 an Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone.\nCitations:\n- Menu for Brothers Italian Cuisine, Anderson, SC - Restaurantji | https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nConfidence: high\n\nStory 2: Coach House Restaurant\nWhat happened: Coach House Restaurant also surfaces as a strong-reviewed Anderson restaurant with Italian dishes.\nKey evidence: Item inventory includes Served with Sauteed Onions and Brown Gravy, Tuesday Dinner Special Chopped Steak, Broccoli Stuffed Chicken Breast, Country Fried Steak Sandwich, and Assorted Home Made Cakes.\nCitations:\n- Menu for Coach House Restaurant, Anderson, SC - Restaurantji | https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nConfidence: high\n\nStory 3: Red Tomato and Wine Restaurant\nWhat happened: Red Tomato and Wine Restaurant completes the three-way comparison set.\nKey evidence: Item inventory includes Ziti with Meat and Rose Sauce, Hummus with Grilled Pita Bread, Fettuccine Alfredo with Shrimp, Spaghetti with Meat Sauce, and Three Cheese Manicotti.\nCitations:\n- Menu for Red Tomato and Wine Restaurant, Anderson, SC - Restaurantji | https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nComparison:\n- Brothers Italian Cuisine emphasizes pasta, salads, and calzones.\n- Coach House Restaurant emphasizes house specials and comfort dishes.\n- Red Tomato and Wine Restaurant emphasizes pasta, Mediterranean starters, and Italian mains.\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T19:58:57Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_rendered_layout_profile, "story_collection");
        assert_eq!(facts.selected_source_urls.len(), 3);
        assert_eq!(facts.briefing_successful_citation_url_count, 3);
        assert_eq!(facts.local_business_menu_inventory_source_urls.len(), 3);
        assert!(facts.local_business_menu_inventory_total_item_count >= 6);
        assert!(facts.local_business_menu_inventory_floor_met);
        assert!(final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn final_summary_selection_prefers_contract_compliant_document_briefing_output() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt:
                        "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt:
                        "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://newsroom.ibm.com/2024-08-13-ibm-developed-algorithms-announced-as-worlds-first-post-quantum-cryptography-standards".to_string(),
                    title: Some(
                        "IBM-Developed Algorithms Announced as NIST's First Published Post-Quantum Cryptography Standards"
                            .to_string(),
                    ),
                    excerpt:
                        "IBM-developed algorithms announced as NIST's first published post-quantum cryptography standards."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };
        let deterministic_summary =
            synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
        let bad_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.".to_string();
        let selection = select_final_web_summary_from_candidates(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            vec![
                FinalWebSummaryCandidate {
                    provider: "hybrid",
                    summary: bad_summary,
                },
                FinalWebSummaryCandidate {
                    provider: "deterministic",
                    summary: deterministic_summary.clone(),
                },
            ],
        )
        .expect("summary selection");

        assert_eq!(selection.provider, "deterministic");
        assert!(selection.contract_ready);
        assert_eq!(selection.summary, deterministic_summary);
        assert_eq!(selection.evaluations.len(), 2);
        assert!(!selection.evaluations[0].contract_ready);
        assert_eq!(selection.evaluations[0].provider, "hybrid");
        assert_eq!(
            selection.evaluations[0]
                .facts
                .briefing_rendered_layout_profile,
            "story_collection"
        );
        assert!(selection.evaluations[1].contract_ready);
        assert_eq!(selection.evaluations[1].provider, "deterministic");
    }

    #[test]
    fn final_summary_selection_prefers_stronger_non_ready_document_briefing_fallback() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                            .to_string(),
                    ),
                    excerpt: "The other finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms while HQC serves as a backup."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                    title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                    excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards."
                        .to_string(),
                },
            ],
            min_sources: 2,
        };
        let better_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T12:19:24Z UTC)\n\nWhat happened: As of 2026-03-10, retrieved authoritative sources identify the currently published standards as FIPS 204 and FIPS 205. According to NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST, the other finished standards are FIPS 204 and FIPS 205 while HQC serves as a backup. According to Diving Into NIST’s New Post-Quantum Standards, the finalized standards set includes FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- According to NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST, the other finished standards are FIPS 204 and FIPS 205 while HQC serves as a backup.\n- According to Diving Into NIST’s New Post-Quantum Standards, the finalized standards set includes FIPS 203, FIPS 204, and FIPS 205.\n\nCitations:\n- NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST | https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption | 2026-03-10T12:19:24Z | retrieved_utc\n- Diving Into NIST’s New Post-Quantum Standards | https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/ | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: medium"
            .to_string();
        let worse_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nCitations:\n- NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST | https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption | 2026-03-10T12:19:24Z | retrieved_utc"
            .to_string();

        let selection = select_final_web_summary_from_candidates(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            vec![
                FinalWebSummaryCandidate {
                    provider: "hybrid",
                    summary: better_summary.clone(),
                },
                FinalWebSummaryCandidate {
                    provider: "deterministic",
                    summary: worse_summary,
                },
            ],
        )
        .expect("summary selection");

        assert_eq!(selection.provider, "hybrid");
        assert!(!selection.contract_ready);
        assert_eq!(selection.summary, better_summary);
        assert!(selection.facts.briefing_document_layout_met);
        assert_eq!(
            selection.facts.briefing_rendered_layout_profile,
            "document_briefing"
        );
        assert_eq!(selection.evaluations.len(), 2);
        assert!(!selection.evaluations[0].contract_ready);
        assert!(!selection.evaluations[1].contract_ready);
        assert_eq!(
            selection.evaluations[1]
                .facts
                .briefing_rendered_layout_profile,
            "story_collection"
        );
    }
}
