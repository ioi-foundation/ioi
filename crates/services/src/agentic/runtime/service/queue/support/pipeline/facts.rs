use super::*;

mod rendered_answer;
mod semantic;
mod types;

pub(super) use rendered_answer::rendered_summary_citation_urls;
use rendered_answer::*;
pub(crate) use types::{
    FinalWebCompletionFacts, FinalWebSummaryCandidate, FinalWebSummaryCandidateEvaluation,
    FinalWebSummarySelection,
};
use types::{RenderedAnswerContractFacts, RenderedAnswerShapeFacts, RenderedSummaryLayoutProfile};

fn rendered_answer_shape_facts(
    rendered_summary: &str,
    required_sections: &[RequiredAnswerSection],
) -> RenderedAnswerShapeFacts {
    let lines = rendered_summary
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let heading_present = lines.first().is_some_and(|line| {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        trimmed.starts_with("# ")
            || trimmed.starts_with("## ")
            || trimmed.starts_with("### ")
            || lower.starts_with("summary:")
            || lower.starts_with("answer:")
            || lower.starts_with("based on ")
    });
    let legacy_source_cluster_header_count = lines
        .iter()
        .filter(|line| rendered_summary_line_is_legacy_source_cluster_header(line))
        .count();
    let comparison_label_count = lines
        .iter()
        .filter(|line| line.eq_ignore_ascii_case("Comparison:"))
        .count();
    let single_snapshot_heading_present = lines.first().is_some_and(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("right now")
            || lower.starts_with("current snapshot")
            || lower.starts_with("current answer")
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
            ((trimmed.starts_with("- ")
                || lower.starts_with("current conditions:")
                || lower.starts_with("current conditions from ")
                || lower.starts_with("current pricing:")
                || lower.starts_with("current pricing from ")
                || lower.starts_with("available observed details")
                || lower.starts_with("the current "))
                && has_quantitative_metric_payload(metric_candidate, false))
                || ((lower.starts_with("current answer:")
                    || lower.starts_with("current answer from ")
                    || lower.starts_with("current status from "))
                    && single_snapshot_has_direct_fact_line(metric_candidate))
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

    RenderedAnswerShapeFacts {
        heading_present,
        rendered_required_section_label_count,
        rendered_required_section_label_floor_met,
        legacy_source_cluster_header_count,
        comparison_label_count,
        single_snapshot_heading_present,
        single_snapshot_metric_line_count,
        single_snapshot_support_url_count,
        single_snapshot_temporal_signal_present,
    }
}

pub(crate) fn market_quote_source_is_quote_grade(
    source: &PendingSearchReadSummary,
    query_contract: &str,
) -> bool {
    let observed_text = format!(
        "{} {}",
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    );
    if !has_price_quote_payload(&observed_text) {
        return false;
    }

    let url = source.url.trim().to_ascii_lowercase();
    let title = source
        .title
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let excerpt = source.excerpt.to_ascii_lowercase();
    let surface = format!("{url} {title} {excerpt}");
    let quote_surface = surface.contains("coingecko simple price api")
        || url.contains("coingecko.com/en/coins/")
        || url.contains("coinmarketcap.com/currencies/")
        || url.contains("crypto.com/price/")
        || url.contains("crypto.com/en/price/")
        || url.contains("coinbase.com/price/")
        || (url.contains("binance.com") && url.contains("/price/"))
        || title.contains("live price")
        || title.contains("price today")
        || title.contains("live usd price quote");
    if !quote_surface {
        return false;
    }

    let comparison_surface = [
        " compare ",
        " comparison ",
        " vs ",
        " versus ",
        " investment ",
        " prediction ",
        " forecast ",
        " analysis ",
    ]
    .iter()
    .any(|marker| {
        let padded_title = format!(" {title} ");
        let padded_url = format!(" {url} ");
        padded_title.contains(marker) || padded_url.contains(marker)
    });
    if comparison_surface
        && !url.contains("coingecko.com/en/coins/")
        && !url.contains("coinmarketcap.com/currencies/")
        && !url.contains("crypto.com/price/")
        && !url.contains("crypto.com/en/price/")
        && !url.contains("coinbase.com/price/")
    {
        return false;
    }

    let groups = query_market_quote_entity_anchor_groups(query_contract);
    if groups.is_empty() {
        return true;
    }
    let source_tokens = source_anchor_tokens(
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    );
    groups
        .iter()
        .any(|group| group.iter().any(|token| source_tokens.contains(token)))
}

pub(crate) fn market_quote_source_has_structured_metric_payload(
    source: &PendingSearchReadSummary,
) -> bool {
    let surface = format!(
        "{} {} {}",
        source.url,
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    )
    .to_ascii_lowercase();
    surface.contains("coingecko simple price api")
        && surface.contains("market cap:")
        && surface.contains("24h trading volume:")
}

pub(crate) fn market_quote_structured_metric_source_count_for_sources<'a>(
    sources: impl IntoIterator<Item = &'a PendingSearchReadSummary>,
    query_contract: &str,
) -> usize {
    let groups = query_market_quote_entity_anchor_groups(query_contract);
    let structured_sources = sources
        .into_iter()
        .filter(|source| market_quote_source_is_quote_grade(source, query_contract))
        .filter(|source| market_quote_source_has_structured_metric_payload(source))
        .collect::<Vec<_>>();

    if groups.len() < 2 {
        return structured_sources.len();
    }

    let mut covered_groups = BTreeSet::new();
    for source in structured_sources {
        let source_tokens = source_anchor_tokens(
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            &source.excerpt,
        );
        for (idx, group) in groups.iter().enumerate() {
            if group.iter().any(|token| source_tokens.contains(token)) {
                covered_groups.insert(idx);
            }
        }
    }
    covered_groups.len()
}

pub(crate) fn market_quote_structured_metrics_required(
    query_contract: &str,
    comparison_required: bool,
) -> bool {
    query_requires_market_quote_grounding(query_contract)
        && (comparison_required || query_requests_comparison(query_contract))
}

pub(crate) fn market_quote_source_is_comparison_context_grade(
    source: &PendingSearchReadSummary,
    query_contract: &str,
) -> bool {
    if market_quote_source_is_quote_grade(source, query_contract) {
        return false;
    }

    let url = source.url.trim().to_ascii_lowercase();
    let title = source
        .title
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let excerpt = source.excerpt.to_ascii_lowercase();
    let padded = format!(" {url} {title} {excerpt} ");
    let comparison_or_thesis_surface = [
        " compare ",
        "/compare/",
        "-compare-",
        " comparison ",
        " vs ",
        "-vs-",
        "_vs_",
        " versus ",
        " better investment ",
        " investment ",
        " market cap ",
        " performance ",
        " growth ",
        " risk ",
        " risks ",
        " strengths ",
        " thesis ",
        " tokenomics ",
        " investors ",
        " backing ",
        " founder ",
        " use case ",
        " cloud computing ",
        " decentralized cloud ",
        " infrastructure ",
        " depin ",
        " decentralized compute ",
        " decentralized storage ",
        " ai ",
        " storage ",
        " compute ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    if !comparison_or_thesis_surface {
        return false;
    }

    let groups = query_market_quote_entity_anchor_groups(query_contract);
    if groups.is_empty() {
        return true;
    }
    let source_tokens = source_anchor_tokens(
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    );
    let covered_groups = groups
        .iter()
        .filter(|group| group.iter().any(|token| source_tokens.contains(token)))
        .count();
    covered_groups >= groups.len().min(2)
}

pub(crate) fn market_quote_grounding_source_count_for_sources<'a>(
    sources: impl IntoIterator<Item = &'a PendingSearchReadSummary>,
    query_contract: &str,
) -> usize {
    let groups = query_market_quote_entity_anchor_groups(query_contract);
    let quote_sources = sources
        .into_iter()
        .filter(|source| market_quote_source_is_quote_grade(source, query_contract))
        .collect::<Vec<_>>();

    if groups.len() < 2 {
        return quote_sources.len();
    }

    let mut covered_groups = BTreeSet::new();
    for source in quote_sources {
        let source_tokens = source_anchor_tokens(
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            &source.excerpt,
        );
        for (idx, group) in groups.iter().enumerate() {
            if group.iter().any(|token| source_tokens.contains(token)) {
                covered_groups.insert(idx);
            }
        }
    }
    covered_groups.len()
}

pub(crate) fn market_quote_comparison_context_source_count_for_sources<'a>(
    sources: impl IntoIterator<Item = &'a PendingSearchReadSummary>,
    query_contract: &str,
) -> usize {
    sources
        .into_iter()
        .filter(|source| market_quote_source_is_comparison_context_grade(source, query_contract))
        .count()
}

fn market_quote_grounding_source_count(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> usize {
    market_quote_grounding_source_count_for_sources(&pending.successful_reads, query_contract)
}

pub(crate) fn market_quote_grounding_floor_for_query(
    query_contract: &str,
    comparison_required: bool,
    required_source_cluster_floor: usize,
) -> usize {
    let market_quote_anchor_group_count = query_market_quote_entity_anchor_groups(query_contract)
        .len()
        .max(1);
    if comparison_required || required_source_cluster_floor > 1 {
        market_quote_anchor_group_count.max(2)
    } else {
        1
    }
}

pub(crate) fn market_quote_grounding_contract_ready_for_pending(
    pending: &PendingSearchCompletion,
    query_contract: &str,
    comparison_required: bool,
    required_source_cluster_floor: usize,
) -> bool {
    if !query_requires_market_quote_grounding(query_contract) {
        return false;
    }
    let source_count =
        market_quote_grounding_source_count_for_sources(&pending.successful_reads, query_contract);
    let source_floor = market_quote_grounding_floor_for_query(
        query_contract,
        comparison_required,
        required_source_cluster_floor,
    );
    let quote_floor_met = source_floor > 0 && source_count >= source_floor;
    let comparison_context_ready =
        if comparison_required || query_requests_comparison(query_contract) {
            market_quote_comparison_context_source_count_for_sources(
                &pending.successful_reads,
                query_contract,
            ) > 0
                || quote_floor_met
        } else {
            true
        };
    let structured_metrics_ready =
        !market_quote_structured_metrics_required(query_contract, comparison_required)
            || market_quote_structured_metric_source_count_for_sources(
                &pending.successful_reads,
                query_contract,
            ) >= source_floor
            || quote_floor_met;
    quote_floor_met && comparison_context_ready && structured_metrics_ready
}

fn rendered_summary_layout_profile(
    shape_facts: &RenderedAnswerShapeFacts,
) -> RenderedSummaryLayoutProfile {
    if shape_facts.heading_present
        && shape_facts.rendered_required_section_label_floor_met
        && shape_facts.legacy_source_cluster_header_count == 0
        && shape_facts.comparison_label_count == 0
    {
        return RenderedSummaryLayoutProfile::DocumentReport;
    }
    if shape_facts.legacy_source_cluster_header_count > 0 || shape_facts.comparison_label_count > 0
    {
        return RenderedSummaryLayoutProfile::SourceCollection;
    }
    if shape_facts.single_snapshot_heading_present
        && shape_facts.single_snapshot_metric_line_count > 0
        && shape_facts.single_snapshot_support_url_count > 0
        && shape_facts.single_snapshot_temporal_signal_present
    {
        return RenderedSummaryLayoutProfile::SingleSnapshot;
    }
    if shape_facts.single_snapshot_support_url_count > 0 {
        return RenderedSummaryLayoutProfile::SourcedAnswer;
    }
    RenderedSummaryLayoutProfile::Other
}

fn final_web_comparison_shape_ready(facts: &FinalWebCompletionFacts) -> bool {
    if facts.comparison_required {
        facts.comparison_ready
    } else {
        facts.answer_comparison_absent
    }
}

fn final_model_sourced_answer_contract_ready(facts: &FinalWebCompletionFacts) -> bool {
    let compatible_source_floor =
        facts.evidence_selected_source_compatible >= facts.selected_source_urls.len().min(2).max(1);
    let local_business_menu_floor = facts.local_business_menu_surface_floor_met
        && facts.local_business_menu_inventory_floor_met;
    let market_quote_grounding_ready = final_model_market_quote_grounding_ready(facts);
    let required_source_floor = if facts.market_quote_grounding_required {
        if facts.comparison_required {
            2
        } else {
            1
        }
    } else if facts.comparison_required {
        facts.required_source_cluster_floor.max(2)
    } else {
        1
    };

    (compatible_source_floor || local_business_menu_floor)
        && facts.evidence_selected_source_identifier_coverage_floor_met
        && market_quote_grounding_ready
        && facts.answer_legacy_source_cluster_headers_absent
        && facts.evidence_citation_read_backing_floor_met
        && facts.selected_source_urls.len() >= required_source_floor
}

fn final_model_market_quote_grounding_ready(facts: &FinalWebCompletionFacts) -> bool {
    !facts.market_quote_grounding_required
        || facts.market_quote_grounding_floor_met
        || facts.rendered_summary_semantic_floor_met
}

fn final_model_natural_answer_contract_ready(facts: &FinalWebCompletionFacts) -> bool {
    let required_source_floor = if facts.market_quote_grounding_required {
        if facts.comparison_required {
            2
        } else {
            1
        }
    } else if facts.comparison_required {
        facts.required_source_cluster_floor.max(2)
    } else {
        1
    };
    let selected_source_floor_met = facts.selected_source_urls.len() >= required_source_floor
        && facts.evidence_selected_source_compatible >= required_source_floor
        && facts.evidence_selected_source_identifier_coverage_floor_met;
    let comparison_evidence_ready = !facts.comparison_required
        || facts.comparison_ready
        || (facts.market_quote_grounding_required
            && final_model_market_quote_grounding_ready(facts));
    selected_source_floor_met
        && facts.answer_legacy_source_cluster_headers_absent
        && facts.answer_comparison_absent
        && facts.evidence_citation_read_backing_floor_met
        && final_model_market_quote_grounding_ready(facts)
        && comparison_evidence_ready
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
    required_source_cluster_floor: usize,
    min_sources_required: usize,
) -> (Vec<String>, Vec<String>, usize, bool) {
    let required_source_floor = required_source_cluster_floor
        .max(min_sources_required)
        .max(1);
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

fn rendered_answer_contract_facts(
    pending: &PendingSearchCompletion,
    query_contract: &str,
    rendered_summary: &str,
    required_sections: &[RequiredAnswerSection],
    required_supporting_fragment_floor: usize,
    required_primary_authority_source_count: usize,
) -> RenderedAnswerContractFacts {
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
            (!trimmed.is_empty()).then(|| EvidenceIdentifierObservation {
                url: trimmed.to_string(),
                surface: preferred_source_evidence_identifier_surface(
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
        infer_answer_required_identifier_labels(query_contract, &successful_read_observations);
    let observed_identifier_labels =
        observed_evidence_standard_identifier_labels_with_compressed_fips(
            query_contract,
            &full_surface,
        );
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
            source_counts_as_primary_authority(
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
        let identifiers = source_evidence_standard_identifier_labels(
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
                && !source_evidence_standard_identifier_labels(
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
                observed_evidence_standard_identifier_labels_with_compressed_fips(
                    query_contract,
                    &inventory_surface,
                );
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

    RenderedAnswerContractFacts {
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
    let required_source_cluster_floor =
        retrieval_contract_required_source_cluster_count(retrieval_contract, &query_contract)
            .max(1);
    let evidence_support_floor =
        retrieval_contract_required_support_count(retrieval_contract, &query_contract).max(1);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let local_business_entity_floor_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, &query_contract);
    let local_business_targets = if local_business_entity_floor_required {
        merged_local_business_target_names(
            &pending.attempted_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_source_cluster_floor.max(min_sources_required),
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
    let market_quote_grounding_required = query_requires_market_quote_grounding(&query_contract);
    let local_business_selected_sources = if local_business_targets.is_empty() {
        Vec::new()
    } else {
        selected_local_business_target_sources(
            &query_contract,
            &local_business_targets,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_source_cluster_floor.max(min_sources_required),
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
    let selected_sources = if market_quote_grounding_required {
        selected_sources
            .into_iter()
            .filter(|source| {
                market_quote_source_is_quote_grade(source, &query_contract)
                    || market_quote_source_is_comparison_context_grade(source, &query_contract)
            })
            .collect::<Vec<_>>()
    } else {
        selected_sources
    };
    let selected_source_urls = selected_sources
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
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
            >= required_source_cluster_floor.max(min_sources_required);
    let (
        local_business_menu_inventory_source_urls,
        local_business_menu_inventory_items,
        local_business_menu_inventory_total_item_count,
        local_business_menu_inventory_floor_met,
    ) = if local_business_menu_surface_required {
        local_business_menu_inventory_evidence(
            pending,
            &selected_source_urls,
            required_source_cluster_floor,
            min_sources_required,
        )
    } else {
        (Vec::new(), Vec::new(), 0, true)
    };
    let evidence_successful_citation_url_count = selected_source_urls.len();
    let evidence_unread_citation_url_count = selected_source_urls
        .len()
        .saturating_sub(evidence_successful_citation_url_count);
    let selected_primary_authority_source_count = selected_sources
        .iter()
        .filter(|source| {
            source_counts_as_primary_authority(
                &query_contract,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
        })
        .count();
    let required_citations = retrieval_contract_required_citations_per_source_cluster(
        retrieval_contract,
        &query_contract,
    )
    .max(1);
    let answer_required_section_specs = build_required_answer_sections(&query_contract);
    let answer_required_sections = answer_required_section_specs
        .iter()
        .map(|section| section.key.clone())
        .collect::<Vec<_>>();
    let answer_query_layout_expected = query_prefers_document_report_layout(&query_contract)
        && !query_requests_comparison(&query_contract);
    let layout_profile = synthesis_layout_profile(retrieval_contract, &query_contract);
    let answer_required_supporting_fragment_floor = evidence_support_floor.min(2).max(1);
    let (headline_actionable_sources_observed, headline_actionable_domains_observed) =
        if headline_collection_mode {
            headline_actionable_source_inventory(&pending.successful_reads)
        } else {
            (0, 0)
        };
    let observed_source_clusters = if headline_collection_mode {
        headline_actionable_sources_observed.min(required_source_cluster_floor)
    } else {
        selected_source_urls
            .len()
            .min(required_source_cluster_floor)
    };
    let source_cluster_floor_met = if headline_collection_mode {
        headline_actionable_sources_observed >= required_source_cluster_floor
            && headline_actionable_domains_observed >= required_source_cluster_floor
    } else {
        observed_source_clusters >= required_source_cluster_floor
    };
    let source_cluster_citation_floor_met = selected_source_urls.len()
        >= required_source_cluster_floor
            .max(1)
            .saturating_mul(required_citations.max(1));
    let comparison_required =
        retrieval_contract_requests_comparison(retrieval_contract, &query_contract)
            && required_source_cluster_floor > 1;
    let comparison_ready = !comparison_required || source_cluster_floor_met;
    let answer_document_layout_met =
        matches!(layout_profile, SynthesisLayoutProfile::DocumentReport);
    let answer_legacy_source_cluster_headers_absent = answer_document_layout_met;
    let answer_comparison_absent = answer_document_layout_met && !comparison_required;
    let answer_required_section_floor_met = false;
    let answer_query_grounding_floor_met = false;
    let evidence_citation_read_backing_floor_met = evidence_unread_citation_url_count == 0
        && evidence_successful_citation_url_count
            >= answer_required_supporting_fragment_floor.max(required_citations);
    let run_timestamp_ms = web_pipeline_now_ms();
    let run_date = iso_date_from_unix_ms(run_timestamp_ms);
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);
    let trace_temporal_anchor_floor_met =
        run_timestamp_ms > 0 && is_iso_utc_datetime(run_timestamp_iso_utc.trim());
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
            source_counts_as_primary_authority(
                &query_contract,
                url,
                hint.and_then(|value| value.title.as_deref())
                    .unwrap_or_default(),
                hint.map(|value| value.excerpt.as_str()).unwrap_or_default(),
            )
        })
        .count();
    let attempted_url_set = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .map(|url| url.trim().to_ascii_lowercase())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>();
    let successful_url_set = pending
        .successful_reads
        .iter()
        .map(|source| source.url.trim().to_ascii_lowercase())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>();
    let available_primary_authority_source_count = merged_evidence_sources(pending)
        .iter()
        .filter(|source| {
            let normalized_url = source.url.trim().to_ascii_lowercase();
            successful_url_set.contains(&normalized_url)
                || !attempted_url_set.contains(&normalized_url)
        })
        .filter(|source| {
            source_counts_as_primary_authority(
                &query_contract,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
        })
        .count();
    let evidence_primary_authority_source_floor_applicable = !comparison_required
        && query_facets.grounded_external_required
        && retrieval_contract_requires_primary_authority_source(
            retrieval_contract,
            &query_contract,
        );
    let answer_required_primary_authority_source_count =
        if evidence_primary_authority_source_floor_applicable {
            available_primary_authority_source_count.min(
                crate::agentic::runtime::service::queue::support::retrieval_contract_primary_authority_source_slot_cap(
                    retrieval_contract,
                    &query_contract,
                    required_citations.max(1),
                ),
            )
        } else {
            0
        };
    let evidence_primary_authority_source_floor_met =
        !evidence_primary_authority_source_floor_applicable
            || (answer_required_primary_authority_source_count == 0
                && available_primary_authority_source_count == 0
                && attempted_primary_authority_source_count == 0)
            || selected_primary_authority_source_count
                >= answer_required_primary_authority_source_count.max(1);
    let selected_identifier_observations = pending
        .successful_reads
        .iter()
        .filter_map(|source| {
            let trimmed = source.url.trim();
            let title = source.title.as_deref().unwrap_or_default();
            (!trimmed.is_empty()).then(|| EvidenceIdentifierObservation {
                url: trimmed.to_string(),
                surface: preferred_source_evidence_identifier_surface(
                    &query_contract,
                    &source.url,
                    title,
                    &source.excerpt,
                ),
                authoritative: source_has_document_authority(
                    &query_contract,
                    trimmed,
                    title,
                    &source.excerpt,
                ),
            })
        })
        .collect::<Vec<_>>();
    let required_identifier_labels =
        infer_answer_required_identifier_labels(&query_contract, &selected_identifier_observations);
    let evidence_standard_identifier_group_floor = required_identifier_labels.len();
    let mut evidence_standard_identifiers = BTreeSet::new();
    let mut evidence_required_standard_identifiers = BTreeSet::new();
    let mut evidence_authority_standard_identifiers = BTreeSet::new();
    let mut evidence_required_authority_standard_identifiers = BTreeSet::new();
    let mut evidence_standard_identifier_authority_source_urls = BTreeSet::new();
    for source in &selected_sources {
        let title = source.title.as_deref().unwrap_or_default();
        let identifiers = source_evidence_standard_identifier_labels(
            &query_contract,
            &source.url,
            title,
            &source.excerpt,
        );
        if identifiers.is_empty() {
            continue;
        }
        let authoritative =
            source_has_document_authority(&query_contract, &source.url, title, &source.excerpt);
        if authoritative {
            evidence_standard_identifier_authority_source_urls
                .insert(source.url.trim().to_ascii_lowercase());
        }
        for label in identifiers {
            if required_identifier_labels.contains(&label) {
                evidence_required_standard_identifiers.insert(label.clone());
                if authoritative {
                    evidence_required_authority_standard_identifiers.insert(label.clone());
                }
            }
            evidence_standard_identifiers.insert(label.clone());
            if authoritative {
                evidence_authority_standard_identifiers.insert(label);
            }
        }
    }
    let evidence_available_standard_identifier_authority_source_count = pending
        .successful_reads
        .iter()
        .filter(|source| {
            let title = source.title.as_deref().unwrap_or_default();
            source_has_document_authority(&query_contract, &source.url, title, &source.excerpt)
                && !source_evidence_standard_identifier_labels(
                    &query_contract,
                    &source.url,
                    title,
                    &source.excerpt,
                )
                .is_empty()
        })
        .map(|source| source.url.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len();
    let evidence_standard_identifier_floor_met = evidence_standard_identifier_group_floor == 0
        || evidence_required_standard_identifiers.len() >= evidence_standard_identifier_group_floor;
    let evidence_authority_standard_identifier_floor_met = evidence_standard_identifier_group_floor
        == 0
        || evidence_available_standard_identifier_authority_source_count == 0
        || evidence_required_authority_standard_identifiers.len()
            >= evidence_standard_identifier_group_floor;
    let trace_metadata_floor_met = trace_temporal_anchor_floor_met
        && matches!(reason, WebPipelineCompletionReason::MinSourcesReached)
        && matches!("medium", "high" | "medium" | "low");
    let single_snapshot_metric_required =
        single_snapshot_requires_current_metric_observation_contract(pending);
    let single_snapshot_metric_grounding =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract)
            && if single_snapshot_metric_required {
                single_snapshot_has_metric_grounding(pending)
            } else {
                pending.successful_reads.iter().any(|source| {
                    single_snapshot_fact_grounding_signal_with_contract(
                        retrieval_contract,
                        &query_contract,
                        pending.min_sources as usize,
                        source,
                    )
                })
            };
    let market_quote_grounding_source_count =
        market_quote_grounding_source_count(pending, &query_contract);
    let market_quote_grounding_floor = market_quote_grounding_floor_for_query(
        &query_contract,
        comparison_required,
        required_source_cluster_floor,
    );
    let market_quote_comparison_context_ready = !(market_quote_grounding_required
        && (comparison_required || query_requests_comparison(&query_contract)))
        || market_quote_comparison_context_source_count_for_sources(
            &pending.successful_reads,
            &query_contract,
        ) > 0
        || market_quote_grounding_source_count >= market_quote_grounding_floor;
    let market_quote_structured_metrics_ready =
        !market_quote_structured_metrics_required(&query_contract, comparison_required)
            || market_quote_structured_metric_source_count_for_sources(
                &pending.successful_reads,
                &query_contract,
            ) >= market_quote_grounding_floor
            || market_quote_grounding_source_count >= market_quote_grounding_floor;
    let market_quote_grounding_floor_met = !market_quote_grounding_required
        || (market_quote_grounding_source_count >= market_quote_grounding_floor
            && market_quote_comparison_context_ready
            && market_quote_structured_metrics_ready);

    FinalWebCompletionFacts {
        selected_source_urls,
        evidence_selected_source_total: selected_source_observation.total_sources,
        evidence_selected_source_compatible: selected_source_observation.compatible_sources,
        evidence_selected_source_quality_floor_met: selected_source_observation.quality_floor_met,
        evidence_selected_source_identifier_coverage_floor_met: selected_source_observation
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
        required_source_cluster_floor,
        required_citations_per_source_cluster: required_citations,
        answer_required_sections,
        answer_required_section_count: answer_required_section_specs.len(),
        answer_rendered_required_section_count: 0,
        answer_query_grounded_required_section_count: 0,
        answer_required_narrative_sections: 0,
        answer_single_block_narrative_sections: 0,
        answer_required_evidence_sections: 0,
        answer_rendered_evidence_block_count: 0,
        answer_qualifying_evidence_sections: 0,
        answer_required_supporting_fragment_floor,
        answer_aggregated_narrative_sections: 0,
        evidence_standard_identifier_count: evidence_standard_identifiers.len(),
        evidence_required_standard_identifier_count: evidence_required_standard_identifiers.len(),
        evidence_standard_identifier_group_floor,
        evidence_authority_standard_identifier_count: evidence_authority_standard_identifiers.len(),
        evidence_required_authority_standard_identifier_count:
            evidence_required_authority_standard_identifiers.len(),
        evidence_inventory_identifier_count: 0,
        evidence_inventory_required_identifier_count: 0,
        evidence_inventory_optional_identifier_count: 0,
        evidence_inventory_authority_identifier_count: 0,
        evidence_standard_identifier_authority_source_count:
            evidence_standard_identifier_authority_source_urls.len(),
        evidence_available_standard_identifier_authority_source_count:
            evidence_available_standard_identifier_authority_source_count,
        answer_required_primary_authority_source_count,
        evidence_successful_citation_url_count,
        evidence_unread_citation_url_count,
        trace_run_date: run_date,
        trace_run_timestamp_iso_utc: run_timestamp_iso_utc,
        trace_overall_confidence: "medium".to_string(),
        answer_query_layout_expected,
        answer_layout_profile: match layout_profile {
            SynthesisLayoutProfile::SingleSnapshot => "single_snapshot".to_string(),
            SynthesisLayoutProfile::DocumentReport => "document_report".to_string(),
            SynthesisLayoutProfile::MultiSourceCollection => "multi_source_collection".to_string(),
        },
        answer_rendered_layout_profile: "unobserved".to_string(),
        answer_render_heading_floor_met: answer_document_layout_met,
        answer_rendered_required_section_label_count: 0,
        answer_rendered_required_section_label_floor_met: false,
        answer_legacy_source_cluster_header_count: usize::from(
            !answer_legacy_source_cluster_headers_absent,
        ),
        answer_comparison_label_count: usize::from(!answer_comparison_absent),
        observed_source_clusters,
        source_cluster_floor_met,
        source_cluster_citation_floor_met,
        comparison_required,
        comparison_ready,
        answer_document_layout_met,
        answer_legacy_source_cluster_headers_absent,
        answer_comparison_absent,
        answer_required_section_floor_met,
        answer_query_grounding_floor_met,
        evidence_standard_identifier_floor_met,
        evidence_authority_standard_identifier_floor_met,
        evidence_inventory_floor_met: false,
        answer_narrative_aggregation_floor_met: false,
        answer_evidence_block_floor_met: false,
        evidence_primary_authority_source_floor_met,
        evidence_citation_read_backing_floor_met,
        trace_temporal_anchor_floor_met,
        trace_metadata_floor_met,
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
        market_quote_grounding_required,
        market_quote_grounding_source_count,
        market_quote_grounding_floor_met,
        rendered_summary_semantic_floor_met: true,
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
    let required_sections = build_required_answer_sections(&query_contract);
    let shape_facts = rendered_answer_shape_facts(rendered_summary, &required_sections);
    let rendered_layout_profile = rendered_summary_layout_profile(&shape_facts);
    let rendered_contract_facts = rendered_answer_contract_facts(
        pending,
        &query_contract,
        rendered_summary,
        &required_sections,
        facts.answer_required_supporting_fragment_floor,
        facts.answer_required_primary_authority_source_count,
    );
    facts.answer_render_heading_floor_met = shape_facts.heading_present;
    facts.answer_rendered_required_section_label_count =
        shape_facts.rendered_required_section_label_count;
    facts.answer_rendered_required_section_label_floor_met =
        shape_facts.rendered_required_section_label_floor_met;
    facts.answer_legacy_source_cluster_header_count =
        shape_facts.legacy_source_cluster_header_count;
    facts.answer_comparison_label_count = shape_facts.comparison_label_count;
    facts.answer_legacy_source_cluster_headers_absent =
        shape_facts.legacy_source_cluster_header_count == 0;
    facts.answer_comparison_absent = shape_facts.comparison_label_count == 0;
    facts.answer_rendered_layout_profile = rendered_layout_profile.as_str().to_string();
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
    let rendered_market_quote_citations_valid = if facts.market_quote_grounding_required
        && !rendered_contract_facts.citation_urls.is_empty()
    {
        rendered_contract_facts.citation_urls.iter().all(|url| {
            successful_read_for_url(pending, url)
                .map(|source| {
                    market_quote_source_is_quote_grade(source, &query_contract)
                        || market_quote_source_is_comparison_context_grade(source, &query_contract)
                })
                .unwrap_or(false)
        })
    } else {
        true
    };
    if !rendered_contract_facts.citation_urls.is_empty() {
        facts.selected_source_urls = if facts.market_quote_grounding_required {
            rendered_contract_facts
                .citation_urls
                .iter()
                .filter(|url| {
                    successful_read_for_url(pending, url)
                        .map(|source| {
                            market_quote_source_is_quote_grade(source, &query_contract)
                                || market_quote_source_is_comparison_context_grade(
                                    source,
                                    &query_contract,
                                )
                        })
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        } else {
            rendered_contract_facts.citation_urls.clone()
        };
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
    facts.evidence_selected_source_total = selected_source_observation.total_sources;
    facts.evidence_selected_source_compatible = selected_source_observation.compatible_sources;
    facts.evidence_selected_source_quality_floor_met =
        selected_source_observation.quality_floor_met;
    facts.evidence_selected_source_identifier_coverage_floor_met =
        selected_source_observation.identifier_coverage_floor_met;
    if let Some(run_date) = rendered_contract_facts.run_date.as_ref() {
        facts.trace_run_date = run_date.clone();
    }
    if let Some(run_timestamp_iso_utc) = rendered_contract_facts.run_timestamp_iso_utc.as_ref() {
        facts.trace_run_timestamp_iso_utc = run_timestamp_iso_utc.clone();
    }
    if let Some(overall_confidence) = rendered_contract_facts.overall_confidence.as_ref() {
        facts.trace_overall_confidence = overall_confidence.clone();
    }
    facts.answer_document_layout_met = facts.answer_query_layout_expected
        && matches!(
            rendered_layout_profile,
            RenderedSummaryLayoutProfile::DocumentReport
        );
    facts.answer_rendered_required_section_count =
        rendered_contract_facts.rendered_required_section_count;
    facts.answer_query_grounded_required_section_count =
        rendered_contract_facts.query_grounded_required_section_count;
    facts.answer_required_narrative_sections = rendered_contract_facts.required_narrative_sections;
    facts.answer_single_block_narrative_sections =
        rendered_contract_facts.rendered_single_block_narrative_sections;
    facts.answer_required_evidence_sections = rendered_contract_facts.required_evidence_sections;
    facts.answer_rendered_evidence_block_count =
        rendered_contract_facts.rendered_evidence_block_count;
    facts.answer_qualifying_evidence_sections =
        rendered_contract_facts.qualifying_evidence_sections;
    facts.answer_aggregated_narrative_sections =
        rendered_contract_facts.qualifying_aggregated_narrative_sections;
    facts.evidence_standard_identifier_count = rendered_contract_facts.standard_identifier_count;
    facts.evidence_required_standard_identifier_count =
        rendered_contract_facts.required_standard_identifier_count;
    facts.evidence_standard_identifier_group_floor =
        rendered_contract_facts.standard_identifier_group_floor;
    facts.evidence_authority_standard_identifier_count =
        rendered_contract_facts.authority_standard_identifier_count;
    facts.evidence_required_authority_standard_identifier_count =
        rendered_contract_facts.required_authority_standard_identifier_count;
    facts.evidence_inventory_identifier_count =
        rendered_contract_facts.summary_inventory_identifier_count;
    facts.evidence_inventory_required_identifier_count =
        rendered_contract_facts.summary_inventory_required_identifier_count;
    facts.evidence_inventory_optional_identifier_count =
        rendered_contract_facts.summary_inventory_optional_identifier_count;
    facts.evidence_inventory_authority_identifier_count =
        rendered_contract_facts.summary_inventory_authority_identifier_count;
    facts.evidence_standard_identifier_authority_source_count =
        rendered_contract_facts.standard_identifier_authority_source_count;
    facts.evidence_available_standard_identifier_authority_source_count =
        rendered_contract_facts.available_standard_identifier_authority_source_count;
    facts.answer_required_primary_authority_source_count =
        rendered_contract_facts.required_primary_authority_source_count;
    facts.evidence_successful_citation_url_count =
        rendered_contract_facts.successful_citation_url_count;
    facts.evidence_unread_citation_url_count = rendered_contract_facts.unread_citation_url_count;
    facts.answer_required_section_floor_met =
        facts.answer_document_layout_met && rendered_contract_facts.required_section_floor_met;
    facts.answer_query_grounding_floor_met =
        facts.answer_document_layout_met && rendered_contract_facts.query_grounding_floor_met;
    facts.evidence_standard_identifier_floor_met =
        facts.answer_document_layout_met && rendered_contract_facts.standard_identifier_floor_met;
    facts.evidence_authority_standard_identifier_floor_met = facts.answer_document_layout_met
        && rendered_contract_facts.authority_standard_identifier_floor_met;
    facts.evidence_inventory_floor_met =
        facts.answer_document_layout_met && rendered_contract_facts.summary_inventory_floor_met;
    facts.answer_narrative_aggregation_floor_met =
        facts.answer_document_layout_met && rendered_contract_facts.narrative_aggregation_floor_met;
    facts.answer_evidence_block_floor_met =
        facts.answer_document_layout_met && rendered_contract_facts.evidence_block_floor_met;
    facts.evidence_primary_authority_source_floor_met =
        if !rendered_contract_facts.citation_urls.is_empty() {
            rendered_contract_facts.primary_authority_source_floor_met
        } else {
            facts.evidence_primary_authority_source_floor_met
        };
    facts.evidence_citation_read_backing_floor_met = if matches!(
        rendered_layout_profile,
        RenderedSummaryLayoutProfile::DocumentReport
    ) {
        facts.answer_document_layout_met && rendered_contract_facts.citation_read_backing_floor_met
    } else if !rendered_contract_facts.citation_urls.is_empty() {
        rendered_contract_facts.citation_read_backing_floor_met
    } else {
        facts.evidence_citation_read_backing_floor_met
    };
    if facts.market_quote_grounding_required && !rendered_market_quote_citations_valid {
        facts.evidence_citation_read_backing_floor_met = false;
    }
    facts.trace_temporal_anchor_floor_met = rendered_contract_facts.temporal_anchor_floor_met;
    facts.trace_metadata_floor_met = rendered_contract_facts.postamble_floor_met;
    if facts.market_quote_grounding_required && !rendered_contract_facts.citation_urls.is_empty() {
        let selected_quote_sources = facts
            .selected_source_urls
            .iter()
            .filter_map(|url| successful_read_for_url(pending, url))
            .collect::<Vec<_>>();
        facts.market_quote_grounding_source_count = market_quote_grounding_source_count_for_sources(
            selected_quote_sources.iter().copied(),
            &query_contract,
        );
        let market_quote_grounding_floor = market_quote_grounding_floor_for_query(
            &query_contract,
            facts.comparison_required,
            facts.required_source_cluster_floor,
        );
        let structured_metrics_ready =
            !market_quote_structured_metrics_required(&query_contract, facts.comparison_required)
                || market_quote_structured_metric_source_count_for_sources(
                    selected_quote_sources.iter().copied(),
                    &query_contract,
                ) >= market_quote_grounding_floor;
        let comparison_context_ready =
            if facts.comparison_required || query_requests_comparison(&query_contract) {
                market_quote_comparison_context_source_count_for_sources(
                    selected_quote_sources.iter().copied(),
                    &query_contract,
                ) > 0
                    || facts.market_quote_grounding_source_count >= market_quote_grounding_floor
            } else {
                true
            };
        facts.market_quote_grounding_floor_met = rendered_market_quote_citations_valid
            && facts.market_quote_grounding_source_count >= market_quote_grounding_floor
            && structured_metrics_ready
            && comparison_context_ready;
    }
    facts.rendered_summary_semantic_floor_met =
        semantic::rendered_summary_semantic_floor_met(pending, rendered_summary);
    facts
}

pub(crate) fn final_web_completion_contract_ready(facts: &FinalWebCompletionFacts) -> bool {
    let comparison_shape_ready = final_web_comparison_shape_ready(facts);
    if facts.answer_rendered_layout_profile == "sourced_answer" {
        return final_model_sourced_answer_contract_ready(facts);
    }
    if facts.answer_rendered_layout_profile == "other"
        && final_model_natural_answer_contract_ready(facts)
    {
        return true;
    }
    if !facts.answer_query_layout_expected
        && facts.answer_rendered_layout_profile == "document_report"
        && final_model_natural_answer_contract_ready(facts)
    {
        return true;
    }
    if facts.answer_query_layout_expected {
        return facts.evidence_selected_source_quality_floor_met
            && facts.evidence_selected_source_identifier_coverage_floor_met
            && facts.answer_document_layout_met
            && facts.answer_render_heading_floor_met
            && facts.answer_rendered_required_section_label_floor_met
            && facts.answer_legacy_source_cluster_headers_absent
            && comparison_shape_ready
            && facts.answer_required_section_floor_met
            && facts.answer_query_grounding_floor_met
            && facts.evidence_standard_identifier_floor_met
            && facts.evidence_authority_standard_identifier_floor_met
            && facts.evidence_inventory_floor_met
            && facts.answer_narrative_aggregation_floor_met
            && facts.answer_evidence_block_floor_met
            && facts.evidence_primary_authority_source_floor_met
            && facts.evidence_citation_read_backing_floor_met
            && facts.trace_temporal_anchor_floor_met
            && facts.trace_metadata_floor_met
            && facts.market_quote_grounding_floor_met
            && (!facts.comparison_required || facts.comparison_ready);
    }
    if facts.answer_layout_profile == "single_snapshot" {
        return facts.single_snapshot_metric_grounding
            && facts.single_snapshot_rendered_layout_met
            && facts.single_snapshot_rendered_metric_line_floor_met
            && facts.single_snapshot_rendered_support_url_floor_met
            && facts.single_snapshot_rendered_read_backed_url_floor_met
            && facts.single_snapshot_rendered_temporal_signal_present
            && facts.evidence_primary_authority_source_floor_met
            && facts.market_quote_grounding_floor_met
            && facts.answer_legacy_source_cluster_headers_absent
            && comparison_shape_ready
            && !facts.selected_source_urls.is_empty()
            && (!facts.comparison_required || facts.comparison_ready);
    }
    if facts.answer_document_layout_met {
        return facts.evidence_selected_source_quality_floor_met
            && facts.evidence_selected_source_identifier_coverage_floor_met
            && facts.answer_required_section_floor_met
            && facts.answer_query_grounding_floor_met
            && facts.evidence_standard_identifier_floor_met
            && facts.evidence_authority_standard_identifier_floor_met
            && facts.evidence_inventory_floor_met
            && facts.answer_narrative_aggregation_floor_met
            && facts.answer_evidence_block_floor_met
            && facts.evidence_primary_authority_source_floor_met
            && facts.market_quote_grounding_floor_met
            && facts.evidence_citation_read_backing_floor_met
            && facts.trace_temporal_anchor_floor_met
            && facts.trace_metadata_floor_met
            && (!facts.comparison_required || facts.comparison_ready);
    }
    if matches!(
        facts.answer_rendered_layout_profile.as_str(),
        "other" | "source_collection"
    ) {
        return false;
    }
    facts.source_cluster_floor_met
        && facts.source_cluster_citation_floor_met
        && facts.local_business_menu_surface_floor_met
        && facts.local_business_menu_inventory_floor_met
        && facts.market_quote_grounding_floor_met
        && facts.observed_source_clusters >= facts.required_source_cluster_floor
        && (!facts.comparison_required || facts.comparison_ready)
}

pub(crate) fn final_web_completion_retry_feedback(facts: &FinalWebCompletionFacts) -> Vec<String> {
    let mut feedback = Vec::new();
    if !facts.answer_legacy_source_cluster_headers_absent {
        feedback.push(
            "remove retrieval scaffolding, source-inventory prose, and intermediate labels"
                .to_string(),
        );
    }
    if matches!(
        facts.answer_rendered_layout_profile.as_str(),
        "source_collection"
    ) {
        feedback.push("do not terminalize as a source list alone".to_string());
    }
    if facts.answer_rendered_layout_profile == "other"
        && !final_model_natural_answer_contract_ready(facts)
    {
        feedback.push("write a complete natural answer instead of a thin handoff".to_string());
    }
    if facts.answer_query_layout_expected && !facts.answer_document_layout_met {
        feedback.push(
            "complete the requested document/report shape with substantive sections".to_string(),
        );
    }
    if !facts.answer_query_grounding_floor_met {
        feedback.push("answer the user's actual question using the gathered evidence".to_string());
    }
    if !facts.evidence_citation_read_backing_floor_met
        || !facts.single_snapshot_rendered_read_backed_url_floor_met
    {
        feedback.push("cite read-backed sources that directly support the claims".to_string());
    }
    if !facts.evidence_selected_source_identifier_coverage_floor_met {
        feedback.push(
            "connect cited sources to the named subject, company, asset, or place they support"
                .to_string(),
        );
    }
    if facts.market_quote_grounding_required && !facts.market_quote_grounding_floor_met {
        feedback.push(
            "ground every live price or market claim in same-subject evidence; gather more evidence if needed"
                .to_string(),
        );
    }
    if facts.comparison_required && !facts.comparison_ready {
        feedback.push("make the comparison directly, then explain the tradeoffs".to_string());
    }
    if !facts.rendered_summary_semantic_floor_met {
        feedback.push(
            "replace generic output with substantive synthesis from the evidence".to_string(),
        );
    }
    if feedback.is_empty() {
        feedback.push("rewrite naturally using only the supplied evidence".to_string());
    }
    feedback
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
    let mut first_allowed_non_ready: Option<FinalWebSummarySelection> = None;
    for candidate in candidates {
        let facts =
            final_web_completion_facts_with_rendered_summary(pending, reason, &candidate.summary);
        let provider_key = candidate.provider.to_ascii_lowercase();
        let provider_allowed = matches!(
            provider_key.as_str(),
            "model_direct_sourced_answer" | "model_chat_reply"
        );
        let contract_ready = provider_allowed && final_web_completion_contract_ready(&facts);
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
        if provider_allowed && first_allowed_non_ready.is_none() {
            first_allowed_non_ready = Some(selection);
        }
    }

    first_allowed_non_ready.map(|mut selection| {
        selection.evaluations = evaluations;
        selection
    })
}
