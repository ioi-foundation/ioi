use super::*;
use ioi_types::app::agentic::WebRetrievalContract;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SynthesisLayoutProfile {
    SingleSnapshot,
    DocumentReport,
    MultiSourceCollection,
}

pub(crate) fn retrieval_contract_prefers_single_fact_snapshot(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    contract
        .map(|contract| {
            contract.entity_cardinality_min <= 1
                && !contract.comparison_required
                && (contract.structured_record_preferred || prefers_single_fact_snapshot(query))
        })
        .unwrap_or_else(|| prefers_single_fact_snapshot(query))
}

pub(crate) fn retrieval_contract_requires_runtime_locality(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    contract
        .map(|contract| {
            contract.runtime_locality_required || query_requires_runtime_locality_scope(query)
        })
        .unwrap_or_else(|| query_requires_runtime_locality_scope(query))
}

pub(crate) fn retrieval_contract_prefers_multi_item_cardinality(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    contract
        .map(|contract| {
            contract.entity_cardinality_min > 1
                || contract.comparison_required
                || query_prefers_multi_item_cardinality(query)
        })
        .unwrap_or_else(|| query_prefers_multi_item_cardinality(query))
}

pub(crate) fn retrieval_contract_requests_comparison(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    contract
        .map(|contract| contract.comparison_required || query_requests_comparison(query))
        .unwrap_or_else(|| query_requests_comparison(query))
}

pub(crate) fn retrieval_or_query_requests_comparison(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    retrieval_contract_requests_comparison(contract, query) || query_requests_comparison(query)
}

pub(crate) fn retrieval_contract_is_generic_headline_collection(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    contract
        .map(|contract| {
            (contract.ordered_collection_preferred || query_is_generic_headline_collection(query))
                && contract.entity_cardinality_min > 1
                && !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(contract)
        })
        .unwrap_or_else(|| query_is_generic_headline_collection(query))
}

pub(crate) fn retrieval_or_query_prefers_single_fact_snapshot(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    retrieval_contract_prefers_single_fact_snapshot(contract, query)
        || (contract.is_none() && prefers_single_fact_snapshot(query))
}

pub(crate) fn retrieval_or_query_is_generic_headline_collection(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    retrieval_contract_is_generic_headline_collection(contract, query)
        || (contract.is_none() && query_is_generic_headline_collection(query))
}

pub(crate) fn retrieval_contract_entity_diversity_required(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    contract
        .map(|contract| {
            crate::agentic::web::contract_requires_geo_scoped_entity_expansion(contract)
                || query_requires_local_business_entity_diversity(query)
        })
        .unwrap_or_else(|| query_requires_local_business_entity_diversity(query))
}

pub(crate) fn retrieval_contract_required_source_cluster_count(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    if query_prefers_document_report_layout(query)
        && !retrieval_contract_requests_comparison(contract, query)
    {
        return 1;
    }
    contract
        .map(|contract| contract.entity_cardinality_min.max(1) as usize)
        .unwrap_or_else(|| required_source_cluster_count(query).max(1))
}

pub(crate) fn retrieval_contract_required_support_count(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    if matches!(
        synthesis_layout_profile(contract, query),
        SynthesisLayoutProfile::DocumentReport
    ) {
        let identifier_group_floor = evidence_standard_identifier_group_floor(query) as u32;
        return contract
            .map(|contract| {
                contract
                    .source_independence_min
                    .max(contract.citation_count_min.max(1))
                    .max(identifier_group_floor) as usize
            })
            .unwrap_or_else(|| retrieval_contract_required_source_cluster_count(contract, query))
            .max(1);
    }
    retrieval_contract_required_source_cluster_count(contract, query).max(1)
}

pub(crate) fn retrieval_contract_required_document_report_citation_count(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    if matches!(
        synthesis_layout_profile(contract, query),
        SynthesisLayoutProfile::DocumentReport
    ) {
        return retrieval_contract_required_support_count(contract, query).max(1);
    }
    retrieval_contract_required_citations_per_source_cluster(contract, query).max(1)
}

pub(crate) fn retrieval_contract_requires_document_report_identifier_evidence(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    matches!(
        synthesis_layout_profile(contract, query),
        SynthesisLayoutProfile::DocumentReport
    ) && !retrieval_contract_requests_comparison(contract, query)
        && analyze_query_facets(query).grounded_external_required
        && evidence_standard_identifier_group_floor(query) > 0
}

pub(crate) fn retrieval_contract_required_citations_per_source_cluster(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    contract
        .map(|contract| contract.citation_count_min.max(1) as usize)
        .unwrap_or_else(|| required_citations_per_source_cluster(query).max(1))
}

pub(crate) fn retrieval_contract_required_distinct_domain_floor(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    contract
        .map(|contract| {
            if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(contract) {
                0
            } else if matches!(
                synthesis_layout_profile(Some(contract), query),
                SynthesisLayoutProfile::DocumentReport
            ) {
                contract.source_independence_min.max(1) as usize
            } else if contract.entity_cardinality_min > 1 {
                contract
                    .source_independence_min
                    .max(contract.entity_cardinality_min) as usize
            } else {
                0
            }
        })
        .unwrap_or_else(|| required_distinct_domain_floor(query))
}

pub(crate) fn retrieval_contract_requires_primary_authority_source(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    let Some(contract) = contract else {
        return false;
    };

    let document_report_authority = matches!(
        synthesis_layout_profile(Some(contract), query),
        SynthesisLayoutProfile::DocumentReport
    ) && !query_requests_comparison(query)
        && crate::agentic::runtime::service::decision_loop::signals::analyze_query_facets(query)
            .grounded_external_required
        && (contract.currentness_required || contract.source_independence_min > 1);

    let host_anchored_authority = query_requires_host_anchored_primary_authority(query)
        && !query_requests_comparison(query)
        && crate::agentic::runtime::service::decision_loop::signals::analyze_query_facets(query)
            .grounded_external_required
        && contract.currentness_required;

    document_report_authority || host_anchored_authority
}

pub(crate) fn retrieval_contract_primary_authority_source_slot_cap(
    contract: Option<&WebRetrievalContract>,
    query: &str,
    expected_count: usize,
) -> usize {
    let Some(contract) = contract else {
        return 0;
    };
    if expected_count == 0 {
        return 0;
    }
    if !retrieval_contract_requires_primary_authority_source(Some(contract), query) {
        return 0;
    }

    let required_domain_floor =
        retrieval_contract_required_distinct_domain_floor(Some(contract), query)
            .min(expected_count);
    let reserved_non_authority_slots = required_domain_floor
        .saturating_sub(1)
        .min(expected_count.saturating_sub(1));
    expected_count
        .saturating_sub(reserved_non_authority_slots)
        .max(1)
}

pub(crate) fn retrieval_contract_required_distinct_citations(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    if matches!(
        synthesis_layout_profile(contract, query),
        SynthesisLayoutProfile::DocumentReport
    ) {
        return retrieval_contract_required_document_report_citation_count(contract, query).max(
            retrieval_contract_required_citations_per_source_cluster(contract, query),
        );
    }
    retrieval_contract_required_support_count(contract, query).saturating_mul(
        retrieval_contract_required_citations_per_source_cluster(contract, query),
    )
}

pub(crate) fn retrieval_contract_min_sources(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> u32 {
    contract
        .map(|contract| {
            let citation_floor = contract
                .citation_count_min
                .max(1)
                .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX);
            let base_floor = contract
                .source_independence_min
                .max(contract.entity_cardinality_min.max(1))
                .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX);
            if retrieval_contract_prefers_single_fact_snapshot(Some(contract), query) {
                base_floor
                    .max(citation_floor)
                    .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX)
            } else {
                base_floor
                    .max(citation_floor)
                    .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX)
            }
        })
        .unwrap_or_else(|| web_pipeline_min_sources(query).max(1))
}

pub(crate) fn synthesis_layout_profile(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> SynthesisLayoutProfile {
    if retrieval_contract_prefers_single_fact_snapshot(contract, query) {
        return SynthesisLayoutProfile::SingleSnapshot;
    }
    if query_prefers_document_report_layout(query)
        && !retrieval_contract_requests_comparison(contract, query)
    {
        return SynthesisLayoutProfile::DocumentReport;
    }
    SynthesisLayoutProfile::MultiSourceCollection
}

pub(crate) fn required_citations_per_source_cluster(query: &str) -> usize {
    let tokens = query.split_whitespace().collect::<Vec<_>>();
    let normalized_query = normalized_phrase_query(query);
    let has_for_each_directive = normalized_query.contains(" for each ");
    for idx in 0..tokens.len() {
        let Some(value) = parse_small_count_token(tokens[idx]) else {
            continue;
        };
        let next = tokens
            .get(idx + 1)
            .map(|value| {
                value
                    .trim()
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let third = tokens
            .get(idx + 2)
            .map(|value| {
                value
                    .trim()
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let fourth = tokens
            .get(idx + 3)
            .map(|value| {
                value
                    .trim()
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();

        let looks_like_citation_directive = matches!(
            next.as_str(),
            "citation" | "citations" | "source" | "sources"
        ) || ((next == "source" || next == "sources")
            && matches!(third.as_str(), "citation" | "citations"));
        let explicit_each_directive = next == "each" || third == "each" || fourth == "each";
        let explicit_per_source_cluster_directive =
            third == "per" && matches!(fourth.as_str(), "story" | "stories" | "item" | "items");
        if looks_like_citation_directive
            && (explicit_each_directive
                || explicit_per_source_cluster_directive
                || has_for_each_directive)
        {
            return value.clamp(1, 6);
        }
    }

    if prefers_single_fact_snapshot(query) {
        return 1;
    }

    if query_is_generic_headline_collection(query) {
        return 1;
    }

    if query_prefers_multi_item_cardinality(query) {
        // Ordered collections cite the primary source for each item by default.
        // Explicit "N citations/sources each" directives are handled above.
        return 1;
    }

    WEB_PIPELINE_CITATIONS_PER_STORY
}

pub(crate) fn required_distinct_citations(query: &str) -> usize {
    required_source_cluster_count(query)
        .saturating_mul(required_citations_per_source_cluster(query))
}

pub(crate) fn web_pipeline_min_sources(query: &str) -> u32 {
    if query_prefers_multi_item_cardinality(query) {
        let target = required_source_cluster_count(query).max(1) as u32;
        return target.min(WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX).max(1);
    }
    if prefers_single_fact_snapshot(query) {
        return 2;
    }
    let lower = query.to_ascii_lowercase();
    let explicit_citation_floor =
        lower.contains("citation") || lower.contains("citations") || lower.contains("sources");
    if explicit_citation_floor {
        let target = required_distinct_citations(query) as u32;
        return target.clamp(
            WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MIN,
            WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX,
        );
    }
    WEB_PIPELINE_DEFAULT_MIN_SOURCES
}

#[cfg(test)]
#[path = "response/tests.rs"]
mod tests;

pub(crate) fn requires_mailbox_access_notice(query: &str) -> bool {
    is_mailbox_connector_intent(query)
}

#[cfg(test)]
pub(crate) fn render_mailbox_access_limited_reply(query: &str, run_timestamp_ms: u64) -> String {
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);
    let mut lines = Vec::new();
    lines.push(format!(
        "Mailbox retrieval request (as of {} UTC)",
        run_timestamp_iso_utc
    ));
    lines.push(
        "Access limitation: I cannot access your mailbox directly from public web evidence."
            .to_string(),
    );
    lines.push(
        "Next step: You can connect mailbox access or provide the latest email headers/body, and I will read it."
            .to_string(),
    );
    lines.push("Citations:".to_string());

    let citations_per_source_cluster = required_citations_per_source_cluster(query).max(1);
    for _ in 0..citations_per_source_cluster {
        lines.push(format!(
            "- Mailbox connector policy | imap://mailbox/access-policy | {} | Direct mailbox connector access is required for personal inbox reads.",
            run_timestamp_iso_utc
        ));
    }
    lines.push("Mailbox content cannot be verified without direct mailbox access.".to_string());
    lines.join("\n")
}
