use super::*;
use ioi_types::app::agentic::WebRetrievalContract;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SynthesisLayoutProfile {
    SingleSnapshot,
    DocumentBriefing,
    MultiStoryCollection,
}

pub(crate) fn retrieval_contract_prefers_single_fact_snapshot(
    contract: Option<&WebRetrievalContract>,
    _query: &str,
) -> bool {
    contract
        .map(|contract| {
            contract.entity_cardinality_min <= 1
                && contract.structured_record_preferred
                && !contract.comparison_required
        })
        .unwrap_or(false)
}

pub(crate) fn retrieval_contract_requires_runtime_locality(
    contract: Option<&WebRetrievalContract>,
    _query: &str,
) -> bool {
    contract
        .map(|contract| contract.runtime_locality_required)
        .unwrap_or(false)
}

pub(crate) fn retrieval_contract_prefers_multi_item_cardinality(
    contract: Option<&WebRetrievalContract>,
    _query: &str,
) -> bool {
    contract
        .map(|contract| contract.entity_cardinality_min > 1 || contract.comparison_required)
        .unwrap_or(false)
}

pub(crate) fn retrieval_contract_requests_comparison(
    contract: Option<&WebRetrievalContract>,
    _query: &str,
) -> bool {
    contract
        .map(|contract| contract.comparison_required)
        .unwrap_or(false)
}

pub(crate) fn retrieval_contract_is_generic_headline_collection(
    contract: Option<&WebRetrievalContract>,
    _query: &str,
) -> bool {
    contract
        .map(|contract| {
            contract.ordered_collection_preferred
                && contract.entity_cardinality_min > 1
                && !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(contract)
        })
        .unwrap_or(false)
}

pub(crate) fn retrieval_contract_entity_diversity_required(
    contract: Option<&WebRetrievalContract>,
    _query: &str,
) -> bool {
    contract
        .map(crate::agentic::web::contract_requires_geo_scoped_entity_expansion)
        .unwrap_or(false)
}

pub(crate) fn retrieval_contract_required_story_count(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    if query_prefers_document_briefing_layout(query)
        && !retrieval_contract_requests_comparison(contract, query)
    {
        return 1;
    }
    contract
        .map(|contract| contract.entity_cardinality_min.max(1) as usize)
        .unwrap_or(1)
}

pub(crate) fn retrieval_contract_required_support_count(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    if matches!(
        synthesis_layout_profile(contract, query),
        SynthesisLayoutProfile::DocumentBriefing
    ) {
        let identifier_group_floor = briefing_standard_identifier_group_floor(query) as u32;
        return contract
            .map(|contract| {
                contract
                    .source_independence_min
                    .max(contract.citation_count_min.max(1))
                    .max(identifier_group_floor) as usize
            })
            .unwrap_or_else(|| retrieval_contract_required_story_count(contract, query))
            .max(1);
    }
    retrieval_contract_required_story_count(contract, query).max(1)
}

pub(crate) fn retrieval_contract_required_document_briefing_citation_count(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    if matches!(
        synthesis_layout_profile(contract, query),
        SynthesisLayoutProfile::DocumentBriefing
    ) {
        return retrieval_contract_required_support_count(contract, query).max(1);
    }
    retrieval_contract_required_citations_per_story(contract, query).max(1)
}

pub(crate) fn retrieval_contract_requires_document_briefing_identifier_evidence(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> bool {
    matches!(
        synthesis_layout_profile(contract, query),
        SynthesisLayoutProfile::DocumentBriefing
    ) && !retrieval_contract_requests_comparison(contract, query)
        && analyze_query_facets(query).grounded_external_required
        && briefing_standard_identifier_group_floor(query) > 0
}

pub(crate) fn retrieval_contract_required_citations_per_story(
    contract: Option<&WebRetrievalContract>,
    _query: &str,
) -> usize {
    contract
        .map(|contract| contract.citation_count_min.max(1) as usize)
        .unwrap_or(1)
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
                SynthesisLayoutProfile::DocumentBriefing
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
        .unwrap_or(0)
}

pub(crate) fn retrieval_contract_required_distinct_citations(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> usize {
    if matches!(
        synthesis_layout_profile(contract, query),
        SynthesisLayoutProfile::DocumentBriefing
    ) {
        return retrieval_contract_required_document_briefing_citation_count(contract, query).max(
            retrieval_contract_required_citations_per_story(contract, query),
        );
    }
    retrieval_contract_required_support_count(contract, query).saturating_mul(
        retrieval_contract_required_citations_per_story(contract, query),
    )
}

pub(crate) fn retrieval_contract_min_sources(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> u32 {
    contract
        .map(|contract| {
            let base_floor = contract
                .source_independence_min
                .max(contract.entity_cardinality_min.max(1))
                .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX);
            if retrieval_contract_prefers_single_fact_snapshot(Some(contract), query) {
                base_floor
                    .max(contract.citation_count_min.max(1))
                    .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX)
            } else {
                base_floor
            }
        })
        .unwrap_or(1)
}

pub(crate) fn synthesis_layout_profile(
    contract: Option<&WebRetrievalContract>,
    query: &str,
) -> SynthesisLayoutProfile {
    if retrieval_contract_prefers_single_fact_snapshot(contract, query) {
        return SynthesisLayoutProfile::SingleSnapshot;
    }
    if query_prefers_document_briefing_layout(query)
        && !retrieval_contract_requests_comparison(contract, query)
    {
        return SynthesisLayoutProfile::DocumentBriefing;
    }
    SynthesisLayoutProfile::MultiStoryCollection
}

pub(crate) fn required_citations_per_story(query: &str) -> usize {
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
        let explicit_per_story_directive =
            third == "per" && matches!(fourth.as_str(), "story" | "stories" | "item" | "items");
        if looks_like_citation_directive
            && (explicit_each_directive || explicit_per_story_directive || has_for_each_directive)
        {
            return value.clamp(1, 6);
        }
    }

    if query_prefers_multi_item_cardinality(query) {
        // Ordered collections cite the primary source for each item by default.
        // Explicit "N citations/sources each" directives are handled above.
        return 1;
    }

    WEB_PIPELINE_CITATIONS_PER_STORY
}

pub(crate) fn required_distinct_citations(query: &str) -> usize {
    required_story_count(query).saturating_mul(required_citations_per_story(query))
}

pub(crate) fn web_pipeline_min_sources(query: &str) -> u32 {
    if query_prefers_multi_item_cardinality(query) {
        let target = required_story_count(query).max(1) as u32;
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
mod tests {
    use ioi_types::app::agentic::WebRetrievalContract;

    use super::{
        required_citations_per_story, retrieval_contract_min_sources,
        retrieval_contract_required_distinct_citations,
        retrieval_contract_required_document_briefing_citation_count,
        retrieval_contract_required_support_count,
        retrieval_contract_requires_document_briefing_identifier_evidence,
    };

    #[test]
    fn document_briefing_support_count_follows_structural_source_independence_floor() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");

        assert_eq!(contract.source_independence_min, 2);
        assert_eq!(
            retrieval_contract_required_support_count(Some(&contract), query),
            2
        );
    }

    #[test]
    fn document_briefing_distinct_citations_follow_structural_support_floor() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");

        assert_eq!(
            retrieval_contract_required_document_briefing_citation_count(Some(&contract), query),
            2
        );
        assert_eq!(
            retrieval_contract_required_distinct_citations(Some(&contract), query),
            2
        );
    }

    #[test]
    fn document_briefing_identifier_evidence_is_not_required_without_generic_identifier_model() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");

        assert!(
            !retrieval_contract_requires_document_briefing_identifier_evidence(
                Some(&contract),
                query
            )
        );
    }

    #[test]
    fn single_snapshot_min_sources_honors_citation_floor() {
        let query = "What's the current price of Bitcoin?";
        let contract = WebRetrievalContract {
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
        };

        assert_eq!(retrieval_contract_min_sources(Some(&contract), query), 2);
    }

    #[test]
    fn generic_headline_collections_default_to_one_citation_per_story() {
        let query = "Tell me today's top news headlines.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");

        assert_eq!(required_citations_per_story(query), 1);
        assert_eq!(contract.citation_count_min, 1);
        assert!(contract.ordered_collection_preferred);
    }
}

pub(crate) fn requires_mailbox_access_notice(query: &str) -> bool {
    is_mailbox_connector_intent(query)
}

pub(crate) fn render_mailbox_access_limited_draft(draft: &SynthesisDraft) -> String {
    let citations_per_story = required_citations_per_story(&draft.query).max(1);
    let mut lines = Vec::new();
    lines.push(format!(
        "Mailbox retrieval request (as of {} UTC)",
        draft.run_timestamp_iso_utc
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

    let mut emitted = 0usize;
    let mut emitted_ids = BTreeSet::new();
    for story in &draft.stories {
        for citation_id in &story.citation_ids {
            if emitted >= citations_per_story {
                break;
            }
            if !emitted_ids.insert(citation_id.clone()) {
                continue;
            }
            if let Some(citation) = draft.citations_by_id.get(citation_id) {
                lines.push(format!(
                    "- {} | {} | {} | {}",
                    citation.source_label, citation.url, citation.timestamp_utc, citation.note
                ));
                emitted += 1;
            }
        }
        if emitted >= citations_per_story {
            break;
        }
    }

    if emitted == 0 {
        for citation in draft.citations_by_id.values().take(citations_per_story) {
            lines.push(format!(
                "- {} | {} | {} | {}",
                citation.source_label, citation.url, citation.timestamp_utc, citation.note
            ));
            emitted += 1;
        }
    }

    if emitted == 0 {
        lines.push(format!(
            "- Mailbox connector policy | imap://mailbox/access-policy | {} | Direct mailbox connector access is required for personal inbox reads.",
            draft.run_timestamp_iso_utc
        ));
        emitted += 1;
    }

    while emitted < citations_per_story {
        lines.push(format!(
            "- Mailbox connector policy | imap://mailbox/access-policy | {} | Direct mailbox connector access is required for personal inbox reads.",
            draft.run_timestamp_iso_utc
        ));
        emitted += 1;
    }

    lines.push("Confidence: medium".to_string());
    lines.push(
        "Caveat: Mailbox content cannot be verified without direct mailbox access.".to_string(),
    );
    lines.push(format!("Run date (UTC): {}", draft.run_date));
    lines.push(format!(
        "Run timestamp (UTC): {}",
        draft.run_timestamp_iso_utc
    ));
    lines.push(format!("Overall confidence: {}", draft.overall_confidence));
    lines.push(format!("Overall caveat: {}", draft.overall_caveat));
    if !draft.query.is_empty() {
        lines.push(format!("Query: {}", draft.query));
    }

    lines.join("\n")
}

pub(crate) fn render_mailbox_access_limited_reply(query: &str, run_timestamp_ms: u64) -> String {
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);
    let draft = SynthesisDraft {
        query: query.to_string(),
        retrieval_contract: None,
        run_date: iso_date_from_unix_ms(run_timestamp_ms),
        run_timestamp_ms,
        run_timestamp_iso_utc: run_timestamp_iso_utc.clone(),
        completion_reason: "MailboxConnectorRequired".to_string(),
        overall_confidence: "medium".to_string(),
        overall_caveat:
            "Mailbox content requires connector-backed access and cannot be inferred from public web sources."
                .to_string(),
        stories: Vec::new(),
        citations_by_id: BTreeMap::new(),
        blocked_urls: Vec::new(),
        partial_note: None,
    };
    render_mailbox_access_limited_draft(&draft)
}
