use crate::agentic::runtime::service::step::action::{
    is_search_results_url, search_query_from_url,
};
use crate::agentic::runtime::service::step::helpers::{
    is_live_external_research_goal, is_mailbox_connector_goal,
};
use crate::agentic::runtime::service::step::queue::web_pipeline::{
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint,
    explicit_query_scope_hint, local_business_discovery_query_contract,
    local_business_entity_discovery_query_contract, next_pending_web_candidate,
    query_native_anchor_tokens, query_prefers_document_briefing_layout, query_requests_comparison,
    query_requires_local_business_menu_surface, resolved_query_contract_with_locality_hint,
    select_web_pipeline_query_contract,
    semantic_retrieval_query_contract_with_contract_and_locality_hint, url_structurally_equivalent,
    web_pipeline_min_sources, WEB_PIPELINE_SEARCH_LIMIT,
};
use crate::agentic::runtime::types::PendingSearchCompletion;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, ResolvedIntentState};
use std::collections::BTreeSet;
use url::Url;

fn normalized_web_query_contract(fallback_query: &str, retrieval_query: &str) -> Option<String> {
    let contract = select_web_pipeline_query_contract(fallback_query, retrieval_query);
    let trimmed = contract.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn normalized_web_search_query(fallback_query: &str, retrieval_query: &str) -> Option<String> {
    let retrieval_scope = explicit_query_scope_hint(retrieval_query);
    let mut contract = normalized_web_query_contract(fallback_query, retrieval_query)?;
    if explicit_query_scope_hint(&contract).is_none() {
        let resolved_with_retrieval_scope =
            resolved_query_contract_with_locality_hint(&contract, retrieval_scope.as_deref());
        if !resolved_with_retrieval_scope.trim().is_empty() {
            contract = resolved_with_retrieval_scope;
        }
    }
    let min_sources = web_pipeline_min_sources(&contract).max(1);
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&contract, Some(&contract)).ok();
    if should_preserve_explicit_web_query(
        fallback_query,
        retrieval_query,
        retrieval_scope.as_deref(),
        retrieval_contract.as_ref(),
    ) {
        return Some(retrieval_query.trim().to_string());
    }
    if let Some(cleaned_local_business_query) = normalized_local_business_explicit_query(
        fallback_query,
        &contract,
        retrieval_query,
        retrieval_scope.as_deref(),
        retrieval_contract.as_ref(),
    ) {
        return Some(cleaned_local_business_query);
    }
    let grounded = retrieval_contract
        .as_ref()
        .filter(|retrieval_contract| {
            crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract)
        })
        .map(|_| {
            local_business_entity_discovery_query_contract(&contract, retrieval_scope.as_deref())
        })
        .unwrap_or_else(|| {
            constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
                &contract,
                retrieval_contract.as_ref(),
                min_sources,
                &[],
                retrieval_scope.as_deref(),
            )
        });
    let trimmed = grounded.trim();
    if !trimmed.is_empty() {
        return Some(trimmed.to_string());
    }
    let fallback_trimmed = contract.trim();
    (!fallback_trimmed.is_empty()).then(|| fallback_trimmed.to_string())
}

fn quoted_query_phrases(query: &str) -> Vec<String> {
    let mut phrases = Vec::new();
    let mut current = String::new();
    let mut inside_quotes = false;

    for ch in query.chars() {
        if ch == '"' {
            if inside_quotes {
                let phrase = current.trim();
                if !phrase.is_empty() {
                    phrases.push(phrase.to_string());
                }
                current.clear();
            }
            inside_quotes = !inside_quotes;
            continue;
        }
        if inside_quotes {
            current.push(ch);
        }
    }

    phrases
}

fn normalized_phrase_key(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|token| !token.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn unquoted_query_text(query: &str) -> String {
    let mut outside_quotes = String::new();
    let mut inside_quotes = false;

    for ch in query.chars() {
        if ch == '"' {
            inside_quotes = !inside_quotes;
            outside_quotes.push(' ');
            continue;
        }
        if !inside_quotes {
            outside_quotes.push(ch);
        }
    }

    outside_quotes
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn query_has_redundant_quoted_phrases(query: &str) -> bool {
    let outside_quotes = normalized_phrase_key(&unquoted_query_text(query));
    if outside_quotes.is_empty() {
        return false;
    }

    quoted_query_phrases(query).into_iter().any(|phrase| {
        let normalized = normalized_phrase_key(&phrase);
        !normalized.is_empty() && outside_quotes.contains(&normalized)
    })
}

fn retrieval_query_matches_fallback_query(fallback_query: &str, retrieval_query: &str) -> bool {
    let fallback_key = normalized_phrase_key(fallback_query);
    let retrieval_key = normalized_phrase_key(retrieval_query);
    !fallback_key.is_empty() && fallback_key == retrieval_key
}

fn preserve_explicit_local_business_target_query(
    fallback_query: &str,
    retrieval_query: &str,
    retrieval_scope: Option<&str>,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
) -> bool {
    let Some(retrieval_contract) = retrieval_contract else {
        return false;
    };
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return false;
    }

    let fallback_phrases = quoted_query_phrases(fallback_query)
        .into_iter()
        .map(|phrase| normalized_phrase_key(&phrase))
        .collect::<BTreeSet<_>>();
    let scope_key = retrieval_scope.map(normalized_phrase_key);
    let unquoted_query_key = normalized_phrase_key(&unquoted_query_text(retrieval_query));

    quoted_query_phrases(retrieval_query)
        .into_iter()
        .any(|phrase| {
            let normalized = normalized_phrase_key(&phrase);
            !normalized.is_empty()
                && !fallback_phrases.contains(&normalized)
                && !unquoted_query_key.contains(&normalized)
                && scope_key
                    .as_ref()
                    .map(|scope| normalized != *scope)
                    .unwrap_or(true)
        })
}

fn should_preserve_explicit_web_query(
    fallback_query: &str,
    retrieval_query: &str,
    retrieval_scope: Option<&str>,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
) -> bool {
    let trimmed = retrieval_query.trim();
    if trimmed.is_empty() || retrieval_query_matches_fallback_query(fallback_query, trimmed) {
        return false;
    }

    if preserve_explicit_local_business_target_query(
        fallback_query,
        trimmed,
        retrieval_scope,
        retrieval_contract,
    ) {
        return true;
    }

    !query_has_redundant_quoted_phrases(trimmed)
}

fn normalized_local_business_explicit_query(
    fallback_query: &str,
    query_contract: &str,
    retrieval_query: &str,
    retrieval_scope: Option<&str>,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
) -> Option<String> {
    if !query_has_redundant_quoted_phrases(retrieval_query) {
        return None;
    }

    let discovery_contract = local_business_discovery_query_contract(
        if fallback_query.trim().is_empty() {
            query_contract
        } else {
            fallback_query
        },
        retrieval_scope,
    );
    let cleaned = semantic_retrieval_query_contract_with_contract_and_locality_hint(
        &discovery_contract,
        retrieval_contract,
        retrieval_scope,
    );
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn is_http_web_url(url: &str) -> bool {
    Url::parse(url.trim())
        .ok()
        .map(|parsed| matches!(parsed.scheme(), "http" | "https"))
        .unwrap_or(false)
}

fn resolved_intent_uses_receipt_bound_verifier_lane(
    resolved_intent: Option<&ResolvedIntentState>,
) -> bool {
    resolved_intent
        .and_then(|resolved| resolved.instruction_contract.as_ref())
        .map(|contract| {
            contract.slot_bindings.iter().any(|binding| {
                let slot = binding.slot.trim();
                let value = binding.value.as_deref().map(str::trim).unwrap_or_default();
                (!value.is_empty())
                    && ((slot.eq_ignore_ascii_case("template_id")
                        && value.eq_ignore_ascii_case("verifier"))
                        || (slot.eq_ignore_ascii_case("workflow_id")
                            && matches!(
                                value,
                                "citation_audit"
                                    | "postcondition_audit"
                                    | "artifact_validation_audit"
                                    | "targeted_test_audit"
                                    | "browser_postcondition_audit"
                            )))
            })
        })
        .unwrap_or(false)
}

fn pending_url_already_exhausted(pending: &PendingSearchCompletion, url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return false;
    }
    pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .any(|existing| {
            let existing_trimmed = existing.trim();
            !existing_trimmed.is_empty()
                && (existing_trimmed.eq_ignore_ascii_case(trimmed)
                    || url_structurally_equivalent(existing_trimmed, trimmed))
        })
}

fn pending_url_matches(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    !left.is_empty()
        && !right.is_empty()
        && (left.eq_ignore_ascii_case(right) || url_structurally_equivalent(left, right))
}

fn pending_url_already_observed_for_redirect(
    pending: &PendingSearchCompletion,
    candidate_url: &str,
) -> bool {
    pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .any(|existing| pending_url_matches(existing, candidate_url))
}

fn query_requests_synthesized_output(query: &str) -> bool {
    let padded = format!(" {} ", query.trim().to_ascii_lowercase());
    [
        " summarize ",
        " summarise ",
        " write ",
        " draft ",
        " rewrite ",
        " return ",
        " prepare ",
        " produce ",
        " generate ",
        " briefing ",
        " brief ",
        " memo ",
    ]
    .iter()
    .any(|marker| padded.contains(marker))
}

fn strict_pending_web_read_fallback_contract(pending: &PendingSearchCompletion) -> bool {
    if let Some(retrieval_contract) = pending.retrieval_contract.as_ref() {
        return !retrieval_contract.browser_fallback_allowed;
    }

    let query_contract = pending.query_contract.trim();
    !query_contract.is_empty()
        && query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && query_requests_synthesized_output(query_contract)
}

fn next_pending_redirect_candidate(
    pending: &PendingSearchCompletion,
    current_url: &str,
) -> Option<String> {
    if let Some(candidate) = next_pending_web_candidate(pending) {
        if !pending_url_matches(&candidate, current_url) {
            return Some(candidate);
        }
    }

    let mut seen = BTreeSet::new();
    for candidate in pending
        .candidate_urls
        .iter()
        .chain(pending.candidate_source_hints.iter().map(|hint| &hint.url))
    {
        let trimmed = candidate.trim();
        if trimmed.is_empty()
            || !seen.insert(trimmed.to_string())
            || pending_url_matches(trimmed, current_url)
            || pending_url_already_observed_for_redirect(pending, trimmed)
        {
            continue;
        }
        return Some(trimmed.to_string());
    }

    None
}

fn normalized_browser_research_query(fallback_query: &str) -> Option<String> {
    let query_contract = normalized_web_query_contract(fallback_query, fallback_query)?;
    let locality_hint = explicit_query_scope_hint(&query_contract);

    if query_requires_local_business_menu_surface(&query_contract, None, locality_hint.as_deref()) {
        let menu_axis_query = query_native_anchor_tokens(&query_contract)
            .into_iter()
            .filter(|token| {
                matches!(token.as_str(), "menu" | "menus")
                    || !matches!(
                        token.as_str(),
                        "bar"
                            | "bars"
                            | "cafe"
                            | "cafes"
                            | "diner"
                            | "diners"
                            | "food"
                            | "foods"
                            | "restaurant"
                            | "restaurants"
                    )
            })
            .collect::<Vec<_>>();
        let has_menu_surface = menu_axis_query
            .iter()
            .any(|token| matches!(token.as_str(), "menu" | "menus"));
        let has_subject_anchor = menu_axis_query
            .iter()
            .any(|token| !matches!(token.as_str(), "menu" | "menus"));
        if has_menu_surface && has_subject_anchor {
            return Some(menu_axis_query.join(" "));
        }
    }

    normalized_web_search_query(fallback_query, fallback_query)
}

pub(crate) fn reconcile_pending_web_research_tool_call(
    tool: &mut AgentTool,
    pending: Option<&PendingSearchCompletion>,
) -> Option<(String, String)> {
    let pending = pending?;
    if strict_pending_web_read_fallback_contract(pending) {
        return None;
    }
    let current_url = match tool {
        AgentTool::WebRead { url, .. } => url.trim().to_string(),
        _ => return None,
    };
    if !pending_url_already_exhausted(pending, &current_url) {
        return None;
    }

    let replacement_url = next_pending_redirect_candidate(pending, &current_url)?;
    if pending_url_matches(current_url.as_str(), replacement_url.as_str()) {
        return None;
    }

    if let AgentTool::WebRead { url, .. } = tool {
        *url = replacement_url.clone();
    }
    Some((current_url, replacement_url))
}

pub(crate) fn normalize_web_research_tool_call(
    tool: &mut AgentTool,
    resolved_intent: Option<&ResolvedIntentState>,
    fallback_query: &str,
) {
    let mailbox_connector_goal = is_mailbox_connector_goal(fallback_query);
    if mailbox_connector_goal {
        return;
    }
    let is_web_research_scope = resolved_intent
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false);
    if resolved_intent_uses_receipt_bound_verifier_lane(resolved_intent) {
        return;
    }
    let live_external_research_goal = is_live_external_research_goal(fallback_query);
    if !is_web_research_scope && !live_external_research_goal {
        return;
    }

    match tool {
        AgentTool::BrowserNavigate { url } => {
            if is_search_results_url(url) {
                let query = search_query_from_url(url)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| fallback_query.trim().to_string());
                let normalized_query =
                    normalized_web_search_query(fallback_query, &query).unwrap_or(query);
                if normalized_query.trim().is_empty() {
                    return;
                }
                let query_contract =
                    normalized_web_query_contract(fallback_query, normalized_query.as_str());

                *tool = AgentTool::WebSearch {
                    query: normalized_query.clone(),
                    query_contract,
                    retrieval_contract: None,
                    limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                    url: Some(crate::agentic::web::build_default_search_url(
                        &normalized_query,
                    )),
                };
                return;
            }
            if !is_http_web_url(url) {
                return;
            }
            *tool = AgentTool::WebRead {
                url: url.trim().to_string(),
                max_chars: None,
                allow_browser_fallback: None,
            };
        }
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            let preserve_grounded_query = !query.trim().is_empty()
                && query_contract
                    .as_ref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false)
                && retrieval_contract.is_some();
            if preserve_grounded_query {
                if limit.is_none() {
                    *limit = Some(WEB_PIPELINE_SEARCH_LIMIT);
                }
                if url
                    .as_ref()
                    .map(|value| value.trim().is_empty())
                    .unwrap_or(true)
                {
                    *url = Some(crate::agentic::web::build_default_search_url(query));
                }
                return;
            }

            let raw_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
            let normalized_query =
                normalized_web_search_query(fallback_query, &raw_query).unwrap_or(raw_query);
            if normalized_query.is_empty() {
                return;
            }
            *query = normalized_query.clone();
            let query_contract_value =
                normalized_web_query_contract(fallback_query, &normalized_query);
            if query_contract
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                *query_contract = query_contract_value;
            }
            *retrieval_contract = None;
            *limit = Some(WEB_PIPELINE_SEARCH_LIMIT);
            if url
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                *url = Some(crate::agentic::web::build_default_search_url(
                    &normalized_query,
                ));
            }
        }
        AgentTool::MemorySearch { query } => {
            let raw_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
            let normalized_query =
                normalized_web_search_query(fallback_query, &raw_query).unwrap_or(raw_query);
            if normalized_query.is_empty() {
                return;
            }
            let query_contract = normalized_web_query_contract(fallback_query, &normalized_query);

            // WebResearch is expected to gather fresh external evidence; avoid
            // memory-only retrieval loops by pivoting memory search to web search.
            *tool = AgentTool::WebSearch {
                query: normalized_query.clone(),
                query_contract,
                retrieval_contract: None,
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(
                    &normalized_query,
                )),
            };
        }
        AgentTool::BrowserSnapshot { .. }
        | AgentTool::BrowserClick { .. }
        | AgentTool::BrowserHover { .. }
        | AgentTool::BrowserMoveMouse { .. }
        | AgentTool::BrowserMouseDown { .. }
        | AgentTool::BrowserMouseUp { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::BrowserSelectText { .. }
        | AgentTool::BrowserKey { .. }
        | AgentTool::BrowserCopySelection {}
        | AgentTool::BrowserPasteClipboard { .. }
        | AgentTool::BrowserFindText { .. }
        | AgentTool::BrowserCanvasSummary { .. }
        | AgentTool::BrowserScreenshot { .. }
        | AgentTool::BrowserWait { .. }
        | AgentTool::BrowserUploadFile { .. }
        | AgentTool::BrowserDropdownOptions { .. }
        | AgentTool::BrowserSelectDropdown { .. }
        | AgentTool::BrowserGoBack { .. }
        | AgentTool::BrowserTabList {}
        | AgentTool::BrowserTabSwitch { .. }
        | AgentTool::BrowserTabClose { .. } => {
            let normalized_query = normalized_browser_research_query(fallback_query)
                .unwrap_or_else(|| fallback_query.trim().to_string());
            if normalized_query.is_empty() {
                return;
            }
            let query_contract =
                normalized_web_query_contract(fallback_query, normalized_query.as_str());
            *tool = AgentTool::WebSearch {
                query: normalized_query.to_string(),
                query_contract,
                retrieval_contract: None,
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(
                    &normalized_query,
                )),
            };
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::{
        ArgumentOrigin, CapabilityId, InstructionBindingKind, InstructionContract,
        InstructionSideEffectMode, InstructionSlotBinding, IntentConfidenceBand, ProtectedSlotKind,
    };

    fn resolved_intent_with_contract(
        scope: IntentScopeProfile,
        operation: &str,
        slot_bindings: Vec<InstructionSlotBinding>,
    ) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "delegation.task".to_string(),
            scope,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("memory.access")],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "test".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: Some(InstructionContract {
                operation: operation.to_string(),
                side_effect_mode: InstructionSideEffectMode::ReadOnly,
                slot_bindings,
                negative_constraints: vec![],
                success_criteria: vec![],
            }),
            constrained: false,
        }
    }

    fn literal_slot(slot: &str, value: &str) -> InstructionSlotBinding {
        InstructionSlotBinding {
            slot: slot.to_string(),
            binding_kind: InstructionBindingKind::UserLiteral,
            value: Some(value.to_string()),
            origin: ArgumentOrigin::ModelInferred,
            protected_slot_kind: ProtectedSlotKind::Unknown,
        }
    }

    #[test]
    fn normalized_web_search_query_preserves_entity_bound_local_business_expansion_queries() {
        let goal =
            "Find the three best-reviewed Italian restaurants near me and compare their menus.";
        let retrieval_query = "\"Brothers Italian Cuisine\" italian \"Anderson, SC\"";

        let normalized =
            normalized_web_search_query(goal, retrieval_query).expect("normalized query");
        let lower = normalized.to_ascii_lowercase();

        assert!(
            lower.contains("\"brothers italian cuisine\""),
            "expected entity-bound query to survive normalization: {}",
            normalized
        );
        assert!(
            lower.contains("\"anderson, sc\""),
            "expected locality scope to survive normalization: {}",
            normalized
        );
        assert!(
            !lower.eq("italian in anderson, sc"),
            "entity-bound expansion query collapsed to generic discovery query: {}",
            normalized
        );
    }

    #[test]
    fn normalized_web_search_query_keeps_generic_local_business_discovery_queries_generic() {
        let goal =
            "Find the three best-reviewed Italian restaurants near me and compare their menus.";
        let retrieval_query = "italian restaurants in Anderson, SC";

        let normalized =
            normalized_web_search_query(goal, retrieval_query).expect("normalized query");

        assert_eq!(normalized, "italian restaurants in Anderson, SC");
    }

    #[test]
    fn normalize_web_research_tool_call_preserves_memory_search_for_citation_audit_verifier() {
        let resolved = resolved_intent_with_contract(
            IntentScopeProfile::Conversation,
            "verify",
            vec![
                literal_slot("template_id", "verifier"),
                literal_slot("workflow_id", "citation_audit"),
            ],
        );
        let mut tool = AgentTool::MemorySearch {
            query: "the latest NIST post-quantum cryptography standards".to_string(),
        };

        normalize_web_research_tool_call(
            &mut tool,
            Some(&resolved),
            "Verify whether the cited brief for the latest NIST post-quantum cryptography standards is current, grounded, and supported by independent sources, then return a citation verifier scorecard with blockers and next checks.",
        );

        assert!(matches!(tool, AgentTool::MemorySearch { .. }));
    }

    #[test]
    fn normalize_web_research_tool_call_still_promotes_live_research_memory_search() {
        let resolved =
            resolved_intent_with_contract(IntentScopeProfile::WebResearch, "web.research", vec![]);
        let mut tool = AgentTool::MemorySearch {
            query: "the latest NIST post-quantum cryptography standards".to_string(),
        };

        normalize_web_research_tool_call(
            &mut tool,
            Some(&resolved),
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        );

        let AgentTool::WebSearch { query, .. } = tool else {
            panic!("expected live research memory search to become web search");
        };
        assert!(query.to_ascii_lowercase().contains("nist"), "query={query}");
    }
}
