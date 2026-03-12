use crate::agentic::desktop::service::step::action::{
    is_search_results_url, search_query_from_url,
};
use crate::agentic::desktop::service::step::helpers::{
    is_live_external_research_goal, is_mailbox_connector_goal,
};
use crate::agentic::desktop::service::step::queue::web_pipeline::{
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint,
    explicit_query_scope_hint, local_business_entity_discovery_query_contract,
    next_pending_web_candidate, query_prefers_document_briefing_layout, query_requests_comparison,
    resolved_query_contract_with_locality_hint, select_web_pipeline_query_contract,
    url_structurally_equivalent, web_pipeline_min_sources, WEB_PIPELINE_SEARCH_LIMIT,
};
use crate::agentic::desktop::types::PendingSearchCompletion;
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
    if preserve_explicit_local_business_target_query(
        fallback_query,
        retrieval_query,
        retrieval_scope.as_deref(),
        retrieval_contract.as_ref(),
    ) {
        return Some(retrieval_query.trim().to_string());
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

    quoted_query_phrases(retrieval_query)
        .into_iter()
        .any(|phrase| {
            let normalized = normalized_phrase_key(&phrase);
            !normalized.is_empty()
                && !fallback_phrases.contains(&normalized)
                && scope_key
                    .as_ref()
                    .map(|scope| normalized != *scope)
                    .unwrap_or(true)
        })
}

fn is_http_web_url(url: &str) -> bool {
    Url::parse(url.trim())
        .ok()
        .map(|parsed| matches!(parsed.scheme(), "http" | "https"))
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

pub(crate) fn reconcile_pending_web_research_tool_call(
    tool: &mut AgentTool,
    pending: Option<&PendingSearchCompletion>,
) -> Option<(String, String)> {
    let pending = pending?;
    let strict_no_fallback_contract = pending
        .retrieval_contract
        .as_ref()
        .map(|contract| !contract.browser_fallback_allowed)
        .unwrap_or_else(|| {
            query_prefers_document_briefing_layout(&pending.query_contract)
                && !query_requests_comparison(&pending.query_contract)
        });
    if strict_no_fallback_contract {
        return None;
    }
    let current_url = match tool {
        AgentTool::WebRead { url, .. } => url.trim().to_string(),
        _ => return None,
    };
    if !pending_url_already_exhausted(pending, &current_url) {
        return None;
    }

    let replacement_url = next_pending_web_candidate(pending)?;
    if current_url.eq_ignore_ascii_case(replacement_url.as_str())
        || url_structurally_equivalent(current_url.as_str(), replacement_url.as_str())
    {
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
        | AgentTool::BrowserClickElement { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::BrowserKey { .. }
        | AgentTool::BrowserFindText { .. }
        | AgentTool::BrowserScreenshot { .. }
        | AgentTool::BrowserWait { .. }
        | AgentTool::BrowserUploadFile { .. }
        | AgentTool::BrowserDropdownOptions { .. }
        | AgentTool::BrowserSelectDropdown { .. }
        | AgentTool::BrowserGoBack { .. }
        | AgentTool::BrowserTabList {}
        | AgentTool::BrowserTabSwitch { .. }
        | AgentTool::BrowserTabClose { .. } => {
            let normalized_query = normalized_web_search_query(fallback_query, fallback_query)
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
}
