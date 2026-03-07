use crate::agentic::desktop::service::step::action::{
    is_search_results_url, search_query_from_url,
};
use crate::agentic::desktop::service::step::helpers::is_mailbox_connector_goal;
use crate::agentic::desktop::service::step::queue::web_pipeline::{
    select_web_pipeline_query_contract, WEB_PIPELINE_SEARCH_LIMIT,
};
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, ResolvedIntentState};
use url::Url;

fn normalized_web_query_contract(fallback_query: &str, retrieval_query: &str) -> Option<String> {
    let contract = select_web_pipeline_query_contract(fallback_query, retrieval_query);
    let trimmed = contract.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn is_http_web_url(url: &str) -> bool {
    Url::parse(url.trim())
        .ok()
        .map(|parsed| matches!(parsed.scheme(), "http" | "https"))
        .unwrap_or(false)
}

pub(super) fn normalize_web_research_tool_call(
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
    if !is_web_research_scope {
        return;
    }

    match tool {
        AgentTool::BrowserNavigate { url } => {
            if is_search_results_url(url) {
                let query = search_query_from_url(url)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| fallback_query.trim().to_string());
                if query.trim().is_empty() {
                    return;
                }
                let query_contract = normalized_web_query_contract(fallback_query, &query);

                *tool = AgentTool::WebSearch {
                    query: query.clone(),
                    query_contract,
                    retrieval_contract: None,
                    limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                    url: Some(crate::agentic::web::build_default_search_url(&query)),
                };
                return;
            }
            if !is_http_web_url(url) {
                return;
            }
            *tool = AgentTool::WebRead {
                url: url.trim().to_string(),
                max_chars: None,
            };
        }
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            let normalized_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
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
            let normalized_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
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
            let normalized_query = fallback_query.trim();
            if normalized_query.is_empty() {
                return;
            }
            let query_contract = normalized_web_query_contract(fallback_query, normalized_query);
            *tool = AgentTool::WebSearch {
                query: normalized_query.to_string(),
                query_contract,
                retrieval_contract: None,
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(
                    normalized_query,
                )),
            };
        }
        _ => {}
    }
}
