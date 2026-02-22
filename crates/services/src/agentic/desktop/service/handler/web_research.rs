use crate::agentic::desktop::service::step::action::{
    is_search_results_url, search_query_from_url,
};
use crate::agentic::desktop::service::step::helpers::{
    is_live_external_research_goal, is_mailbox_connector_goal,
};
use crate::agentic::desktop::service::step::queue::WEB_PIPELINE_SEARCH_LIMIT;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, ResolvedIntentState};

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
    let is_live_external_research = is_live_external_research_goal(fallback_query);
    let is_effective_web_research = is_web_research_scope || is_live_external_research;
    if !is_effective_web_research {
        return;
    }

    match tool {
        AgentTool::BrowserNavigate { url } => {
            if !is_search_results_url(url) {
                return;
            }

            let query = search_query_from_url(url)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| fallback_query.trim().to_string());
            if query.trim().is_empty() {
                return;
            }

            *tool = AgentTool::WebSearch {
                query: query.clone(),
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(&query)),
            };
        }
        AgentTool::WebSearch { query, limit, url } => {
            let normalized_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
            if normalized_query.is_empty() {
                return;
            }
            *query = normalized_query.clone();
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

            // WebResearch is expected to gather fresh external evidence; avoid
            // memory-only retrieval loops by pivoting memory search to web search.
            *tool = AgentTool::WebSearch {
                query: normalized_query.clone(),
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(
                    &normalized_query,
                )),
            };
        }
        _ => {}
    }
}
