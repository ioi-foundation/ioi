use super::super::search::is_search_scope;
use super::{
    ActionContext, ActionRequest, ActionTarget, AgentState, FailureClass, TransactionError,
};
use crate::agentic::runtime::service::decision_loop::helpers::is_mailbox_connector_goal;
use ioi_types::app::agentic::{IntentScopeProfile, ResolvedIntentState};
use serde_json::json;

const WEB_RESEARCH_BOOTSTRAP_SEARCH_LIMIT: u32 = 15;

fn is_web_retrieval_timeout_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "web__search"
            | "web__read"
            | "media__extract_transcript"
            | "media__extract_evidence"
            | "browser__navigate"
    )
}

pub(super) fn should_fail_fast_web_timeout(
    resolved_intent: Option<&ResolvedIntentState>,
    tool_name: &str,
    class: FailureClass,
    has_active_web_pipeline: bool,
) -> bool {
    if !matches!(class, FailureClass::TimeoutOrHang) {
        return false;
    }
    if !is_web_retrieval_timeout_tool(tool_name) {
        return false;
    }
    if has_active_web_pipeline && tool_name == "web__read" {
        return false;
    }

    let in_web_research_scope = resolved_intent
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false);
    in_web_research_scope
}

pub(super) fn extract_web_read_url_from_payload(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("arguments")
        .and_then(|args| args.get("url"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn is_effective_web_research_scope(agent_state: &AgentState) -> bool {
    is_search_scope(agent_state.resolved_intent.as_ref())
}

pub(super) fn should_use_web_research_path(agent_state: &AgentState) -> bool {
    is_effective_web_research_scope(agent_state) && !is_mailbox_connector_goal(&agent_state.goal)
}

pub(super) fn is_empty_memory_search_output(output: &str) -> bool {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return true;
    }
    trimmed
        .to_ascii_lowercase()
        .contains("no matching memories found")
}

pub(super) fn is_transient_browser_snapshot_unexpected_state(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("browser__inspect")
        && lower.contains("transient unexpected state")
        && lower.contains("continuing web research")
}

fn normalize_web_search_query(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let lower = trimmed.to_ascii_lowercase();
    let mut cut_at = trimmed.len();
    for marker in [
        " provide ",
        " with citations",
        " cite ",
        " include ",
        " summarize ",
        " in a chat reply",
    ] {
        if let Some(idx) = lower.find(marker) {
            cut_at = cut_at.min(idx);
        }
    }

    let base = trimmed[..cut_at]
        .trim()
        .trim_matches(|ch: char| matches!(ch, '?' | '!' | '.' | ':' | ';'))
        .trim();
    if base.is_empty() {
        trimmed.to_string()
    } else {
        base.to_string()
    }
}

pub(super) fn queue_web_search_bootstrap(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    query: &str,
) -> Result<bool, TransactionError> {
    let normalized_query = normalize_web_search_query(query);
    if normalized_query.trim().is_empty() {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({
        "query": normalized_query,
        "limit": WEB_RESEARCH_BOOTSTRAP_SEARCH_LIMIT
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
