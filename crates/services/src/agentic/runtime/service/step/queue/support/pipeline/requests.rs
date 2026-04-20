use super::*;

fn queue_web_retrieve_request(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    params: Vec<u8>,
) -> bool {
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
        return false;
    }

    agent_state.execution_queue.insert(0, request);
    true
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

    Ok(queue_web_retrieve_request(agent_state, session_id, params))
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

    Ok(queue_web_retrieve_request(agent_state, session_id, params))
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
#[path = "requests/tests.rs"]
mod tests;
