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
mod tests {
    use super::*;
    use crate::agentic::runtime::types::ExecutionTier;
    use crate::agentic::runtime::{AgentMode, AgentStatus};
    use std::collections::{BTreeMap, VecDeque};

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: String::new(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Idle,
            step_count: 0,
            max_steps: 0,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: Vec::new(),
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: Vec::new(),
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    #[test]
    fn queue_web_read_skips_seen_urls_and_duplicate_requests() {
        let mut agent_state = test_agent_state();
        agent_state.pending_search_completion = Some(PendingSearchCompletion {
            attempted_urls: vec!["https://example.com/known".to_string()],
            ..PendingSearchCompletion::default()
        });

        assert!(!queue_web_read_from_pipeline(
            &mut agent_state,
            [1u8; 32],
            "https://example.com/known",
            false
        )
        .expect("queue result"));

        agent_state
            .pending_search_completion
            .as_mut()
            .expect("pending")
            .attempted_urls
            .clear();

        assert!(queue_web_read_from_pipeline(
            &mut agent_state,
            [1u8; 32],
            "https://example.com/new",
            true
        )
        .expect("queue result"));
        assert_eq!(agent_state.execution_queue.len(), 1);
        assert!(!queue_web_read_from_pipeline(
            &mut agent_state,
            [1u8; 32],
            "https://example.com/new",
            true
        )
        .expect("duplicate queue result"));
    }

    #[test]
    fn queue_web_search_deduplicates_identical_search_requests() {
        let mut agent_state = test_agent_state();

        assert!(queue_web_search_from_pipeline(
            &mut agent_state,
            [2u8; 32],
            "latest pqc standards",
            Some("latest pqc standards"),
            None,
            3,
        )
        .expect("queue result"));
        assert_eq!(agent_state.execution_queue.len(), 1);
        assert!(!queue_web_search_from_pipeline(
            &mut agent_state,
            [2u8; 32],
            "latest pqc standards",
            Some("latest pqc standards"),
            None,
            3,
        )
        .expect("duplicate queue result"));
    }

    #[test]
    fn human_challenge_detection_matches_common_provider_surfaces() {
        assert!(is_human_challenge_error(
            "recaptcha required before continuing"
        ));
        assert!(is_human_challenge_error(
            "error_class=HumanChallengeRequired"
        ));
        assert!(!is_human_challenge_error("connection reset by peer"));
    }
}
