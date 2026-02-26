use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_web_research_followups(
    agent_state: &mut AgentState,
    success: bool,
    current_tool_name: &str,
    session_id: [u8; 32],
    step_index: u32,
    tool_args: &serde_json::Value,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    if success
        && current_tool_name == "browser__navigate"
        && agent_state.pending_search_completion.is_none()
        && should_use_web_research_path(agent_state)
    {
        if let Some(url) = extract_navigation_url(tool_args) {
            if is_search_results_url(&url) {
                let query = search_query_from_url(&url)
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| agent_state.goal.clone());
                let extract_params = serde_jcs::to_vec(&json!({}))
                    .or_else(|_| serde_json::to_vec(&json!({})))
                    .unwrap_or_else(|_| b"{}".to_vec());
                agent_state.execution_queue.push(ActionRequest {
                    target: ActionTarget::BrowserInspect,
                    params: extract_params,
                    context: ActionContext {
                        agent_id: "desktop_agent".to_string(),
                        session_id: Some(session_id),
                        window_id: None,
                    },
                    nonce: agent_state.step_count as u64 + 1,
                });
                let query_contract = {
                    let trimmed_goal = agent_state.goal.trim();
                    if trimmed_goal.is_empty() {
                        query.clone()
                    } else {
                        trimmed_goal.to_string()
                    }
                };
                let min_sources = web_pipeline_min_sources(&query_contract);
                agent_state.pending_search_completion = Some(PendingSearchCompletion {
                    query,
                    query_contract,
                    url: url.clone(),
                    started_step: step_index,
                    started_at_ms: web_pipeline_now_ms(),
                    deadline_ms: 0,
                    candidate_urls: Vec::new(),
                    candidate_source_hints: Vec::new(),
                    attempted_urls: vec![url],
                    blocked_urls: Vec::new(),
                    successful_reads: Vec::new(),
                    min_sources,
                });
                log::info!(
                    "Search intent detected after browser__navigate. Queued browser__snapshot for deterministic completion."
                );
            }
        }
    }

    if success
        && current_tool_name == "browser__snapshot"
        && agent_state.pending_search_completion.is_none()
        && history_entry
            .as_deref()
            .map(is_transient_browser_snapshot_unexpected_state)
            .unwrap_or(false)
    {
        let bootstrap_query = agent_state.goal.clone();
        let queued = queue_web_search_bootstrap(agent_state, session_id, &bootstrap_query)?;
        verification_checks.push(format!(
            "web_search_bootstrap_from_browser_snapshot={}",
            queued
        ));
        if queued {
            let note =
                "Browser snapshot recovery was transient; queued deterministic web__search to continue."
                    .to_string();
            *history_entry = Some(note.clone());
            *action_output = Some(note);
        }
    }

    Ok(())
}
