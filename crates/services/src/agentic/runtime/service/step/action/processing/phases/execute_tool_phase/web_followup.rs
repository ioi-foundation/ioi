use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_web_research_followups(
    agent_state: &mut AgentState,
    success: bool,
    current_tool_name: &str,
    session_id: [u8; 32],
    _step_index: u32,
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
                let queued = queue_web_search_bootstrap(agent_state, session_id, &query)?;
                verification_checks
                    .push(format!("web_search_bootstrap_from_browser_serp={}", queued));
                if queued {
                    let note = "Search-engine browser navigation was converted into deterministic web__search bootstrap."
                        .to_string();
                    *history_entry = Some(note.clone());
                    *action_output = Some(note);
                }
                log::info!(
                    "Search intent detected after browser__navigate. Queued deterministic web__search bootstrap."
                );
            }
        }
    }

    if success
        && current_tool_name == "browser__inspect"
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
