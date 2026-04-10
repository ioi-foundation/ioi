use super::*;

pub(in super::super) fn maybe_handle_browser_snapshot(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
) {
    if is_gated || tool_name != "browser__snapshot" {
        return;
    }
    let Some(pending) = agent_state.pending_search_completion.clone() else {
        return;
    };
    let summary = if *success {
        summarize_search_results(&pending.query, &pending.url, out.as_deref().unwrap_or(""))
    } else {
        fallback_search_summary(&pending.query, &pending.url)
    };
    complete_with_summary(
        agent_state,
        summary,
        success,
        out,
        err,
        completion_summary,
        true,
    );
    log::info!(
        "Search flow completed after browser__snapshot for session {}.",
        hex::encode(&session_id[..4])
    );
}
