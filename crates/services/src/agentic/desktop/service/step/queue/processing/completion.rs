use crate::agentic::desktop::service::step::action::{
    is_command_probe_intent, summarize_command_probe_output,
};
use crate::agentic::desktop::service::step::helpers::should_auto_complete_open_app_goal;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use ioi_types::app::agentic::AgentTool;

pub(super) fn complete_with_summary(
    agent_state: &mut AgentState,
    summary: String,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    clear_pending_search: bool,
) {
    *success = true;
    *out = Some(summary.clone());
    *err = None;
    *completion_summary = Some(summary.clone());
    agent_state.status = AgentStatus::Completed(Some(summary));
    if clear_pending_search {
        agent_state.pending_search_completion = None;
    }
    agent_state.execution_queue.clear();
    agent_state.recent_actions.clear();
}

pub(super) fn maybe_complete_command_probe(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    session_id: [u8; 32],
) {
    if is_gated
        || completion_summary.is_some()
        || !matches!(
            tool_wrapper,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
        || !is_command_probe_intent(agent_state.resolved_intent.as_ref())
    {
        return;
    }
    let Some(raw) = out.as_deref() else {
        return;
    };
    if let Some(summary) = summarize_command_probe_output(tool_wrapper, raw) {
        // Probe markers are deterministic completion signals even when the
        // underlying command exits non-zero (e.g. NOT_FOUND_IN_PATH).
        complete_with_summary(
            agent_state,
            summary,
            success,
            out,
            err,
            completion_summary,
            false,
        );
        log::info!(
            "Auto-completed command probe after shell-command tool for session {}.",
            hex::encode(&session_id[..4])
        );
    }
}

pub(super) fn maybe_complete_open_app(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }
    let AgentTool::OsLaunchApp { app_name } = tool_wrapper else {
        return;
    };
    if should_auto_complete_open_app_goal(
        &agent_state.goal,
        app_name,
        agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.as_deref()),
    ) {
        complete_with_summary(
            agent_state,
            format!("Opened {}.", app_name),
            success,
            out,
            err,
            completion_summary,
            false,
        );
        log::info!(
            "Auto-completed app-launch queue flow for session {}.",
            hex::encode(&session_id[..4])
        );
    }
}
