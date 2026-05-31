use super::*;

pub(in super::super) fn maybe_handle_browser_snapshot(
    _agent_state: &mut AgentState,
    session_id: [u8; 32],
    tool_name: &str,
    is_gated: bool,
    _success: &mut bool,
    _out: &mut Option<String>,
    _err: &mut Option<String>,
    _completion_summary: &mut Option<String>,
) {
    if is_gated || tool_name != "browser__inspect" {
        return;
    }
    log::info!(
        "Browser snapshot captured for web pipeline session {}; final answer remains model-authored.",
        hex::encode(&session_id[..4])
    );
}
