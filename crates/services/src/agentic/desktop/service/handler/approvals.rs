use crate::agentic::desktop::runtime_secret;
use crate::agentic::desktop::types::AgentState;
use ioi_types::app::agentic::AgentTool;

const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

pub(super) fn is_runtime_secret_install_retry_approved(
    tool: &AgentTool,
    tool_hash: [u8; 32],
    session_id: [u8; 32],
    agent_state: &AgentState,
) -> bool {
    if !matches!(tool, AgentTool::SysInstallPackage { .. }) {
        return false;
    }
    if agent_state.pending_tool_hash != Some(tool_hash) {
        return false;
    }

    let session_id_hex = hex::encode(session_id);
    runtime_secret::has_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD)
}
