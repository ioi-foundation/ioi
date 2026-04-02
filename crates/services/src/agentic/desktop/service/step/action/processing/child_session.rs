use crate::agentic::desktop::service::lifecycle::await_child_worker_result;
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;

pub(super) async fn await_child_session_status(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    step_index: u32,
    block_height: u64,
    call_context: ServiceCallContext<'_>,
    child_session_id_hex: &str,
) -> Result<String, String> {
    await_child_worker_result(
        service,
        state,
        parent_state,
        step_index,
        block_height,
        call_context,
        child_session_id_hex,
    )
    .await
}
