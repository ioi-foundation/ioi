use crate::agentic::runtime::service::lifecycle::await_child_worker_result;
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::AgentState;
use ioi_api::state::StateAccess;

pub(super) async fn await_child_session_status(
    service: &RuntimeAgentService,
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
