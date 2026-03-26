use crate::agentic::desktop::utils::await_child_session_status_for_inspection;
use ioi_api::state::StateAccess;
use ioi_memory::MemoryRuntime;
use std::sync::Arc;

pub(super) fn await_child_session_status(
    state: &dyn StateAccess,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    child_session_id_hex: &str,
) -> Result<String, String> {
    await_child_session_status_for_inspection(state, memory_runtime, child_session_id_hex)
}
