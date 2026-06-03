use crate::agentic::runtime::types::AgentStatus;

const STEP_RETRY_FAILURE_CEILING: u8 = 5;
const RETRY_LIMIT_EXCEEDED_STATUS: &str = "Resources/Retry limit exceeded";

pub(super) fn retry_failure_ceiling_reached(consecutive_failures: u8) -> bool {
    consecutive_failures >= STEP_RETRY_FAILURE_CEILING
}

pub(super) fn retry_limit_exceeded_status() -> AgentStatus {
    AgentStatus::Failed(RETRY_LIMIT_EXCEEDED_STATUS.into())
}
