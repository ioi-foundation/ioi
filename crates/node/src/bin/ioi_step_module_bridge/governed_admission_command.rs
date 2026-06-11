use ioi_services::agentic::runtime::kernel::governed_admission::{
    admit_governed_runtime_improvement_proposal_response as core_admit_governed_runtime_improvement_proposal,
    admit_l1_settlement_attempt_response as core_admit_l1_settlement_attempt,
    GovernedAdmissionError,
};
use serde_json::Value;

use super::BridgeError;
pub(super) use ioi_services::agentic::runtime::kernel::governed_admission::{
    GovernedRuntimeImprovementBridgeRequest, L1SettlementAdmissionBridgeRequest,
};

pub(super) fn admit_l1_settlement_attempt(
    request: L1SettlementAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_admit_l1_settlement_attempt(request).map_err(bridge_error)
}

pub(super) fn admit_governed_runtime_improvement_proposal(
    request: GovernedRuntimeImprovementBridgeRequest,
) -> Result<Value, BridgeError> {
    core_admit_governed_runtime_improvement_proposal(request).map_err(bridge_error)
}

fn bridge_error(error: GovernedAdmissionError) -> BridgeError {
    BridgeError::new(error.code(), error.message().to_string())
}
