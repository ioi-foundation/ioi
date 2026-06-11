use ioi_services::agentic::runtime::kernel::model_mount::{
    admit_model_mount_invocation_response as core_admit_model_mount_invocation,
    admit_model_mount_provider_execution_response as core_admit_model_mount_provider_execution,
    admit_model_mount_provider_result_response as core_admit_model_mount_provider_result,
    admit_model_mount_route_decision_response as core_admit_model_mount_route_decision,
    execute_model_mount_provider_invocation_response as core_execute_model_mount_provider_invocation,
    execute_model_mount_provider_stream_invocation_response as core_execute_model_mount_provider_stream_invocation,
    plan_model_mount_backend_lifecycle_required_response as core_plan_model_mount_backend_lifecycle_required,
    plan_model_mount_backend_process_response as core_plan_model_mount_backend_process,
    plan_model_mount_instance_lifecycle_response as core_plan_model_mount_instance_lifecycle,
    plan_model_mount_provider_inventory_response as core_plan_model_mount_provider_inventory,
    plan_model_mount_provider_lifecycle_response as core_plan_model_mount_provider_lifecycle,
    plan_model_mount_read_projection_response as core_plan_model_mount_read_projection,
    plan_model_mount_route_control_required_response as core_plan_model_mount_route_control_required,
    plan_model_mount_runtime_engine_required_response as core_plan_model_mount_runtime_engine_required,
    plan_model_mount_server_control_required_response as core_plan_model_mount_server_control_required,
    plan_model_mount_tokenizer_required_response as core_plan_model_mount_tokenizer_required,
    ModelMountError, ModelMountReadProjectionError,
};
use serde_json::Value;

use super::BridgeError;

pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountBackendLifecycleRequiredBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountBackendProcessPlanBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountInstanceLifecycleBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountInvocationAdmissionBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountProviderExecutionBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountProviderInventoryBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountProviderInvocationBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountProviderLifecycleBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountProviderResultAdmissionBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountReadProjectionBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountRouteControlRequiredBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountRouteDecisionBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountRuntimeEngineRequiredBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountServerControlRequiredBridgeRequest;
pub(super) use ioi_services::agentic::runtime::kernel::model_mount::ModelMountTokenizerRequiredBridgeRequest;

pub(super) fn admit_model_mount_route_decision(
    request: ModelMountRouteDecisionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_admit_model_mount_route_decision(request).map_err(|error| {
        BridgeError::new("model_mount_route_decision_rejected", format!("{error:?}"))
    })
}

pub(super) fn admit_model_mount_invocation(
    request: ModelMountInvocationAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_admit_model_mount_invocation(request)
        .map_err(|error| BridgeError::new("model_mount_invocation_rejected", format!("{error:?}")))
}

pub(super) fn admit_model_mount_provider_execution(
    request: ModelMountProviderExecutionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_admit_model_mount_provider_execution(request).map_err(|error| {
        BridgeError::new(
            "model_mount_provider_execution_rejected",
            format!("{error:?}"),
        )
    })
}

pub(super) fn execute_model_mount_provider_invocation(
    request: ModelMountProviderInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    core_execute_model_mount_provider_invocation(request).map_err(|error| {
        BridgeError::new(
            "model_mount_provider_invocation_rejected",
            format!("{error:?}"),
        )
    })
}

pub(super) fn execute_model_mount_provider_stream_invocation(
    request: ModelMountProviderInvocationBridgeRequest,
) -> Result<Value, BridgeError> {
    core_execute_model_mount_provider_stream_invocation(request).map_err(|error| {
        BridgeError::new(
            "model_mount_provider_stream_invocation_rejected",
            format!("{error:?}"),
        )
    })
}

pub(super) fn plan_model_mount_provider_lifecycle(
    request: ModelMountProviderLifecycleBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_provider_lifecycle(request)
        .map_err(|error| model_mount_bridge_error("model_mount_provider_lifecycle_rejected", error))
}

pub(super) fn plan_model_mount_provider_inventory(
    request: ModelMountProviderInventoryBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_provider_inventory(request)
        .map_err(|error| model_mount_bridge_error("model_mount_provider_inventory_rejected", error))
}

pub(super) fn plan_model_mount_instance_lifecycle(
    request: ModelMountInstanceLifecycleBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_instance_lifecycle(request)
        .map_err(|error| model_mount_bridge_error("model_mount_instance_lifecycle_rejected", error))
}

pub(super) fn admit_model_mount_provider_result(
    request: ModelMountProviderResultAdmissionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_admit_model_mount_provider_result(request).map_err(|error| {
        BridgeError::new("model_mount_provider_result_rejected", format!("{error:?}"))
    })
}

pub(super) fn plan_model_mount_backend_process(
    request: ModelMountBackendProcessPlanBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_backend_process(request).map_err(|error| {
        model_mount_bridge_error("model_mount_backend_process_plan_rejected", error)
    })
}

pub(super) fn plan_model_mount_backend_lifecycle_required(
    request: ModelMountBackendLifecycleRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_backend_lifecycle_required(request).map_err(|error| {
        model_mount_bridge_error("model_mount_backend_lifecycle_required_invalid", error)
    })
}

pub(super) fn plan_model_mount_server_control_required(
    request: ModelMountServerControlRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_server_control_required(request).map_err(|error| {
        model_mount_bridge_error("model_mount_server_control_required_invalid", error)
    })
}

pub(super) fn plan_model_mount_runtime_engine_required(
    request: ModelMountRuntimeEngineRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_runtime_engine_required(request).map_err(|error| {
        model_mount_bridge_error("model_mount_runtime_engine_required_invalid", error)
    })
}

pub(super) fn plan_model_mount_tokenizer_required(
    request: ModelMountTokenizerRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_tokenizer_required(request)
        .map_err(|error| model_mount_bridge_error("model_mount_tokenizer_required_invalid", error))
}

pub(super) fn plan_model_mount_route_control_required(
    request: ModelMountRouteControlRequiredBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_route_control_required(request).map_err(|error| {
        model_mount_bridge_error("model_mount_route_control_required_invalid", error)
    })
}

pub(super) fn plan_model_mount_read_projection(
    request: ModelMountReadProjectionBridgeRequest,
) -> Result<Value, BridgeError> {
    core_plan_model_mount_read_projection(request).map_err(read_projection_bridge_error)
}

fn read_projection_bridge_error(error: ModelMountReadProjectionError) -> BridgeError {
    BridgeError::new(error.code, error.message)
}

fn model_mount_bridge_error(code: &'static str, error: ModelMountError) -> BridgeError {
    BridgeError::new(code, format!("{error:?}"))
}
