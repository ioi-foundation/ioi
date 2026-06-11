mod admission;
pub use admission::{
    ModelMountInvocationAdmissionRecord, ModelMountInvocationAdmissionRequest,
    ModelMountRouteDecisionRecord, ModelMountRouteDecisionRequest,
};
mod accepted_receipt;
pub use accepted_receipt::{
    ModelMountAcceptedReceiptHead, ModelMountAcceptedReceiptHeadRequest,
    ModelMountAcceptedReceiptTransition, ModelMountAcceptedReceiptTransitionRequest,
};
mod backend_process;
pub use backend_process::{
    plan_model_mount_backend_process_response, ModelMountBackendProcessLoadOptions,
    ModelMountBackendProcessPlan, ModelMountBackendProcessPlanBridgeRequest,
    ModelMountBackendProcessPlanRequest,
};
mod common;
pub(super) use common::{
    non_empty_string, option_trimmed, push_unique_ref, require_non_empty, sha256_hex,
    trimmed_string, validate_receipt_refs,
};
pub use common::{
    ModelMountError, MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION,
    MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION, MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
    MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_RESULT_SCHEMA_VERSION, MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
    MODEL_MOUNT_SERVER_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_SERVER_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_TOKENIZER_REQUIRED_RESULT_SCHEMA_VERSION,
};
mod lifecycle;
pub use lifecycle::{
    plan_model_mount_instance_lifecycle_response, plan_model_mount_provider_inventory_response,
    plan_model_mount_provider_lifecycle_response, ModelMountInstanceLifecycleBridgeRequest,
    ModelMountInstanceLifecycleRequest, ModelMountInstanceLifecycleResult,
    ModelMountProviderInventoryBridgeRequest, ModelMountProviderInventoryRequest,
    ModelMountProviderInventoryResult, ModelMountProviderLifecycleBridgeRequest,
    ModelMountProviderLifecycleRequest, ModelMountProviderLifecycleResult,
};
mod provider_execution;
pub use provider_execution::{
    ModelMountProviderExecutionRecord, ModelMountProviderExecutionRequest,
    ModelMountProviderInvocationRequest, ModelMountProviderInvocationResult,
    ModelMountProviderStreamInvocationResult, ModelMountTokenCount,
};
mod provider_result;
pub use provider_result::{
    ModelMountProviderResultAdmissionRecord, ModelMountProviderResultAdmissionRequest,
};
mod read_projection;
pub use read_projection::{
    plan_model_mount_read_projection_response, ModelMountReadProjectionBridgeRequest,
    ModelMountReadProjectionError, ModelMountReadProjectionPlan, ModelMountReadProjectionRequest,
};
mod required;
pub use required::{
    plan_model_mount_backend_lifecycle_required_response,
    plan_model_mount_route_control_required_response,
    plan_model_mount_runtime_engine_required_response,
    plan_model_mount_server_control_required_response,
    plan_model_mount_tokenizer_required_response, ModelMountBackendLifecycleRequiredBridgeRequest,
    ModelMountBackendLifecycleRequiredRecord, ModelMountBackendLifecycleRequiredRequest,
    ModelMountRouteControlRequiredBridgeRequest, ModelMountRouteControlRequiredRecord,
    ModelMountRouteControlRequiredRequest, ModelMountRuntimeEngineRequiredBridgeRequest,
    ModelMountRuntimeEngineRequiredRecord, ModelMountRuntimeEngineRequiredRequest,
    ModelMountServerControlRequiredBridgeRequest, ModelMountServerControlRequiredRecord,
    ModelMountServerControlRequiredRequest, ModelMountTokenizerRequiredBridgeRequest,
    ModelMountTokenizerRequiredRecord, ModelMountTokenizerRequiredRequest,
};

#[derive(Debug, Default, Clone)]
pub struct ModelMountCore;

impl ModelMountCore {
    pub fn plan_read_projection(
        &self,
        request: &ModelMountReadProjectionRequest,
    ) -> Result<ModelMountReadProjectionPlan, ModelMountReadProjectionError> {
        read_projection::plan_read_projection(request)
    }

    pub fn admit_route_decision(
        &self,
        request: &ModelMountRouteDecisionRequest,
    ) -> Result<ModelMountRouteDecisionRecord, ModelMountError> {
        admission::admit_route_decision(request)
    }

    pub fn admit_invocation(
        &self,
        request: &ModelMountInvocationAdmissionRequest,
    ) -> Result<ModelMountInvocationAdmissionRecord, ModelMountError> {
        admission::admit_invocation(request)
    }

    pub fn admit_provider_execution(
        &self,
        request: &ModelMountProviderExecutionRequest,
    ) -> Result<ModelMountProviderExecutionRecord, ModelMountError> {
        provider_execution::admit_provider_execution(request)
    }

    pub fn invoke_provider(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderInvocationResult, ModelMountError> {
        provider_execution::invoke_provider(request)
    }

    pub fn invoke_provider_stream(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderStreamInvocationResult, ModelMountError> {
        provider_execution::invoke_provider_stream(request)
    }

    pub fn plan_provider_lifecycle(
        &self,
        request: &ModelMountProviderLifecycleRequest,
    ) -> Result<ModelMountProviderLifecycleResult, ModelMountError> {
        lifecycle::plan_provider_lifecycle(request)
    }

    pub fn plan_provider_inventory(
        &self,
        request: &ModelMountProviderInventoryRequest,
    ) -> Result<ModelMountProviderInventoryResult, ModelMountError> {
        lifecycle::plan_provider_inventory(request)
    }

    pub fn plan_instance_lifecycle(
        &self,
        request: &ModelMountInstanceLifecycleRequest,
    ) -> Result<ModelMountInstanceLifecycleResult, ModelMountError> {
        lifecycle::plan_instance_lifecycle(request)
    }

    pub fn admit_provider_result(
        &self,
        request: &ModelMountProviderResultAdmissionRequest,
    ) -> Result<ModelMountProviderResultAdmissionRecord, ModelMountError> {
        provider_result::admit_provider_result(request)
    }

    pub fn plan_backend_process(
        &self,
        request: &ModelMountBackendProcessPlanRequest,
    ) -> Result<ModelMountBackendProcessPlan, ModelMountError> {
        backend_process::plan_backend_process(request)
    }

    pub fn plan_backend_lifecycle_required(
        &self,
        request: &ModelMountBackendLifecycleRequiredRequest,
    ) -> Result<ModelMountBackendLifecycleRequiredRecord, ModelMountError> {
        required::plan_backend_lifecycle_required(request)
    }

    pub fn plan_server_control_required(
        &self,
        request: &ModelMountServerControlRequiredRequest,
    ) -> Result<ModelMountServerControlRequiredRecord, ModelMountError> {
        required::plan_server_control_required(request)
    }

    pub fn plan_runtime_engine_required(
        &self,
        request: &ModelMountRuntimeEngineRequiredRequest,
    ) -> Result<ModelMountRuntimeEngineRequiredRecord, ModelMountError> {
        required::plan_runtime_engine_required(request)
    }

    pub fn plan_tokenizer_required(
        &self,
        request: &ModelMountTokenizerRequiredRequest,
    ) -> Result<ModelMountTokenizerRequiredRecord, ModelMountError> {
        required::plan_tokenizer_required(request)
    }

    pub fn plan_route_control_required(
        &self,
        request: &ModelMountRouteControlRequiredRequest,
    ) -> Result<ModelMountRouteControlRequiredRecord, ModelMountError> {
        required::plan_route_control_required(request)
    }

    pub fn plan_accepted_receipt_head(
        &self,
        request: &ModelMountAcceptedReceiptHeadRequest,
    ) -> Result<ModelMountAcceptedReceiptHead, ModelMountError> {
        accepted_receipt::plan_accepted_receipt_head(request)
    }

    pub fn plan_accepted_receipt_transition(
        &self,
        request: &ModelMountAcceptedReceiptTransitionRequest,
    ) -> Result<ModelMountAcceptedReceiptTransition, ModelMountError> {
        accepted_receipt::plan_accepted_receipt_transition(request)
    }

    pub fn validate_accepted_receipt_transition(
        &self,
        transition: &ModelMountAcceptedReceiptTransition,
    ) -> Result<(), ModelMountError> {
        accepted_receipt::validate_accepted_receipt_transition(transition)
    }
}
