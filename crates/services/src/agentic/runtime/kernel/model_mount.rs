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
mod backend_lifecycle;
pub use backend_lifecycle::{
    plan_model_mount_backend_lifecycle_response, ModelMountBackendLifecycleBridgeRequest,
    ModelMountBackendLifecyclePlan, ModelMountBackendLifecycleRequest,
};
mod artifact_endpoint;
pub use artifact_endpoint::{ModelMountArtifactEndpointPlan, ModelMountArtifactEndpointRequest};
mod storage_control;
pub use storage_control::{ModelMountStorageControlPlan, ModelMountStorageControlRequest};
mod mcp_workflow;
pub use mcp_workflow::{ModelMountMcpWorkflowPlan, ModelMountMcpWorkflowRequest};
mod common;
pub(super) use common::{
    non_empty_string, option_trimmed, push_unique_ref, require_non_empty, sha256_hex,
    trimmed_string, validate_receipt_refs,
};
pub use common::{
    ModelMountError, MODEL_MOUNT_ACCEPTED_RECEIPT_HEAD_SCHEMA_VERSION,
    MODEL_MOUNT_ACCEPTED_RECEIPT_TRANSITION_SCHEMA_VERSION,
    MODEL_MOUNT_ARTIFACT_ENDPOINT_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_SCHEMA_VERSION, MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
    MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION,
    MODEL_MOUNT_CONVERSATION_STATE_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_CONVERSATION_STATE_SCHEMA_VERSION, MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
    MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION, MODEL_MOUNT_MCP_WORKFLOW_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_MCP_WORKFLOW_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_LIFECYCLE_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION,
    MODEL_MOUNT_RECEIPT_GATE_PLAN_SCHEMA_VERSION, MODEL_MOUNT_RECEIPT_GATE_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION, MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION, MODEL_MOUNT_RUNTIME_ENGINE_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_SCHEMA_VERSION, MODEL_MOUNT_RUNTIME_SURVEY_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_SURVEY_SCHEMA_VERSION, MODEL_MOUNT_SERVER_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_SERVER_CONTROL_SCHEMA_VERSION, MODEL_MOUNT_STORAGE_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION, MODEL_MOUNT_STREAM_CANCEL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_STREAM_CANCEL_SCHEMA_VERSION, MODEL_MOUNT_STREAM_COMPLETION_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_STREAM_COMPLETION_SCHEMA_VERSION, MODEL_MOUNT_TOKENIZER_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_TOKENIZER_REQUIRED_RESULT_SCHEMA_VERSION, MODEL_MOUNT_TOKENIZER_SCHEMA_VERSION,
    MODEL_MOUNT_VAULT_CONTROL_PLAN_SCHEMA_VERSION, MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION,
};
mod capability_token_control;
pub use capability_token_control::{
    ModelMountCapabilityTokenControlPlan, ModelMountCapabilityTokenControlRequest,
};
mod catalog_provider_control;
pub use catalog_provider_control::{
    ModelMountCatalogProviderControlPlan, ModelMountCatalogProviderControlRequest,
};
mod provider_control;
pub use provider_control::{ModelMountProviderControlPlan, ModelMountProviderControlRequest};
mod conversation;
pub use conversation::{
    plan_model_mount_conversation_state_response, plan_model_mount_stream_cancel_response,
    plan_model_mount_stream_completion_response, ModelMountConversationStateBridgeRequest,
    ModelMountConversationStatePlan, ModelMountConversationStateRequest,
    ModelMountStreamCancelBridgeRequest, ModelMountStreamCancelPlan, ModelMountStreamCancelRequest,
    ModelMountStreamCompletionBridgeRequest, ModelMountStreamCompletionPlan,
    ModelMountStreamCompletionRequest,
};
mod lifecycle;
pub use lifecycle::{
    ModelMountInstanceLifecycleRequest, ModelMountInstanceLifecycleResult,
    ModelMountProviderInventoryRequest, ModelMountProviderInventoryResult,
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
mod route_control;
pub use route_control::{ModelMountRouteControlPlan, ModelMountRouteControlRequest};
mod runtime_engine;
pub use runtime_engine::{ModelMountRuntimeEnginePlan, ModelMountRuntimeEngineRequest};
mod runtime_survey;
pub use runtime_survey::{ModelMountRuntimeSurveyPlan, ModelMountRuntimeSurveyRequest};
mod server_control;
pub use server_control::{ModelMountServerControlPlan, ModelMountServerControlRequest};
mod tokenizer;
pub use tokenizer::{
    plan_model_mount_tokenizer_response, ModelMountTokenizerBridgeRequest, ModelMountTokenizerPlan,
    ModelMountTokenizerRequest,
};
mod vault_control;
pub use vault_control::{ModelMountVaultControlPlan, ModelMountVaultControlRequest};
mod receipt_gate;
pub use receipt_gate::{ModelMountReceiptGatePlan, ModelMountReceiptGateRequest};
mod required;
pub use required::{
    plan_model_mount_route_control_required_response, plan_model_mount_tokenizer_required_response,
    ModelMountRouteControlRequiredBridgeRequest, ModelMountRouteControlRequiredRecord,
    ModelMountRouteControlRequiredRequest, ModelMountTokenizerRequiredBridgeRequest,
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

    pub fn plan_backend_lifecycle(
        &self,
        request: &ModelMountBackendLifecycleRequest,
    ) -> Result<ModelMountBackendLifecyclePlan, ModelMountError> {
        backend_lifecycle::plan_backend_lifecycle(request)
    }

    pub fn plan_artifact_endpoint(
        &self,
        request: &ModelMountArtifactEndpointRequest,
    ) -> Result<ModelMountArtifactEndpointPlan, ModelMountError> {
        artifact_endpoint::plan_artifact_endpoint(request)
    }

    pub fn plan_storage_control(
        &self,
        request: &ModelMountStorageControlRequest,
    ) -> Result<ModelMountStorageControlPlan, ModelMountError> {
        storage_control::plan_storage_control(request)
    }

    pub fn plan_mcp_workflow(
        &self,
        request: &ModelMountMcpWorkflowRequest,
    ) -> Result<ModelMountMcpWorkflowPlan, ModelMountError> {
        mcp_workflow::plan_mcp_workflow(request)
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

    pub fn plan_route_control(
        &self,
        request: &ModelMountRouteControlRequest,
    ) -> Result<ModelMountRouteControlPlan, ModelMountError> {
        route_control::plan_route_control(request)
    }

    pub fn plan_catalog_provider_control(
        &self,
        request: &ModelMountCatalogProviderControlRequest,
    ) -> Result<ModelMountCatalogProviderControlPlan, ModelMountError> {
        catalog_provider_control::plan_catalog_provider_control(request)
    }

    pub fn plan_provider_control(
        &self,
        request: &ModelMountProviderControlRequest,
    ) -> Result<ModelMountProviderControlPlan, ModelMountError> {
        provider_control::plan_provider_control(request)
    }

    pub fn plan_capability_token_control(
        &self,
        request: &ModelMountCapabilityTokenControlRequest,
    ) -> Result<ModelMountCapabilityTokenControlPlan, ModelMountError> {
        capability_token_control::plan_capability_token_control(request)
    }

    pub fn plan_vault_control(
        &self,
        request: &ModelMountVaultControlRequest,
    ) -> Result<ModelMountVaultControlPlan, ModelMountError> {
        vault_control::plan_vault_control(request)
    }

    pub fn plan_receipt_gate(
        &self,
        request: &ModelMountReceiptGateRequest,
    ) -> Result<ModelMountReceiptGatePlan, ModelMountError> {
        receipt_gate::plan_receipt_gate(request)
    }

    pub fn plan_tokenizer(
        &self,
        request: &ModelMountTokenizerRequest,
    ) -> Result<ModelMountTokenizerPlan, ModelMountError> {
        tokenizer::plan_tokenizer(request)
    }

    pub fn plan_conversation_state(
        &self,
        request: &ModelMountConversationStateRequest,
    ) -> Result<ModelMountConversationStatePlan, ModelMountError> {
        conversation::plan_conversation_state(request)
    }

    pub fn plan_stream_completion(
        &self,
        request: &ModelMountStreamCompletionRequest,
    ) -> Result<ModelMountStreamCompletionPlan, ModelMountError> {
        conversation::plan_stream_completion(request)
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

    pub fn plan_runtime_engine(
        &self,
        request: &ModelMountRuntimeEngineRequest,
    ) -> Result<ModelMountRuntimeEnginePlan, ModelMountError> {
        runtime_engine::plan_runtime_engine(request)
    }

    pub fn plan_runtime_survey(
        &self,
        request: &ModelMountRuntimeSurveyRequest,
    ) -> Result<ModelMountRuntimeSurveyPlan, ModelMountError> {
        runtime_survey::plan_runtime_survey(request)
    }

    pub fn validate_accepted_receipt_transition(
        &self,
        transition: &ModelMountAcceptedReceiptTransition,
    ) -> Result<(), ModelMountError> {
        accepted_receipt::validate_accepted_receipt_transition(transition)
    }
}
