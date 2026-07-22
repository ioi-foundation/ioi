//! Trusted compatibility boundary for effectful runtime operations that have not
//! yet proven owner-qualified pre-effect authority and post-effect receipt binding.
//!
//! The residual allowlist is intentionally closed and machine-verified. New effects
//! must not enter this facade; each method leaves only after its denial and receipt
//! invariants are proven at the owning service boundary.

use super::{
    coding_tool_step_module::{
        run_coding_tool_step_module, CodingToolStepModuleRunError, CodingToolStepModuleRunRequest,
    },
    ctee::{
        CteeNodeTrust, CteePrivateWorkspaceError, CteePrivateWorkspaceExecutionRecord,
        PrivateWorkspaceCteeModule,
    },
    model_mount::{
        supervise_model_mount_backend_process, ModelMountBackendProcessSupervisionPlan,
        ModelMountBackendProcessSupervisionRequest, ModelMountCore, ModelMountError,
        ModelMountProviderInvocationRequest, ModelMountProviderInvocationResult,
        ModelMountProviderStreamInvocationResult,
    },
    step_module::StepModuleInvocation,
    workspace_restore::{
        self, apply_workspace_snapshot_restore_protocol_response, WorkspaceRestoreOperationError,
        WorkspaceRestoreOperationRecord, WorkspaceRestoreOperationsCore,
        WorkspaceRestoreOperationsRequest, WorkspaceSnapshotCaptureCore,
        WorkspaceSnapshotCaptureRequest, WorkspaceSnapshotCaptureResult,
        WorkspaceSnapshotRestoreProtocolRequest,
    },
};

#[derive(Debug, Default, Clone)]
pub struct RuntimeEffectCompatibilityGateway;

impl RuntimeEffectCompatibilityGateway {
    pub fn new() -> Self {
        Self
    }

    pub fn invoke_model_mount_provider(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderInvocationResult, ModelMountError> {
        ModelMountCore.invoke_provider(request)
    }

    pub fn invoke_model_mount_provider_stream(
        &self,
        request: &ModelMountProviderInvocationRequest,
    ) -> Result<ModelMountProviderStreamInvocationResult, ModelMountError> {
        ModelMountCore.invoke_provider_stream(request)
    }

    pub fn supervise_model_mount_backend_process(
        &self,
        request: &ModelMountBackendProcessSupervisionRequest,
    ) -> Result<ModelMountBackendProcessSupervisionPlan, ModelMountError> {
        supervise_model_mount_backend_process(request)
    }

    pub fn run_coding_tool_step_module(
        &self,
        request: &CodingToolStepModuleRunRequest,
    ) -> Result<serde_json::Value, CodingToolStepModuleRunError> {
        run_coding_tool_step_module(request.clone())
    }

    pub fn execute_private_workspace_ctee_action(
        &self,
        invocation: &StepModuleInvocation,
        node_trust: &CteeNodeTrust,
    ) -> Result<CteePrivateWorkspaceExecutionRecord, CteePrivateWorkspaceError> {
        PrivateWorkspaceCteeModule.execute_and_admit(invocation, node_trust)
    }

    pub fn apply_workspace_restore_operations(
        &self,
        request: &WorkspaceRestoreOperationsRequest,
    ) -> Result<Vec<WorkspaceRestoreOperationRecord>, WorkspaceRestoreOperationError> {
        WorkspaceRestoreOperationsCore.apply_operations(request)
    }

    pub fn capture_workspace_snapshot_files(
        &self,
        request: &WorkspaceSnapshotCaptureRequest,
    ) -> Result<WorkspaceSnapshotCaptureResult, WorkspaceRestoreOperationError> {
        WorkspaceSnapshotCaptureCore.capture_files(request)
    }

    pub fn apply_workspace_snapshot_restore(
        &self,
        request: WorkspaceSnapshotRestoreProtocolRequest,
    ) -> Result<serde_json::Value, workspace_restore::WorkspaceRestoreProtocolError> {
        apply_workspace_snapshot_restore_protocol_response(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION;

    fn unadmitted_provider_request() -> ModelMountProviderInvocationRequest {
        ModelMountProviderInvocationRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: "model-provider-execution://denied".to_string(),
            provider_execution_hash: "sha256:denied".to_string(),
            route_decision_ref: "model-mount-route-decision://denied".to_string(),
            route_receipt_ref: "receipt://route/denied".to_string(),
            route_ref: "model-route://denied".to_string(),
            provider_ref: "model-provider://denied".to_string(),
            provider_kind: "local_folder".to_string(),
            endpoint_ref: "model-endpoint://denied".to_string(),
            model_ref: "model://denied".to_string(),
            capability: "chat.completions".to_string(),
            invocation_kind: "chat".to_string(),
            input: "must not execute".to_string(),
            request_hash: "sha256:request-denied".to_string(),
            execution_backend: "rust_model_mount_fixture".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            base_url: None,
            provider_auth_materialization_ref: None,
            outbound_header_binding_ref: None,
            auth_header_materialization_status: None,
            ctee_egress_resolver_ref: None,
            ctee_egress_resolver_hash: None,
            ctee_egress_resolution_status: None,
            stream_status: None,
            receipt_refs: vec!["receipt://route/denied".to_string()],
            evidence_refs: Vec::new(),
            admitted_provider_execution: None,
        }
    }

    #[test]
    fn provider_effect_refuses_before_execution_without_bound_admission() {
        let error = RuntimeEffectCompatibilityGateway::new()
            .invoke_model_mount_provider(&unadmitted_provider_request())
            .expect_err("an unadmitted provider request must not reach the provider backend");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);
    }
}
