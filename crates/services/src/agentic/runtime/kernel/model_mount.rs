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
    ModelMountBackendProcessLoadOptions, ModelMountBackendProcessPlan,
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
    ModelMountInstanceLifecycleRequest, ModelMountInstanceLifecycleResult,
    ModelMountProviderInventoryRequest, ModelMountProviderInventoryResult,
    ModelMountProviderLifecycleRequest, ModelMountProviderLifecycleResult,
};
mod provider_execution;
pub use provider_execution::{
    ModelMountProviderExecutionRecord, ModelMountProviderExecutionRequest,
    ModelMountProviderInvocationRequest, ModelMountProviderInvocationResult,
    ModelMountProviderResultAdmissionRecord, ModelMountProviderResultAdmissionRequest,
    ModelMountProviderStreamInvocationResult, ModelMountTokenCount,
};
mod read_projection;
pub use read_projection::{
    ModelMountReadProjectionError, ModelMountReadProjectionPlan, ModelMountReadProjectionRequest,
};
mod required;
pub use required::{
    ModelMountBackendLifecycleRequiredRecord, ModelMountBackendLifecycleRequiredRequest,
    ModelMountRouteControlRequiredRecord, ModelMountRouteControlRequiredRequest,
    ModelMountRuntimeEngineRequiredRecord, ModelMountRuntimeEngineRequiredRequest,
    ModelMountServerControlRequiredRecord, ModelMountServerControlRequiredRequest,
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
        provider_execution::admit_provider_result(request)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ModelMountRouteDecisionRequest {
        ModelMountRouteDecisionRequest {
            schema_version: MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION.to_string(),
            route_ref: "model-route://default/local-first".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            capability: "chat".to_string(),
            policy_hash: "sha256:model-route-policy".to_string(),
            idempotency_key: "model-route:thread:test".to_string(),
            receipt_refs: vec!["receipt://model-route/qwen3".to_string()],
            authority_grant_refs: vec![],
            authority_receipt_refs: vec![],
            custody_ref: None,
            privacy_profile: Some("internal".to_string()),
            node_plaintext_allowed: false,
            workflow_graph_ref: Some("workflow://graph".to_string()),
            workflow_node_ref: Some("workflow://node/model-router".to_string()),
        }
    }

    fn invocation_request() -> ModelMountInvocationAdmissionRequest {
        ModelMountInvocationAdmissionRequest {
            schema_version: MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION.to_string(),
            invocation_ref: "model-invocation://response/test".to_string(),
            route_decision_ref: "model_mount://route_decision/test".to_string(),
            route_receipt_ref: "receipt://route/test".to_string(),
            invocation_receipt_ref: "receipt://invocation/test".to_string(),
            route_ref: "model-route://default/local-first".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            capability: "chat".to_string(),
            invocation_kind: "responses".to_string(),
            policy_hash: "sha256:model-route-policy".to_string(),
            input_hash: "sha256:input".to_string(),
            output_hash: "sha256:output".to_string(),
            idempotency_key: "model-invocation:thread:test".to_string(),
            receipt_refs: vec![
                "receipt://route/test".to_string(),
                "receipt://invocation/test".to_string(),
            ],
            authority_grant_refs: vec!["grant://wallet/model-chat".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/model-chat".to_string()],
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["backend://native-local".to_string()],
            tool_receipt_refs: vec![],
            custody_ref: None,
            privacy_profile: Some("internal".to_string()),
            node_plaintext_allowed: false,
            workflow_graph_ref: Some("workflow://graph".to_string()),
            workflow_node_ref: Some("workflow://node/model-invocation".to_string()),
            response_ref: Some("response://test".to_string()),
            previous_response_ref: None,
            stream_status: None,
        }
    }

    fn provider_execution_request() -> ModelMountProviderExecutionRequest {
        ModelMountProviderExecutionRequest {
            schema_version: MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION.to_string(),
            invocation_ref: "model-provider-execution://response/test".to_string(),
            route_decision_ref: "model_mount://route_decision/test".to_string(),
            route_receipt_ref: "receipt://route/test".to_string(),
            route_ref: "model-route://default/local-first".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            capability: "chat".to_string(),
            invocation_kind: "responses".to_string(),
            policy_hash: "sha256:model-route-policy".to_string(),
            input_hash: "sha256:input".to_string(),
            request_hash: "sha256:request".to_string(),
            idempotency_key: "model-provider-execution:thread:test".to_string(),
            receipt_refs: vec!["receipt://route/test".to_string()],
            authority_grant_refs: vec!["grant://wallet/model-chat".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/model-chat".to_string()],
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["backend://native-local".to_string()],
            tool_receipt_refs: vec![],
            custody_ref: None,
            privacy_profile: Some("internal".to_string()),
            node_plaintext_allowed: false,
            workflow_graph_ref: Some("workflow://graph".to_string()),
            workflow_node_ref: Some("workflow://node/model-provider-execution".to_string()),
            response_ref: Some("response://test".to_string()),
            previous_response_ref: None,
            stream_status: None,
        }
    }

    fn provider_invocation_request() -> ModelMountProviderInvocationRequest {
        let admission = ModelMountCore
            .admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");
        ModelMountProviderInvocationRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "local_folder".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            input: "user: hello".to_string(),
            request_hash: admission.request_hash.clone(),
            execution_backend: "rust_model_mount_fixture".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            stream_status: None,
            receipt_refs: admission.receipt_refs.clone(),
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    fn provider_stream_invocation_request() -> ModelMountProviderInvocationRequest {
        let mut execution_request = provider_execution_request();
        execution_request.stream_status = Some("started".to_string());
        let admission = ModelMountCore
            .admit_provider_execution(&execution_request)
            .expect("stream provider execution admitted");
        ModelMountProviderInvocationRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "ioi_native_local".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            input: "user: hello".to_string(),
            request_hash: admission.request_hash.clone(),
            execution_backend: "rust_model_mount_native_local_stream".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    fn provider_lifecycle_request() -> ModelMountProviderLifecycleRequest {
        ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            provider_kind: "ioi_native_local".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            action: "load".to_string(),
            execution_backend: "rust_model_mount_native_local_lifecycle".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_model_load_request".to_string()],
            process_evidence_refs: vec!["autopilot_native_local_process_started".to_string()],
        }
    }

    fn fixture_provider_lifecycle_request() -> ModelMountProviderLifecycleRequest {
        ModelMountProviderLifecycleRequest {
            schema_version: MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://fixture".to_string(),
            provider_kind: "local_folder".to_string(),
            endpoint_ref: "endpoint://fixture/qwen3".to_string(),
            model_ref: "model://fixture/qwen3".to_string(),
            action: "health".to_string(),
            execution_backend: "rust_model_mount_fixture_lifecycle".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            evidence_refs: vec!["daemon_fixture_health_request".to_string()],
            process_evidence_refs: vec![],
        }
    }

    fn provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            provider_kind: "ioi_native_local".to_string(),
            action: "list_loaded".to_string(),
            execution_backend: "rust_model_mount_native_local_inventory".to_string(),
            api_format: Some("ioi_native".to_string()),
            driver: Some("native_local".to_string()),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            item_refs: vec!["model_instance://native/qwen3".to_string()],
            evidence_refs: vec!["daemon_native_local_list_loaded_request".to_string()],
        }
    }

    fn fixture_provider_inventory_request() -> ModelMountProviderInventoryRequest {
        ModelMountProviderInventoryRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION.to_string(),
            provider_ref: "provider://fixture".to_string(),
            provider_kind: "local_folder".to_string(),
            action: "list_models".to_string(),
            execution_backend: "rust_model_mount_fixture_inventory".to_string(),
            api_format: Some("ioi_fixture".to_string()),
            driver: Some("fixture".to_string()),
            backend_ref: Some("backend.fixture".to_string()),
            provider_status: Some("configured".to_string()),
            item_refs: vec!["model://fixture/qwen3".to_string()],
            evidence_refs: vec!["daemon_fixture_list_models_request".to_string()],
        }
    }

    fn instance_lifecycle_request() -> ModelMountInstanceLifecycleRequest {
        ModelMountInstanceLifecycleRequest {
            schema_version: MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION.to_string(),
            instance_ref: "model_instance://native/qwen3".to_string(),
            endpoint_ref: "endpoint://ioi-native-local/qwen3".to_string(),
            model_ref: "model://qwen/qwen3.5-9b".to_string(),
            provider_ref: "provider://ioi-native-local".to_string(),
            action: "load".to_string(),
            target_status: "loaded".to_string(),
            execution_backend: "rust_model_mount_instance_lifecycle".to_string(),
            backend_ref: "backend.autopilot.native-local.fixture".to_string(),
            driver: "native_local".to_string(),
            provider_lifecycle_hash: "sha256:provider-lifecycle".to_string(),
            evidence_refs: vec!["rust_model_mount_provider_lifecycle".to_string()],
        }
    }

    fn provider_result_admission_request() -> ModelMountProviderResultAdmissionRequest {
        let admission = ModelMountCore
            .admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");
        let output_text = "fixture provider answer".to_string();
        let output_hash = format!(
            "sha256:{}",
            sha256_hex(output_text.as_bytes()).expect("output hash")
        );
        ModelMountProviderResultAdmissionRequest {
            schema_version: MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "local_folder".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            request_hash: admission.request_hash.clone(),
            output_text,
            output_hash,
            token_count: ModelMountTokenCount {
                prompt_tokens: 1,
                completion_tokens: 2,
                total_tokens: 3,
            },
            provider_response_kind: Some("rust_model_mount.fixture".to_string()),
            execution_backend: "rust_model_mount_fixture".to_string(),
            backend_ref: Some("backend.fixture".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["rust_model_mount_fixture_backend".to_string()],
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    fn backend_process_plan_request() -> ModelMountBackendProcessPlanRequest {
        ModelMountBackendProcessPlanRequest {
            schema_version: MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION.to_string(),
            backend_ref: "backend.llama".to_string(),
            backend_kind: "llama_cpp".to_string(),
            base_url: Some("http://127.0.0.1:8091/v1".to_string()),
            model_ref: Some("model://qwen/qwen3.5-9b".to_string()),
            artifact_path: Some("/models/private/model.gguf".to_string()),
            binary_configured: true,
            load_options: ModelMountBackendProcessLoadOptions {
                context_length: Some(4096),
                parallel: Some(2),
                gpu: Some("auto".to_string()),
                identifier: Some("llama profile".to_string()),
                embeddings: true,
                ..Default::default()
            },
        }
    }

    #[test]
    fn backend_process_plan_owns_supervision_args_and_readiness() {
        let plan = ModelMountCore
            .plan_backend_process(&backend_process_plan_request())
            .expect("backend process planned");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_BACKEND_PROCESS_PLAN_SCHEMA_VERSION
        );
        assert!(plan.supports_supervision);
        assert_eq!(plan.supervisor_kind, "external_process");
        assert_eq!(plan.spawn_status, "spawn_ready");
        assert!(plan.spawn_required);
        assert_eq!(plan.public_args[0], "llama-server");
        assert_eq!(plan.public_args[1], "--model");
        assert!(plan.public_args[2].starts_with("artifact:"));
        assert!(plan.public_args.contains(&"--gpu-layers".to_string()));
        assert!(plan.public_args.contains(&"-1".to_string()));
        assert_eq!(plan.spawn_args[0], "--model");
        assert_eq!(plan.spawn_args[1], "/models/private/model.gguf");
        assert!(plan.spawn_args.contains(&"--embedding".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"rust_model_mount_backend_process_plan".to_string()));
        assert!(plan.plan_hash.starts_with("sha256:"));
    }

    #[test]
    fn backend_lifecycle_required_is_planned_in_rust_model_mount() {
        let record = ModelMountCore
            .plan_backend_lifecycle_required(&ModelMountBackendLifecycleRequiredRequest {
                schema_version: MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "model_mount.backend_lifecycle".to_string(),
                operation_kind: "model_mount.backend.start".to_string(),
                backend_id: "backend.llama_cpp".to_string(),
                backend_kind: None,
                source: Some("runtime-daemon.model_mounting.backend_lifecycle".to_string()),
                evidence_refs: vec![],
            })
            .expect("backend lifecycle required record");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.model_mount_backend_lifecycle_required");
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(
            record.code,
            "model_mount_backend_lifecycle_rust_core_required"
        );
        assert_eq!(record.backend_id, "backend.llama_cpp");
        assert_eq!(record.backend_kind, None);
        assert_eq!(record.operation_kind, "model_mount.backend.start");
        assert_eq!(record.rust_core_boundary, "model_mount.backend_lifecycle");
        assert_eq!(record.details["backend_id"], "backend.llama_cpp");
        assert_eq!(record.details["backend_kind"], serde_json::Value::Null);
        assert_eq!(
            record.details["operation_kind"],
            "model_mount.backend.start"
        );
        assert!(record
            .evidence_refs
            .contains(&"public_backend_lifecycle_js_facade_retired".to_string()));
        assert!(record.details.get("backendId").is_none());
        assert!(record.details.get("operationKind").is_none());
    }

    #[test]
    fn server_control_required_is_planned_in_rust_model_mount() {
        let record = ModelMountCore
            .plan_server_control_required(&ModelMountServerControlRequiredRequest {
                schema_version: MODEL_MOUNT_SERVER_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "model_mount.server_control".to_string(),
                operation_kind: "model_mount.server_control.record_operation".to_string(),
                source: Some("runtime-daemon.model_mounting.server_control".to_string()),
                evidence_refs: vec![],
                details: serde_json::json!({
                    "base_url": "http://daemon.test",
                    "reason": "test",
                    "server_control_id": "server-control.default",
                }),
            })
            .expect("server control required record");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_SERVER_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.model_mount_server_control_required");
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "model_mount_server_control_rust_core_required");
        assert_eq!(
            record.operation_kind,
            "model_mount.server_control.record_operation"
        );
        assert_eq!(record.rust_core_boundary, "model_mount.server_control");
        assert_eq!(record.details["base_url"], "http://daemon.test");
        assert_eq!(record.details["reason"], "test");
        assert_eq!(
            record.details["server_control_id"],
            "server-control.default"
        );
        assert_eq!(
            record.details["operation_kind"],
            "model_mount.server_control.record_operation"
        );
        assert!(record
            .evidence_refs
            .contains(&"public_server_control_js_facade_retired".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"agentgres_server_control_truth_required".to_string()));
        assert!(record.details.get("operationKind").is_none());
        assert!(record.details.get("serverControlId").is_none());
    }

    #[test]
    fn runtime_engine_required_is_planned_in_rust_model_mount() {
        let record = ModelMountCore
            .plan_runtime_engine_required(&ModelMountRuntimeEngineRequiredRequest {
                schema_version: MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "model_mount.runtime_engine".to_string(),
                operation_kind: "model_mount.runtime_engine_profile.write".to_string(),
                source: Some("runtime-daemon.model_mounting.runtime_engine".to_string()),
                evidence_refs: vec![],
                details: serde_json::json!({
                    "engine_id": "backend.llama-cpp",
                }),
            })
            .expect("runtime engine required record");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.model_mount_runtime_engine_required");
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "model_mount_runtime_engine_rust_core_required");
        assert_eq!(
            record.operation_kind,
            "model_mount.runtime_engine_profile.write"
        );
        assert_eq!(record.rust_core_boundary, "model_mount.runtime_engine");
        assert_eq!(record.details["engine_id"], "backend.llama-cpp");
        assert_eq!(
            record.details["operation_kind"],
            "model_mount.runtime_engine_profile.write"
        );
        assert!(record
            .evidence_refs
            .contains(&"public_runtime_engine_js_facade_retired".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"agentgres_runtime_engine_truth_required".to_string()));
        assert!(record.details.get("engineId").is_none());
        assert!(record.details.get("operationKind").is_none());
    }

    #[test]
    fn tokenizer_required_is_planned_in_rust_model_mount() {
        let record = ModelMountCore
            .plan_tokenizer_required(&ModelMountTokenizerRequiredRequest {
                schema_version: MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION.to_string(),
                operation: "context_fit".to_string(),
                source: Some("runtime-daemon.model_mounting.tokenizer".to_string()),
                evidence_refs: vec![],
                details: serde_json::json!({
                    "model": "llama-test",
                    "route_id": "route.local-first",
                    "requested_scope": "model.context:*",
                }),
            })
            .expect("tokenizer required record");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_TOKENIZER_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.model_mount_tokenizer_required");
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "model_mount_tokenizer_rust_core_required");
        assert_eq!(record.operation, "context_fit");
        assert_eq!(record.rust_core_boundary, "model_mount.tokenizer");
        assert_eq!(record.details["operation"], "context_fit");
        assert_eq!(record.details["model"], "llama-test");
        assert_eq!(record.details["route_id"], "route.local-first");
        assert_eq!(record.details["requested_scope"], "model.context:*");
        assert!(record
            .evidence_refs
            .contains(&"model_mount_tokenizer_js_facade_retired".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"rust_daemon_core_model_context_fit_required".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"agentgres_model_tokenizer_truth_required".to_string()));
        assert!(record.details.get("routeId").is_none());
        assert!(record.details.get("requestedScope").is_none());
    }

    #[test]
    fn route_control_required_is_planned_in_rust_model_mount() {
        let record = ModelMountCore
            .plan_route_control_required(&ModelMountRouteControlRequiredRequest {
                schema_version: MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "model_mount.route_control".to_string(),
                operation_kind: "model_mount.route.selection_update".to_string(),
                source: Some("runtime-daemon.model_mounting.route_control".to_string()),
                evidence_refs: vec![],
                details: serde_json::json!({
                    "route_id": "route.local-first",
                    "selected_model": "model.local",
                    "receipt_id": "receipt-route-test",
                    "route_selection_boundary": "model_mount.route_selection",
                }),
            })
            .expect("route control required record");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.model_mount_route_control_required");
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "model_mount_route_control_rust_core_required");
        assert_eq!(record.operation, "model_mount.route_control");
        assert_eq!(record.operation_kind, "model_mount.route.selection_update");
        assert_eq!(record.rust_core_boundary, "model_mount.route_control");
        assert_eq!(record.details["route_id"], "route.local-first");
        assert_eq!(record.details["selected_model"], "model.local");
        assert_eq!(record.details["receipt_id"], "receipt-route-test");
        assert_eq!(
            record.details["route_selection_boundary"],
            "model_mount.route_selection"
        );
        assert!(record
            .evidence_refs
            .contains(&"model_mount_route_control_js_facade_retired".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"agentgres_route_truth_required".to_string()));
        assert!(record.details.get("routeId").is_none());
        assert!(record.details.get("selectedModel").is_none());
        assert!(record.details.get("receiptId").is_none());
    }

    #[test]
    fn backend_process_plan_blocks_llama_spawn_without_model_artifact() {
        let mut request = backend_process_plan_request();
        request.artifact_path = None;
        request.load_options.model_path = None;

        let plan = ModelMountCore
            .plan_backend_process(&request)
            .expect("backend process planned");

        assert!(plan.supports_supervision);
        assert!(!plan.spawn_required);
        assert_eq!(plan.spawn_status, "waiting_for_model");
        assert!(!plan.spawn_args.contains(&"--model".to_string()));
    }

    #[test]
    fn backend_process_plan_supports_vllm_bind_spawn_args() {
        let mut request = backend_process_plan_request();
        request.backend_ref = "backend.vllm".to_string();
        request.backend_kind = "vllm".to_string();
        request.base_url = Some("http://0.0.0.0:8092/v1".to_string());
        request.artifact_path = None;
        request.load_options = ModelMountBackendProcessLoadOptions {
            model_path: Some("/models/raw/vllm".to_string()),
            max_model_len: Some(16384),
            tensor_parallel_size: Some(2),
            dtype: Some("bfloat16".to_string()),
            ..Default::default()
        };

        let plan = ModelMountCore
            .plan_backend_process(&request)
            .expect("vllm backend process planned");

        assert_eq!(
            plan.spawn_args,
            vec![
                "serve",
                "/models/raw/vllm",
                "--host",
                "0.0.0.0",
                "--port",
                "8092",
                "--max-model-len",
                "16384",
                "--tensor-parallel-size",
                "2",
                "--dtype",
                "bfloat16"
            ]
        );
        assert_eq!(plan.spawn_status, "spawn_ready");
    }

    #[test]
    fn admits_resolved_model_route_decision() {
        let record = ModelMountCore
            .admit_route_decision(&request())
            .expect("route decision admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION
        );
        assert_eq!(record.model_ref, "model://qwen/qwen3.5-9b");
        assert_eq!(record.receipt_refs, vec!["receipt://model-route/qwen3"]);
        assert!(record.route_decision_hash.starts_with("sha256:"));
        assert!(record
            .route_decision_ref
            .starts_with("model_mount://route_decision/"));
    }

    #[test]
    fn rejects_unresolved_auto_model_before_provider_invocation() {
        let mut request = request();
        request.model_ref = "auto".to_string();

        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("auto must be resolved before provider invocation");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn route_decision_requires_receipt_refs() {
        let mut request = request();
        request.receipt_refs.clear();

        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("route decision must be receipt bound");

        assert_eq!(error, ModelMountError::MissingReceiptRef);

        request.receipt_refs = vec![" ".to_string()];
        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("route decision cannot use a blank receipt ref");

        assert_eq!(error, ModelMountError::MissingReceiptRef);
    }

    #[test]
    fn private_workspace_route_requires_ctee_custody_without_plaintext() {
        let mut request = request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("private workspace route requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = ModelMountCore
            .admit_route_decision(&request)
            .expect_err("private workspace route cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);

        request.node_plaintext_allowed = false;
        let record = ModelMountCore
            .admit_route_decision(&request)
            .expect("private cTEE route admitted");

        assert_eq!(
            record.custody_ref.as_deref(),
            Some("ctee://custody/private-workspace")
        );
    }

    #[test]
    fn admits_model_invocation_with_route_and_invocation_receipts() {
        let record = ModelMountCore
            .admit_invocation(&invocation_request())
            .expect("invocation admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION
        );
        assert_eq!(
            record.route_decision_ref,
            "model_mount://route_decision/test"
        );
        assert_eq!(record.route_receipt_ref, "receipt://route/test");
        assert_eq!(record.invocation_receipt_ref, "receipt://invocation/test");
        assert!(record.invocation_admission_hash.starts_with("sha256:"));
        assert!(record
            .invocation_admission_ref
            .starts_with("model_mount://invocation_admission/"));
    }

    #[test]
    fn invocation_requires_bound_route_and_invocation_receipts() {
        let mut request = invocation_request();
        request.receipt_refs = vec![request.invocation_receipt_ref.clone()];

        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("route receipt must be bound");

        assert_eq!(error, ModelMountError::MissingRouteReceiptRef);

        request.receipt_refs = vec![request.route_receipt_ref.clone()];
        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("invocation receipt must be bound");

        assert_eq!(error, ModelMountError::MissingInvocationReceiptRef);

        request.receipt_refs.clear();
        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("invocation admission requires receipts");

        assert_eq!(error, ModelMountError::MissingReceiptRef);
    }

    #[test]
    fn invocation_rejects_auto_model_before_receipt_admission() {
        let mut request = invocation_request();
        request.model_ref = "auto".to_string();

        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("auto must be resolved before invocation admission");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn private_workspace_invocation_requires_ctee_custody_without_plaintext() {
        let mut request = invocation_request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("private workspace invocation requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = ModelMountCore
            .admit_invocation(&request)
            .expect_err("private workspace invocation cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);
    }

    #[test]
    fn admits_provider_execution_with_route_receipt_before_driver_call() {
        let record = ModelMountCore
            .admit_provider_execution(&provider_execution_request())
            .expect("provider execution admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION
        );
        assert_eq!(
            record.route_decision_ref,
            "model_mount://route_decision/test"
        );
        assert_eq!(record.route_receipt_ref, "receipt://route/test");
        assert_eq!(record.request_hash, "sha256:request");
        assert!(record.provider_execution_hash.starts_with("sha256:"));
        assert!(record
            .provider_execution_ref
            .starts_with("model_mount://provider_execution/"));
    }

    #[test]
    fn provider_execution_requires_route_receipt_binding() {
        let mut request = provider_execution_request();
        request.receipt_refs.clear();

        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("provider execution requires receipts");

        assert_eq!(error, ModelMountError::MissingReceiptRef);

        request.receipt_refs = vec!["receipt://other".to_string()];
        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("provider execution requires the route receipt");

        assert_eq!(
            error,
            ModelMountError::MissingProviderExecutionRouteReceiptRef
        );
    }

    #[test]
    fn provider_execution_rejects_auto_model_before_driver_call() {
        let mut request = provider_execution_request();
        request.model_ref = "auto".to_string();

        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("auto must be resolved before provider execution");

        assert_eq!(error, ModelMountError::UnresolvedAutoModel);
    }

    #[test]
    fn private_workspace_provider_execution_requires_ctee_custody_without_plaintext() {
        let mut request = provider_execution_request();
        request.privacy_profile = Some("private_workspace_ctee".to_string());
        request.node_plaintext_allowed = true;

        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("private workspace provider execution requires custody ref first");

        assert_eq!(error, ModelMountError::PrivateWorkspaceMissingCustodyRef);

        request.custody_ref = Some("ctee://custody/private-workspace".to_string());
        let error = ModelMountCore
            .admit_provider_execution(&request)
            .expect_err("private workspace provider execution cannot allow plaintext");

        assert_eq!(error, ModelMountError::PrivateWorkspacePlaintextNotAllowed);
    }

    #[test]
    fn fixture_provider_invocation_executes_in_rust_model_mount() {
        let result = ModelMountCore
            .invoke_provider(&provider_invocation_request())
            .expect("fixture provider invocation executes in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION
        );
        assert_eq!(result.execution_backend, "rust_model_mount_fixture");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert!(result
            .output_text
            .starts_with("IOI model router fixture response from model://qwen/qwen3.5-9b."));
        assert_eq!(
            result.token_count.total_tokens,
            result.token_count.prompt_tokens + result.token_count.completion_tokens
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_invocation".to_string()));
        assert!(result.invocation_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_invocation_executes_in_rust_model_mount() {
        let mut request = provider_invocation_request();
        request.execution_backend = "rust_model_mount_native_local".to_string();
        request.provider_kind = "ioi_native_local".to_string();
        request.api_format = Some("ioi_native".to_string());
        request.driver = Some("native_local".to_string());
        request.backend_ref = Some("backend.autopilot.native-local.fixture".to_string());
        request.admitted_provider_execution = Some(ModelMountProviderExecutionRecord {
            provider_ref: request.provider_ref.clone(),
            endpoint_ref: request.endpoint_ref.clone(),
            model_ref: request.model_ref.clone(),
            capability: request.capability.clone(),
            invocation_kind: request.invocation_kind.clone(),
            request_hash: request.request_hash.clone(),
            ..request
                .admitted_provider_execution
                .clone()
                .expect("admission")
        });

        let result = ModelMountCore
            .invoke_provider(&request)
            .expect("native-local provider invocation executes in Rust");

        assert_eq!(result.execution_backend, "rust_model_mount_native_local");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(
            result.provider_response_kind.as_deref(),
            Some("rust_model_mount.native_local")
        );
        assert!(result
            .output_text
            .starts_with("Autopilot native local model response from model://qwen/qwen3.5-9b."));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_stream_invocation_executes_in_rust_model_mount() {
        let request = provider_stream_invocation_request();
        let result = ModelMountCore
            .invoke_provider_stream(&request)
            .expect("native-local provider stream executes in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION
        );
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_stream"
        );
        assert_eq!(result.stream_format, "ioi_jsonl");
        assert_eq!(result.stream_kind, "openai_responses_native_local");
        assert_eq!(
            result.provider_response_kind,
            "rust_model_mount.native_local.stream"
        );
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert!(result
            .output_text
            .starts_with("Autopilot native local model response from model://qwen/qwen3.5-9b."));
        assert!(result.stream_chunks.len() >= 2);
        assert!(result.stream_chunks[0].contains("\"done\":false"));
        assert!(result
            .stream_chunks
            .last()
            .expect("done chunk")
            .contains("\"done\":true"));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_stream_invocation".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_stream_backend".to_string()));
        assert!(result.invocation_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_lifecycle_is_planned_in_rust_model_mount() {
        let result = ModelMountCore
            .plan_provider_lifecycle(&provider_lifecycle_request())
            .expect("native-local provider lifecycle planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_lifecycle"
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_lifecycle".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_process_started".to_string()));
        assert!(result.lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn native_local_provider_unload_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = provider_lifecycle_request();
        request.action = "unload".to_string();
        request.evidence_refs.clear();

        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("native-local provider unload lifecycle planned in Rust");

        assert_eq!(result.action, "unload");
        assert_eq!(result.status, "unloaded");
        assert!(!result
            .evidence_refs
            .contains(&"autopilot_native_local_backend_registry".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_health_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = provider_lifecycle_request();
        request.action = "health".to_string();
        request.evidence_refs = vec!["daemon_native_local_health_request".to_string()];
        request.process_evidence_refs.clear();

        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("native-local provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(result.status, "available");
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_backend_registry".to_string()));
        assert!(!result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));

        request.provider_status = Some("blocked".to_string());
        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("blocked native-local provider health planned in Rust");

        assert_eq!(result.status, "blocked");
    }

    #[test]
    fn fixture_provider_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = fixture_provider_lifecycle_request();

        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("fixture provider health planned in Rust");

        assert_eq!(result.action, "health");
        assert_eq!(result.status, "available");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert_eq!(result.driver, "fixture");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_lifecycle_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_registry_fixture".to_string()));

        request.action = "load".to_string();
        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("fixture provider load planned in Rust");
        assert_eq!(result.status, "loaded");

        request.action = "unload".to_string();
        let result = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect("fixture provider unload planned in Rust");
        assert_eq!(result.status, "unloaded");
    }

    #[test]
    fn native_local_provider_lifecycle_rejects_unsupported_backend_and_action() {
        let mut request = provider_lifecycle_request();
        request.execution_backend = "daemon_js".to_string();

        let error = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleBackend);

        request = provider_lifecycle_request();
        request.action = "restart".to_string();
        let error = ModelMountCore
            .plan_provider_lifecycle(&request)
            .expect_err("lifecycle planner only supports explicit health/load/unload actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderLifecycleAction);
    }

    #[test]
    fn native_local_provider_inventory_is_planned_in_rust_model_mount() {
        let result = ModelMountCore
            .plan_provider_inventory(&provider_inventory_request())
            .expect("native-local provider inventory planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(result.action, "list_loaded");
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "autopilot.native_local.fixture");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_native_local_inventory"
        );
        assert_eq!(result.item_count, 1);
        assert_eq!(
            result.item_refs,
            vec!["model_instance://native/qwen3".to_string()]
        );
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_inventory".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"autopilot_native_local_process_supervisor".to_string()));
        assert!(result.inventory_hash.starts_with("sha256:"));
    }

    #[test]
    fn fixture_provider_inventory_is_planned_in_rust_model_mount() {
        let mut request = fixture_provider_inventory_request();

        let result = ModelMountCore
            .plan_provider_inventory(&request)
            .expect("fixture provider model inventory planned in Rust");

        assert_eq!(result.action, "list_models");
        assert_eq!(result.status, "listed");
        assert_eq!(result.backend, "ioi_fixture");
        assert_eq!(result.backend_id, "backend.fixture");
        assert_eq!(result.driver, "fixture");
        assert_eq!(result.item_count, 1);
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_inventory_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_registry_fixture".to_string()));

        request.action = "list_loaded".to_string();
        request.item_refs = vec!["model_instance://fixture/qwen3".to_string()];
        let result = ModelMountCore
            .plan_provider_inventory(&request)
            .expect("fixture provider loaded inventory planned in Rust");
        assert_eq!(result.action, "list_loaded");
        assert!(result
            .evidence_refs
            .contains(&"agentgres_model_instance_registry_fixture".to_string()));
    }

    #[test]
    fn native_local_provider_inventory_rejects_unsupported_backend_and_action() {
        let mut request = provider_inventory_request();
        request.execution_backend = "daemon_js".to_string();

        let error = ModelMountCore
            .plan_provider_inventory(&request)
            .expect_err("inventory planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderInventoryBackend);

        request = provider_inventory_request();
        request.action = "scan".to_string();
        let error = ModelMountCore
            .plan_provider_inventory(&request)
            .expect_err("inventory planner only supports explicit listing actions");

        assert_eq!(error, ModelMountError::UnsupportedProviderInventoryAction);
    }

    #[test]
    fn model_instance_lifecycle_is_planned_in_rust_model_mount() {
        let result = ModelMountCore
            .plan_instance_lifecycle(&instance_lifecycle_request())
            .expect("model instance lifecycle planned in Rust");

        assert_eq!(
            result.schema_version,
            MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION
        );
        assert_eq!(result.action, "load");
        assert_eq!(result.status, "loaded");
        assert_eq!(result.backend_id, "backend.autopilot.native-local.fixture");
        assert_eq!(result.driver, "native_local");
        assert_eq!(
            result.execution_backend,
            "rust_model_mount_instance_lifecycle"
        );
        assert_eq!(result.provider_lifecycle_hash, "sha256:provider-lifecycle");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_instance_lifecycle".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_provider_lifecycle_bound".to_string()));
        assert!(result.instance_lifecycle_hash.starts_with("sha256:"));
    }

    #[test]
    fn model_instance_unload_lifecycle_is_planned_in_rust_model_mount() {
        let mut request = instance_lifecycle_request();
        request.action = "unload".to_string();
        request.target_status = "unloaded".to_string();
        request.evidence_refs = vec!["rust_model_mount_fixture_lifecycle_backend".to_string()];

        let result = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect("model instance unload lifecycle planned in Rust");

        assert_eq!(result.action, "unload");
        assert_eq!(result.status, "unloaded");
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_fixture_lifecycle_backend".to_string()));
    }

    #[test]
    fn model_instance_eviction_and_supersede_lifecycle_are_planned_in_rust_model_mount() {
        let mut request = instance_lifecycle_request();
        request.action = "evict".to_string();
        request.target_status = "evicted".to_string();
        request.evidence_refs = vec!["model_idle_evict".to_string()];

        let result = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect("model instance eviction lifecycle planned in Rust");

        assert_eq!(result.action, "evict");
        assert_eq!(result.status, "evicted");
        assert!(result
            .evidence_refs
            .contains(&"model_idle_evict".to_string()));

        request = instance_lifecycle_request();
        request.action = "supersede".to_string();
        request.target_status = "superseded".to_string();
        request.evidence_refs = vec!["model_supersede".to_string()];

        let result = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect("model instance supersede lifecycle planned in Rust");

        assert_eq!(result.action, "supersede");
        assert_eq!(result.status, "superseded");
        assert!(result
            .evidence_refs
            .contains(&"model_supersede".to_string()));
    }

    #[test]
    fn model_instance_lifecycle_rejects_js_backend_and_status_drift() {
        let mut request = instance_lifecycle_request();
        request.execution_backend = "daemon_js".to_string();

        let error = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect_err("instance lifecycle planner must reject JS backend");

        assert_eq!(error, ModelMountError::UnsupportedInstanceLifecycleBackend);

        request = instance_lifecycle_request();
        request.target_status = "unloaded".to_string();
        let error = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect_err("load action must bind the loaded target status");

        assert_eq!(error, ModelMountError::InstanceLifecycleStatusMismatch);

        request = instance_lifecycle_request();
        request.action = "restart".to_string();
        let error = ModelMountCore
            .plan_instance_lifecycle(&request)
            .expect_err("instance lifecycle planner only supports canonical instance transitions");

        assert_eq!(error, ModelMountError::UnsupportedInstanceLifecycleAction);
    }

    #[test]
    fn fixture_provider_invocation_requires_bound_provider_execution() {
        let mut request = provider_invocation_request();
        request.admitted_provider_execution = None;

        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("provider invocation requires the full admission record");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);

        request = provider_invocation_request();
        let admitted_ref = request.provider_execution_ref.clone();
        request.provider_execution_ref = "model_mount://provider_execution/drifted".to_string();

        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("provider execution ref must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionRefMismatch);

        request.provider_execution_ref = admitted_ref;
        request.provider_execution_hash = "sha256:drifted".to_string();
        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("provider execution hash must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionHashMismatch);
    }

    #[test]
    fn provider_invocation_rejects_unmigrated_or_stream_backends() {
        let mut request = provider_invocation_request();
        request.provider_kind = "openai".to_string();
        request.driver = Some("openai_compatible".to_string());
        request.api_format = Some("openai".to_string());

        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("only migrated provider backends execute in Rust");

        assert_eq!(error, ModelMountError::UnsupportedProviderInvocationBackend);

        let mut request = provider_invocation_request();
        request.stream_status = Some("started".to_string());
        let error = ModelMountCore
            .invoke_provider(&request)
            .expect_err("streaming provider execution remains a later slice");

        assert_eq!(error, ModelMountError::StreamProviderInvocationUnsupported);
    }

    #[test]
    fn native_local_provider_stream_invocation_rejects_unstarted_or_wrong_backends() {
        let mut request = provider_stream_invocation_request();
        request.stream_status = None;
        let error = ModelMountCore
            .invoke_provider_stream(&request)
            .expect_err("stream invocation requires started admission");

        assert_eq!(error, ModelMountError::StreamProviderInvocationUnsupported);

        let mut request = provider_stream_invocation_request();
        request.execution_backend = "js_provider_driver_observation".to_string();
        let error = ModelMountCore
            .invoke_provider_stream(&request)
            .expect_err("stream invocation requires Rust native-local stream backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderInvocationBackend);
    }

    #[test]
    fn admits_rust_provider_result_bound_to_execution() {
        let record = ModelMountCore
            .admit_provider_result(&provider_result_admission_request())
            .expect("Rust provider result admitted");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.execution_backend, "rust_model_mount_fixture");
        assert_eq!(
            record.provider_response_kind.as_deref(),
            Some("rust_model_mount.fixture")
        );
        assert_eq!(record.output_hash.len(), "sha256:".len() + 64);
        assert!(record
            .provider_result_ref
            .starts_with("model_mount://provider_result/"));
        assert!(record.provider_result_hash.starts_with("sha256:"));
        assert!(record
            .evidence_refs
            .contains(&"rust_model_mount_provider_result_admission".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"rust_model_mount_provider_result_backend_bound".to_string()));
        assert!(!record
            .evidence_refs
            .iter()
            .any(|value| value == "js_provider_driver_observation_bound"));
    }

    #[test]
    fn admits_stream_start_rust_provider_result_bound_to_execution() {
        let mut execution_request = provider_execution_request();
        execution_request.stream_status = Some("started".to_string());
        let admission = ModelMountCore
            .admit_provider_execution(&execution_request)
            .expect("stream provider execution admitted");
        let output_text = String::new();
        let output_hash = format!(
            "sha256:{}",
            sha256_hex(output_text.as_bytes()).expect("output hash")
        );
        let request = ModelMountProviderResultAdmissionRequest {
            schema_version: MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "ioi_native_local".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            request_hash: admission.request_hash.clone(),
            output_text,
            output_hash,
            token_count: ModelMountTokenCount {
                prompt_tokens: 1,
                completion_tokens: 0,
                total_tokens: 1,
            },
            provider_response_kind: Some("rust_model_mount.native_local.stream".to_string()),
            execution_backend: "rust_model_mount_native_local_stream".to_string(),
            backend_ref: Some("backend.autopilot.native-local.fixture".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            provider_auth_evidence_refs: vec![],
            backend_evidence_refs: vec!["autopilot_native_local_provider_native_stream".to_string()],
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        };

        let record = ModelMountCore
            .admit_provider_result(&request)
            .expect("stream Rust provider result admitted");

        assert_eq!(record.stream_status.as_deref(), Some("started"));
        assert_eq!(
            record.provider_response_kind.as_deref(),
            Some("rust_model_mount.native_local.stream")
        );
        assert_eq!(
            record.execution_backend,
            "rust_model_mount_native_local_stream"
        );
    }

    #[test]
    fn provider_result_admission_requires_bound_provider_execution() {
        let mut request = provider_result_admission_request();
        request.admitted_provider_execution = None;

        let error = ModelMountCore
            .admit_provider_result(&request)
            .expect_err("provider result requires the full admission record");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);

        request = provider_result_admission_request();
        request.provider_execution_ref = "model_mount://provider_execution/drifted".to_string();
        let error = ModelMountCore
            .admit_provider_result(&request)
            .expect_err("provider result ref must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionRefMismatch);
    }

    #[test]
    fn provider_result_admission_rejects_hash_drift_or_wrong_backend() {
        let mut request = provider_result_admission_request();
        request.output_hash = "sha256:drifted".to_string();
        let error = ModelMountCore
            .admit_provider_result(&request)
            .expect_err("output hash must bind output text");

        assert_eq!(error, ModelMountError::ProviderResultOutputHashMismatch);

        let mut request = provider_result_admission_request();
        request.execution_backend = "js_provider_driver_observation".to_string();
        let error = ModelMountCore
            .admit_provider_result(&request)
            .expect_err("JS provider result observations are retired");

        assert_eq!(error, ModelMountError::UnsupportedProviderResultBackend);
    }
}
