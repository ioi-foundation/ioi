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
}
