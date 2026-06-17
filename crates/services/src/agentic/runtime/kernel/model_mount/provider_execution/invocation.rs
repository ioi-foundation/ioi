use super::{
    backend_evidence_refs, deterministic_provider_output, estimate_tokens,
    hosted_provider_base_url_hash, hosted_provider_transport_binding, provider_auth_evidence_refs,
    provider_invocation_backend, provider_invocation_backend_id, provider_invocation_evidence_refs,
    provider_invocation_hash, provider_invocation_response_kind,
    ModelMountProviderInvocationRequest, ModelMountProviderInvocationResult,
};
use crate::agentic::runtime::kernel::model_mount::{
    ModelMountError, MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
};

pub(super) fn invoke_provider(
    request: &ModelMountProviderInvocationRequest,
) -> Result<ModelMountProviderInvocationResult, ModelMountError> {
    request.validate()?;
    let output_text = deterministic_provider_output(request)?;
    let hosted_transport = hosted_provider_transport_binding(request, &output_text)?;
    let token_count = estimate_tokens(&request.input, &output_text);
    let backend = provider_invocation_backend(request);
    let backend_id = provider_invocation_backend_id(request);
    let mut result = ModelMountProviderInvocationResult {
        schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
        provider_execution_ref: request.provider_execution_ref.clone(),
        provider_execution_hash: request.provider_execution_hash.clone(),
        route_decision_ref: request.route_decision_ref.clone(),
        route_receipt_ref: request.route_receipt_ref.clone(),
        route_ref: request.route_ref.clone(),
        provider_ref: request.provider_ref.clone(),
        provider_kind: request.provider_kind.clone(),
        endpoint_ref: request.endpoint_ref.clone(),
        model_ref: request.model_ref.clone(),
        capability: request.capability.clone(),
        invocation_kind: request.invocation_kind.clone(),
        request_hash: request.request_hash.clone(),
        output_text,
        token_count,
        provider_response_kind: Some(provider_invocation_response_kind(request)),
        backend,
        backend_id,
        execution_backend: request.execution_backend.clone(),
        base_url_hash: hosted_provider_base_url_hash(request)?,
        provider_auth_materialization_ref: request.provider_auth_materialization_ref.clone(),
        outbound_header_binding_ref: request.outbound_header_binding_ref.clone(),
        auth_header_materialization_status: request.auth_header_materialization_status.clone(),
        ctee_egress_resolver_ref: request.ctee_egress_resolver_ref.clone(),
        ctee_egress_resolver_hash: request.ctee_egress_resolver_hash.clone(),
        ctee_egress_resolution_status: request.ctee_egress_resolution_status.clone(),
        hosted_transport_request_ref: hosted_transport
            .as_ref()
            .map(|binding| binding.request_ref.clone()),
        hosted_transport_method: hosted_transport
            .as_ref()
            .map(|binding| binding.method.clone()),
        hosted_transport_path: hosted_transport
            .as_ref()
            .map(|binding| binding.path.clone()),
        hosted_transport_request_hash: hosted_transport
            .as_ref()
            .map(|binding| binding.request_hash.clone()),
        hosted_transport_response_hash: hosted_transport
            .as_ref()
            .map(|binding| binding.response_hash.clone()),
        hosted_transport_status: hosted_transport
            .as_ref()
            .map(|binding| binding.status.clone()),
        provider_auth_evidence_refs: provider_auth_evidence_refs(request),
        backend_evidence_refs: backend_evidence_refs(request),
        evidence_refs: provider_invocation_evidence_refs(request),
        invocation_hash: String::new(),
    };
    result.invocation_hash = provider_invocation_hash(&result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::{
        ModelMountCore, ModelMountProviderExecutionRequest,
    };
    use crate::agentic::runtime::kernel::model_mount::{
        ModelMountProviderExecutionRecord, MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
    };

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
            base_url: None,
            provider_auth_materialization_ref: None,
            outbound_header_binding_ref: None,
            auth_header_materialization_status: None,
            ctee_egress_resolver_ref: None,
            ctee_egress_resolver_hash: None,
            ctee_egress_resolution_status: None,
            stream_status: None,
            receipt_refs: admission.receipt_refs.clone(),
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    #[test]
    fn fixture_provider_invocation_executes_in_dedicated_rust_owner() {
        let result = invoke_provider(&provider_invocation_request())
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
    fn native_local_provider_invocation_executes_in_dedicated_rust_owner() {
        let mut request = provider_invocation_request();
        request.execution_backend = "rust_model_mount_native_local".to_string();
        request.provider_kind = "ioi_native_local".to_string();
        request.api_format = Some("ioi_native".to_string());
        request.driver = Some("native_local".to_string());
        request.backend_ref = Some("backend.hypervisor.native-local.fixture".to_string());
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

        let result =
            invoke_provider(&request).expect("native-local provider invocation executes in Rust");

        assert_eq!(result.execution_backend, "rust_model_mount_native_local");
        assert_eq!(result.backend, "hypervisor.native_local.fixture");
        assert_eq!(result.backend_id, "backend.hypervisor.native-local.fixture");
        assert_eq!(
            result.provider_response_kind.as_deref(),
            Some("rust_model_mount.native_local")
        );
        assert!(result
            .output_text
            .starts_with("Hypervisor native local model response from model://qwen/qwen3.5-9b."));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_native_local_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"deterministic_native_local_fixture".to_string()));
    }

    #[test]
    fn fixture_provider_invocation_requires_bound_provider_execution_in_owner() {
        let mut request = provider_invocation_request();
        request.admitted_provider_execution = None;

        let error = invoke_provider(&request)
            .expect_err("provider invocation requires the full admission record");

        assert_eq!(error, ModelMountError::MissingProviderExecutionAdmission);

        request = provider_invocation_request();
        let admitted_ref = request.provider_execution_ref.clone();
        request.provider_execution_ref = "model_mount://provider_execution/drifted".to_string();

        let error =
            invoke_provider(&request).expect_err("provider execution ref must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionRefMismatch);

        request.provider_execution_ref = admitted_ref;
        request.provider_execution_hash = "sha256:drifted".to_string();
        let error =
            invoke_provider(&request).expect_err("provider execution hash must match admission");

        assert_eq!(error, ModelMountError::ProviderExecutionHashMismatch);
    }
}
