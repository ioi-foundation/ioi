use super::{
    backend_evidence_refs, deterministic_native_local_output, estimate_tokens,
    hosted_provider_base_url_hash, hosted_provider_stream_transport_output,
    hosted_provider_transport_binding, is_hosted_provider_stream_invocation_backend,
    provider_auth_evidence_refs, provider_stream_invocation_hash,
    ModelMountProviderInvocationRequest, ModelMountProviderStreamInvocationResult,
    ModelMountTokenCount,
};
use crate::agentic::runtime::kernel::model_mount::{
    ModelMountError, MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION,
};

pub(super) fn invoke_provider_stream(
    request: &ModelMountProviderInvocationRequest,
) -> Result<ModelMountProviderStreamInvocationResult, ModelMountError> {
    request.validate_stream()?;
    let hosted_provider_stream = is_hosted_provider_stream_invocation_backend(request);
    let (output_text, token_count, stream_chunks) = if hosted_provider_stream {
        let streamed = hosted_provider_stream_transport_output(request)?;
        let token_count = estimate_tokens(&request.input, &streamed.output_text);
        let stream_chunks =
            live_hosted_provider_stream_chunks(&streamed.stream_deltas, &token_count)?;
        (streamed.output_text, token_count, stream_chunks)
    } else {
        let output_text = deterministic_native_local_output(
            &request.invocation_kind,
            &request.input,
            &request.model_ref,
        )?;
        let token_count = estimate_tokens(&request.input, &output_text);
        let stream_chunks = deterministic_stream_chunks(&output_text, &token_count)?;
        (output_text, token_count, stream_chunks)
    };
    let hosted_transport = hosted_provider_transport_binding(request, &output_text)?;
    let mut result = ModelMountProviderStreamInvocationResult {
        schema_version: MODEL_MOUNT_PROVIDER_STREAM_INVOCATION_SCHEMA_VERSION.to_string(),
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
        provider_response_kind: provider_stream_response_kind(request),
        backend: provider_stream_backend(request),
        backend_id: provider_stream_backend_id(request),
        execution_backend: request.execution_backend.clone(),
        base_url_hash: hosted_provider_base_url_hash(request)?,
        provider_auth_materialization_ref: request.provider_auth_materialization_ref.clone(),
        outbound_header_binding_ref: request.outbound_header_binding_ref.clone(),
        auth_header_materialization_status: request.auth_header_materialization_status.clone(),
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
        stream_format: "ioi_jsonl".to_string(),
        stream_kind: provider_stream_kind(request),
        stream_chunks,
        provider_auth_evidence_refs: provider_auth_evidence_refs(request),
        backend_evidence_refs: backend_evidence_refs(request),
        evidence_refs: provider_stream_invocation_evidence_refs(request),
        invocation_hash: String::new(),
    };
    result.invocation_hash = provider_stream_invocation_hash(&result)?;
    Ok(result)
}

fn provider_stream_response_kind(request: &ModelMountProviderInvocationRequest) -> String {
    if is_hosted_provider_stream_invocation_backend(request) {
        return "rust_model_mount.hosted_provider.stream".to_string();
    }
    "rust_model_mount.native_local.stream".to_string()
}

fn provider_stream_backend(request: &ModelMountProviderInvocationRequest) -> String {
    if is_hosted_provider_stream_invocation_backend(request) {
        return request
            .api_format
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("hosted_provider_stream_transport")
            .to_string();
    }
    "autopilot.native_local.fixture".to_string()
}

fn provider_stream_backend_id(request: &ModelMountProviderInvocationRequest) -> String {
    if is_hosted_provider_stream_invocation_backend(request) {
        return request
            .backend_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "backend.hosted.stream.{}",
                    request
                        .provider_kind
                        .trim()
                        .chars()
                        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
                        .collect::<String>()
                        .trim_matches('-')
                        .to_string()
                )
            });
    }
    request
        .backend_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("backend.autopilot.native-local.fixture")
        .to_string()
}

fn provider_stream_kind(request: &ModelMountProviderInvocationRequest) -> String {
    if is_hosted_provider_stream_invocation_backend(request) {
        return hosted_provider_stream_kind(&request.invocation_kind);
    }
    native_local_stream_kind(&request.invocation_kind)
}

fn hosted_provider_stream_kind(invocation_kind: &str) -> String {
    if invocation_kind == "responses" {
        return "openai_responses_hosted_provider".to_string();
    }
    "openai_chat_completions_hosted_provider".to_string()
}

fn native_local_stream_kind(invocation_kind: &str) -> String {
    if invocation_kind == "responses" {
        return "openai_responses_native_local".to_string();
    }
    "openai_chat_completions_native_local".to_string()
}

fn deterministic_stream_chunks(
    output_text: &str,
    token_count: &ModelMountTokenCount,
) -> Result<Vec<String>, ModelMountError> {
    let mut text_chunks = Vec::new();
    let chars: Vec<char> = output_text.chars().collect();
    if chars.is_empty() {
        text_chunks.push(String::new());
    } else {
        for chunk in chars.chunks(64) {
            text_chunks.push(chunk.iter().collect::<String>());
        }
    }
    let mut records = Vec::new();
    for chunk in text_chunks {
        let record = serde_json::json!({
            "delta": chunk,
            "done": false,
        });
        records.push(
            serde_json::to_string(&record)
                .map_err(|error| ModelMountError::HashFailed(error.to_string()))?
                + "\n",
        );
    }
    let done = serde_json::json!({
        "delta": "",
        "done": true,
        "done_reason": "stop",
        "prompt_eval_count": token_count.prompt_tokens,
        "eval_count": token_count.completion_tokens,
    });
    records.push(
        serde_json::to_string(&done)
            .map_err(|error| ModelMountError::HashFailed(error.to_string()))?
            + "\n",
    );
    Ok(records)
}

fn live_hosted_provider_stream_chunks(
    deltas: &[String],
    token_count: &ModelMountTokenCount,
) -> Result<Vec<String>, ModelMountError> {
    if deltas.is_empty() {
        return Err(ModelMountError::HostedProviderTransportExecutionFailed(
            "hosted provider stream yielded no Rust-owned deltas".to_string(),
        ));
    }
    let mut records = Vec::new();
    for delta in deltas {
        let record = serde_json::json!({
            "delta": delta,
            "done": false,
            "source": "rust_hosted_provider_stream_transport",
        });
        records.push(
            serde_json::to_string(&record)
                .map_err(|error| ModelMountError::HashFailed(error.to_string()))?
                + "\n",
        );
    }
    let done = serde_json::json!({
        "delta": "",
        "done": true,
        "done_reason": "stop",
        "source": "rust_hosted_provider_stream_transport",
        "prompt_eval_count": token_count.prompt_tokens,
        "eval_count": token_count.completion_tokens,
    });
    records.push(
        serde_json::to_string(&done)
            .map_err(|error| ModelMountError::HashFailed(error.to_string()))?
            + "\n",
    );
    Ok(records)
}

fn provider_stream_invocation_evidence_refs(
    request: &ModelMountProviderInvocationRequest,
) -> Vec<String> {
    let mut refs = vec![
        "rust_model_mount_provider_stream_invocation".to_string(),
        request.provider_execution_ref.clone(),
    ];
    if is_hosted_provider_stream_invocation_backend(request) {
        refs.push("rust_model_mount_hosted_provider_stream_backend".to_string());
        refs.push("rust_hosted_provider_stream_transport_materialized".to_string());
        refs.push("rust_hosted_provider_stream_live_chunks_executed".to_string());
        refs.push("rust_hosted_provider_stream_semantics_owned".to_string());
        refs.push("rust_hosted_provider_stream_sse_chunks_bound".to_string());
        refs.push("rust_hosted_provider_transport_request_bound".to_string());
        refs.push("rust_hosted_provider_transport_response_bound".to_string());
        refs.push("rust_hosted_provider_endpoint_url_bound".to_string());
        refs.push("wallet_network_provider_transport_authority_bound".to_string());
        refs.push("ctee_hosted_provider_secret_not_exposed".to_string());
        refs.push("ctee_outbound_header_binding_ref_bound".to_string());
        refs.push("rust_provider_auth_materialization_bound".to_string());
        refs.push("hosted_provider_auth_header_materialized_by_rust".to_string());
        refs.push("hosted_provider_auth_header_materialization_contract_bound".to_string());
    } else {
        refs.push("rust_model_mount_native_local_stream_backend".to_string());
        refs.push("autopilot_native_local_openai_compatible_serving".to_string());
        refs.push("deterministic_native_local_fixture".to_string());
    }
    for evidence_ref in provider_auth_evidence_refs(request)
        .iter()
        .chain(backend_evidence_refs(request).iter())
    {
        if !evidence_ref.trim().is_empty() && !refs.contains(evidence_ref) {
            refs.push(evidence_ref.clone());
        }
    }
    for evidence_ref in &request.evidence_refs {
        if !evidence_ref.trim().is_empty() && !refs.contains(evidence_ref) {
            refs.push(evidence_ref.clone());
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::{
        ModelMountCore, ModelMountProviderExecutionRequest,
        MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
        MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::{self, JoinHandle};

    fn hosted_transport_server(response_body: &'static str) -> (String, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("hosted stream test server binds");
        let address = listener
            .local_addr()
            .expect("hosted stream test server address");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("hosted stream request accepted");
            let mut buffer = [0_u8; 8192];
            let read = stream
                .read(&mut buffer)
                .expect("hosted stream request read");
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("hosted stream response written");
            request
        });
        (format!("http://{address}"), handle)
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
            stream_status: Some("started".to_string()),
        }
    }

    fn provider_stream_invocation_request() -> ModelMountProviderInvocationRequest {
        let admission = ModelMountCore
            .admit_provider_execution(&provider_execution_request())
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
            base_url: None,
            provider_auth_materialization_ref: None,
            outbound_header_binding_ref: None,
            auth_header_materialization_status: None,
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    fn hosted_provider_stream_invocation_request() -> ModelMountProviderInvocationRequest {
        let mut execution_request = provider_execution_request();
        execution_request.provider_ref = "provider.openai".to_string();
        execution_request.endpoint_ref = "endpoint.openai".to_string();
        execution_request.model_ref = "model.openai.gpt-4.1".to_string();
        execution_request.provider_auth_evidence_refs = vec![
            "rust_model_mount_hosted_provider_auth_gate".to_string(),
            "wallet_network_provider_vault_ref_bound".to_string(),
            "ctee_hosted_provider_secret_not_exposed".to_string(),
            "rust_provider_auth_materialization_bound".to_string(),
            "provider_vault_ref_hash:sha256-vault".to_string(),
        ];
        let admission = ModelMountCore
            .admit_provider_execution(&execution_request)
            .expect("hosted stream provider execution admitted");
        ModelMountProviderInvocationRequest {
            schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
            provider_execution_ref: admission.provider_execution_ref.clone(),
            provider_execution_hash: admission.provider_execution_hash.clone(),
            route_decision_ref: admission.route_decision_ref.clone(),
            route_receipt_ref: admission.route_receipt_ref.clone(),
            route_ref: admission.route_ref.clone(),
            provider_ref: admission.provider_ref.clone(),
            provider_kind: "openai".to_string(),
            endpoint_ref: admission.endpoint_ref.clone(),
            model_ref: admission.model_ref.clone(),
            capability: admission.capability.clone(),
            invocation_kind: admission.invocation_kind.clone(),
            input: "user: hosted stream".to_string(),
            request_hash: admission.request_hash.clone(),
            execution_backend: "rust_model_mount_hosted_provider_stream".to_string(),
            api_format: Some("openai".to_string()),
            driver: Some("openai_compatible".to_string()),
            backend_ref: Some("backend.openai-compatible".to_string()),
            base_url: Some("https://api.openai.example/v1".to_string()),
            provider_auth_materialization_ref: Some(
                "agentgres://model-mounting/model-provider-auth-materializations/provider.openai_auth_header"
                    .to_string(),
            ),
            outbound_header_binding_ref: Some(
                "provider_auth_header://provider.openai_auth_header#sha256:provider-auth"
                    .to_string(),
            ),
            auth_header_materialization_status: Some("rust_ctee_outbound_header_bound".to_string()),
            stream_status: admission.stream_status.clone(),
            receipt_refs: admission.receipt_refs.clone(),
            evidence_refs: vec![admission.provider_execution_ref.clone()],
            admitted_provider_execution: Some(admission),
        }
    }

    #[test]
    fn native_local_provider_stream_invocation_executes_in_dedicated_rust_owner() {
        let request = provider_stream_invocation_request();
        let result = invoke_provider_stream(&request)
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
    fn native_local_provider_stream_invocation_rejects_unstarted_or_wrong_backends_in_owner() {
        let mut request = provider_stream_invocation_request();
        request.stream_status = None;
        let error = invoke_provider_stream(&request)
            .expect_err("stream invocation requires started admission");

        assert_eq!(error, ModelMountError::StreamProviderInvocationUnsupported);

        let mut request = provider_stream_invocation_request();
        request.execution_backend = "js_provider_driver_observation".to_string();
        let error = invoke_provider_stream(&request)
            .expect_err("stream invocation requires Rust native-local stream backend");

        assert_eq!(error, ModelMountError::UnsupportedProviderInvocationBackend);
    }

    #[test]
    fn hosted_provider_stream_invocation_executes_transport_contract_in_rust_owner() {
        let mut missing_auth = hosted_provider_stream_invocation_request();
        missing_auth
            .admitted_provider_execution
            .as_mut()
            .expect("admission")
            .provider_auth_evidence_refs
            .clear();
        let error = invoke_provider_stream(&missing_auth)
            .expect_err("hosted provider stream requires auth evidence");

        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingAuthEvidence
        );

        let (base_url, hosted_request) = hosted_transport_server(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"live hosted \"}\n\n\
             data: {\"type\":\"response.output_text.delta\",\"delta\":\"stream answer\"}\n\n\
             data: [DONE]\n\n",
        );
        let mut request = hosted_provider_stream_invocation_request();
        request.base_url = Some(format!("{base_url}/v1"));
        let result =
            invoke_provider_stream(&request).expect("hosted provider stream executes in Rust");
        let raw_hosted_request = hosted_request
            .join()
            .expect("hosted stream request captured");

        assert_eq!(
            result.execution_backend,
            "rust_model_mount_hosted_provider_stream"
        );
        assert_eq!(
            result.provider_response_kind,
            "rust_model_mount.hosted_provider.stream"
        );
        assert_eq!(result.backend, "openai");
        assert_eq!(result.backend_id, "backend.openai-compatible");
        assert_eq!(result.stream_format, "ioi_jsonl");
        assert_eq!(result.stream_kind, "openai_responses_hosted_provider");
        assert_eq!(result.output_text, "live hosted stream answer");
        assert!(raw_hosted_request.contains("POST /v1/responses HTTP/1.1"));
        assert!(raw_hosted_request
            .to_ascii_lowercase()
            .contains("accept: text/event-stream"));
        assert!(raw_hosted_request
            .to_ascii_lowercase()
            .contains("x-ioi-outbound-header-binding-ref"));
        assert!(result
            .provider_auth_evidence_refs
            .contains(&"wallet_network_provider_vault_ref_bound".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_stream_transport_materialized".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_stream_live_chunks_executed".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_stream_semantics_owned".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_stream_sse_chunks_bound".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_live_network_io_executed".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_transport_executor_owned".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_transport_request_bound".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"rust_hosted_provider_transport_response_bound".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"rust_model_mount_hosted_provider_stream_backend".to_string()));
        assert!(result
            .evidence_refs
            .contains(&"ctee_hosted_provider_secret_not_exposed".to_string()));
        assert!(result
            .backend_evidence_refs
            .contains(&"ctee_outbound_secret_injection_ref_bound".to_string()));
        assert!(result.hosted_transport_request_ref.is_some());
        assert_eq!(result.hosted_transport_method.as_deref(), Some("POST"));
        assert_eq!(result.hosted_transport_path.as_deref(), Some("/responses"));
        assert!(result.hosted_transport_request_hash.is_some());
        assert!(result.hosted_transport_response_hash.is_some());
        assert_eq!(
            result.hosted_transport_status.as_deref(),
            Some("rust_hosted_provider_transport_response_bound")
        );
        assert!(result.stream_chunks.len() >= 2);
        assert!(result.stream_chunks[0].contains("live hosted "));
        assert!(result.stream_chunks[0].contains("rust_hosted_provider_stream_transport"));
        assert!(result.stream_chunks[1].contains("stream answer"));
        assert!(result.invocation_hash.starts_with("sha256:"));

        let mut missing_authority = hosted_provider_stream_invocation_request();
        missing_authority
            .admitted_provider_execution
            .as_mut()
            .expect("admission")
            .authority_grant_refs
            .clear();
        let error = invoke_provider_stream(&missing_authority)
            .expect_err("hosted provider stream requires wallet authority");

        assert_eq!(
            error,
            ModelMountError::HostedProviderInvocationMissingAuthority
        );
    }

    #[test]
    fn stream_owner_keeps_backend_gate_before_chunk_planning() {
        let request = provider_stream_invocation_request();
        assert!(super::super::is_native_local_provider_stream_invocation_backend(&request));
    }
}
