use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{
    provider_execution::{
        ModelMountProviderExecutionRecord, ModelMountProviderExecutionRequest,
        ModelMountProviderInvocationRequest,
    },
    provider_result::ModelMountProviderResultAdmissionRequest,
    require_non_empty, sha256_hex, ModelMountError, ModelMountInvocationAdmissionRequest,
    MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION,
    MODEL_MOUNT_INVOCATION_AUTHORITY_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_INVOCATION_AUTHORITY_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION, MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountInvocationAuthorityRequest {
    pub schema_version: String,
    pub operation: String,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub selection: Value,
    #[serde(default)]
    pub instance: Value,
    #[serde(default)]
    pub route_receipt: Value,
    #[serde(default)]
    pub ephemeral_mcp: Value,
    #[serde(default)]
    pub token: Value,
    #[serde(default)]
    pub provider_execution_admission: Value,
    #[serde(default)]
    pub provider_result: Value,
    #[serde(default)]
    pub provider_result_admission: Value,
    #[serde(default)]
    pub invocation_admission: Value,
    #[serde(default)]
    pub invocation_admission_request: Value,
    #[serde(default)]
    pub agentgres_transition: Value,
    #[serde(default)]
    pub current_head: Value,
    #[serde(default)]
    pub receipt_details: Value,
    #[serde(default)]
    pub continuation: Value,
    #[serde(default)]
    pub input: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub capability: String,
    #[serde(default)]
    pub response_id: Option<String>,
    #[serde(default)]
    pub previous_response_id: Option<String>,
    #[serde(default)]
    pub required_scope: Option<String>,
    #[serde(default)]
    pub receipt_id: String,
    #[serde(default)]
    pub receipt_kind: String,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub stream_status: Option<String>,
    #[serde(default)]
    pub latency_ms: u64,
}

pub fn plan_model_mount_invocation_authority(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<Value, ModelMountError> {
    request.validate()?;
    let mut plan = base_plan(&request.operation);
    match request.operation.as_str() {
        "provider_execution" => {
            let provider_execution_request = provider_execution_request(request)?;
            plan_insert(
                &mut plan,
                "provider_execution_request",
                json!(provider_execution_request),
            );
        }
        "provider_invocation" | "provider_stream_invocation" => {
            let provider_invocation_request = provider_invocation_request(
                request,
                request.operation == "provider_stream_invocation",
            )?;
            plan_insert(
                &mut plan,
                "provider_invocation_request",
                json!(provider_invocation_request),
            );
        }
        "provider_result_admission" => {
            let provider_result_request = provider_result_admission_request(request)?;
            plan_insert(
                &mut plan,
                "provider_result_admission_request",
                json!(provider_result_request),
            );
        }
        "invocation_admission" => {
            let receipt_details = invocation_receipt_details(request)?;
            let invocation_admission_request =
                invocation_admission_request(request, &receipt_details)?;
            plan_insert(&mut plan, "receipt_details", receipt_details);
            plan_insert(
                &mut plan,
                "invocation_admission_request",
                json!(invocation_admission_request),
            );
        }
        "accepted_receipt_transition" => {
            plan_insert(
                &mut plan,
                "accepted_receipt_transition_request",
                accepted_receipt_transition_request(request)?,
            );
        }
        "receipt_binding" => {
            plan_insert(
                &mut plan,
                "receipt_binding_request",
                receipt_binding_request(request)?,
            );
        }
        _ => return Err(ModelMountError::UnsupportedInvocationAuthorityOperation),
    }
    let evidence_refs = plan
        .as_object_mut()
        .expect("plan object")
        .get_mut("evidence_refs")
        .and_then(Value::as_array_mut)
        .expect("evidence array");
    evidence_refs.push(Value::String(format!(
        "rust_model_mount_invocation_authority_{}",
        request.operation
    )));
    Ok(plan)
}

impl ModelMountInvocationAuthorityRequest {
    fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_INVOCATION_AUTHORITY_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_INVOCATION_AUTHORITY_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        Ok(())
    }
}

fn base_plan(operation: &str) -> Value {
    json!({
        "schema_version": MODEL_MOUNT_INVOCATION_AUTHORITY_PLAN_SCHEMA_VERSION,
        "source": "rust_daemon_core.model_mount.invocation_authority",
        "rust_core_boundary": "model_mount.invocation_authority",
        "operation": operation,
        "evidence_refs": [
            "rust_daemon_core_model_mount_invocation_authority",
            "model_mount_invocation_contract_js_authoring_retired",
            "agentgres_model_invocation_truth_required",
            "step_module_router_model_invocation_dispatch_bound"
        ]
    })
}

fn provider_execution_request(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<ModelMountProviderExecutionRequest, ModelMountError> {
    let route_receipt_ref = receipt_ref(&required_string_path(
        &request.route_receipt,
        &["id"],
        "route_receipt.id",
    )?);
    let route_decision_ref = route_decision_ref(request)?;
    let endpoint_id = endpoint_string(request, "id", "endpoint.id")?;
    let kind = non_empty_request_field(&request.kind, "kind")?;
    let stream_status = request.stream_status.clone();
    let request_hash = hash_ref(&stable_js_hash(&json!({
        "endpointId": endpoint_id,
        "invocationKind": kind,
        "providerBody": request.body.clone(),
        "streamStatus": stream_status.clone(),
    }))?);
    let input_hash = hash_text(&request.input)?;
    let policy_hash = hash_ref(&stable_js_hash(
        request
            .body
            .get("model_policy")
            .unwrap_or(&Value::Object(Map::new())),
    )?);
    let provider_execution = ModelMountProviderExecutionRequest {
        schema_version: MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION.to_string(),
        invocation_ref: format!(
            "model-provider-execution://{}",
            request_hash.replacen("sha256:", "sha256/", 1)
        ),
        route_decision_ref,
        route_receipt_ref: route_receipt_ref.clone(),
        route_ref: route_string(request, "id", "route.id")?,
        provider_ref: provider_string(request, "id", "provider.id")?,
        endpoint_ref: endpoint_id,
        model_ref: endpoint_string(request, "model_id", "endpoint.model_id")?,
        capability: non_empty_request_field(&request.capability, "capability")?,
        invocation_kind: kind,
        policy_hash,
        input_hash,
        request_hash: request_hash.clone(),
        idempotency_key: format!("model_provider_execution:{route_receipt_ref}:{request_hash}"),
        receipt_refs: unique_strings(
            std::iter::once(Some(route_receipt_ref)).chain(
                string_array_path(&request.ephemeral_mcp, &["tool_receipt_ids"])
                    .into_iter()
                    .map(|value| Some(receipt_ref(&value))),
            ),
        ),
        authority_grant_refs: unique_strings(
            std::iter::once(optional_string_path(&request.token, &["grant_ref"])).chain(
                string_array_path(&request.body, &["authority_grant_refs"])
                    .into_iter()
                    .map(Some),
            ),
        ),
        authority_receipt_refs: string_array_path(&request.body, &["authority_receipt_refs"]),
        provider_auth_evidence_refs: hosted_provider_auth_evidence_refs(request)?,
        backend_evidence_refs: unique_strings([
            optional_string_path(&request.instance, &["backend_id"]),
            optional_endpoint_string(request, "backend_id"),
        ]),
        tool_receipt_refs: string_array_path(&request.ephemeral_mcp, &["tool_receipt_ids"]),
        custody_ref: invocation_custody_ref(request),
        privacy_profile: invocation_privacy_profile(request),
        node_plaintext_allowed: invocation_node_plaintext_allowed(request),
        workflow_graph_ref: optional_route_receipt_detail(request, "workflow_graph_id"),
        workflow_node_ref: optional_route_receipt_detail(request, "workflow_node_id"),
        response_ref: request.response_id.clone(),
        previous_response_ref: request.previous_response_id.clone(),
        stream_status,
    };
    provider_execution.validate()?;
    Ok(provider_execution)
}

fn provider_invocation_request(
    request: &ModelMountInvocationAuthorityRequest,
    stream: bool,
) -> Result<ModelMountProviderInvocationRequest, ModelMountError> {
    let admission = provider_execution_admission_record(request)?;
    let provider_invocation = ModelMountProviderInvocationRequest {
        schema_version: MODEL_MOUNT_PROVIDER_INVOCATION_SCHEMA_VERSION.to_string(),
        provider_execution_ref: admission.provider_execution_ref.clone(),
        provider_execution_hash: admission.provider_execution_hash.clone(),
        route_decision_ref: admission.route_decision_ref.clone(),
        route_receipt_ref: admission.route_receipt_ref.clone(),
        route_ref: admission.route_ref.clone(),
        provider_ref: admission.provider_ref.clone(),
        provider_kind: provider_string(request, "kind", "provider.kind")?,
        endpoint_ref: admission.endpoint_ref.clone(),
        model_ref: admission.model_ref.clone(),
        capability: admission.capability.clone(),
        invocation_kind: admission.invocation_kind.clone(),
        input: request.input.clone(),
        request_hash: admission.request_hash.clone(),
        execution_backend: provider_invocation_backend(request, stream)?,
        api_format: optional_endpoint_or_provider_string(request, "api_format"),
        driver: optional_endpoint_or_provider_string(request, "driver"),
        backend_ref: optional_string_path(&request.instance, &["backend_id"])
            .or_else(|| optional_endpoint_string(request, "backend_id")),
        base_url: optional_endpoint_or_provider_string(request, "base_url"),
        provider_auth_materialization_ref: optional_endpoint_or_provider_string(
            request,
            "provider_auth_materialization_ref",
        ),
        outbound_header_binding_ref: optional_endpoint_or_provider_string(
            request,
            "outbound_header_binding_ref",
        ),
        auth_header_materialization_status: optional_endpoint_or_provider_string(
            request,
            "auth_header_materialization_status",
        ),
        ctee_egress_resolver_ref: optional_endpoint_or_provider_string(
            request,
            "ctee_egress_resolver_ref",
        ),
        ctee_egress_resolver_hash: optional_endpoint_or_provider_string(
            request,
            "ctee_egress_resolver_hash",
        ),
        ctee_egress_resolution_status: optional_endpoint_or_provider_string(
            request,
            "ctee_egress_resolution_status",
        ),
        stream_status: if stream {
            Some("started".to_string())
        } else {
            admission.stream_status.clone()
        },
        receipt_refs: admission.receipt_refs.clone(),
        evidence_refs: unique_strings(
            std::iter::once(Some(admission.provider_execution_ref.clone())).chain(
                string_array_path(&request.provider_execution_admission, &["evidence_refs"])
                    .into_iter()
                    .map(Some),
            ),
        ),
        admitted_provider_execution: Some(admission),
    };
    if stream {
        provider_invocation.validate_stream()?;
    } else {
        provider_invocation.validate()?;
    }
    Ok(provider_invocation)
}

fn provider_result_admission_request(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<ModelMountProviderResultAdmissionRequest, ModelMountError> {
    let admission = provider_execution_admission_record(request)?;
    let stream = admission
        .stream_status
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let output_text = string_path_or(&request.provider_result, &["output_text"], "");
    let provider_result = ModelMountProviderResultAdmissionRequest {
        schema_version: MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION.to_string(),
        provider_execution_ref: admission.provider_execution_ref.clone(),
        provider_execution_hash: admission.provider_execution_hash.clone(),
        route_decision_ref: admission.route_decision_ref.clone(),
        route_receipt_ref: admission.route_receipt_ref.clone(),
        route_ref: admission.route_ref.clone(),
        provider_ref: admission.provider_ref.clone(),
        provider_kind: provider_string(request, "kind", "provider.kind")?,
        endpoint_ref: admission.endpoint_ref.clone(),
        model_ref: admission.model_ref.clone(),
        capability: admission.capability.clone(),
        invocation_kind: admission.invocation_kind.clone(),
        request_hash: admission.request_hash.clone(),
        output_text: output_text.clone(),
        output_hash: hash_text(&output_text)?,
        token_count: serde_json::from_value(
            request
                .provider_result
                .get("token_count")
                .cloned()
                .unwrap_or_else(
                    || json!({"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}),
                ),
        )
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?,
        provider_response_kind: optional_string_path(
            &request.provider_result,
            &["provider_response_kind"],
        ),
        execution_backend: string_path(
            &request.provider_result,
            &["execution_backend"],
            "provider_result.execution_backend",
        )?,
        backend_ref: optional_string_path(&request.provider_result, &["backend_id"])
            .or_else(|| optional_string_path(&request.instance, &["backend_id"]))
            .or_else(|| optional_endpoint_string(request, "backend_id")),
        stream_status: if stream {
            admission.stream_status.clone()
        } else {
            None
        },
        hosted_transport_request_ref: optional_string_path(
            &request.provider_result,
            &["hosted_transport_request_ref"],
        ),
        hosted_transport_request_hash: optional_string_path(
            &request.provider_result,
            &["hosted_transport_request_hash"],
        ),
        hosted_transport_response_hash: optional_string_path(
            &request.provider_result,
            &["hosted_transport_response_hash"],
        ),
        hosted_transport_status: optional_string_path(
            &request.provider_result,
            &["hosted_transport_status"],
        ),
        ctee_egress_resolver_ref: optional_string_path(
            &request.provider_result,
            &["ctee_egress_resolver_ref"],
        ),
        ctee_egress_resolver_hash: optional_string_path(
            &request.provider_result,
            &["ctee_egress_resolver_hash"],
        ),
        ctee_egress_resolution_status: optional_string_path(
            &request.provider_result,
            &["ctee_egress_resolution_status"],
        ),
        receipt_refs: admission.receipt_refs.clone(),
        provider_auth_evidence_refs: string_array_path(
            &request.provider_result,
            &["provider_auth_evidence_refs"],
        ),
        backend_evidence_refs: string_array_path(
            &request.provider_result,
            &["backend_evidence_refs"],
        ),
        evidence_refs: unique_strings(
            std::iter::once(Some(admission.provider_execution_ref.clone())).chain(
                string_array_path(&request.provider_execution_admission, &["evidence_refs"])
                    .into_iter()
                    .map(Some),
            ),
        ),
        admitted_provider_execution: Some(admission),
    };
    provider_result.validate()?;
    Ok(provider_result)
}

fn invocation_admission_request(
    request: &ModelMountInvocationAuthorityRequest,
    receipt_details: &Value,
) -> Result<ModelMountInvocationAdmissionRequest, ModelMountError> {
    let route_receipt_ref = receipt_ref(&required_string_path(
        &request.route_receipt,
        &["id"],
        "route_receipt.id",
    )?);
    let invocation_receipt_ref =
        receipt_ref(&non_empty_request_field(&request.receipt_id, "receipt_id")?);
    let invocation_admission = ModelMountInvocationAdmissionRequest {
        schema_version: MODEL_MOUNT_INVOCATION_ADMISSION_SCHEMA_VERSION.to_string(),
        invocation_ref: format!(
            "model-invocation://{}",
            non_empty_request_field(&request.receipt_id, "receipt_id")?
        ),
        route_decision_ref: route_decision_ref(request)?,
        route_receipt_ref: route_receipt_ref.clone(),
        invocation_receipt_ref: invocation_receipt_ref.clone(),
        route_ref: route_string(request, "id", "route.id")?,
        provider_ref: provider_string(request, "id", "provider.id")?,
        endpoint_ref: endpoint_string(request, "id", "endpoint.id")?,
        model_ref: endpoint_string(request, "model_id", "endpoint.model_id")?,
        capability: non_empty_request_field(&request.capability, "capability")?,
        invocation_kind: non_empty_request_field(&request.kind, "kind")?,
        policy_hash: hash_ref(&string_path(
            receipt_details,
            &["policy_hash"],
            "receipt_details.policy_hash",
        )?),
        input_hash: hash_ref(&string_path(
            receipt_details,
            &["input_hash"],
            "receipt_details.input_hash",
        )?),
        output_hash: hash_ref(&string_path(
            receipt_details,
            &["output_hash"],
            "receipt_details.output_hash",
        )?),
        idempotency_key: format!(
            "{}:{}",
            non_empty_request_field(&request.receipt_kind, "receipt_kind")?,
            request.receipt_id
        ),
        receipt_refs: unique_strings(
            [Some(route_receipt_ref), Some(invocation_receipt_ref)]
                .into_iter()
                .chain(
                    string_array_path(receipt_details, &["tool_receipt_ids"])
                        .into_iter()
                        .map(|value| Some(receipt_ref(&value))),
                ),
        ),
        authority_grant_refs: unique_strings(
            std::iter::once(optional_string_path(receipt_details, &["grant_id"])).chain(
                string_array_path(&request.body, &["authority_grant_refs"])
                    .into_iter()
                    .map(Some),
            ),
        ),
        authority_receipt_refs: string_array_path(&request.body, &["authority_receipt_refs"]),
        provider_auth_evidence_refs: string_array_path(
            receipt_details,
            &["provider_auth_evidence_refs"],
        ),
        backend_evidence_refs: string_array_path(receipt_details, &["backend_evidence_refs"]),
        tool_receipt_refs: string_array_path(receipt_details, &["tool_receipt_ids"]),
        custody_ref: invocation_custody_ref(request),
        privacy_profile: invocation_privacy_profile(request),
        node_plaintext_allowed: invocation_node_plaintext_allowed(request),
        workflow_graph_ref: optional_route_receipt_detail(request, "workflow_graph_id"),
        workflow_node_ref: optional_route_receipt_detail(request, "workflow_node_id"),
        response_ref: optional_string_path(receipt_details, &["response_id"]),
        previous_response_ref: optional_string_path(receipt_details, &["previous_response_id"]),
        stream_status: optional_string_path(receipt_details, &["stream_status"]),
    };
    invocation_admission.validate()?;
    Ok(invocation_admission)
}

fn invocation_receipt_details(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<Value, ModelMountError> {
    let provider_result = &request.provider_result;
    let provider_result_admission = &request.provider_result_admission;
    let backend_id = optional_string_path(provider_result, &["backend_id"])
        .or_else(|| optional_string_path(&request.instance, &["backend_id"]))
        .or_else(|| optional_endpoint_string(request, "backend_id"));
    let input_hash = stable_js_hash(&Value::String(request.input.clone()))?;
    let output_text = string_path_or(provider_result, &["output_text"], "");
    let output_hash = stable_js_hash(&Value::String(output_text))?;
    let mut details = Map::new();
    details.insert(
        "route_id".to_string(),
        json!(route_string(request, "id", "route.id")?),
    );
    details.insert(
        "route_receipt_id".to_string(),
        json!(required_string_path(
            &request.route_receipt,
            &["id"],
            "route_receipt.id"
        )?),
    );
    details.insert(
        "selected_model".to_string(),
        json!(endpoint_string(request, "model_id", "endpoint.model_id")?),
    );
    details.insert(
        "endpoint_id".to_string(),
        json!(endpoint_string(request, "id", "endpoint.id")?),
    );
    details.insert(
        "provider_id".to_string(),
        json!(provider_string(request, "id", "provider.id")?),
    );
    details.insert(
        "instance_id".to_string(),
        json!(string_path(&request.instance, &["id"], "instance.id")?),
    );
    details.insert(
        "backend".to_string(),
        json!(
            optional_string_path(provider_result, &["execution_backend"])
                .or_else(|| optional_endpoint_or_provider_string(request, "api_format"))
        ),
    );
    details.insert("backend_id".to_string(), json!(backend_id.clone()));
    details.insert("selected_backend".to_string(), json!(backend_id));
    details.insert(
        "policy_hash".to_string(),
        json!(stable_js_hash(
            request
                .body
                .get("model_policy")
                .unwrap_or(&Value::Object(Map::new()))
        )?),
    );
    details.insert("required_scope".to_string(), json!(request.required_scope));
    details.insert(
        "grant_id".to_string(),
        json!(optional_string_path(&request.token, &["grant_ref"])),
    );
    details.insert(
        "token_count".to_string(),
        provider_result
            .get("token_count")
            .cloned()
            .unwrap_or(Value::Null),
    );
    details.insert("latency_ms".to_string(), json!(request.latency_ms));
    details.insert("input_hash".to_string(), json!(input_hash));
    details.insert("output_hash".to_string(), json!(output_hash));
    details.insert(
        "provider_response_kind".to_string(),
        json!(optional_string_path(
            provider_result,
            &["provider_response_kind"]
        )),
    );
    details.insert(
        "backend_process".to_string(),
        request
            .instance
            .get("backend_process")
            .cloned()
            .unwrap_or(Value::Null),
    );
    details.insert(
        "backend_process_id".to_string(),
        json!(optional_string_path(
            &request.instance,
            &["backend_process_id"]
        )),
    );
    details.insert(
        "backend_process_pid_hash".to_string(),
        json!(optional_string_path(
            &request.instance,
            &["backend_process_pid_hash"]
        )),
    );
    details.insert(
        "backend_evidence_refs".to_string(),
        json!(string_array_path(
            provider_result,
            &["backend_evidence_refs"]
        )),
    );
    details.insert(
        "provider_auth_evidence_refs".to_string(),
        json!(string_array_path(
            provider_result,
            &["provider_auth_evidence_refs"]
        )),
    );
    details.insert("provider_auth_header_names".to_string(), json!([]));
    details.insert(
        "model_mount_route_decision_ref".to_string(),
        json!(route_decision_ref(request)?),
    );
    details.insert(
        "model_mount_provider_result_admission_schema_version".to_string(),
        json!(optional_string_path(
            provider_result,
            &["model_mount_provider_result_admission_schema_version"]
        )
        .or_else(|| Some(MODEL_MOUNT_PROVIDER_RESULT_SCHEMA_VERSION.to_string()))),
    );
    details.insert(
        "model_mount_provider_result_admission_ref".to_string(),
        json!(optional_string_path(
            provider_result_admission,
            &["provider_result_ref"]
        )),
    );
    details.insert(
        "model_mount_provider_result_admission_hash".to_string(),
        json!(optional_string_path(
            provider_result_admission,
            &["provider_result_hash"]
        )),
    );
    details.insert(
        "model_mount_provider_result_admission_source".to_string(),
        json!(optional_string_path(provider_result_admission, &["source"])),
    );
    details.insert(
        "model_mount_provider_result_admission_backend".to_string(),
        json!(optional_string_path(
            provider_result_admission,
            &["backend"]
        )),
    );
    details.insert(
        "model_mount_provider_result_admission_receipt_refs".to_string(),
        json!(string_array_path(
            provider_result_admission,
            &["receipt_refs"]
        )),
    );
    details.insert(
        "model_mount_provider_result_admission_evidence_refs".to_string(),
        json!(string_array_path(
            provider_result_admission,
            &["evidence_refs"]
        )),
    );
    details.insert(
        "model_mount_provider_result_admission".to_string(),
        provider_result_admission
            .get("record")
            .cloned()
            .unwrap_or(Value::Null),
    );
    details.insert(
        "tool_receipt_ids".to_string(),
        json!(string_array_path(
            &request.ephemeral_mcp,
            &["tool_receipt_ids"]
        )),
    );
    details.insert(
        "ephemeral_mcp_server_ids".to_string(),
        json!(string_array_path(&request.ephemeral_mcp, &["server_ids"])),
    );
    details.insert("response_id".to_string(), json!(request.response_id));
    details.insert(
        "previous_response_id".to_string(),
        json!(request.previous_response_id),
    );
    details.insert("continuation".to_string(), request.continuation.clone());
    details.insert(
        "invocation_kind".to_string(),
        json!(if request.stream {
            "model_mount.invocation.stream_start"
        } else {
            "model_mount.invocation.invoke"
        }),
    );
    details.insert(
        "stream_status".to_string(),
        json!(if request.stream {
            Some("started")
        } else {
            None::<&str>
        }),
    );
    details.insert(
        "stream_source".to_string(),
        json!(if request.stream {
            Some("provider_native")
        } else {
            None::<&str>
        }),
    );
    details.insert(
        "send_options".to_string(),
        request
            .body
            .get("send_options")
            .cloned()
            .unwrap_or(Value::Null),
    );
    details.insert(
        "memory".to_string(),
        request
            .body
            .get("memory")
            .cloned()
            .or_else(|| request.body.pointer("/send_options/memory").cloned())
            .unwrap_or(Value::Null),
    );
    Ok(Value::Object(details))
}

fn accepted_receipt_transition_request(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<Value, ModelMountError> {
    let admission = &request.invocation_admission;
    Ok(json!({
        "schema_version": "ioi.model_mount.accepted_receipt_transition.v1",
        "current_sequence": number_path(&request.current_head, &["sequence"]).unwrap_or(0),
        "current_head_ref": string_path(&request.current_head, &["head_ref"], "current_head.head_ref")?,
        "current_state_root": hash_ref(&string_path(&request.current_head, &["state_root"], "current_head.state_root")?),
        "receipt_id": non_empty_request_field(&request.receipt_id, "receipt_id")?,
        "receipt_kind": non_empty_request_field(&request.receipt_kind, "receipt_kind")?,
        "route_decision_ref": optional_string_path(&request.invocation_admission_request, &["route_decision_ref"]),
        "invocation_admission_ref": optional_string_path(admission, &["invocation_admission_ref"]),
        "invocation_admission_hash": optional_string_path(admission, &["invocation_admission_hash"]),
        "input_hash": optional_string_path(&request.invocation_admission_request, &["input_hash"])
            .or_else(|| optional_string_path(&request.receipt_details, &["input_hash"])),
        "output_hash": optional_string_path(&request.invocation_admission_request, &["output_hash"])
            .or_else(|| optional_string_path(&request.receipt_details, &["output_hash"]))
    }))
}

fn receipt_binding_request(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<Value, ModelMountError> {
    let admission_request = &request.invocation_admission_request;
    let transition = &request.agentgres_transition;
    let receipt_ref = receipt_ref(&non_empty_request_field(&request.receipt_id, "receipt_id")?);
    let invocation_ref = string_path(
        admission_request,
        &["invocation_ref"],
        "admission_request.invocation_ref",
    )?;
    let workflow_graph_id = optional_string_path(admission_request, &["workflow_graph_ref"])
        .unwrap_or_else(|| "workflow:model-mount".to_string());
    let workflow_node_id = optional_string_path(admission_request, &["workflow_node_ref"])
        .unwrap_or_else(|| format!("node:model-mount:{}", request.receipt_id));
    let authority_grant_refs = string_array_path(admission_request, &["authority_grant_refs"]);
    let context_refs = unique_strings([
        optional_string_path(admission_request, &["route_ref"]),
        optional_string_path(admission_request, &["provider_ref"]),
        optional_string_path(admission_request, &["endpoint_ref"]),
        optional_string_path(admission_request, &["model_ref"]),
        optional_string_path(admission_request, &["route_decision_ref"]),
        optional_string_path(admission_request, &["route_receipt_ref"]),
    ]);
    let module_id = format!(
        "{}:{}:{}",
        string_path(
            admission_request,
            &["capability"],
            "admission_request.capability"
        )?,
        string_path(
            admission_request,
            &["route_ref"],
            "admission_request.route_ref"
        )?,
        string_path(
            admission_request,
            &["endpoint_ref"],
            "admission_request.endpoint_ref"
        )?
    );
    let invocation = json!({
        "schema_version": "ioi.step_module_invocation.v1",
        "invocation_id": invocation_ref,
        "run_id": "run:model-mount",
        "task_id": "task:model-mount",
        "thread_id": Value::Null,
        "workflow_graph_id": workflow_graph_id,
        "workflow_node_id": workflow_node_id,
        "context_chamber_ref": Value::Null,
        "action_proposal_ref": format!("action:model-mount:{}", safe_ref_segment(&string_path(admission_request, &["invocation_ref"], "admission_request.invocation_ref")?)),
        "gate_result_ref": format!("gate:model-mount:{}", safe_ref_segment(&string_path(admission_request, &["invocation_ref"], "admission_request.invocation_ref")?)),
        "module_ref": {
            "kind": "model_mount",
            "id": module_id,
            "version": "migration",
            "manifest_ref": Value::Null
        },
        "actor": {
            "actor_id": "runtime:hypervisor-daemon",
            "runtime_node_ref": "node://local"
        },
        "authority": {
            "authority_grant_refs": authority_grant_refs,
            "policy_hash": hash_ref(&string_path(admission_request, &["policy_hash"], "admission_request.policy_hash")?),
            "primitive_capabilities": [
                format!("model:{}", string_path(admission_request, &["capability"], "admission_request.capability")?),
                format!("model:{}", string_path(admission_request, &["invocation_kind"], "admission_request.invocation_kind")?)
            ],
            "authority_scopes": [],
            "approval_ref": Value::Null
        },
        "input": {
            "input_hash": hash_ref(&string_path(admission_request, &["input_hash"], "admission_request.input_hash")?),
            "expected_schema_ref": format!("schema://model-mount/{}/input", string_path(admission_request, &["invocation_kind"], "admission_request.invocation_kind")?),
            "context_refs": context_refs,
            "artifact_refs": [],
            "payload_refs": [],
            "state_root_before": string_path(transition, &["state_root_before"], "agentgres_transition.state_root_before")?,
            "projection_watermark": string_path(transition, &["projection_watermark"], "agentgres_transition.projection_watermark")?,
            "data_plane_handle": Value::Null
        },
        "custody": {
            "privacy_profile": privacy_profile_for_step_module(optional_string_path(admission_request, &["privacy_profile"])),
            "plaintext_policy": {
                "node_plaintext_allowed": bool_path(admission_request, &["node_plaintext_allowed"]).unwrap_or(false),
                "declassification_required": false
            },
            "custody_proof_ref": optional_string_path(admission_request, &["custody_ref"]),
            "leakage_profile_ref": Value::Null
        },
        "execution": {
            "backend": "model_mount",
            "idempotency_key": optional_string_path(admission_request, &["idempotency_key"])
                .unwrap_or_else(|| format!("step-module:{}", request.receipt_id)),
            "deadline_ms": 300000,
            "resource_lease_ref": Value::Null,
            "retry_policy_ref": Value::Null
        }
    });
    let result_hash = hash_json(&json!({
        "invocationId": invocation["invocation_id"],
        "receipt_ref": receipt_ref,
        "output_hash": hash_ref(&string_path(admission_request, &["output_hash"], "admission_request.output_hash")?),
        "status": "success"
    }))?;
    let result_id =
        &result_hash.trim_start_matches("sha256:")[..32.min(result_hash.len().saturating_sub(7))];
    let result = json!({
        "schema_version": "ioi.step_module_result.v1",
        "invocation_id": invocation["invocation_id"],
        "status": "success",
        "execution_result_ref": format!("result://model-mount/{result_id}"),
        "normalized_observation_ref": format!("observation://model-mount/{result_id}"),
        "receipt_refs": [receipt_ref],
        "artifact_refs": [],
        "payload_refs": [],
        "agentgres_operation_refs": [string_path(transition, &["operation_ref"], "agentgres_transition.operation_ref")?],
        "state_root_after": string_path(transition, &["state_root_after"], "agentgres_transition.state_root_after")?,
        "resulting_head": string_path(transition, &["resulting_head"], "agentgres_transition.resulting_head")?,
        "workflow_projection": {
            "workflow_graph_id": invocation["workflow_graph_id"],
            "workflow_node_id": invocation["workflow_node_id"],
            "component_kind": "ModelInvocationNode",
            "status": "live",
            "attempt_id": format!("attempt://model-mount/{result_id}"),
            "evidence_refs": unique_strings(
                [
                    Some("rust_model_mount_core".to_string()),
                    optional_string_path(&request.invocation_admission, &["invocation_admission_ref"]),
                ]
                .into_iter()
                .chain(
                string_array_path(&request.invocation_admission, &["evidence_refs"])
                    .into_iter()
                    .map(Some)
                )
                .chain(
                string_array_path(&request.receipt_details, &["provider_auth_evidence_refs"])
                    .into_iter()
                    .map(Some)
                )
                .chain(
                string_array_path(&request.receipt_details, &["backend_evidence_refs"])
                    .into_iter()
                    .map(Some)
                )
            ),
            "receipt_refs": [receipt_ref]
        },
        "next": {
            "model_reentry_required": false,
            "verifier_required": false
        }
    });
    Ok(json!({
        "invocation": invocation,
        "result": result,
        "acceptedReceiptTransition": request.agentgres_transition.get("acceptedReceiptTransition")
            .cloned()
            .or_else(|| request.agentgres_transition.get("transition").cloned())
            .unwrap_or_else(|| request.agentgres_transition.clone()),
        "receiptRef": receipt_ref
    }))
}

fn provider_execution_admission_record(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<ModelMountProviderExecutionRecord, ModelMountError> {
    let record = request
        .provider_execution_admission
        .get("record")
        .cloned()
        .unwrap_or_else(|| request.provider_execution_admission.clone());
    serde_json::from_value(record).map_err(|error| ModelMountError::HashFailed(error.to_string()))
}

fn provider_invocation_backend(
    request: &ModelMountInvocationAuthorityRequest,
    stream: bool,
) -> Result<String, ModelMountError> {
    if native_local_provider(request) {
        return Ok(if stream {
            "rust_model_mount_native_local_stream"
        } else {
            "rust_model_mount_native_local"
        }
        .to_string());
    }
    if !stream && fixture_provider(request) {
        return Ok("rust_model_mount_fixture".to_string());
    }
    if hosted_provider(request) {
        return Ok(if stream {
            "rust_model_mount_hosted_provider_stream"
        } else {
            "rust_model_mount_hosted_provider"
        }
        .to_string());
    }
    Err(ModelMountError::UnsupportedProviderInvocationBackend)
}

fn hosted_provider_auth_evidence_refs(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<Vec<String>, ModelMountError> {
    if fixture_provider(request) || native_local_provider(request) {
        return Ok(vec![]);
    }
    if !hosted_provider(request) {
        return Ok(vec![]);
    }
    let secret_ref = optional_endpoint_or_provider_string(request, "secret_ref")
        .or_else(|| optional_endpoint_or_provider_string(request, "auth_vault_ref"))
        .or_else(|| optional_endpoint_or_provider_string(request, "api_key_vault_ref"));
    let mut refs = vec![
        "rust_model_mount_hosted_provider_auth_gate".to_string(),
        "wallet_network_provider_transport_authority_bound".to_string(),
        "ctee_hosted_provider_secret_not_exposed".to_string(),
        "provider_env_secret_material_fallback_retired".to_string(),
    ];
    if let Some(secret_ref) = secret_ref.filter(|value| value.starts_with("vault://")) {
        refs.extend([
            "wallet_network_provider_vault_ref_bound".to_string(),
            "rust_provider_auth_materialization_bound".to_string(),
            "hosted_provider_auth_header_materialized_by_rust".to_string(),
            "rust_ctee_egress_resolver_bound".to_string(),
            "ctee_outbound_egress_resolver_depth_bound".to_string(),
            format!(
                "provider_vault_ref_hash:{}",
                stable_js_hash(&Value::String(secret_ref))?
            ),
        ]);
    } else {
        refs.push("wallet_network_provider_vault_ref_required".to_string());
    }
    Ok(unique(refs))
}

fn native_local_provider(request: &ModelMountInvocationAuthorityRequest) -> bool {
    provider_value(request, "kind").as_deref() == Some("ioi_native_local")
        || optional_endpoint_or_provider_string(request, "driver").as_deref()
            == Some("native_local")
        || optional_endpoint_or_provider_string(request, "api_format").as_deref()
            == Some("ioi_native")
}

fn fixture_provider(request: &ModelMountInvocationAuthorityRequest) -> bool {
    provider_value(request, "kind").as_deref() == Some("local_folder")
        || optional_endpoint_or_provider_string(request, "driver").as_deref() == Some("fixture")
        || optional_endpoint_or_provider_string(request, "api_format").as_deref()
            == Some("ioi_fixture")
}

fn hosted_provider(request: &ModelMountInvocationAuthorityRequest) -> bool {
    let provider_kind = provider_value(request, "kind").unwrap_or_default();
    let api_format =
        optional_endpoint_or_provider_string(request, "api_format").unwrap_or_default();
    let driver = optional_endpoint_or_provider_string(request, "driver").unwrap_or_default();
    matches!(
        provider_kind.as_str(),
        "openai"
            | "anthropic"
            | "gemini"
            | "custom_http"
            | "openai_compatible"
            | "ollama"
            | "vllm"
            | "llama_cpp"
            | "lm_studio"
            | "depin_tee"
    ) || matches!(
        api_format.as_str(),
        "openai" | "anthropic" | "gemini" | "custom" | "openai_compatible" | "ollama"
    ) || matches!(driver.as_str(), "openai_compatible" | "hosted_provider")
}

fn route_decision_ref(
    request: &ModelMountInvocationAuthorityRequest,
) -> Result<String, ModelMountError> {
    optional_route_receipt_detail(request, "model_mount_route_decision_ref")
        .or_else(|| {
            optional_string_path(
                &request.selection,
                &["route_decision", "route_decision_ref"],
            )
        })
        .ok_or(ModelMountError::MissingField(
            "route_receipt.details.model_mount_route_decision_ref",
        ))
}

fn invocation_custody_ref(request: &ModelMountInvocationAuthorityRequest) -> Option<String> {
    optional_string_path(&request.body, &["custody_ref"])
        .or_else(|| optional_endpoint_string(request, "custody_ref"))
        .or_else(|| provider_value(request, "custody_ref"))
}

fn invocation_privacy_profile(request: &ModelMountInvocationAuthorityRequest) -> Option<String> {
    optional_string_path(&request.body, &["privacy_profile"])
        .or_else(|| optional_string_path(&request.body, &["model_policy", "privacy_profile"]))
        .or_else(|| optional_string_path(&request.body, &["model_policy", "privacy"]))
        .or_else(|| route_value(request, "privacy"))
        .or_else(|| provider_value(request, "privacy_class"))
}

fn invocation_node_plaintext_allowed(request: &ModelMountInvocationAuthorityRequest) -> bool {
    bool_path(&request.body, &["node_plaintext_allowed"])
        .or_else(|| bool_path(&request.selection, &["endpoint", "node_plaintext_allowed"]))
        .or_else(|| bool_path(&request.selection, &["provider", "node_plaintext_allowed"]))
        .unwrap_or(false)
}

fn route_string(
    request: &ModelMountInvocationAuthorityRequest,
    field: &'static str,
    error: &'static str,
) -> Result<String, ModelMountError> {
    string_path(&request.selection, &["route", field], error)
}

fn endpoint_string(
    request: &ModelMountInvocationAuthorityRequest,
    field: &'static str,
    error: &'static str,
) -> Result<String, ModelMountError> {
    string_path(&request.selection, &["endpoint", field], error)
}

fn provider_string(
    request: &ModelMountInvocationAuthorityRequest,
    field: &'static str,
    error: &'static str,
) -> Result<String, ModelMountError> {
    string_path(&request.selection, &["provider", field], error)
}

fn optional_endpoint_string(
    request: &ModelMountInvocationAuthorityRequest,
    field: &'static str,
) -> Option<String> {
    optional_string_path(&request.selection, &["endpoint", field])
}

fn optional_endpoint_or_provider_string(
    request: &ModelMountInvocationAuthorityRequest,
    field: &'static str,
) -> Option<String> {
    optional_endpoint_string(request, field).or_else(|| provider_value(request, field))
}

fn optional_route_receipt_detail(
    request: &ModelMountInvocationAuthorityRequest,
    field: &'static str,
) -> Option<String> {
    optional_string_path(&request.route_receipt, &["details", field])
}

fn route_value(
    request: &ModelMountInvocationAuthorityRequest,
    field: &'static str,
) -> Option<String> {
    optional_string_path(&request.selection, &["route", field])
}

fn provider_value(
    request: &ModelMountInvocationAuthorityRequest,
    field: &'static str,
) -> Option<String> {
    optional_string_path(&request.selection, &["provider", field])
}

fn string_path(
    value: &Value,
    path: &[&str],
    field: &'static str,
) -> Result<String, ModelMountError> {
    optional_string_path(value, path).ok_or(ModelMountError::MissingField(field))
}

fn required_string_path(
    value: &Value,
    path: &[&str],
    field: &'static str,
) -> Result<String, ModelMountError> {
    string_path(value, path, field)
}

fn string_path_or(value: &Value, path: &[&str], fallback: &str) -> String {
    optional_string_path(value, path).unwrap_or_else(|| fallback.to_string())
}

fn optional_string_path(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    match current {
        Value::String(value) => {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn string_array_path(value: &Value, path: &[&str]) -> Vec<String> {
    let mut current = value;
    for segment in path {
        let Some(next) = current.get(*segment) else {
            return vec![];
        };
        current = next;
    }
    current
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn bool_path(value: &Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_bool()
}

fn number_path(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_u64()
}

fn non_empty_request_field(value: &str, field: &'static str) -> Result<String, ModelMountError> {
    require_non_empty(field, value)?;
    Ok(value.trim().to_string())
}

fn receipt_ref(value: &str) -> String {
    if value.contains("://") {
        value.to_string()
    } else {
        format!("receipt://{value}")
    }
}

fn hash_ref(value: &str) -> String {
    if value.starts_with("sha256:") {
        value.to_string()
    } else {
        format!("sha256:{value}")
    }
}

fn hash_text(value: &str) -> Result<String, ModelMountError> {
    Ok(format!("sha256:{}", sha256_hex(value.as_bytes())?))
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    let bytes = serde_json::to_vec(&sort_json_value(value))
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)?))
}

fn stable_js_hash(value: &Value) -> Result<String, ModelMountError> {
    let stable = stable_js_stringify(value);
    Ok(hex::encode(Sha256::digest(stable.as_bytes())))
}

fn stable_js_stringify(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null | Value::Bool(_) | Value::Number(_) => value.to_string(),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(stable_js_stringify)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string()),
                        stable_js_stringify(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn sort_json_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sort_json_value).collect()),
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                if let Some(value) = map.get(key) {
                    sorted.insert(key.clone(), sort_json_value(value));
                }
            }
            Value::Object(sorted)
        }
        _ => value.clone(),
    }
}

fn safe_ref_segment(value: &str) -> String {
    let without_scheme = value
        .split_once("://")
        .map(|(_, right)| right)
        .unwrap_or(value);
    let segment = without_scheme
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-') {
                ch
            } else {
                '-'
            }
        })
        .take(96)
        .collect::<String>();
    if segment.is_empty() {
        "unknown".to_string()
    } else {
        segment
    }
}

fn privacy_profile_for_step_module(value: Option<String>) -> String {
    match value.as_deref() {
        Some("private_workspace_ctee" | "tee_confidential" | "redacted" | "public") => {
            value.unwrap()
        }
        _ => "internal".to_string(),
    }
}

fn unique_strings(values: impl IntoIterator<Item = Option<String>>) -> Vec<String> {
    let mut refs = vec![];
    for value in values {
        let Some(value) = value else {
            continue;
        };
        let trimmed = value.trim();
        if !trimmed.is_empty() && !refs.iter().any(|existing| existing == trimmed) {
            refs.push(trimmed.to_string());
        }
    }
    refs
}

fn unique(values: Vec<String>) -> Vec<String> {
    let mut refs = vec![];
    for value in values {
        if !refs.iter().any(|existing| existing == &value) {
            refs.push(value);
        }
    }
    refs
}

fn plan_insert(plan: &mut Value, key: &'static str, value: Value) {
    plan.as_object_mut()
        .expect("plan object")
        .insert(key.to_string(), value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: &str) -> ModelMountInvocationAuthorityRequest {
        ModelMountInvocationAuthorityRequest {
            schema_version: MODEL_MOUNT_INVOCATION_AUTHORITY_SCHEMA_VERSION.to_string(),
            operation: operation.to_string(),
            body: json!({
                "input": "hello",
                "model": "local-model",
                "model_policy": {"privacy": "internal"}
            }),
            selection: json!({
                "route": {"id": "route.local", "privacy": "internal"},
                "endpoint": {
                    "id": "endpoint.local",
                    "model_id": "local-model",
                    "provider_id": "provider.local",
                    "api_format": "ioi_fixture",
                    "driver": "fixture",
                    "backend_id": "backend.fixture"
                },
                "provider": {
                    "id": "provider.local",
                    "kind": "local_folder",
                    "driver": "fixture"
                },
                "route_decision": {"route_decision_ref": "model_mount://route_decision/test"}
            }),
            instance: json!({"id": "instance.local", "backend_id": "backend.fixture"}),
            route_receipt: json!({
                "id": "receipt.route",
                "details": {"model_mount_route_decision_ref": "model_mount://route_decision/test"}
            }),
            ephemeral_mcp: json!({"tool_receipt_ids": ["receipt.tool"], "server_ids": ["mcp.server"]}),
            token: json!({"grant_ref": "wallet://grant/model"}),
            input: "hello".to_string(),
            kind: "chat".to_string(),
            capability: "chat".to_string(),
            response_id: Some("resp.1".to_string()),
            previous_response_id: None,
            required_scope: Some("model.invoke".to_string()),
            receipt_id: "receipt.invocation".to_string(),
            receipt_kind: "model_invocation".to_string(),
            latency_ms: 25,
            ..Default::default()
        }
    }

    impl Default for ModelMountInvocationAuthorityRequest {
        fn default() -> Self {
            Self {
                schema_version: MODEL_MOUNT_INVOCATION_AUTHORITY_SCHEMA_VERSION.to_string(),
                operation: String::new(),
                body: Value::Null,
                selection: Value::Null,
                instance: Value::Null,
                route_receipt: Value::Null,
                ephemeral_mcp: Value::Null,
                token: Value::Null,
                provider_execution_admission: Value::Null,
                provider_result: Value::Null,
                provider_result_admission: Value::Null,
                invocation_admission: Value::Null,
                invocation_admission_request: Value::Null,
                agentgres_transition: Value::Null,
                current_head: Value::Null,
                receipt_details: Value::Null,
                continuation: Value::Null,
                input: String::new(),
                kind: String::new(),
                capability: String::new(),
                response_id: None,
                previous_response_id: None,
                required_scope: None,
                receipt_id: String::new(),
                receipt_kind: String::new(),
                stream: false,
                stream_status: None,
                latency_ms: 0,
            }
        }
    }

    #[test]
    fn rust_plans_provider_execution_contract() {
        let plan = plan_model_mount_invocation_authority(&request("provider_execution"))
            .expect("authority plan");
        assert_eq!(
            plan["rust_core_boundary"],
            "model_mount.invocation_authority"
        );
        assert_eq!(
            plan["provider_execution_request"]["schema_version"],
            MODEL_MOUNT_PROVIDER_EXECUTION_SCHEMA_VERSION
        );
        assert_eq!(
            plan["provider_execution_request"]["route_receipt_ref"],
            "receipt://receipt.route"
        );
        assert!(plan["evidence_refs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "model_mount_invocation_contract_js_authoring_retired"));
    }

    #[test]
    fn rust_plans_receipt_binding_step_module_projection() {
        let mut req = request("receipt_binding");
        req.invocation_admission_request = json!({
            "invocation_ref": "model-invocation://receipt.invocation",
            "route_ref": "route.local",
            "provider_ref": "provider.local",
            "endpoint_ref": "endpoint.local",
            "model_ref": "local-model",
            "capability": "chat",
            "invocation_kind": "chat",
            "input_hash": "sha256:input",
            "output_hash": "sha256:output",
            "policy_hash": "sha256:policy",
            "route_decision_ref": "model_mount://route_decision/test",
            "route_receipt_ref": "receipt://receipt.route",
            "idempotency_key": "model_invocation:receipt.invocation",
            "authority_grant_refs": ["wallet://grant/model"],
            "privacy_profile": "internal",
            "node_plaintext_allowed": false
        });
        req.invocation_admission = json!({
            "invocation_admission_ref": "model_mount://invocation_admission/test",
            "evidence_refs": ["rust_model_mount_core"]
        });
        req.agentgres_transition = json!({
            "operation_ref": "agentgres://model-mounting/accepted-receipts/op_1",
            "state_root_before": "sha256:before",
            "state_root_after": "sha256:after",
            "resulting_head": "agentgres://model-mounting/accepted-receipts/head/1",
            "projection_watermark": "model-mounting-accepted-receipts:1",
            "acceptedReceiptTransition": {
                "expected_heads": ["agentgres://model-mounting/accepted-receipts/head/0"]
            }
        });
        let plan = plan_model_mount_invocation_authority(&req).expect("authority plan");
        assert_eq!(
            plan["receipt_binding_request"]["invocation"]["module_ref"]["kind"],
            "model_mount"
        );
        assert_eq!(
            plan["receipt_binding_request"]["result"]["workflow_projection"]["component_kind"],
            "ModelInvocationNode"
        );
    }
}
