use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    admission::{admit_route_decision, rust_authored_route_selection_receipt},
    non_empty_string, require_non_empty, sha256_hex, trimmed_string, ModelMountError,
    ModelMountRouteDecisionRequest, MODEL_MOUNT_ROUTE_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION, MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountRouteControlRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub current_route: Value,
    #[serde(default)]
    pub endpoints: Vec<Value>,
    #[serde(default)]
    pub providers: Vec<Value>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountRouteControlPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub control_hash: String,
}

impl ModelMountRouteControlRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !self.current_route.is_null() && !self.current_route.is_object() {
            return Err(ModelMountError::MissingField("current_route"));
        }
        Ok(())
    }
}

pub(super) fn plan_route_control(
    request: &ModelMountRouteControlRequest,
) -> Result<ModelMountRouteControlPlan, ModelMountError> {
    request.validate()?;
    match request.operation_kind.as_str() {
        "model_mount.route.write" => plan_route_write(request),
        "model_mount.route.test" => plan_route_test(request),
        "model_mount.route.select" => plan_route_select(request),
        "model_mount.route.explicit_model_endpoints" => plan_explicit_model_endpoints(request),
        _ => Err(ModelMountError::UnsupportedRouteControlKind),
    }
}

fn plan_route_write(
    request: &ModelMountRouteControlRequest,
) -> Result<ModelMountRouteControlPlan, ModelMountError> {
    let route_id = route_id_for_write(request)?;
    let body = object_or_empty(&request.body);
    let current = object_or_empty(&request.current_route);
    let source = source_for(request);
    let receipt_refs = receipt_refs_for(request, &route_id)?;
    let evidence_refs = route_control_evidence_refs();
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let record = json!({
        "id": route_id,
        "role": string_field(body, "role")
            .or_else(|| string_field(current, "role"))
            .unwrap_or_else(|| "default".to_string()),
        "description": string_field(body, "description")
            .or_else(|| string_field(current, "description"))
            .unwrap_or_else(|| "Rust-authored model route.".to_string()),
        "privacy": string_field(body, "privacy")
            .or_else(|| string_field(current, "privacy"))
            .unwrap_or_else(|| "local_or_enterprise".to_string()),
        "quality": string_field(body, "quality")
            .or_else(|| string_field(current, "quality"))
            .unwrap_or_else(|| "adaptive".to_string()),
        "maxCostUsd": number_field(body, "max_cost_usd")
            .or_else(|| number_field(current, "maxCostUsd"))
            .unwrap_or(0.25),
        "maxLatencyMs": integer_field(body, "max_latency_ms")
            .or_else(|| integer_field(current, "maxLatencyMs"))
            .unwrap_or(30000),
        "providerEligibility": array_field(body, "provider_eligibility")
            .or_else(|| array_field(current, "providerEligibility"))
            .unwrap_or_default(),
        "fallback": array_field(body, "fallback")
            .or_else(|| array_field(current, "fallback"))
            .unwrap_or_default(),
        "deniedProviders": array_field(body, "denied_providers")
            .or_else(|| array_field(current, "deniedProviders"))
            .unwrap_or_default(),
        "status": string_field(body, "status")
            .or_else(|| string_field(current, "status"))
            .unwrap_or_else(|| "active".to_string()),
        "lastSelectedModel": string_field(body, "last_selected_model")
            .or_else(|| string_field(current, "lastSelectedModel")),
        "lastReceiptId": string_field(body, "last_receipt_id")
            .or_else(|| string_field(current, "lastReceiptId")),
        "receiptRefs": receipt_refs,
        "authorityReceiptRefs": array_field(body, "authority_receipt_refs").unwrap_or_default(),
        "updatedAt": generated_at,
        "routeControl": {
            "source": source,
            "operation_kind": request.operation_kind,
            "rust_core_boundary": "model_mount.route_control",
            "evidence_refs": evidence_refs,
        },
    });
    route_control_plan(
        request,
        "model-routes",
        &route_id,
        record,
        receipt_refs,
        evidence_refs,
    )
}

fn plan_route_test(
    request: &ModelMountRouteControlRequest,
) -> Result<ModelMountRouteControlPlan, ModelMountError> {
    let route_id = request
        .route_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .ok_or(ModelMountError::MissingField("route_id"))?;
    let source = source_for(request);
    let receipt_refs = receipt_refs_for(request, &route_id)?;
    let evidence_refs = route_control_evidence_refs();
    let body = object_or_empty(&request.body);
    let model = string_field(body, "model").or_else(|| string_field(body, "model_id"));
    let control_hash = route_control_hash(request, &route_id, &receipt_refs)?;
    let record_id = format!("route_test:{route_id}:{}", &control_hash[..16]);
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let record = json!({
        "id": record_id,
        "object": "ioi.model_mount_route_test",
        "route_id": route_id,
        "status": "planned",
        "model": model,
        "model_policy": body.get("model_policy").cloned().unwrap_or(Value::Null),
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "rust_core_boundary": "model_mount.route_control",
        "source": source,
        "tested_at": generated_at,
        "current_route": request.current_route,
    });
    route_control_plan(
        request,
        "model-route-tests",
        &record_id,
        record,
        receipt_refs,
        evidence_refs,
    )
}

fn plan_route_select(
    request: &ModelMountRouteControlRequest,
) -> Result<ModelMountRouteControlPlan, ModelMountError> {
    let route = object_or_non_empty(&request.current_route, "current_route")?;
    let route_id = route_id_for_selection(request, route)?;
    let source = source_for(request);
    let body = object_or_empty(&request.body);
    let capability = string_field(body, "capability").unwrap_or_else(|| "chat".to_string());
    let selected = select_route_endpoint(request, route, &capability)?;
    let receipt_refs = receipt_refs_for(request, &route_id)?;
    let policy_hash = policy_hash_for(request, &route_id, &capability)?;
    let idempotency_key = route_selection_id(request, &route_id, &selected.endpoint_id)?;
    let decision_request = ModelMountRouteDecisionRequest {
        schema_version: MODEL_MOUNT_ROUTE_DECISION_SCHEMA_VERSION.to_string(),
        route_ref: route_id.clone(),
        provider_ref: selected.provider_id.clone(),
        endpoint_ref: selected.endpoint_id.clone(),
        model_ref: selected.model_id.clone(),
        capability: capability.clone(),
        policy_hash: format!("sha256:{policy_hash}"),
        idempotency_key: idempotency_key.clone(),
        receipt_refs: receipt_refs.clone(),
        authority_grant_refs: string_array_field(body, "authority_grant_refs"),
        authority_receipt_refs: string_array_field(body, "authority_receipt_refs"),
        custody_ref: string_field(body, "custody_ref")
            .or_else(|| string_field_any(selected.endpoint, &["custody_ref", "custodyRef"]))
            .or_else(|| string_field_any(selected.provider, &["custody_ref", "custodyRef"])),
        privacy_profile: string_field(body, "privacy_profile")
            .or_else(|| string_field(body, "model_policy_privacy_profile"))
            .or_else(|| nested_string_field(body, "model_policy", "privacy_profile"))
            .or_else(|| nested_string_field(body, "model_policy", "privacy"))
            .or_else(|| string_field(route, "privacy"))
            .or_else(|| string_field_any(selected.provider, &["privacy_class", "privacyClass"])),
        node_plaintext_allowed: bool_field(body, "node_plaintext_allowed")
            .or_else(|| {
                bool_field_any(
                    selected.endpoint,
                    &["node_plaintext_allowed", "nodePlaintextAllowed"],
                )
            })
            .or_else(|| {
                bool_field_any(
                    selected.provider,
                    &["node_plaintext_allowed", "nodePlaintextAllowed"],
                )
            })
            .unwrap_or(false),
        workflow_graph_ref: string_field(body, "workflow_graph_id"),
        workflow_node_ref: string_field(body, "workflow_node_id"),
    };
    let decision_record = admit_route_decision(&decision_request)?;
    let accepted_receipt_record = rust_authored_route_selection_receipt(&decision_record)?;
    let evidence_refs = route_control_evidence_refs();
    let selected_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let record_id = format!(
        "route_selection:{}:{}",
        route_id,
        decision_record
            .route_decision_hash
            .trim_start_matches("sha256:")
            .chars()
            .take(16)
            .collect::<String>()
    );
    let record = json!({
        "id": record_id,
        "object": "ioi.model_mount_route_selection",
        "route_id": route_id,
        "selected_model": selected.model_id,
        "endpoint_id": selected.endpoint_id,
        "provider_id": selected.provider_id,
        "capability": capability,
        "policy_hash": decision_record.policy_hash,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "rust_core_boundary": "model_mount.route_control",
        "route_selection_boundary": "model_mount.route_selection",
        "source": source,
        "selected_at": selected_at,
        "route": selected.route,
        "endpoint": selected.endpoint,
        "provider": selected.provider,
        "route_decision": decision_record,
        "accepted_receipt_record": accepted_receipt_record,
    });
    route_control_plan(
        request,
        "model-route-selections",
        &record_id,
        record,
        receipt_refs,
        evidence_refs,
    )
}

fn plan_explicit_model_endpoints(
    request: &ModelMountRouteControlRequest,
) -> Result<ModelMountRouteControlPlan, ModelMountError> {
    let route = object_or_non_empty(&request.current_route, "current_route")?;
    let route_id = route_id_for_selection(request, route)?;
    let body = object_or_empty(&request.body);
    let model_id = string_field(body, "model").or_else(|| string_field(body, "model_id"));
    let model_id = model_id.ok_or(ModelMountError::MissingField("model_id"))?;
    let endpoints: Vec<Value> = endpoint_objects(request)
        .into_iter()
        .filter(|endpoint| endpoint_is_mounted(endpoint))
        .filter(|endpoint| {
            string_field_any(endpoint, &["model_id", "modelId"]).as_deref()
                == Some(model_id.as_str())
        })
        .filter(|endpoint| endpoint_allowed_by_route(route, endpoint, &request.providers))
        .map(|endpoint| Value::Object(endpoint.clone()))
        .collect();
    if endpoints.is_empty() {
        return Err(ModelMountError::NoRouteCandidate);
    }
    let endpoint_ids: Vec<Value> = endpoints
        .iter()
        .filter_map(|endpoint| endpoint.as_object())
        .filter_map(|endpoint| string_field(endpoint, "id"))
        .map(Value::String)
        .collect();
    let receipt_refs = receipt_refs_for(request, &route_id)?;
    let evidence_refs = route_control_evidence_refs();
    let record_id = format!(
        "route_endpoint_resolution:{}:{}",
        route_id,
        route_control_hash(request, &model_id, &receipt_refs)?
            .chars()
            .take(16)
            .collect::<String>()
    );
    let resolved_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let record = json!({
        "id": record_id,
        "object": "ioi.model_mount_explicit_model_endpoints",
        "route_id": route_id,
        "model_id": model_id,
        "endpoint_ids": endpoint_ids,
        "endpoints": endpoints,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "rust_core_boundary": "model_mount.route_control",
        "route_selection_boundary": "model_mount.route_selection",
        "source": source_for(request),
        "resolved_at": resolved_at,
    });
    route_control_plan(
        request,
        "model-route-endpoint-resolutions",
        &record_id,
        record,
        receipt_refs,
        evidence_refs,
    )
}

struct SelectedRouteEndpoint<'a> {
    route: &'a serde_json::Map<String, Value>,
    endpoint: &'a serde_json::Map<String, Value>,
    provider: &'a serde_json::Map<String, Value>,
    endpoint_id: String,
    provider_id: String,
    model_id: String,
}

fn route_id_for_selection(
    request: &ModelMountRouteControlRequest,
    route: &serde_json::Map<String, Value>,
) -> Result<String, ModelMountError> {
    let body = object_or_empty(&request.body);
    string_field(body, "route_id")
        .or_else(|| {
            request
                .route_id
                .as_ref()
                .and_then(|value| non_empty_string(value))
        })
        .or_else(|| string_field(route, "id"))
        .ok_or(ModelMountError::MissingField("route_id"))
}

fn select_route_endpoint<'a>(
    request: &'a ModelMountRouteControlRequest,
    route: &'a serde_json::Map<String, Value>,
    capability: &str,
) -> Result<SelectedRouteEndpoint<'a>, ModelMountError> {
    let body = object_or_empty(&request.body);
    let requested_model = string_field(body, "model")
        .or_else(|| string_field(body, "model_id"))
        .filter(|value| !value.eq_ignore_ascii_case("auto"));
    let route_endpoint_ids = route_endpoint_ids(route);
    let endpoints = endpoint_objects(request);
    for endpoint in endpoints {
        if !endpoint_is_mounted(endpoint) {
            continue;
        }
        let endpoint_id = match string_field(endpoint, "id") {
            Some(value) => value,
            None => continue,
        };
        if !route_endpoint_ids.is_empty()
            && !route_endpoint_ids
                .iter()
                .any(|candidate| candidate == &endpoint_id)
        {
            continue;
        }
        let model_id = match string_field_any(endpoint, &["model_id", "modelId"]) {
            Some(value) => value,
            None => continue,
        };
        if requested_model
            .as_ref()
            .is_some_and(|requested| requested != &model_id)
        {
            continue;
        }
        let provider = match provider_for_endpoint(endpoint, &request.providers) {
            Some(value) => value,
            None => continue,
        };
        if !provider_allowed_by_route(route, endpoint, provider) {
            continue;
        }
        if !supports_capability(endpoint, provider, capability) {
            continue;
        }
        let provider_id =
            string_field(provider, "id").ok_or(ModelMountError::MissingField("provider.id"))?;
        return Ok(SelectedRouteEndpoint {
            route,
            endpoint,
            provider,
            endpoint_id,
            provider_id,
            model_id,
        });
    }
    Err(ModelMountError::NoRouteCandidate)
}

fn endpoint_allowed_by_route(
    route: &serde_json::Map<String, Value>,
    endpoint: &serde_json::Map<String, Value>,
    providers: &[Value],
) -> bool {
    provider_for_endpoint(endpoint, providers)
        .map(|provider| provider_allowed_by_route(route, endpoint, provider))
        .unwrap_or(false)
}

fn provider_allowed_by_route(
    route: &serde_json::Map<String, Value>,
    endpoint: &serde_json::Map<String, Value>,
    provider: &serde_json::Map<String, Value>,
) -> bool {
    let provider_id = string_field_any(endpoint, &["provider_id", "providerId"])
        .or_else(|| string_field(provider, "id"))
        .unwrap_or_default();
    let provider_kind = string_field(provider, "kind").unwrap_or_default();
    let eligibility =
        string_array_field_any(route, &["providerEligibility", "provider_eligibility"]);
    let denied = string_array_field_any(route, &["deniedProviders", "denied_providers"]);
    let eligible = eligibility.is_empty()
        || eligibility
            .iter()
            .any(|value| value == &provider_id || value == &provider_kind);
    let blocked = denied
        .iter()
        .any(|value| value == &provider_id || value == &provider_kind);
    eligible && !blocked
}

fn supports_capability(
    endpoint: &serde_json::Map<String, Value>,
    provider: &serde_json::Map<String, Value>,
    capability: &str,
) -> bool {
    let endpoint_capabilities = string_array_field(endpoint, "capabilities");
    let provider_capabilities = string_array_field(provider, "capabilities");
    if endpoint_capabilities.is_empty() && provider_capabilities.is_empty() {
        return true;
    }
    endpoint_capabilities
        .iter()
        .any(|value| value == capability)
        || provider_capabilities
            .iter()
            .any(|value| value == capability)
}

fn provider_for_endpoint<'a>(
    endpoint: &serde_json::Map<String, Value>,
    providers: &'a [Value],
) -> Option<&'a serde_json::Map<String, Value>> {
    let provider_id = string_field_any(endpoint, &["provider_id", "providerId"])?;
    providers
        .iter()
        .filter_map(Value::as_object)
        .find(|provider| string_field(provider, "id").as_deref() == Some(provider_id.as_str()))
}

fn endpoint_objects(
    request: &ModelMountRouteControlRequest,
) -> Vec<&serde_json::Map<String, Value>> {
    request
        .endpoints
        .iter()
        .filter_map(Value::as_object)
        .collect()
}

fn endpoint_is_mounted(endpoint: &serde_json::Map<String, Value>) -> bool {
    !matches!(
        string_field(endpoint, "status").as_deref(),
        Some("unmounted") | Some("blocked")
    )
}

fn route_endpoint_ids(route: &serde_json::Map<String, Value>) -> Vec<String> {
    let fallback = string_array_field(route, "fallback");
    if !fallback.is_empty() {
        return fallback;
    }
    string_array_field_any(route, &["endpoint_ids", "endpointIds"])
}

fn route_selection_id(
    request: &ModelMountRouteControlRequest,
    route_id: &str,
    endpoint_id: &str,
) -> Result<String, ModelMountError> {
    let seed = json!({
        "operation_kind": request.operation_kind,
        "route_id": route_id,
        "endpoint_id": endpoint_id,
        "body": request.body,
        "current_route": request.current_route,
    });
    serde_json::to_vec(&seed)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))
        .and_then(|bytes| sha256_hex(&bytes))
        .map(|hash| format!("model_route_selection:{route_id}:{}", &hash[..16]))
}

fn policy_hash_for(
    request: &ModelMountRouteControlRequest,
    route_id: &str,
    capability: &str,
) -> Result<String, ModelMountError> {
    let body = object_or_empty(&request.body);
    let value = json!({
        "route_id": route_id,
        "capability": capability,
        "model_policy": body.get("model_policy").cloned().unwrap_or(Value::Null),
        "authority_grant_refs": body.get("authority_grant_refs").cloned().unwrap_or(Value::Null),
        "authority_receipt_refs": body.get("authority_receipt_refs").cloned().unwrap_or(Value::Null),
        "custody_ref": body.get("custody_ref").cloned().unwrap_or(Value::Null),
        "privacy_profile": body.get("privacy_profile").cloned().unwrap_or(Value::Null),
        "node_plaintext_allowed": body.get("node_plaintext_allowed").cloned().unwrap_or(Value::Null),
    });
    serde_json::to_vec(&value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))
        .and_then(|bytes| sha256_hex(&bytes))
}

fn route_control_plan(
    request: &ModelMountRouteControlRequest,
    record_dir: &str,
    record_id: &str,
    record: Value,
    receipt_refs: Vec<String>,
    evidence_refs: Vec<String>,
) -> Result<ModelMountRouteControlPlan, ModelMountError> {
    let control_hash = route_control_hash(request, record_id, &receipt_refs)?;
    Ok(ModelMountRouteControlPlan {
        schema_version: MODEL_MOUNT_ROUTE_CONTROL_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_route_control_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.route_control".to_string(),
        operation_kind: trimmed_string(&request.operation_kind, "operation_kind")?,
        source: source_for(request),
        record_dir: record_dir.to_string(),
        record_id: record_id.to_string(),
        record,
        receipt_refs,
        evidence_refs,
        control_hash,
    })
}

fn route_id_for_write(request: &ModelMountRouteControlRequest) -> Result<String, ModelMountError> {
    let body = object_or_empty(&request.body);
    if let Some(route_id) = string_field(body, "id").or_else(|| {
        request
            .route_id
            .as_ref()
            .and_then(|value| non_empty_string(value))
    }) {
        return Ok(route_id);
    }
    let role = string_field(body, "role").ok_or(ModelMountError::MissingField("id"))?;
    Ok(format!("route:{role}"))
}

fn route_control_hash(
    request: &ModelMountRouteControlRequest,
    record_id: &str,
    receipt_refs: &[String],
) -> Result<String, ModelMountError> {
    let value = json!({
        "schema_version": MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION,
        "operation_kind": request.operation_kind,
        "record_id": record_id,
        "body": request.body,
        "current_route": request.current_route,
        "endpoints": request.endpoints,
        "providers": request.providers,
        "receipt_refs": receipt_refs,
    });
    serde_json::to_vec(&value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))
        .and_then(|bytes| sha256_hex(&bytes))
}

fn receipt_refs_for(
    request: &ModelMountRouteControlRequest,
    route_id: &str,
) -> Result<Vec<String>, ModelMountError> {
    let mut refs: Vec<String> = request
        .receipt_refs
        .iter()
        .filter_map(|value| non_empty_string(value))
        .collect();
    if refs.is_empty() {
        let seed = json!({
            "operation_kind": request.operation_kind,
            "route_id": route_id,
            "body": request.body,
        });
        let hash = serde_json::to_vec(&seed)
            .map_err(|error| ModelMountError::HashFailed(error.to_string()))
            .and_then(|bytes| sha256_hex(&bytes))?;
        refs.push(format!(
            "receipt://model-mount/route-control/{}/{}",
            request.operation_kind, hash
        ));
    }
    Ok(refs)
}

fn source_for(request: &ModelMountRouteControlRequest) -> String {
    request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_daemon_core.model_mount.route_control".to_string())
}

fn route_control_evidence_refs() -> Vec<String> {
    vec![
        "model_mount_route_control_rust_owned".to_string(),
        "rust_daemon_core_route_control_plan".to_string(),
        "agentgres_route_truth_required".to_string(),
    ]
}

fn object_or_empty(value: &Value) -> &serde_json::Map<String, Value> {
    static EMPTY: std::sync::OnceLock<serde_json::Map<String, Value>> = std::sync::OnceLock::new();
    value
        .as_object()
        .unwrap_or_else(|| EMPTY.get_or_init(serde_json::Map::new))
}

fn object_or_non_empty<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a serde_json::Map<String, Value>, ModelMountError> {
    value
        .as_object()
        .filter(|map| !map.is_empty())
        .ok_or(ModelMountError::MissingField(field))
}

fn string_field(map: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    map.get(field)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn string_field_any(map: &serde_json::Map<String, Value>, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| string_field(map, field))
}

fn nested_string_field(
    map: &serde_json::Map<String, Value>,
    object_field: &str,
    field: &str,
) -> Option<String> {
    map.get(object_field)
        .and_then(Value::as_object)
        .and_then(|nested| string_field(nested, field))
}

fn number_field(map: &serde_json::Map<String, Value>, field: &str) -> Option<f64> {
    map.get(field)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

fn integer_field(map: &serde_json::Map<String, Value>, field: &str) -> Option<i64> {
    map.get(field).and_then(Value::as_i64)
}

fn array_field(map: &serde_json::Map<String, Value>, field: &str) -> Option<Vec<Value>> {
    map.get(field).and_then(Value::as_array).cloned()
}

fn string_array_field(map: &serde_json::Map<String, Value>, field: &str) -> Vec<String> {
    map.get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(non_empty_string)
                .collect()
        })
        .unwrap_or_default()
}

fn string_array_field_any(map: &serde_json::Map<String, Value>, fields: &[&str]) -> Vec<String> {
    fields
        .iter()
        .map(|field| string_array_field(map, field))
        .find(|values| !values.is_empty())
        .unwrap_or_default()
}

fn bool_field(map: &serde_json::Map<String, Value>, field: &str) -> Option<bool> {
    map.get(field).and_then(Value::as_bool)
}

fn bool_field_any(map: &serde_json::Map<String, Value>, fields: &[&str]) -> Option<bool> {
    fields.iter().find_map(|field| bool_field(map, field))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_core_plans_model_mount_route_write_control() {
        let plan = plan_route_control(&ModelMountRouteControlRequest {
            schema_version: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.route.write".to_string(),
            source: Some("runtime-daemon.model_mounting.route_control".to_string()),
            route_id: None,
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            body: json!({
                "role": "Review",
                "fallback": ["endpoint.local"],
                "provider_eligibility": ["local_folder"],
                "max_cost_usd": 0.5,
                "max_latency_ms": 1500,
            }),
            current_route: Value::Null,
            endpoints: vec![],
            providers: vec![],
            receipt_refs: vec![],
        })
        .expect("route write control plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_ROUTE_CONTROL_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.object, "ioi.model_mount_route_control_plan");
        assert_eq!(plan.status, "planned");
        assert_eq!(plan.record_dir, "model-routes");
        assert_eq!(plan.record_id, "route:Review");
        assert_eq!(plan.record["id"], "route:Review");
        assert_eq!(plan.record["fallback"][0], "endpoint.local");
        assert_eq!(plan.record["providerEligibility"][0], "local_folder");
        assert_eq!(plan.record["maxCostUsd"], 0.5);
        assert_eq!(plan.record["maxLatencyMs"], 1500);
        assert!(plan
            .evidence_refs
            .contains(&"model_mount_route_control_rust_owned".to_string()));
        assert_eq!(plan.record.get("max_cost_usd"), None);
    }

    #[test]
    fn rust_core_plans_model_mount_route_test_control() {
        let plan = plan_route_control(&ModelMountRouteControlRequest {
            schema_version: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.route.test".to_string(),
            source: Some("runtime-daemon.model_mounting.route_control".to_string()),
            route_id: Some("route.local-first".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            body: json!({
                "model": "model.local",
                "model_policy": {"privacy": "local_only"},
            }),
            current_route: json!({"id": "route.local-first"}),
            endpoints: vec![],
            providers: vec![],
            receipt_refs: vec!["receipt://route/test".to_string()],
        })
        .expect("route test control plan");

        assert_eq!(plan.record_dir, "model-route-tests");
        assert!(plan.record_id.starts_with("route_test:route.local-first:"));
        assert_eq!(plan.record["object"], "ioi.model_mount_route_test");
        assert_eq!(plan.record["route_id"], "route.local-first");
        assert_eq!(plan.record["model"], "model.local");
        assert_eq!(plan.receipt_refs, vec!["receipt://route/test"]);
        assert_eq!(plan.record.get("modelId"), None);
    }

    #[test]
    fn rust_core_plans_model_mount_route_selection_control() {
        let plan = plan_route_control(&ModelMountRouteControlRequest {
            schema_version: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.route.select".to_string(),
            source: Some("runtime-daemon.model_mounting.route_control".to_string()),
            route_id: Some("route.local-first".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            body: json!({
                "model": "model.local",
                "capability": "chat",
                "model_policy": {"privacy": "local_only"},
                "authority_receipt_refs": ["receipt://wallet/model-chat"],
            }),
            current_route: json!({
                "id": "route.local-first",
                "fallback": ["endpoint.local"],
                "providerEligibility": ["local_folder"],
                "deniedProviders": ["openai"],
                "privacy": "local_only",
            }),
            endpoints: vec![json!({
                "id": "endpoint.local",
                "providerId": "provider.local",
                "modelId": "model.local",
                "status": "mounted",
                "capabilities": ["chat"],
            })],
            providers: vec![json!({
                "id": "provider.local",
                "kind": "local_folder",
                "capabilities": ["chat"],
                "privacyClass": "local_private",
            })],
            receipt_refs: vec![],
        })
        .expect("route selection control plan");

        assert_eq!(plan.record_dir, "model-route-selections");
        assert!(plan
            .record_id
            .starts_with("route_selection:route.local-first:"));
        assert_eq!(plan.record["object"], "ioi.model_mount_route_selection");
        assert_eq!(plan.record["route_id"], "route.local-first");
        assert_eq!(plan.record["selected_model"], "model.local");
        assert_eq!(plan.record["endpoint_id"], "endpoint.local");
        assert_eq!(plan.record["provider_id"], "provider.local");
        assert_eq!(
            plan.record["route_decision"]["route_ref"],
            "route.local-first"
        );
        assert_eq!(
            plan.record["accepted_receipt_record"]["kind"],
            "model_route_selection"
        );
        assert_eq!(
            plan.record["accepted_receipt_record"]["details"]["model_mount_route_decision_ref"],
            plan.record["route_decision"]["route_decision_ref"]
        );
        assert_eq!(plan.record.get("selectedModel"), None);
    }

    #[test]
    fn rust_core_plans_explicit_model_endpoint_resolution_control() {
        let plan = plan_route_control(&ModelMountRouteControlRequest {
            schema_version: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.route.explicit_model_endpoints".to_string(),
            source: Some("runtime-daemon.model_mounting.route_control".to_string()),
            route_id: Some("route.local-first".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            body: json!({"model_id": "model.local"}),
            current_route: json!({
                "id": "route.local-first",
                "fallback": ["endpoint.local"],
                "providerEligibility": ["local_folder"],
            }),
            endpoints: vec![json!({
                "id": "endpoint.local",
                "providerId": "provider.local",
                "modelId": "model.local",
                "status": "mounted",
            })],
            providers: vec![json!({
                "id": "provider.local",
                "kind": "local_folder",
            })],
            receipt_refs: vec![],
        })
        .expect("explicit endpoint resolution control plan");

        assert_eq!(plan.record_dir, "model-route-endpoint-resolutions");
        assert_eq!(
            plan.record["object"],
            "ioi.model_mount_explicit_model_endpoints"
        );
        assert_eq!(plan.record["route_id"], "route.local-first");
        assert_eq!(plan.record["model_id"], "model.local");
        assert_eq!(plan.record["endpoint_ids"][0], "endpoint.local");
        assert_eq!(plan.record.get("endpointIds"), None);
    }

    #[test]
    fn rust_core_plans_model_mount_route_control_direct_api() {
        let plan = plan_route_control(&ModelMountRouteControlRequest {
            schema_version: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.route.write".to_string(),
            source: None,
            route_id: Some("route.review".to_string()),
            generated_at: None,
            body: json!({"id": "route.review", "role": "Review"}),
            current_route: Value::Null,
            endpoints: vec![],
            providers: vec![],
            receipt_refs: vec!["receipt://route-control/write".to_string()],
        })
        .expect("route control direct API plan");

        assert_eq!(plan.source, "rust_daemon_core.model_mount.route_control");
        assert_eq!(plan.record_dir, "model-routes");
        assert_eq!(plan.record_id, "route.review");
        assert_eq!(plan.record["id"], "route.review");
        assert_eq!(plan.operation_kind, "model_mount.route.write");
        assert_eq!(plan.rust_core_boundary, "model_mount.route_control");
        assert!(plan
            .evidence_refs
            .contains(&"model_mount_route_control_rust_owned".to_string()));
    }

    #[test]
    fn rust_core_rejects_unowned_model_mount_route_control_kind() {
        let error = plan_route_control(&ModelMountRouteControlRequest {
            schema_version: MODEL_MOUNT_ROUTE_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.route.selection_update".to_string(),
            source: None,
            route_id: Some("route.local-first".to_string()),
            generated_at: None,
            body: Value::Null,
            current_route: Value::Null,
            endpoints: vec![],
            providers: vec![],
            receipt_refs: vec![],
        })
        .expect_err("unsupported route control kind");

        assert_eq!(error, ModelMountError::UnsupportedRouteControlKind);
    }
}
