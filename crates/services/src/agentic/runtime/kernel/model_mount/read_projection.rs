use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;

mod adapter_boundary;
mod authority;
mod status;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReadProjectionRequest {
    pub projection_kind: String,
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub engine_id: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    pub state: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReadProjectionPlan {
    pub projection_kind: String,
    pub projection: Value,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelMountReadProjectionError {
    pub code: &'static str,
    pub message: String,
}

impl ModelMountReadProjectionError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub(super) fn plan_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<ModelMountReadProjectionPlan, ModelMountReadProjectionError> {
    let projection = model_mount_read_projection(request)?;
    Ok(ModelMountReadProjectionPlan {
        projection_kind: request.projection_kind.clone(),
        projection,
        evidence_refs: vec![
            "rust_daemon_core_model_mount_projection".to_string(),
            "agentgres_model_mount_read_truth".to_string(),
            "model_mount_js_read_projection_authoring_retired".to_string(),
        ],
    })
}

pub(super) fn model_mount_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    match request.projection_kind.as_str() {
        "snapshot" => Ok(model_mount_snapshot(request)),
        "projection" => Ok(model_mount_projection(request)),
        "projection_summary" => Ok(model_mount_projection_summary(request)),
        "receipt_replay" => model_mount_receipt_replay(request),
        "model_route_decisions" => Ok(model_mount_route_decisions(request)),
        "authority_snapshot" => Ok(authority::authority_snapshot(request)),
        "server_status" => Ok(status::server_status(request)),
        "artifacts" => Ok(Value::Array(Vec::new())),
        "product_artifacts" => Ok(Value::Array(Vec::new())),
        "providers" => Ok(Value::Array(Vec::new())),
        "endpoints" => Ok(Value::Array(Vec::new())),
        "instances" => Ok(Value::Array(Vec::new())),
        "routes" => Ok(Value::Array(Vec::new())),
        "model_capabilities" => Ok(Value::Array(Vec::new())),
        "downloads" => Ok(Value::Array(Vec::new())),
        "backends" => Ok(Value::Array(Vec::new())),
        "oauth_sessions" => Err(ModelMountReadProjectionError::new(
            "model_mount_oauth_read_projection_js_retired",
            "OAuth session read projection requires Rust daemon-core wallet/cTEE projection",
        )),
        "oauth_states" => Err(ModelMountReadProjectionError::new(
            "model_mount_oauth_read_projection_js_retired",
            "OAuth state read projection requires Rust daemon-core wallet/cTEE projection",
        )),
        "provider_health" => Ok(Value::Array(Vec::new())),
        "workflow_bindings" => Ok(adapter_boundary::workflow_bindings()),
        "adapter_boundaries" => Ok(adapter_boundary::adapter_boundaries(&request.state)),
        "runtime_engines" => Ok(Value::Array(Vec::new())),
        "runtime_engine_profiles" => Ok(Value::Array(Vec::new())),
        "runtime_preference" => Ok(Value::Null),
        "runtime_preference_for_endpoint" => Ok(Value::Null),
        "runtime_default_load_options" => Ok(Value::Null),
        "runtime_engine_detail" => model_mount_runtime_engine_detail(request),
        "runtime_model_catalog" => Ok(Value::Array(Vec::new())),
        "open_ai_model_list" => Ok(json!({
            "object": "list",
            "data": [],
        })),
        "latest_provider_health" => model_mount_latest_provider_health(request),
        "latest_vault_health" => model_mount_latest_vault_health(request),
        "latest_runtime_survey" => Ok(model_mount_latest_runtime_survey(request)),
        "catalog_status" => Err(ModelMountReadProjectionError::new(
            "model_catalog_status_js_readback_retired",
            "Model catalog status readback requires Rust daemon-core catalog projection",
        )),
        other => Err(ModelMountReadProjectionError::new(
            "model_mount_read_projection_kind_unsupported",
            format!("unsupported model_mount read projection kind {other}"),
        )),
    }
}

fn model_mount_snapshot(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let receipts = array_field(state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "server": status::server_status(request),
        "catalog": status::catalog_status(request),
        "oauthSessions": [],
        "oauthStates": [],
        "artifacts": [],
        "productArtifacts": [],
        "backends": [],
        "backendProcesses": [],
        "endpoints": [],
        "instances": [],
        "providers": [],
        "routes": [],
        "modelCapabilities": [],
        "runtimeModelCatalog": [],
        "openAiModelList": {
            "object": "list",
            "data": [],
        },
        "downloads": [],
        "providerHealth": [],
        "runtimeEngines": [],
        "runtimeEngineProfiles": [],
        "runtimePreference": Value::Null,
        "runtimeSurvey": model_mount_latest_runtime_survey(request),
        "tokens": array_field(state, "grants"),
        "vaultRefs": array_field(state, "vault_refs"),
        "mcpServers": [],
        "conversationStates": [],
        "workflowNodes": adapter_boundary::workflow_bindings(),
        "receipts": receipts.into_iter().rev().take(25).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>(),
        "projection": model_mount_projection_summary(request),
        "adapterBoundaries": adapter_boundary::adapter_boundaries(state),
    })
}

fn model_mount_projection(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let receipts = array_field(state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection",
        "generatedAt": model_mount_projection_generated_at(request),
        "watermark": receipts.len(),
        "artifacts": [],
        "productArtifacts": [],
        "endpoints": [],
        "instances": [],
        "routes": [],
        "modelCapabilities": [],
        "runtimeModelCatalog": [],
        "openAiModelList": {
            "object": "list",
            "data": [],
        },
        "backends": [],
        "backendProcesses": [],
        "providers": [],
        "catalog": status::catalog_status(request),
        "oauthSessions": [],
        "oauthStates": [],
        "downloads": [],
        "providerHealth": [],
        "runtimeEngines": [],
        "runtimeEngineProfiles": [],
        "runtimePreference": Value::Null,
        "runtimeSurvey": model_mount_latest_runtime_survey(request),
        "grants": array_field(state, "grants"),
        "vaultRefs": array_field(state, "vault_refs"),
        "mcpServers": [],
        "conversationStates": [],
        "workflowBindings": adapter_boundary::workflow_bindings(),
        "adapterBoundaries": adapter_boundary::adapter_boundaries(state),
        "lifecycleEvents": receipts_by_kind(&receipts, "model_lifecycle"),
        "routeReceipts": receipts_by_kind(&receipts, "model_route_selection"),
        "routeDecisions": route_decisions_from_receipts(&receipts),
        "providerHealthReceipts": receipts_by_kind(&receipts, "provider_health"),
        "runtimeSurveyReceipts": receipts_by_kind(&receipts, "runtime_survey"),
        "invocationReceipts": receipts_by_kind(&receipts, "model_invocation"),
        "toolReceipts": receipts_by_kind(&receipts, "mcp_tool_invocation"),
        "receipts": receipts,
    })
}

fn model_mount_runtime_engine_detail(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let engine_id = request
        .engine_id
        .as_deref()
        .unwrap_or("unknown_runtime_engine");
    Err(ModelMountReadProjectionError::new(
        "model_mount_runtime_engine_not_found",
        format!("runtime engine not found: {engine_id}"),
    ))
}

fn model_mount_projection_summary(request: &ModelMountReadProjectionRequest) -> Value {
    let receipts = array_field(&request.state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection",
        "watermark": receipts.len(),
        "receiptCount": receipts.len(),
        "generatedAt": model_mount_projection_generated_at(request),
    })
}

fn model_mount_receipt_replay(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let receipt_id = request.receipt_id.as_deref().ok_or_else(|| {
        ModelMountReadProjectionError::new(
            "model_mount_receipt_id_required",
            "model_mount receipt replay projection requires receipt_id",
        )
    })?;
    let projection = model_mount_receipt_replay_context(request);
    let receipt = find_receipt(&projection, receipt_id)?;
    Ok(model_mount_receipt_replay_projection(
        request,
        &projection,
        &receipt,
    ))
}

fn model_mount_receipt_replay_context(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let receipts = array_field(state, "receipts");
    json!({
        "watermark": receipts.len(),
        "receipts": receipts,
    })
}

fn find_receipt(
    projection: &Value,
    receipt_id: &str,
) -> Result<Value, ModelMountReadProjectionError> {
    projection
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find(|candidate| json_string_field(candidate, "id").as_deref() == Some(receipt_id))
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_receipt_not_found",
                format!("model_mount receipt not found: {receipt_id}"),
            )
        })
}

fn model_mount_receipt_replay_projection(
    request: &ModelMountReadProjectionRequest,
    projection: &Value,
    receipt: &Value,
) -> Value {
    let receipts = projection
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let details = receipt.get("details").cloned().unwrap_or(Value::Null);
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection_replay",
        "receipt": receipt,
        "model_route_decision": details.get("model_route_decision").cloned().unwrap_or(Value::Null),
        "route": Value::Null,
        "endpoint": Value::Null,
        "instance": Value::Null,
        "provider": Value::Null,
        "toolReceipts": tool_receipts_from_details(&receipts, &details),
        "projectionWatermark": projection.get("watermark").cloned().unwrap_or(Value::Null),
    })
}

fn model_mount_route_decisions(request: &ModelMountReadProjectionRequest) -> Value {
    Value::Array(route_decisions_from_receipts(&array_field(
        &request.state,
        "receipts",
    )))
}

fn model_mount_latest_provider_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let provider_id = request.provider_id.as_deref().ok_or_else(|| {
        ModelMountReadProjectionError::new(
            "model_mount_provider_id_required",
            "latest provider health projection requires provider_id",
        )
    })?;
    let projection = model_mount_projection(request);
    let receipt = projection
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|candidate| {
            json_string_field(candidate, "kind").as_deref() == Some("provider_health")
                && candidate
                    .get("details")
                    .and_then(|details| json_string_field(details, "provider_id"))
                    .as_deref()
                    == Some(provider_id)
        })
        .last()
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_provider_health_not_found",
                format!("provider health has not been checked: {provider_id}"),
            )
        })?;
    let health = receipt.get("details").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_provider_health_latest",
        "providerId": provider_id,
        "health": health,
        "receipt": receipt,
        "replay": model_mount_receipt_replay_projection(request, &projection, &receipt),
        "projectionWatermark": projection.get("watermark").cloned().unwrap_or(Value::Null),
    }))
}

fn model_mount_latest_vault_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let projection = model_mount_projection(request);
    let receipt = projection
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|candidate| {
            json_string_field(candidate, "kind").as_deref() == Some("vault_adapter_health")
        })
        .last()
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_vault_health_not_found",
                "vault adapter health has not been checked",
            )
        })?;
    Ok(json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_vault_health_latest",
        "health": receipt.get("details").cloned().unwrap_or(Value::Null),
        "receipt": receipt,
        "replay": model_mount_receipt_replay_projection(request, &projection, &receipt),
        "projectionWatermark": projection.get("watermark").cloned().unwrap_or(Value::Null),
    }))
}

fn model_mount_latest_runtime_survey(request: &ModelMountReadProjectionRequest) -> Value {
    let receipts = array_field(&request.state, "receipts");
    let Some(receipt) = receipts.iter().rev().find(|candidate| {
        json_string_field(candidate, "kind").as_deref() == Some("runtime_survey")
    }) else {
        return model_mount_runtime_survey_not_checked(request);
    };
    let details = receipt.get("details").unwrap_or(&Value::Null);
    json!({
        "status": "checked",
        "receiptId": json_string_field(receipt, "id").unwrap_or_else(|| "none".to_string()),
        "checkedAt": details
            .get("checked_at")
            .cloned()
            .or_else(|| receipt.get("createdAt").cloned())
            .unwrap_or(Value::Null),
        "engineCount": details
            .get("engine_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        "selectedEngines": array_field(details, "selected_engines"),
        "runtimePreference": details
            .get("runtime_preference")
            .cloned()
            .unwrap_or(Value::Null),
        "hardware": details.get("hardware").cloned().unwrap_or(Value::Null),
        "lmStudio": details
            .get("lm_studio")
            .cloned()
            .unwrap_or_else(|| json!({"status": "unknown"})),
    })
}

fn model_mount_runtime_survey_not_checked(_request: &ModelMountReadProjectionRequest) -> Value {
    json!({
        "status": "not_checked",
        "receiptId": "none",
        "checkedAt": Value::Null,
        "engineCount": 0,
        "selectedEngines": Value::Array(Vec::new()),
        "runtimePreference": Value::Null,
        "hardware": Value::Null,
        "lmStudio": {
            "status": "not_checked",
            "evidenceRefs": ["runtime_survey_not_checked"],
        },
    })
}

fn model_mount_projection_schema_version(request: &ModelMountReadProjectionRequest) -> String {
    request
        .schema_version
        .clone()
        .unwrap_or_else(|| MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string())
}

fn model_mount_projection_generated_at(request: &ModelMountReadProjectionRequest) -> String {
    request
        .generated_at
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
}

fn array_field(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn object_or_null(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(_)) => value.cloned().unwrap_or(Value::Null),
        Some(Value::Null) | None => Value::Null,
        Some(other) => other.clone(),
    }
}

fn receipts_by_kind(receipts: &[Value], kind: &str) -> Vec<Value> {
    receipts
        .iter()
        .filter(|receipt| json_string_field(receipt, "kind").as_deref() == Some(kind))
        .cloned()
        .collect()
}

fn route_decisions_from_receipts(receipts: &[Value]) -> Vec<Value> {
    receipts
        .iter()
        .filter(|receipt| {
            json_string_field(receipt, "kind").as_deref() == Some("model_route_selection")
        })
        .filter_map(route_decision_from_receipt)
        .collect()
}

fn route_decision_from_receipt(receipt: &Value) -> Option<Value> {
    let mut decision = receipt
        .get("details")
        .and_then(|details| details.get("model_route_decision"))
        .and_then(Value::as_object)
        .cloned()?;
    decision.insert(
        "receipt_id".to_string(),
        receipt.get("id").cloned().unwrap_or(Value::Null),
    );
    decision.insert(
        "receipt_created_at".to_string(),
        receipt.get("createdAt").cloned().unwrap_or(Value::Null),
    );
    decision.insert(
        "receipt_kind".to_string(),
        receipt.get("kind").cloned().unwrap_or(Value::Null),
    );
    Some(Value::Object(decision))
}

fn tool_receipts_from_details(receipts: &[Value], details: &Value) -> Vec<Value> {
    let refs = match details.get("tool_receipt_ids") {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>(),
        Some(Value::String(value)) if !value.trim().is_empty() => vec![value.clone()],
        _ => vec![],
    };
    refs.into_iter()
        .filter_map(|receipt_id| {
            receipts
                .iter()
                .find(|receipt| {
                    json_string_field(receipt, "id").as_deref() == Some(receipt_id.as_str())
                })
                .cloned()
        })
        .collect()
}

fn json_string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_projection_is_planned_in_rust_model_mount_core() {
        let plan = plan_read_projection(&ModelMountReadProjectionRequest {
            projection_kind: "projection_summary".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            base_url: None,
            state: serde_json::json!({
                "receipts": [
                    {"id": "receipt_1", "kind": "model_route_selection", "details": {}}
                ]
            }),
        })
        .expect("read projection planned in Rust model_mount core");

        assert_eq!(plan.projection_kind, "projection_summary");
        assert_eq!(
            plan.projection["schemaVersion"],
            MODEL_MOUNT_RUNTIME_SCHEMA_VERSION
        );
        assert_eq!(
            plan.projection["source"],
            "agentgres_model_mounting_projection"
        );
        assert_eq!(plan.projection["watermark"], 1);
        assert_eq!(plan.projection["receiptCount"], 1);
        assert_eq!(
            plan.evidence_refs,
            vec![
                "rust_daemon_core_model_mount_projection",
                "agentgres_model_mount_read_truth",
                "model_mount_js_read_projection_authoring_retired",
            ],
        );
    }
}
