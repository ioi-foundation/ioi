use serde_json::{json, Value};

use super::common::{
    array_field, json_string_field, model_mount_projection_generated_at,
    model_mount_projection_schema_version,
};
use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn projection_summary(request: &ModelMountReadProjectionRequest) -> Value {
    let receipts = array_field(&request.state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection",
        "watermark": receipts.len(),
        "receiptCount": receipts.len(),
        "generatedAt": model_mount_projection_generated_at(request),
    })
}

pub(super) fn receipt_replay(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let receipt_id = request.receipt_id.as_deref().ok_or_else(|| {
        ModelMountReadProjectionError::new(
            "model_mount_receipt_id_required",
            "model_mount receipt replay projection requires receipt_id",
        )
    })?;
    let projection = receipt_replay_context(request);
    let receipt = find_receipt(&projection, receipt_id)?;
    Ok(receipt_replay_projection(request, &projection, &receipt))
}

pub(super) fn route_decisions(request: &ModelMountReadProjectionRequest) -> Value {
    Value::Array(route_decisions_from_receipts(&array_field(
        &request.state,
        "receipts",
    )))
}

pub(super) fn latest_provider_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let provider_id = request.provider_id.as_deref().ok_or_else(|| {
        ModelMountReadProjectionError::new(
            "model_mount_provider_id_required",
            "latest provider health projection requires provider_id",
        )
    })?;
    let projection = receipt_replay_context(request);
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
        "replay": receipt_replay_projection(request, &projection, &receipt),
        "projectionWatermark": projection.get("watermark").cloned().unwrap_or(Value::Null),
    }))
}

pub(super) fn latest_vault_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let projection = receipt_replay_context(request);
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
        "replay": receipt_replay_projection(request, &projection, &receipt),
        "projectionWatermark": projection.get("watermark").cloned().unwrap_or(Value::Null),
    }))
}

pub(super) fn latest_runtime_survey(request: &ModelMountReadProjectionRequest) -> Value {
    let receipts = array_field(&request.state, "receipts");
    let Some(receipt) = receipts.iter().rev().find(|candidate| {
        json_string_field(candidate, "kind").as_deref() == Some("runtime_survey")
    }) else {
        return runtime_survey_not_checked();
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

pub(super) fn route_decisions_from_receipts(receipts: &[Value]) -> Vec<Value> {
    receipts
        .iter()
        .filter(|receipt| {
            json_string_field(receipt, "kind").as_deref() == Some("model_route_selection")
        })
        .filter_map(route_decision_from_receipt)
        .collect()
}

fn receipt_replay_context(request: &ModelMountReadProjectionRequest) -> Value {
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

fn receipt_replay_projection(
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

fn runtime_survey_not_checked() -> Value {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;

    fn request(state: Value) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "receipt_replay".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: Some("receipt-route".to_string()),
            engine_id: None,
            provider_id: Some("provider.local".to_string()),
            base_url: None,
            state,
        }
    }

    #[test]
    fn projection_summary_is_planned_from_receipt_truth() {
        let summary = projection_summary(&request(json!({
            "receipts": [
                {"id": "receipt-one", "kind": "model_route_selection"},
                {"id": "receipt-two", "kind": "provider_health"}
            ]
        })));

        assert_eq!(summary["source"], "agentgres_model_mounting_projection");
        assert_eq!(summary["watermark"], 2);
        assert_eq!(summary["receiptCount"], 2);
        assert_eq!(summary["generatedAt"], "2026-06-11T00:00:00.000Z");
    }

    #[test]
    fn receipt_replay_is_planned_from_receipt_only_context() {
        let _proof = "receipt replay projected from receipt-only Rust context";
        let replay = receipt_replay(&request(json!({
            "receipts": [
                {"id": "tool-receipt", "kind": "mcp_tool_invocation"},
                {
                    "id": "receipt-route",
                    "kind": "model_route_selection",
                    "details": {
                        "tool_receipt_ids": ["tool-receipt"],
                        "model_route_decision": {"route_id": "route.local-first"}
                    }
                }
            ],
            "routes": [{"id": "route.js"}],
            "providers": [{"id": "provider.js"}]
        })))
        .expect("receipt replay planned from receipt truth");

        assert_eq!(
            replay["source"],
            "agentgres_model_mounting_projection_replay"
        );
        assert_eq!(
            replay["model_route_decision"]["route_id"],
            "route.local-first"
        );
        assert_eq!(replay["route"], Value::Null);
        assert_eq!(replay["endpoint"], Value::Null);
        assert_eq!(replay["provider"], Value::Null);
        assert_eq!(replay["projectionWatermark"], 2);
        assert_eq!(
            replay["toolReceipts"]
                .as_array()
                .expect("tool receipts")
                .len(),
            1
        );
    }

    #[test]
    fn route_decisions_are_planned_from_route_selection_receipts() {
        let decisions = route_decisions(&request(json!({
            "receipts": [
                {"id": "receipt-other", "kind": "provider_health"},
                {
                    "id": "receipt-route",
                    "createdAt": "2026-06-11T00:02:00.000Z",
                    "kind": "model_route_selection",
                    "details": {"model_route_decision": {"route_id": "route.local-first"}}
                }
            ],
            "routes": [{"id": "route.js"}]
        })));

        let decisions = decisions.as_array().expect("route decisions");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["route_id"], "route.local-first");
        assert_eq!(decisions[0]["receipt_id"], "receipt-route");
        assert_eq!(decisions[0]["receipt_kind"], "model_route_selection");
    }

    #[test]
    fn latest_health_projections_are_planned_from_receipts_only() {
        let request = request(json!({
            "receipts": [
                {
                    "id": "receipt-provider",
                    "kind": "provider_health",
                    "details": {"provider_id": "provider.local", "status": "available"}
                },
                {
                    "id": "receipt-vault",
                    "kind": "vault_adapter_health",
                    "details": {"status": "ready"}
                }
            ],
            "provider_health": [{"provider_id": "provider.js"}],
            "providers": [{"id": "provider.js"}]
        }));

        let provider = latest_provider_health(&request).expect("provider health");
        let vault = latest_vault_health(&request).expect("vault health");

        assert_eq!(provider["providerId"], "provider.local");
        assert_eq!(provider["health"]["status"], "available");
        assert_eq!(provider["replay"]["provider"], Value::Null);
        assert_eq!(provider["projectionWatermark"], 2);
        assert_eq!(vault["health"]["status"], "ready");
        assert_eq!(vault["projectionWatermark"], 2);
    }

    #[test]
    fn runtime_survey_is_planned_from_runtime_survey_receipts() {
        let not_checked = latest_runtime_survey(&request(json!({"receipts": []})));
        assert_eq!(not_checked["engineCount"], 0);
        assert_eq!(not_checked["runtimePreference"], Value::Null);
        assert_eq!(not_checked["hardware"], Value::Null);

        let checked = latest_runtime_survey(&request(json!({
            "receipts": [{
                "id": "receipt-runtime-survey",
                "kind": "runtime_survey",
                "details": {
                    "checked_at": "2026-06-11T00:03:00.000Z",
                    "engine_count": 2,
                    "selected_engines": ["backend.llama-cpp"],
                    "runtime_preference": {"routeId": "route.local-first"},
                    "hardware": {"gpu": "available"},
                    "lm_studio": {"status": "unavailable"}
                }
            }]
        })));

        assert_eq!(checked["receiptId"], "receipt-runtime-survey");
        assert_eq!(checked["engineCount"], 2);
        assert_eq!(
            checked["selectedEngines"]
                .as_array()
                .expect("selected")
                .len(),
            1
        );
        assert_eq!(checked["runtimePreference"]["routeId"], "route.local-first");
        assert_eq!(checked["hardware"]["gpu"], "available");
        assert_eq!(checked["lmStudio"]["status"], "unavailable");
    }
}
