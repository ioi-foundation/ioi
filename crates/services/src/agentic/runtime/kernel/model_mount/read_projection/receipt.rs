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

pub(super) fn receipt_replay_context(request: &ModelMountReadProjectionRequest) -> Value {
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

pub(super) fn receipt_replay_projection(
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
}
