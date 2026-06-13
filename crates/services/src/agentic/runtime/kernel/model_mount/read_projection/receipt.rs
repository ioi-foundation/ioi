use std::{fs, path::Path};

use serde_json::{json, Value};

use super::common::{
    json_string_field, model_mount_projection_generated_at, model_mount_projection_schema_version,
};
use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

const RECEIPT_RECORD_DIR: &str = "receipts";

pub(super) fn projection_summary(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let receipts = receipt_records(request)?;
    Ok(json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection",
        "watermark": receipts.len(),
        "receiptCount": receipts.len(),
        "generatedAt": model_mount_projection_generated_at(request),
    }))
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
    let projection = receipt_replay_context(request)?;
    let receipt = find_receipt(&projection, receipt_id)?;
    Ok(receipt_replay_projection(request, &projection, &receipt))
}

pub(super) fn receipt_replay_context(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let receipts = receipt_records(request)?;
    Ok(json!({
        "watermark": receipts.len(),
        "receipts": receipts,
    }))
}

pub(super) fn receipt_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_receipt_replay_state_dir_required",
                "model_mount receipt projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join(RECEIPT_RECORD_DIR);
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_receipt_replay_read_failed",
            format!("failed to read model_mount receipt records: {error}"),
        )
    })?;
    let mut receipts = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .map(|path| {
            fs::read_to_string(&path)
                .map_err(|error| {
                    ModelMountReadProjectionError::new(
                        "model_mount_receipt_replay_read_failed",
                        format!(
                            "failed to read model_mount receipt record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_receipt_replay_invalid_record",
                            format!(
                                "failed to decode model_mount receipt record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(admitted_receipt_record)
        .collect::<Vec<_>>();
    receipts.sort_by(|left, right| {
        receipt_sort_key(left)
            .cmp(&receipt_sort_key(right))
            .then_with(|| json_string_field(left, "id").cmp(&json_string_field(right, "id")))
    });
    Ok(receipts)
}

fn admitted_receipt_record(receipt: &Value) -> bool {
    json_string_field(receipt, "id")
        .map(|value| !value.is_empty())
        .unwrap_or(false)
        && json_string_field(receipt, "kind")
            .map(|value| !value.is_empty())
            .unwrap_or(false)
}

fn receipt_sort_key(receipt: &Value) -> String {
    json_string_field(receipt, "createdAt")
        .or_else(|| json_string_field(receipt, "created_at"))
        .or_else(|| json_string_field(receipt, "generated_at"))
        .unwrap_or_default()
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

    fn request(state_dir: Option<String>, state: Value) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "receipt_replay".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: Some("receipt-route".to_string()),
            engine_id: None,
            provider_id: Some("provider.local".to_string()),
            download_id: None,
            base_url: None,
            state_dir,
            state,
        }
    }

    fn write_receipts(state_dir: &std::path::Path, receipts: &[Value]) {
        let receipt_dir = state_dir.join(RECEIPT_RECORD_DIR);
        std::fs::create_dir_all(&receipt_dir).expect("receipt dir");
        for receipt in receipts {
            let receipt_id = json_string_field(receipt, "id").expect("receipt id");
            std::fs::write(
                receipt_dir.join(format!("{receipt_id}.json")),
                serde_json::to_string_pretty(receipt).expect("receipt json"),
            )
            .expect("write receipt");
        }
    }

    #[test]
    fn projection_summary_is_planned_from_receipt_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_receipts(
            temp.path(),
            &[
                json!({"id": "receipt-one", "kind": "model_route_selection"}),
                json!({"id": "receipt-two", "kind": "provider_health"}),
            ],
        );
        let summary = projection_summary(&request(
            Some(temp.path().to_string_lossy().to_string()),
            json!({"receipts": [{"id": "receipt-js", "kind": "provider_health"}]}),
        ))
        .expect("projection summary");

        assert_eq!(summary["source"], "agentgres_model_mounting_projection");
        assert_eq!(summary["watermark"], 2);
        assert_eq!(summary["receiptCount"], 2);
        assert_eq!(summary["generatedAt"], "2026-06-11T00:00:00.000Z");
    }

    #[test]
    fn receipt_replay_is_planned_from_receipt_only_context() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_receipts(
            temp.path(),
            &[
                json!({"id": "tool-receipt", "kind": "mcp_tool_invocation"}),
                json!({
                    "id": "receipt-route",
                    "kind": "model_route_selection",
                    "details": {
                        "tool_receipt_ids": ["tool-receipt"],
                        "model_route_decision": {"route_id": "route.local-first"}
                    }
                }),
            ],
        );
        let _proof = "receipt replay projected from receipt-only Rust context";
        let replay = receipt_replay(&request(
            Some(temp.path().to_string_lossy().to_string()),
            json!({
                "receipts": [
                    {"id": "receipt-js", "kind": "model_route_selection"}
                ],
                "routes": [{"id": "route.js"}],
                "providers": [{"id": "provider.js"}]
            }),
        ))
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
    fn receipt_projection_rejects_js_receipt_transport_without_state_dir() {
        let error = projection_summary(&request(
            None,
            json!({"receipts": [{"id": "receipt-js", "kind": "model_route_selection"}]}),
        ))
        .expect_err("state_dir is required");

        assert_eq!(error.code, "model_mount_receipt_replay_state_dir_required");
    }
}
