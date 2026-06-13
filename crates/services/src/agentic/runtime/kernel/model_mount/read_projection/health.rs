use serde_json::{json, Value};

use super::common::{array_field, json_string_field, model_mount_projection_schema_version};
use super::receipt::{receipt_replay_context, receipt_replay_projection};
use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn latest_provider_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let provider_id = request.provider_id.as_deref().ok_or_else(|| {
        ModelMountReadProjectionError::new(
            "model_mount_provider_id_required",
            "latest provider health projection requires provider_id",
        )
    })?;
    let projection = receipt_replay_context(request)?;
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
    let projection = receipt_replay_context(request)?;
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

pub(super) fn latest_runtime_survey(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let projection = receipt_replay_context(request)?;
    let receipts = array_field(&projection, "receipts");
    let Some(receipt) = receipts.iter().rev().find(|candidate| {
        json_string_field(candidate, "kind").as_deref() == Some("runtime_survey")
    }) else {
        return Ok(runtime_survey_not_checked());
    };
    let details = receipt.get("details").unwrap_or(&Value::Null);
    Ok(json!({
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
    }))
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

    fn request(state_dir: Option<String>, state: Value) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "latest_provider_health".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: Some("provider.local".to_string()),
            download_id: None,
            base_url: None,
            state_dir,
            state,
        }
    }

    fn write_receipts(state_dir: &std::path::Path, receipts: &[Value]) {
        let receipt_dir = state_dir.join("receipts");
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
    fn latest_health_projections_have_dedicated_receipt_projection_owner() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_receipts(
            temp.path(),
            &[
                json!({
                    "id": "receipt-provider",
                    "kind": "provider_health",
                    "details": {"provider_id": "provider.local", "status": "available"}
                }),
                json!({
                    "id": "receipt-vault",
                    "kind": "vault_adapter_health",
                    "details": {"status": "ready"}
                }),
            ],
        );
        let request = request(
            Some(temp.path().to_string_lossy().to_string()),
            json!({
                "receipts": [
                    {
                        "id": "receipt-js-provider",
                        "kind": "provider_health",
                        "details": {"provider_id": "provider.local", "status": "js"}
                    }
                ],
                "provider_health": [{"provider_id": "provider.js"}],
                "providers": [{"id": "provider.js"}]
            }),
        );

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
    fn runtime_survey_has_dedicated_receipt_projection_owner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let not_checked = latest_runtime_survey(&request(
            Some(temp.path().to_string_lossy().to_string()),
            json!({"receipts": []}),
        ))
        .expect("not checked");
        assert_eq!(not_checked["engineCount"], 0);
        assert_eq!(not_checked["runtimePreference"], Value::Null);
        assert_eq!(not_checked["hardware"], Value::Null);

        write_receipts(
            temp.path(),
            &[json!({
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
            })],
        );

        let checked = latest_runtime_survey(&request(
            Some(temp.path().to_string_lossy().to_string()),
            json!({"receipts": []}),
        ))
        .expect("checked");

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

    #[test]
    fn latest_health_rejects_js_receipt_transport_without_state_dir() {
        let error = latest_provider_health(&request(
            None,
            json!({
                "receipts": [{
                    "id": "receipt-provider",
                    "kind": "provider_health",
                    "details": {"provider_id": "provider.local", "status": "healthy"}
                }]
            }),
        ))
        .expect_err("state_dir is required");

        assert_eq!(error.code, "model_mount_receipt_replay_state_dir_required");
    }
}
