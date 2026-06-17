use std::{fs, path::Path};

use serde_json::{json, Value};

use super::common::{array_field, json_string_field, model_mount_projection_schema_version};
use super::receipt::{receipt_replay_context, receipt_replay_projection};
use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

const PROVIDER_LIFECYCLE_RECORD_DIR: &str = "model-provider-lifecycle-controls";

pub(super) fn latest_provider_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let provider_id = request.provider_id.as_deref().ok_or_else(|| {
        ModelMountReadProjectionError::new(
            "model_mount_provider_id_required",
            "latest provider health projection requires provider_id",
        )
    })?;
    let records = provider_lifecycle_records(request)?;
    let record = records
        .iter()
        .filter(|candidate| is_provider_health_record(candidate))
        .filter(|candidate| {
            provider_id_from_ref(&string_field(candidate, "provider_ref")) == provider_id
        })
        .last()
        .cloned()
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_provider_health_not_found",
                format!("provider health has not been checked: {provider_id}"),
            )
        })?;
    Ok(provider_health_projection(
        request,
        &record,
        provider_id,
        records.len(),
        "agentgres_provider_lifecycle_health_latest",
    ))
}

pub(super) fn provider_health(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let records = provider_lifecycle_records(request)?;
    let watermark = records.len();
    Ok(Value::Array(
        records
            .iter()
            .filter(|candidate| is_provider_health_record(candidate))
            .map(|record| {
                let provider_id = provider_id_from_ref(&string_field(record, "provider_ref"));
                provider_health_projection(
                    request,
                    record,
                    &provider_id,
                    watermark,
                    "agentgres_provider_lifecycle_health",
                )
            })
            .collect::<Vec<_>>(),
    ))
}

pub(super) fn provider_lifecycle_records_or_empty(
    request: &ModelMountReadProjectionRequest,
) -> Vec<Value> {
    provider_lifecycle_records(request).unwrap_or_default()
}

fn provider_lifecycle_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_provider_lifecycle_replay_state_dir_required",
                "provider lifecycle projection requires Rust Agentgres lifecycle record state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join(PROVIDER_LIFECYCLE_RECORD_DIR);
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_provider_lifecycle_replay_read_failed",
            format!("failed to read provider lifecycle records: {error}"),
        )
    })?;
    let mut records = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .map(|path| {
            fs::read_to_string(&path)
                .map_err(|error| {
                    ModelMountReadProjectionError::new(
                        "model_mount_provider_lifecycle_replay_read_failed",
                        format!(
                            "failed to read provider lifecycle record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_provider_lifecycle_replay_invalid_record",
                            format!(
                                "failed to decode provider lifecycle record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_provider_lifecycle_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(left, "generated_at")
            .cmp(&string_field(right, "generated_at"))
            .then_with(|| string_field(left, "id").cmp(&string_field(right, "id")))
    });
    Ok(records)
}

fn admitted_provider_lifecycle_record(record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    if string_field(&record, "object") != "ioi.model_mount_provider_lifecycle" {
        return None;
    }
    if string_field(&record, "schema_version") != "ioi.model_mount.provider_lifecycle_plan.v1" {
        return None;
    }
    if string_field(&record, "record_dir") != PROVIDER_LIFECYCLE_RECORD_DIR {
        return None;
    }
    if string_field(&record, "rust_core_boundary") != "model_mount.provider_lifecycle" {
        return None;
    }
    for field in [
        "id",
        "record_id",
        "provider_ref",
        "provider_kind",
        "action",
        "operation_kind",
        "status",
        "backend",
        "backend_id",
        "driver",
        "execution_backend",
        "lifecycle_hash",
    ] {
        if string_field(&record, field).is_empty() {
            return None;
        }
    }
    if string_field(&record, "record_id") != string_field(&record, "id") {
        return None;
    }
    let evidence_refs = string_array_field(&record, "evidence_refs");
    if !evidence_refs
        .iter()
        .any(|value| value == "rust_model_mount_provider_lifecycle")
    {
        return None;
    }
    if !evidence_refs
        .iter()
        .any(|value| value == "agentgres_provider_lifecycle_truth_required")
    {
        return None;
    }
    Some(record)
}

fn is_provider_health_record(record: &Value) -> bool {
    string_field(record, "action") == "health"
        && string_field(record, "operation_kind") == "model_mount.provider.health"
}

fn provider_health_projection(
    request: &ModelMountReadProjectionRequest,
    record: &Value,
    provider_id: &str,
    watermark: usize,
    source: &str,
) -> Value {
    let health = json!({
        "provider_id": provider_id,
        "provider_ref": string_field(record, "provider_ref"),
        "provider_kind": string_field(record, "provider_kind"),
        "status": string_field(record, "status"),
        "action": string_field(record, "action"),
        "backend": string_field(record, "backend"),
        "backend_id": string_field(record, "backend_id"),
        "driver": string_field(record, "driver"),
        "execution_backend": string_field(record, "execution_backend"),
        "operation_kind": string_field(record, "operation_kind"),
        "rust_core_boundary": string_field(record, "rust_core_boundary"),
        "lifecycle_hash": string_field(record, "lifecycle_hash"),
        "evidence_refs": string_array_field(record, "evidence_refs"),
    });
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": source,
        "providerId": provider_id,
        "health": health,
        "record": record,
        "receipt": Value::Null,
        "replay": {
            "schemaVersion": model_mount_projection_schema_version(request),
            "source": "agentgres_provider_lifecycle_projection_replay",
            "record": record,
            "receipt": Value::Null,
            "projectionWatermark": watermark,
        },
        "projectionWatermark": watermark,
    })
}

fn provider_id_from_ref(provider_ref: &str) -> String {
    provider_ref
        .strip_prefix("provider://")
        .unwrap_or(provider_ref)
        .to_string()
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("")
        .to_string()
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
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

    fn write_provider_lifecycle_records(state_dir: &std::path::Path, records: &[Value]) {
        let record_dir = state_dir.join(PROVIDER_LIFECYCLE_RECORD_DIR);
        std::fs::create_dir_all(&record_dir).expect("provider lifecycle dir");
        for record in records {
            let record_id = json_string_field(record, "id").expect("record id");
            std::fs::write(
                record_dir.join(format!("{record_id}.json")),
                serde_json::to_string_pretty(record).expect("provider lifecycle json"),
            )
            .expect("write provider lifecycle");
        }
    }

    fn provider_lifecycle_record(
        id: &str,
        provider_ref: &str,
        status: &str,
        generated_at: &str,
    ) -> Value {
        json!({
            "id": id,
            "record_id": id,
            "object": "ioi.model_mount_provider_lifecycle",
            "schema_version": "ioi.model_mount.provider_lifecycle_plan.v1",
            "provider_ref": provider_ref,
            "provider_kind": "ioi_native_local",
            "endpoint_ref": "endpoint://endpoint.local",
            "model_ref": "model://local:auto",
            "action": "health",
            "operation_kind": "model_mount.provider.health",
            "status": status,
            "backend": "hypervisor.native_local.fixture",
            "backend_id": "backend.hypervisor.native-local.fixture",
            "driver": "native_local",
            "execution_backend": "rust_model_mount_native_local_lifecycle",
            "lifecycle_hash": format!("sha256:{id}"),
            "record_dir": PROVIDER_LIFECYCLE_RECORD_DIR,
            "receipt_refs": [format!("sha256:{id}")],
            "rust_core_boundary": "model_mount.provider_lifecycle",
            "source": "rust_model_mount_provider_lifecycle_api",
            "public_response": {
                "object": "ioi.model_mount_provider_lifecycle",
                "status": status,
                "provider_ref": provider_ref,
                "action": "health",
                "js_provider_driver_call": false,
                "js_provider_map_write": false,
                "js_lifecycle_receipt": false,
                "js_projection_write": false
            },
            "generated_at": generated_at,
            "evidence_refs": [
                "public_provider_lifecycle_js_facade_retired",
                "rust_model_mount_provider_lifecycle",
                "agentgres_provider_lifecycle_truth_required"
            ]
        })
    }

    #[test]
    fn latest_provider_health_replays_lifecycle_records_and_ignores_receipts() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_provider_lifecycle_records(
            temp.path(),
            &[
                provider_lifecycle_record(
                    "provider-lifecycle-old",
                    "provider://provider.local",
                    "degraded",
                    "2026-06-11T00:00:00.000Z",
                ),
                provider_lifecycle_record(
                    "provider-lifecycle-new",
                    "provider://provider.local",
                    "available",
                    "2026-06-11T00:00:02.000Z",
                ),
            ],
        );
        write_receipts(
            temp.path(),
            &[
                json!({
                    "id": "receipt-provider-stale",
                    "kind": "provider_health",
                    "details": {"provider_id": "provider.local", "status": "js-stale"}
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
        assert_eq!(
            provider["source"],
            "agentgres_provider_lifecycle_health_latest"
        );
        assert_eq!(provider["record"]["id"], "provider-lifecycle-new");
        assert_eq!(provider["receipt"], Value::Null);
        assert_eq!(provider["replay"]["record"]["id"], "provider-lifecycle-new");
        assert_eq!(provider["projectionWatermark"], 2);
        assert_eq!(vault["health"]["status"], "ready");
        assert_eq!(vault["projectionWatermark"], 2);
    }

    #[test]
    fn provider_health_list_replays_lifecycle_records_and_ignores_js_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_provider_lifecycle_records(
            temp.path(),
            &[
                provider_lifecycle_record(
                    "provider-lifecycle-one",
                    "provider://provider.local",
                    "available",
                    "2026-06-11T00:00:00.000Z",
                ),
                json!({
                    "id": "provider-lifecycle-start",
                    "record_id": "provider-lifecycle-start",
                    "object": "ioi.model_mount_provider_lifecycle",
                    "schema_version": "ioi.model_mount.provider_lifecycle_plan.v1",
                    "provider_ref": "provider://provider.local",
                    "provider_kind": "ioi_native_local",
                    "action": "load",
                    "operation_kind": "model_mount.provider.start",
                    "status": "loaded",
                    "backend": "hypervisor.native_local.fixture",
                    "backend_id": "backend.hypervisor.native-local.fixture",
                    "driver": "native_local",
                    "execution_backend": "rust_model_mount_native_local_lifecycle",
                    "lifecycle_hash": "sha256:start",
                    "record_dir": PROVIDER_LIFECYCLE_RECORD_DIR,
                    "rust_core_boundary": "model_mount.provider_lifecycle",
                    "generated_at": "2026-06-11T00:00:01.000Z",
                    "evidence_refs": [
                        "rust_model_mount_provider_lifecycle",
                        "agentgres_provider_lifecycle_truth_required"
                    ]
                }),
                provider_lifecycle_record(
                    "provider-lifecycle-two",
                    "provider://provider.remote",
                    "degraded",
                    "2026-06-11T00:00:02.000Z",
                ),
                json!({
                    "id": "provider-lifecycle-js",
                    "record_id": "provider-lifecycle-js",
                    "object": "ioi.model_mount_provider_lifecycle",
                    "schema_version": "ioi.model_mount.provider_lifecycle_plan.v1",
                    "provider_ref": "provider://provider.js",
                    "provider_kind": "custom_http",
                    "action": "health",
                    "operation_kind": "model_mount.provider.health",
                    "status": "healthy",
                    "backend": "hosted_provider_metadata",
                    "backend_id": "backend.hosted.custom_http",
                    "driver": "hosted_provider_metadata",
                    "execution_backend": "rust_model_mount_hosted_provider_lifecycle",
                    "lifecycle_hash": "sha256:js",
                    "record_dir": PROVIDER_LIFECYCLE_RECORD_DIR,
                    "rust_core_boundary": "model_mount.provider_lifecycle",
                    "generated_at": "2026-06-11T00:00:03.000Z",
                    "evidence_refs": ["rust_model_mount_provider_lifecycle"]
                }),
            ],
        );
        write_receipts(
            temp.path(),
            &[json!({
                "id": "receipt-provider-js",
                "kind": "provider_health",
                "createdAt": "2026-06-11T00:00:04.000Z",
                "details": {"provider_id": "provider.js", "status": "healthy"}
            })],
        );
        let request = ModelMountReadProjectionRequest {
            projection_kind: "provider_health".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            state: json!({
                "provider_health": [
                    {"provider_id": "provider.js", "status": "healthy"}
                ],
                "receipts": [
                    {
                        "id": "receipt-js",
                        "kind": "provider_health",
                        "details": {"provider_id": "provider.js", "status": "healthy"}
                    }
                ]
            }),
        };

        let health = provider_health(&request).expect("provider health");
        let entries = health.as_array().expect("provider health entries");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["source"], "agentgres_provider_lifecycle_health");
        assert_eq!(entries[0]["providerId"], "provider.local");
        assert_eq!(entries[0]["health"]["status"], "available");
        assert_eq!(entries[0]["record"]["id"], "provider-lifecycle-one");
        assert_eq!(entries[0]["receipt"], Value::Null);
        assert_eq!(
            entries[0]["replay"]["record"]["id"],
            "provider-lifecycle-one"
        );
        assert_eq!(entries[0]["projectionWatermark"], 3);
        assert_eq!(entries[1]["providerId"], "provider.remote");
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

        assert_eq!(
            error.code,
            "model_mount_provider_lifecycle_replay_state_dir_required"
        );
    }

    #[test]
    fn provider_health_list_rejects_js_transport_without_lifecycle_state_dir() {
        let error = provider_health(&ModelMountReadProjectionRequest {
            projection_kind: "provider_health".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: None,
            state: json!({
                "provider_health": [
                    {"provider_id": "provider.js", "status": "healthy"}
                ],
                "receipts": [{
                    "id": "receipt-provider",
                    "kind": "provider_health",
                    "details": {"provider_id": "provider.local", "status": "healthy"}
                }]
            }),
        })
        .expect_err("state_dir is required");

        assert_eq!(
            error.code,
            "model_mount_provider_lifecycle_replay_state_dir_required"
        );
    }
}
