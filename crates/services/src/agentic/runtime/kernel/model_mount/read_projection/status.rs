use std::{collections::BTreeSet, fs, path::Path};

use serde_json::{json, Value};

use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_SERVER_CONTROL_PLAN_SCHEMA_VERSION;

use super::common::model_mount_projection_schema_version;
use super::{topology, ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn server_status(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(server_status_from_records(
        request,
        agentgres_server_control_records(request)?,
        topology::backend_records(request).unwrap_or_default(),
    ))
}

pub(super) fn server_status_or_default(request: &ModelMountReadProjectionRequest) -> Value {
    let server_controls = agentgres_server_control_records(request).unwrap_or_default();
    let backend_records = topology::backend_records(request).unwrap_or_default();
    server_status_from_records(request, server_controls, backend_records)
}

pub(super) fn server_logs(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let records = agentgres_server_control_records(request)?;
    Ok(server_log_projection(request, records, "server_logs"))
}

pub(super) fn server_events(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let records = agentgres_server_control_records(request)?;
    let logs = server_log_entries_from_records(&records, server_log_query_limit(request, 80));
    let events = logs
        .iter()
        .map(|entry| {
            json!({
                "event": entry.get("event").cloned().unwrap_or(Value::Null),
                "timestamp": entry.get("timestamp").cloned().unwrap_or(Value::Null),
                "level": entry.get("level").cloned().unwrap_or(Value::Null),
                "operation_kind": entry.get("operation_kind").cloned().unwrap_or(Value::Null),
                "receiptId": entry.get("receiptId").cloned().unwrap_or(Value::Null),
                "record_id": entry.get("record_id").cloned().unwrap_or(Value::Null),
                "rust_core_boundary": "model_mount.server_control_log_projection",
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "object": "ioi.model_mount_server_events",
        "status": "projected",
        "events": events,
        "count": logs.len(),
        "receiptId": latest_server_control_receipt(&records).map(Value::String).unwrap_or(Value::Null),
        "source": "agentgres_server_control",
        "recordDir": "model-server-controls",
        "recordCount": records.len(),
        "rustCoreBoundary": "model_mount.server_control_log_projection",
        "evidenceRefs": server_log_projection_evidence_refs(),
    }))
}

pub(super) fn server_log_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let records = agentgres_server_control_records(request)?;
    Ok(server_log_projection(
        request,
        records,
        "server_log_records",
    ))
}

fn server_status_from_records(
    request: &ModelMountReadProjectionRequest,
    server_controls: Vec<Value>,
    backend_records: Vec<Value>,
) -> Value {
    let base_url = request.base_url.clone();
    let open_ai_compatible_base_url = base_url
        .as_ref()
        .map(|url| format!("{url}/v1"))
        .unwrap_or_else(|| "/v1".to_string());
    let latest = server_controls.last();
    let public_response = latest
        .and_then(|record| record.get("public_response"))
        .cloned()
        .unwrap_or(Value::Null);
    let last_operation = latest
        .and_then(|record| {
            public_response
                .get("operation")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| non_empty_field(record, "operation_kind"))
        })
        .unwrap_or_else(|| "server_status".to_string());
    let status = public_response
        .get("server_status")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            public_response
                .get("operation_status")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| latest.and_then(|record| non_empty_field(record, "status")))
        .unwrap_or_else(|| "stopped".to_string());
    let last_operation_at = latest
        .map(|record| string_field(record, "generated_at"))
        .filter(|value| !value.is_empty())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let last_receipt = latest
        .and_then(latest_non_control_receipt_ref)
        .map(Value::String)
        .unwrap_or(Value::Null);
    let provider_count = topology::provider_records(request).len();
    let backend_available = backend_records
        .iter()
        .filter(|record| string_field(record, "status") != "stop_planned")
        .count();
    let backend_degraded = backend_records
        .iter()
        .filter(|record| string_field(record, "status") == "stop_planned")
        .count();
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "status": status,
        "gatewayStatus": "running",
        "controlStatus": "running",
        "lastServerOperation": last_operation,
        "lastServerOperationAt": last_operation_at,
        "lastServerReceiptId": last_receipt,
        "openAiCompatibleBaseUrl": open_ai_compatible_base_url,
        "loadedInstances": topology::instance_records(request).len(),
        "mountedEndpoints": topology::endpoint_records(request).len(),
        "providerStates": {
            "available": provider_count,
            "degraded": 0,
        },
        "backendStates": {
            "available": backend_available,
            "degraded": backend_degraded,
        },
        "idleTtlSeconds": 900,
        "autoEvict": true,
        "checkedAt": request.generated_at.clone().map(Value::String).unwrap_or(Value::Null),
        "source": "agentgres_server_control",
        "recordDir": "model-server-controls",
        "recordCount": server_controls.len(),
        "rustCoreBoundary": "model_mount.server_control_projection",
        "evidenceRefs": [
            "rust_daemon_core_server_control_projection",
            "agentgres_server_control_replay_required",
            "model_mount_server_status_js_projection_retired"
        ],
    })
}

fn server_log_projection(
    request: &ModelMountReadProjectionRequest,
    records: Vec<Value>,
    projection_kind: &str,
) -> Value {
    let limit = server_log_query_limit(request, 80);
    let entries = server_log_entries_from_records(&records, limit);
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "object": "ioi.model_mount_server_logs",
        "status": "projected",
        "projectionKind": projection_kind,
        "redaction": "redacted",
        "records": entries,
        "count": records.len().min(limit),
        "receiptId": latest_server_control_receipt(&records).map(Value::String).unwrap_or(Value::Null),
        "source": "agentgres_server_control",
        "recordDir": "model-server-controls",
        "recordCount": records.len(),
        "rustCoreBoundary": "model_mount.server_control_log_projection",
        "evidenceRefs": server_log_projection_evidence_refs(),
    })
}

fn server_log_entries_from_records(records: &[Value], limit: usize) -> Vec<Value> {
    let start = records.len().saturating_sub(limit);
    records.iter().skip(start).map(server_log_entry).collect()
}

fn server_log_entry(record: &Value) -> Value {
    let public_response = record.get("public_response").unwrap_or(&Value::Null);
    let event = server_control_event(record, public_response);
    let level = non_empty_field(public_response, "level")
        .or_else(|| {
            if string_field(public_response, "operation_status") == "blocked" {
                Some("warn".to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "info".to_string());
    let message = non_empty_field(public_response, "message").unwrap_or_else(|| {
        event
            .split('_')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    });
    json!({
        "event": event,
        "level": level,
        "message": message,
        "timestamp": string_field(record, "generated_at"),
        "operation_kind": string_field(record, "operation_kind"),
        "operation_status": non_empty_field(public_response, "operation_status")
            .or_else(|| non_empty_field(record, "status"))
            .map(Value::String)
            .unwrap_or(Value::Null),
        "server_control_id": string_field(record, "server_control_id"),
        "receiptId": latest_non_control_receipt_ref(record).map(Value::String).unwrap_or(Value::Null),
        "receipt_refs": string_array_field(record, "receipt_refs"),
        "record_dir": "model-server-controls",
        "record_id": string_field(record, "id"),
        "control_hash": string_field(record, "control_hash"),
        "source": string_field(record, "source"),
        "rust_core_boundary": "model_mount.server_control_log_projection",
        "evidence_refs": server_log_projection_evidence_refs(),
    })
}

fn server_control_event(record: &Value, public_response: &Value) -> String {
    if let Some(event) = non_empty_field(public_response, "event") {
        return event;
    }
    if let Some(operation) = non_empty_field(public_response, "operation") {
        return operation;
    }
    match string_field(record, "operation_kind").as_str() {
        "model_mount.server_control.start" => "server_start".to_string(),
        "model_mount.server_control.stop" => "server_stop".to_string(),
        "model_mount.server_control.restart" => "server_restart".to_string(),
        "model_mount.server_control.write" => "server_control_state_write".to_string(),
        "model_mount.server_control.record_operation" => "server_operation_recorded".to_string(),
        "model_mount.server_control.log_append" => "server_log_appended".to_string(),
        _ => "server_control_recorded".to_string(),
    }
}

fn server_log_query_limit(
    request: &ModelMountReadProjectionRequest,
    default_limit: usize,
) -> usize {
    let raw_limit = request
        .state
        .get("server_log_query")
        .and_then(|query| query.get("limit"));
    let parsed = raw_limit
        .and_then(Value::as_u64)
        .or_else(|| {
            raw_limit
                .and_then(Value::as_str)
                .and_then(|value| value.trim().parse::<u64>().ok())
        })
        .filter(|value| *value > 0)
        .unwrap_or(default_limit as u64);
    parsed.min(500) as usize
}

fn latest_server_control_receipt(records: &[Value]) -> Option<String> {
    records
        .iter()
        .rev()
        .find_map(latest_non_control_receipt_ref)
}

fn server_log_projection_evidence_refs() -> Vec<&'static str> {
    vec![
        "rust_daemon_core_server_control_log_projection",
        "agentgres_server_control_log_replay_required",
        "model_mount_server_log_read_js_control_path_retired",
    ]
}

fn agentgres_server_control_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_server_control_replay_state_dir_required",
                "server status projection requires Rust Agentgres server-control state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("model-server-controls");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_server_control_replay_read_failed",
            format!("failed to read server-control records: {error}"),
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
                        "model_mount_server_control_replay_read_failed",
                        format!(
                            "failed to read server-control record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_server_control_replay_invalid_record",
                            format!(
                                "failed to decode server-control record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_server_control_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(left, "generated_at")
            .cmp(&string_field(right, "generated_at"))
            .then_with(|| string_field(left, "id").cmp(&string_field(right, "id")))
    });
    Ok(records)
}

fn admitted_server_control_record(record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    if string_field(&record, "schema_version") != MODEL_MOUNT_SERVER_CONTROL_PLAN_SCHEMA_VERSION {
        return None;
    }
    if string_field(&record, "object") != "ioi.model_mount_server_control_record" {
        return None;
    }
    if string_field(&record, "rust_core_boundary") != "model_mount.server_control" {
        return None;
    }
    if !matches!(
        string_field(&record, "operation_kind").as_str(),
        "model_mount.server_control.start"
            | "model_mount.server_control.stop"
            | "model_mount.server_control.restart"
            | "model_mount.server_control.write"
            | "model_mount.server_control.record_operation"
            | "model_mount.server_control.log_append"
    ) {
        return None;
    }
    for field in [
        "id",
        "server_control_id",
        "operation_kind",
        "status",
        "generated_at",
        "control_hash",
    ] {
        if string_field(&record, field).is_empty() {
            return None;
        }
    }
    let evidence_refs = evidence_refs(&record);
    for required in [
        "public_server_control_js_facade_retired",
        "rust_daemon_core_server_control",
        "agentgres_server_control_truth_required",
    ] {
        if !evidence_refs.iter().any(|value| value == required) {
            return None;
        }
    }
    Some(record)
}

fn latest_non_control_receipt_ref(record: &Value) -> Option<String> {
    string_array_field(record, "receipt_refs")
        .into_iter()
        .find(|value| !value.starts_with("sha256:"))
        .or_else(|| {
            string_array_field(record, "receipt_refs")
                .into_iter()
                .next()
        })
}

pub(super) fn catalog_status(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let records = topology::agentgres_provider_inventory_records(request).map_err(|error| {
        if error.code == "model_mount_provider_inventory_replay_state_dir_required" {
            return ModelMountReadProjectionError::new(
                "model_mount_catalog_status_replay_state_dir_required",
                "catalog status projection requires Rust Agentgres provider inventory state_dir replay",
            );
        }
        error
    })?;
    Ok(catalog_status_from_provider_inventory(request, records))
}

pub(super) fn catalog_status_or_default(request: &ModelMountReadProjectionRequest) -> Value {
    topology::agentgres_provider_inventory_records(request)
        .map(|records| catalog_status_from_provider_inventory(request, records))
        .unwrap_or_else(|_| empty_catalog_status(request))
}

fn empty_catalog_status(request: &ModelMountReadProjectionRequest) -> Value {
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "checkedAt": Value::Null,
        "providers": [],
        "adapterBoundary": catalog_adapter_boundary(),
        "filters": {
            "formats": ["gguf", "mlx", "safetensors"],
            "quantization": ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
            "compatibility": ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
        },
        "storage": Value::Null,
        "lastSearch": Value::Null,
        "results": [],
    })
}

fn catalog_status_from_provider_inventory(
    request: &ModelMountReadProjectionRequest,
    records: Vec<Value>,
) -> Value {
    let providers = catalog_provider_statuses(&records);
    let results = catalog_status_results(&records);
    let provider_count = providers.len();
    let result_count = results.len();
    let record_count = records.len();
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "checkedAt": request.generated_at.clone().map(Value::String).unwrap_or(Value::Null),
        "providers": providers,
        "adapterBoundary": catalog_adapter_boundary(),
        "filters": {
            "formats": ["gguf", "mlx", "safetensors"],
            "quantization": ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
            "compatibility": ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
        },
        "storage": {
            "object": "ioi.model_catalog_storage_status",
            "source": "agentgres_provider_inventory",
            "record_dir": "model-provider-inventory",
            "record_count": record_count,
            "rust_core_boundary": "model_mount.catalog_status",
            "evidence_refs": catalog_status_evidence_refs(),
        },
        "lastSearch": {
            "object": "ioi.model_catalog_status_last_search",
            "source": "agentgres_provider_inventory",
            "query": "",
            "provider_count": provider_count,
            "inventory_record_count": record_count,
            "result_count": result_count,
            "rust_core_boundary": "model_mount.catalog_status",
            "evidence_refs": catalog_status_evidence_refs(),
        },
        "results": results,
        "source": "agentgres_provider_inventory",
        "rust_core_boundary": "model_mount.catalog_status",
        "evidence_refs": catalog_status_evidence_refs(),
    })
}

fn catalog_provider_statuses(records: &[Value]) -> Vec<Value> {
    let mut provider_refs = records
        .iter()
        .map(|record| string_field(record, "provider_ref"))
        .filter(|provider_ref| !provider_ref.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    provider_refs.sort();
    provider_refs
        .into_iter()
        .filter_map(|provider_ref| catalog_provider_status(records, &provider_ref))
        .collect()
}

fn catalog_provider_status(records: &[Value], provider_ref: &str) -> Option<Value> {
    let provider_records = records
        .iter()
        .filter(|record| string_field(record, "provider_ref") == provider_ref)
        .collect::<Vec<_>>();
    let first = provider_records.first()?;
    let actions = sorted_unique_strings(
        provider_records
            .iter()
            .map(|record| string_field(record, "action"))
            .collect(),
    );
    let inventory_record_ids = sorted_unique_strings(
        provider_records
            .iter()
            .map(|record| string_field(record, "record_id"))
            .collect(),
    );
    let inventory_hashes = sorted_unique_strings(
        provider_records
            .iter()
            .map(|record| string_field(record, "inventory_hash"))
            .collect(),
    );
    let model_count = provider_records
        .iter()
        .filter(|record| string_field(record, "action") == "list_models")
        .map(|record| string_array_field(record, "item_refs").len())
        .sum::<usize>();
    let loaded_instance_count = provider_records
        .iter()
        .filter(|record| string_field(record, "action") == "list_loaded")
        .map(|record| string_array_field(record, "item_refs").len())
        .sum::<usize>();
    Some(json!({
        "id": provider_ref,
        "object": "ioi.model_catalog_provider_status",
        "provider_ref": provider_ref,
        "provider_kind": string_field(first, "provider_kind"),
        "backend": string_field(first, "backend"),
        "backend_id": string_field(first, "backend_id"),
        "driver": string_field(first, "driver"),
        "status": "available",
        "actions": actions,
        "inventory_record_ids": inventory_record_ids,
        "inventory_hashes": inventory_hashes,
        "model_count": model_count,
        "loaded_instance_count": loaded_instance_count,
        "source": "agentgres_provider_inventory",
        "rust_core_boundary": "model_mount.catalog_status",
        "evidence_refs": catalog_status_evidence_refs(),
    }))
}

fn catalog_status_results(records: &[Value]) -> Vec<Value> {
    let mut results = records
        .iter()
        .filter(|record| string_field(record, "action") == "list_models")
        .flat_map(|record| {
            string_array_field(record, "item_refs")
                .into_iter()
                .map(|item_ref| catalog_status_result(record, &item_ref))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    results.sort_by(|left, right| {
        string_field(left, "model_ref")
            .cmp(&string_field(right, "model_ref"))
            .then_with(|| {
                string_field(left, "provider_ref").cmp(&string_field(right, "provider_ref"))
            })
    });
    results
}

fn catalog_status_result(record: &Value, item_ref: &str) -> Value {
    json!({
        "id": format!(
            "catalog_status_{}_{}",
            record_id_segment(&string_field(record, "record_id"), "record"),
            record_id_segment(item_ref, "model")
        ),
        "object": "ioi.model_catalog_status_result",
        "model_ref": item_ref,
        "model_id": model_id_from_item_ref(item_ref),
        "provider_ref": string_field(record, "provider_ref"),
        "provider_kind": string_field(record, "provider_kind"),
        "backend": string_field(record, "backend"),
        "backend_id": string_field(record, "backend_id"),
        "driver": string_field(record, "driver"),
        "inventory_record_id": string_field(record, "record_id"),
        "inventory_hash": string_field(record, "inventory_hash"),
        "source": "agentgres_provider_inventory",
        "rust_core_boundary": "model_mount.catalog_status",
        "evidence_refs": catalog_status_evidence_refs(),
    })
}

fn catalog_status_evidence_refs() -> Vec<&'static str> {
    vec![
        "rust_daemon_core_catalog_status_projection",
        "agentgres_catalog_status_replay_required",
        "agentgres_provider_inventory_truth_required",
        "model_catalog_status_js_readback_retired",
    ]
}

fn sorted_unique_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn non_empty_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn evidence_refs(value: &Value) -> Vec<String> {
    string_array_field(value, "evidence_refs")
}

fn model_id_from_item_ref(item_ref: &str) -> String {
    item_ref
        .rsplit(|ch| matches!(ch, '/' | ':'))
        .find(|segment| !segment.trim().is_empty())
        .unwrap_or(item_ref)
        .to_string()
}

fn record_id_segment(value: &str, fallback: &str) -> String {
    let mut segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while segment.contains("__") {
        segment = segment.replace("__", "_");
    }
    let segment = segment.trim_matches('_');
    if segment.is_empty() {
        fallback.to_string()
    } else {
        segment.to_string()
    }
}

fn catalog_adapter_boundary() -> Value {
    json!({
        "port": "ModelCatalogProviderPort",
        "operations": ["search", "resolveVariant", "importUrl", "download", "health"],
        "evidenceRefs": ["provider_neutral_model_catalog_adapter_boundary"],
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;

    #[test]
    fn server_status_replays_agentgres_server_control_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_server_control_record(
            temp.path(),
            json!({
                "id": "legacy-js-server-control",
                "schema_version": "ioi.model_mount.server_control_plan.v1",
                "object": "ioi.model_mount_server_control_record",
                "server_control_id": "server-control.default",
                "operation_kind": "model_mount.server_control.start",
                "status": "planned",
                "source": "runtime-daemon.server_control_js",
                "generated_at": "2026-06-13T00:00:00.000Z",
                "rust_core_boundary": "daemon_js",
                "control_hash": "sha256:legacy",
                "evidence_refs": ["legacy_js_server_control"]
            }),
        );
        write_server_control_record(
            temp.path(),
            json!({
                "id": "server-control:record-operation",
                "schema_version": "ioi.model_mount.server_control_plan.v1",
                "object": "ioi.model_mount_server_control_record",
                "server_control_id": "server-control.default",
                "operation_kind": "model_mount.server_control.record_operation",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.server_control",
                "generated_at": "2026-06-13T00:00:01.000Z",
                "rust_core_boundary": "model_mount.server_control",
                "control_hash": "sha256:server-control",
                "public_response": {
                    "object": "ioi.model_mount_server_control",
                    "status": "planned",
                    "operation_kind": "model_mount.server_control.record_operation",
                    "server_control_id": "server-control.default",
                    "rust_core_boundary": "model_mount.server_control",
                    "operation": "server_stop",
                    "operation_status": "blocked",
                    "operation_recorded": true,
                    "js_state_write": false,
                    "js_log_write": false,
                    "js_transport_execution": false
                },
                "receipt_refs": ["receipt://server/operation", "sha256:server-control"],
                "evidence_refs": [
                    "public_server_control_js_facade_retired",
                    "rust_daemon_core_server_control",
                    "agentgres_server_control_truth_required"
                ]
            }),
        );
        let status = server_status(&ModelMountReadProjectionRequest {
            projection_kind: "server_status".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-13T00:00:02.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: Some("http://127.0.0.1:3200".to_string()),
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            state: json!({ "retired_js_status_input": {"status": "js-retired"} }),
        })
        .expect("server status replay");

        assert_eq!(status["schemaVersion"], MODEL_MOUNT_RUNTIME_SCHEMA_VERSION);
        assert_eq!(status["status"], "blocked");
        assert_eq!(status["lastServerOperation"], "server_stop");
        assert_eq!(status["lastServerReceiptId"], "receipt://server/operation");
        assert_eq!(status["recordCount"], 1);
        assert_eq!(
            status["rustCoreBoundary"],
            "model_mount.server_control_projection"
        );
        assert_eq!(status.get("nativeBaseUrl"), None);
        assert_eq!(
            status["openAiCompatibleBaseUrl"],
            "http://127.0.0.1:3200/v1"
        );
        assert_eq!(status["loadedInstances"], 0);
        assert_eq!(status["mountedEndpoints"], 0);
    }

    #[test]
    fn server_status_fails_closed_without_agentgres_state_dir() {
        let error = server_status(&ModelMountReadProjectionRequest {
            projection_kind: "server_status".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: None,
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: None,
            state: json!({}),
        })
        .expect_err("state dir required");

        assert_eq!(
            error.code,
            "model_mount_server_control_replay_state_dir_required"
        );
    }

    #[test]
    fn server_logs_and_events_replay_agentgres_server_control_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_server_control_record(
            temp.path(),
            json!({
                "id": "server-control:restart",
                "schema_version": "ioi.model_mount.server_control_plan.v1",
                "object": "ioi.model_mount_server_control_record",
                "server_control_id": "server-control.default",
                "operation_kind": "model_mount.server_control.restart",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.server_control",
                "generated_at": "2026-06-13T00:00:01.000Z",
                "rust_core_boundary": "model_mount.server_control",
                "control_hash": "sha256:server-restart",
                "public_response": {
                    "object": "ioi.model_mount_server_control",
                    "status": "planned",
                    "operation_kind": "model_mount.server_control.restart",
                    "server_control_id": "server-control.default",
                    "rust_core_boundary": "model_mount.server_control",
                    "server_status": "restart_planned",
                    "js_state_write": false,
                    "js_log_write": false,
                    "js_transport_execution": false
                },
                "receipt_refs": ["receipt://server/restart", "sha256:server-restart"],
                "evidence_refs": [
                    "public_server_control_js_facade_retired",
                    "rust_daemon_core_server_control",
                    "agentgres_server_control_truth_required"
                ]
            }),
        );
        write_server_control_record(
            temp.path(),
            json!({
                "id": "server-control:log-append",
                "schema_version": "ioi.model_mount.server_control_plan.v1",
                "object": "ioi.model_mount_server_control_record",
                "server_control_id": "server-control.default",
                "operation_kind": "model_mount.server_control.log_append",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.server_control",
                "generated_at": "2026-06-13T00:00:02.000Z",
                "rust_core_boundary": "model_mount.server_control",
                "control_hash": "sha256:server-log-append",
                "public_response": {
                    "object": "ioi.model_mount_server_control",
                    "status": "planned",
                    "operation_kind": "model_mount.server_control.log_append",
                    "server_control_id": "server-control.default",
                    "rust_core_boundary": "model_mount.server_control",
                    "event": "provider_probe",
                    "level": "info",
                    "message": "provider probe completed",
                    "log_appended": true,
                    "js_state_write": false,
                    "js_log_write": false,
                    "js_transport_execution": false
                },
                "receipt_refs": ["receipt://server/log-append", "sha256:server-log-append"],
                "evidence_refs": [
                    "public_server_control_js_facade_retired",
                    "rust_daemon_core_server_control",
                    "agentgres_server_control_truth_required"
                ]
            }),
        );
        write_server_control_record(
            temp.path(),
            json!({
                "id": "server-control:retired-logs-read",
                "schema_version": "ioi.model_mount.server_control_plan.v1",
                "object": "ioi.model_mount_server_control_record",
                "server_control_id": "server-control.default",
                "operation_kind": "model_mount.server_control.logs_read",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.server_control",
                "generated_at": "2026-06-13T00:00:03.000Z",
                "rust_core_boundary": "model_mount.server_control",
                "control_hash": "sha256:retired-logs-read",
                "public_response": {
                    "object": "ioi.model_mount_server_control",
                    "status": "planned",
                    "operation_kind": "model_mount.server_control.logs_read",
                    "server_control_id": "server-control.default"
                },
                "receipt_refs": ["receipt://server/logs-read", "sha256:retired-logs-read"],
                "evidence_refs": [
                    "public_server_control_js_facade_retired",
                    "rust_daemon_core_server_control",
                    "agentgres_server_control_truth_required"
                ]
            }),
        );
        let request = ModelMountReadProjectionRequest {
            projection_kind: "server_logs".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-13T00:00:04.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            state: json!({ "server_log_query": { "limit": 2 } }),
        };

        let logs = server_logs(&request).expect("server logs replay");
        let events = server_events(&ModelMountReadProjectionRequest {
            projection_kind: "server_events".to_string(),
            ..request
        })
        .expect("server events replay");

        assert_eq!(logs["redaction"], "redacted");
        assert_eq!(logs["recordCount"], 2);
        assert_eq!(logs["records"][0]["event"], "server_restart");
        assert_eq!(logs["records"][1]["event"], "provider_probe");
        assert_eq!(
            logs["records"][1]["receiptId"],
            "receipt://server/log-append"
        );
        assert_eq!(
            logs["rustCoreBoundary"],
            "model_mount.server_control_log_projection"
        );
        assert_eq!(events["events"][0]["event"], "server_restart");
        assert_eq!(events["events"][1]["event"], "provider_probe");
        assert!(events["events"]
            .as_array()
            .expect("events")
            .iter()
            .all(|event| event["event"] != "server_events_read"));
    }

    #[test]
    fn catalog_status_is_planned_in_rust_model_mount_projection() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_provider_inventory_record(
            temp.path(),
            json!({
                "id": "legacy-js-provider-inventory",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": "ioi.model_mount.provider_inventory.v1",
                "provider_ref": "provider://legacy",
                "provider_kind": "local_folder",
                "action": "list_models",
                "operation_kind": "model_mount.provider.inventory.list_models",
                "status": "listed",
                "backend": "ioi_fixture",
                "backend_id": "backend.fixture",
                "driver": "fixture",
                "execution_backend": "daemon_js",
                "item_refs": ["model://legacy/qwen3"],
                "item_count": 1,
                "inventory_hash": "sha256:legacy",
                "record_dir": "model-provider-inventory",
                "record_id": "legacy-js-provider-inventory",
                "rust_core_boundary": "daemon_js",
                "source": "runtime-daemon.provider_inventory_js",
                "evidence_refs": ["legacy_js_provider_inventory"]
            }),
        );
        write_provider_inventory_record(
            temp.path(),
            json!({
                "id": "provider_inventory_fixture_list_models",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": "ioi.model_mount.provider_inventory.v1",
                "provider_ref": "provider://fixture",
                "provider_kind": "local_folder",
                "action": "list_models",
                "operation_kind": "model_mount.provider.inventory.list_models",
                "status": "listed",
                "backend": "ioi_fixture",
                "backend_id": "backend.fixture",
                "driver": "fixture",
                "execution_backend": "rust_model_mount_fixture_inventory",
                "item_refs": ["model://fixture/qwen3"],
                "item_count": 1,
                "inventory_hash": "sha256:fixture-inventory",
                "record_dir": "model-provider-inventory",
                "record_id": "provider_inventory_fixture_list_models",
                "receipt_refs": [],
                "rust_core_boundary": "model_mount.provider_inventory",
                "source": "rust_model_mount_provider_inventory_api",
                "evidence_refs": [
                    "rust_model_mount_provider_inventory",
                    "agentgres_provider_inventory_truth_required",
                    "rust_model_mount_fixture_inventory_backend"
                ]
            }),
        );

        let status = catalog_status(&ModelMountReadProjectionRequest {
            projection_kind: "catalog_status".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            state: json!({
                "catalog_status_input": {"checkedAt": "retired-js-input"},
            }),
        })
        .expect("catalog status");

        assert_eq!(status["schemaVersion"], MODEL_MOUNT_RUNTIME_SCHEMA_VERSION);
        assert_eq!(
            status["adapterBoundary"]["port"],
            "ModelCatalogProviderPort"
        );
        assert_eq!(status["source"], "agentgres_provider_inventory");
        assert_eq!(status["rust_core_boundary"], "model_mount.catalog_status");
        assert_eq!(status["checkedAt"], "2026-06-13T00:00:00.000Z");
        assert_eq!(status["providers"][0]["provider_ref"], "provider://fixture");
        assert_eq!(status["providers"][0]["model_count"], 1);
        assert_eq!(status["providers"].as_array().expect("providers").len(), 1);
        assert_eq!(status["storage"]["record_count"], 1);
        assert_eq!(status["lastSearch"]["result_count"], 1);
        assert_eq!(status["results"][0]["model_ref"], "model://fixture/qwen3");
        assert!(status["results"]
            .as_array()
            .expect("results")
            .iter()
            .all(|record| record["provider_ref"] != "provider://legacy"));
    }

    #[test]
    fn catalog_status_fails_closed_without_agentgres_state_dir() {
        let error = catalog_status(&ModelMountReadProjectionRequest {
            projection_kind: "catalog_status".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: None,
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: None,
            state: json!({}),
        })
        .expect_err("state dir required");

        assert_eq!(
            error.code,
            "model_mount_catalog_status_replay_state_dir_required"
        );
    }

    fn write_provider_inventory_record(state_dir: &std::path::Path, record: Value) {
        let provider_inventory_dir = state_dir.join("model-provider-inventory");
        fs::create_dir_all(&provider_inventory_dir).expect("provider inventory dir");
        fs::write(
            provider_inventory_dir.join(format!("{}.json", string_field(&record, "id"))),
            serde_json::to_string_pretty(&record).expect("record json"),
        )
        .expect("write provider inventory record");
    }

    fn write_server_control_record(state_dir: &std::path::Path, record: Value) {
        let server_control_dir = state_dir.join("model-server-controls");
        fs::create_dir_all(&server_control_dir).expect("server control dir");
        fs::write(
            server_control_dir.join(format!("{}.json", string_field(&record, "id"))),
            serde_json::to_string_pretty(&record).expect("record json"),
        )
        .expect("write server control record");
    }
}
