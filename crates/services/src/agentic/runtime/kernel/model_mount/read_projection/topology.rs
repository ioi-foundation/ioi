use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde_json::{json, Value};

use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION;

use super::{route_decision, ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn artifacts(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(artifact_records_from_provider_inventory(
        request,
        "ioi.model_mount_model_artifact",
    )?))
}

pub(super) fn artifact_records(request: &ModelMountReadProjectionRequest) -> Vec<Value> {
    artifact_records_from_provider_inventory(request, "ioi.model_mount_model_artifact")
        .unwrap_or_default()
}

pub(super) fn product_artifacts(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(artifact_records_from_provider_inventory(
        request,
        "ioi.product_model_artifact",
    )?))
}

pub(super) fn product_artifact_records(request: &ModelMountReadProjectionRequest) -> Vec<Value> {
    artifact_records_from_provider_inventory(request, "ioi.product_model_artifact")
        .unwrap_or_default()
}

pub(super) fn providers(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(provider_records_from_provider_inventory(
        request,
    )?))
}

pub(super) fn provider_records(request: &ModelMountReadProjectionRequest) -> Vec<Value> {
    provider_records_from_provider_inventory(request).unwrap_or_default()
}

pub(super) fn endpoints(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(endpoint_records_from_route_control(request)?))
}

pub(super) fn endpoint_records(request: &ModelMountReadProjectionRequest) -> Vec<Value> {
    endpoint_records_from_route_control(request).unwrap_or_default()
}

pub(super) fn instances(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(agentgres_instance_records(request)?))
}

pub(super) fn instance_records(request: &ModelMountReadProjectionRequest) -> Vec<Value> {
    agentgres_instance_records(request).unwrap_or_default()
}

pub(super) fn provider_inventory_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(agentgres_provider_inventory_records(request)?))
}

pub(super) fn catalog_search(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let input = catalog_search_input(&request.state);
    let query = catalog_search_string(input, "query");
    let format = catalog_search_string(input, "format");
    let quantization = catalog_search_string(input, "quantization");
    let provider_ref = catalog_search_string(input, "provider_ref");
    let limit = catalog_search_limit(input);
    let query_lower = query.to_ascii_lowercase();
    let format_lower = format.to_ascii_lowercase();
    let quantization_lower = quantization.to_ascii_lowercase();
    let provider_ref_lower = provider_ref.to_ascii_lowercase();
    let mut results = Vec::new();
    for record in agentgres_provider_inventory_records(request)? {
        if string_field(&record, "action") != "list_models" {
            continue;
        }
        if !provider_ref_lower.is_empty()
            && string_field(&record, "provider_ref").to_ascii_lowercase() != provider_ref_lower
        {
            continue;
        }
        for item_ref in string_array_field(&record, "item_refs") {
            let haystack = format!(
                "{} {} {} {} {} {}",
                item_ref,
                string_field(&record, "provider_ref"),
                string_field(&record, "provider_kind"),
                string_field(&record, "backend"),
                string_field(&record, "backend_id"),
                string_field(&record, "driver")
            )
            .to_ascii_lowercase();
            if !query_lower.is_empty() && !haystack.contains(&query_lower) {
                continue;
            }
            if !format_lower.is_empty() && !haystack.contains(&format_lower) {
                continue;
            }
            if !quantization_lower.is_empty() && !haystack.contains(&quantization_lower) {
                continue;
            }
            results.push(catalog_search_result_for_inventory_record(
                &record, &item_ref,
            ));
            if results.len() >= limit {
                break;
            }
        }
        if results.len() >= limit {
            break;
        }
    }
    results.sort_by(|left, right| {
        string_field(left, "model_ref")
            .cmp(&string_field(right, "model_ref"))
            .then_with(|| {
                string_field(left, "provider_ref").cmp(&string_field(right, "provider_ref"))
            })
    });
    Ok(json!({
        "schema_version": request.schema_version.clone().unwrap_or_default(),
        "object": "ioi.model_catalog_search_result",
        "source": "rust_model_mount_catalog_search_projection",
        "rust_core_boundary": "model_mount.catalog_search",
        "generated_at": request.generated_at.clone().unwrap_or_default(),
        "query": query,
        "filters": {
            "format": format,
            "quantization": quantization,
            "provider_ref": provider_ref,
        },
        "result_count": results.len(),
        "results": results,
        "evidence_refs": [
            "rust_daemon_core_catalog_search_projection",
            "agentgres_catalog_search_replay_required",
            "agentgres_provider_inventory_truth_required",
            "model_catalog_search_js_orchestrator_retired"
        ],
    }))
}

pub(super) fn routes(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(agentgres_route_records(request)?))
}

pub(super) fn route_records(request: &ModelMountReadProjectionRequest) -> Vec<Value> {
    agentgres_route_records(request).unwrap_or_default()
}

pub(super) fn tokenizer_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(agentgres_tokenizer_records(request)?))
}

pub(super) fn model_capabilities() -> Value {
    empty_list()
}

pub(super) fn downloads(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(agentgres_download_records(request)?))
}

pub(super) fn download_records(request: &ModelMountReadProjectionRequest) -> Vec<Value> {
    agentgres_download_records(request).unwrap_or_default()
}

pub(super) fn download_status(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let download_id = request
        .download_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_download_id_required",
                "download status projection requires download_id",
            )
        })?;
    agentgres_download_records(request)?
        .into_iter()
        .find(|record| {
            string_field(record, "id") == download_id
                || string_field(record, "record_id") == download_id
                || string_field(record.get("details").unwrap_or(&Value::Null), "job_id")
                    == download_id
        })
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_download_not_found",
                format!("download job not found: {download_id}"),
            )
        })
}

pub(super) fn storage_summary(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let downloads = agentgres_download_records(request)?;
    let catalog_imports = agentgres_catalog_import_records(request)?;
    let storage_controls = agentgres_storage_control_records(request)?;
    let active_download_count = downloads
        .iter()
        .filter(|record| string_field(record, "status") == "queued")
        .count();
    let cancelled_download_count = downloads
        .iter()
        .filter(|record| string_field(record, "status") == "cancelled")
        .count();
    let total_bytes = downloads
        .iter()
        .filter_map(|record| {
            record
                .get("details")
                .and_then(|details| details.get("bytes_total"))
                .and_then(Value::as_u64)
        })
        .reduce(|left, right| left + right);
    Ok(json!({
        "schema_version": request.schema_version.clone().unwrap_or_default(),
        "object": "ioi.model_mount_storage_summary",
        "source": "rust_model_mount_storage_summary_projection",
        "rust_core_boundary": "model_mount.storage_projection",
        "generated_at": request.generated_at.clone().unwrap_or_default(),
        "state_dir_replay_required": true,
        "filesystem_scanned": false,
        "record_dirs": [
            "model-catalog-imports",
            "model-downloads",
            "model-storage-controls"
        ],
        "record_counts": {
            "catalog_imports": catalog_imports.len(),
            "downloads": downloads.len(),
            "storage_controls": storage_controls.len(),
        },
        "catalog_import_count": catalog_imports.len(),
        "download_count": downloads.len(),
        "active_download_count": active_download_count,
        "cancelled_download_count": cancelled_download_count,
        "storage_control_count": storage_controls.len(),
        "total_bytes": total_bytes,
        "quota_bytes": Value::Null,
        "orphan_count": Value::Null,
        "destructive_actions_require_unload": true,
        "evidence_refs": [
            "rust_daemon_core_model_storage_projection",
            "agentgres_model_storage_replay_required",
            "public_model_storage_js_facade_retired",
            "model_mount_storage_summary_js_facade_retired"
        ],
    }))
}

pub(super) fn backends(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(backend_records(request)?))
}

pub(super) fn backend_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut latest_by_backend = BTreeMap::new();
    for record in agentgres_backend_lifecycle_records(request)? {
        latest_by_backend.insert(string_field(&record, "backend_id"), record);
    }
    Ok(latest_by_backend
        .values()
        .map(projected_backend_lifecycle_record)
        .collect())
}

pub(super) fn runtime_model_catalog(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(runtime_model_catalog_records(request)?))
}

pub(super) fn runtime_model_catalog_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut records = Vec::new();
    for record in agentgres_provider_inventory_records(request)? {
        if string_field(&record, "action") != "list_models" {
            continue;
        }
        for item_ref in string_array_field(&record, "item_refs") {
            records.push(runtime_model_catalog_entry_for_inventory_record(
                &record, &item_ref,
            ));
        }
    }
    records.sort_by(|left, right| {
        string_field(left, "id")
            .cmp(&string_field(right, "id"))
            .then_with(|| {
                string_field(left, "provider_ref").cmp(&string_field(right, "provider_ref"))
            })
    });
    Ok(records)
}

pub(super) fn open_ai_model_list(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(open_ai_model_list_value(request))
}

pub(super) fn open_ai_model_list_value(request: &ModelMountReadProjectionRequest) -> Value {
    let data = open_ai_model_records(request).unwrap_or_default();
    json!({
        "object": "list",
        "data": data,
    })
}

fn empty_list() -> Value {
    Value::Array(Vec::new())
}

fn agentgres_instance_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_instance_replay_state_dir_required",
                "model instance projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("model-instances");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_instance_replay_read_failed",
            format!("failed to read model instance records: {error}"),
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
                        "model_mount_instance_replay_read_failed",
                        format!(
                            "failed to read model instance record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_instance_replay_invalid_record",
                            format!(
                                "failed to decode model instance record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_instance_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(left, "id")
            .cmp(&string_field(right, "id"))
            .then_with(|| string_field(left, "status").cmp(&string_field(right, "status")))
    });
    Ok(records)
}

pub(super) fn agentgres_provider_inventory_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_provider_inventory_replay_state_dir_required",
                "provider inventory projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("model-provider-inventory");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_provider_inventory_replay_read_failed",
            format!("failed to read provider inventory records: {error}"),
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
                        "model_mount_provider_inventory_replay_read_failed",
                        format!(
                            "failed to read provider inventory record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_provider_inventory_replay_invalid_record",
                            format!(
                                "failed to decode provider inventory record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_provider_inventory_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(left, "provider_ref")
            .cmp(&string_field(right, "provider_ref"))
            .then_with(|| string_field(left, "action").cmp(&string_field(right, "action")))
            .then_with(|| string_field(left, "id").cmp(&string_field(right, "id")))
    });
    Ok(records)
}

fn provider_records_from_provider_inventory(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut seen = BTreeSet::new();
    let mut providers = Vec::new();
    for record in agentgres_provider_inventory_records(request)? {
        let provider_ref = string_field(&record, "provider_ref");
        if !seen.insert(provider_ref.clone()) {
            continue;
        }
        providers.push(json!({
            "id": provider_ref,
            "object": "ioi.model_mount_provider",
            "provider_ref": provider_ref,
            "provider_kind": string_field(&record, "provider_kind"),
            "backend": string_field(&record, "backend"),
            "backend_id": string_field(&record, "backend_id"),
            "driver": string_field(&record, "driver"),
            "inventory_record_id": string_field(&record, "record_id"),
            "inventory_hash": string_field(&record, "inventory_hash"),
            "source": "agentgres_provider_inventory",
            "rust_core_boundary": "model_mount.provider_inventory.materialization",
            "evidence_refs": [
                "rust_daemon_core_provider_inventory_materialization",
                "agentgres_provider_inventory_truth_required",
                "model_mount_topology_js_materialization_retired"
            ],
        }));
    }
    providers.sort_by(|left, right| {
        string_field(left, "provider_ref").cmp(&string_field(right, "provider_ref"))
    });
    Ok(providers)
}

fn artifact_records_from_provider_inventory(
    request: &ModelMountReadProjectionRequest,
    object_kind: &str,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut records = Vec::new();
    for record in agentgres_provider_inventory_records(request)? {
        if string_field(&record, "action") != "list_models" {
            continue;
        }
        for item_ref in string_array_field(&record, "item_refs") {
            records.push(artifact_record_for_inventory_record(
                &record,
                &item_ref,
                object_kind,
            ));
        }
    }
    records.sort_by(|left, right| {
        string_field(left, "model_ref")
            .cmp(&string_field(right, "model_ref"))
            .then_with(|| {
                string_field(left, "provider_ref").cmp(&string_field(right, "provider_ref"))
            })
    });
    Ok(records)
}

fn open_ai_model_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut records = Vec::new();
    for record in agentgres_provider_inventory_records(request)? {
        if string_field(&record, "action") != "list_models" {
            continue;
        }
        for item_ref in string_array_field(&record, "item_refs") {
            records.push(open_ai_model_record_for_inventory_record(
                &record, &item_ref,
            ));
        }
    }
    records.sort_by(|left, right| {
        string_field(left, "id")
            .cmp(&string_field(right, "id"))
            .then_with(|| {
                string_field(left, "provider_ref").cmp(&string_field(right, "provider_ref"))
            })
    });
    Ok(records)
}

fn endpoint_records_from_route_control(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for resolution in route_decision::route_endpoint_resolution_records(request)? {
        let endpoints = resolution
            .get("endpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if endpoints.is_empty() {
            for endpoint_id in string_array_field(&resolution, "endpoint_ids") {
                let endpoint = json!({ "id": endpoint_id });
                if let Some(record) = endpoint_record_for_resolution(&resolution, &endpoint) {
                    let key = format!(
                        "{}:{}:{}",
                        string_field(&record, "id"),
                        string_field(&record, "route_id"),
                        string_field(&record, "model_id")
                    );
                    if seen.insert(key) {
                        records.push(record);
                    }
                }
            }
            continue;
        }
        for endpoint in endpoints {
            if let Some(record) = endpoint_record_for_resolution(&resolution, &endpoint) {
                let key = format!(
                    "{}:{}:{}",
                    string_field(&record, "id"),
                    string_field(&record, "route_id"),
                    string_field(&record, "model_id")
                );
                if seen.insert(key) {
                    records.push(record);
                }
            }
        }
    }
    records.sort_by(|left, right| {
        string_field(left, "id")
            .cmp(&string_field(right, "id"))
            .then_with(|| string_field(left, "route_id").cmp(&string_field(right, "route_id")))
            .then_with(|| string_field(left, "model_id").cmp(&string_field(right, "model_id")))
    });
    Ok(records)
}

fn endpoint_record_for_resolution(resolution: &Value, endpoint: &Value) -> Option<Value> {
    let endpoint_id = string_field(endpoint, "id");
    if endpoint_id.is_empty() {
        return None;
    }
    let model_id = string_field_any(endpoint, &["model_id", "modelId"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| string_field(resolution, "model_id"));
    if model_id.is_empty() {
        return None;
    }
    let provider_id = string_field_any(endpoint, &["provider_id", "providerId"])
        .filter(|value| !value.is_empty());
    let status = string_field(endpoint, "status");
    let status = if status.is_empty() {
        "mounted".to_string()
    } else {
        status
    };
    let mut evidence_refs = string_array_field(resolution, "evidence_refs");
    for evidence_ref in [
        "rust_daemon_core_model_endpoint_projection",
        "agentgres_model_route_endpoint_resolution_replay_required",
        "model_mount_endpoint_list_js_facade_retired",
    ] {
        if !evidence_refs.iter().any(|value| value == evidence_ref) {
            evidence_refs.push(evidence_ref.to_string());
        }
    }
    json_object_without_nulls(json!({
        "id": endpoint_id,
        "object": "ioi.model_mount_endpoint",
        "endpoint_id": endpoint_id,
        "model_id": model_id,
        "provider_id": provider_id,
        "status": status,
        "route_id": string_field(resolution, "route_id"),
        "endpoint_resolution_record_id": string_field(resolution, "id"),
        "record_dir": "model-route-endpoint-resolutions",
        "receipt_refs": resolution.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "evidence_refs": evidence_refs,
        "source": "agentgres_route_endpoint_resolution",
        "rust_core_boundary": "model_mount.route_control",
        "route_selection_boundary": "model_mount.route_selection",
    }))
}

fn agentgres_route_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_route_replay_state_dir_required",
                "model route projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("model-routes");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_route_replay_read_failed",
            format!("failed to read model route records: {error}"),
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
                        "model_mount_route_replay_read_failed",
                        format!(
                            "failed to read model route record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_route_replay_invalid_record",
                            format!(
                                "failed to decode model route record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_route_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(left, "id")
            .cmp(&string_field(right, "id"))
            .then_with(|| string_field(left, "status").cmp(&string_field(right, "status")))
    });
    Ok(records)
}

fn agentgres_tokenizer_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_tokenizer_replay_state_dir_required",
                "model tokenizer projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("model-tokenizer-utilities");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_tokenizer_replay_read_failed",
            format!("failed to read model tokenizer records: {error}"),
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
                        "model_mount_tokenizer_replay_read_failed",
                        format!(
                            "failed to read model tokenizer record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_tokenizer_replay_invalid_record",
                            format!(
                                "failed to decode model tokenizer record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_tokenizer_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(left, "operation")
            .cmp(&string_field(right, "operation"))
            .then_with(|| string_field(left, "id").cmp(&string_field(right, "id")))
    });
    Ok(records)
}

fn agentgres_download_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut records = agentgres_storage_control_records_from_dir(
        request,
        "model-downloads",
        "model_mount_download_replay_state_dir_required",
        "download projection requires Rust Agentgres state_dir replay",
        "model_mount_download_replay_read_failed",
        "model_mount_download_replay_invalid_record",
        "download",
        admitted_download_record,
    )?;
    records.sort_by(|left, right| {
        string_field(left, "id")
            .cmp(&string_field(right, "id"))
            .then_with(|| string_field(left, "status").cmp(&string_field(right, "status")))
    });
    Ok(records)
}

fn agentgres_backend_lifecycle_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_backend_lifecycle_replay_state_dir_required",
                "backend lifecycle projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("model-backend-lifecycle-controls");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_backend_lifecycle_replay_read_failed",
            format!("failed to read backend lifecycle records: {error}"),
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
                        "model_mount_backend_lifecycle_replay_read_failed",
                        format!(
                            "failed to read backend lifecycle record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_backend_lifecycle_replay_invalid_record",
                            format!(
                                "failed to decode backend lifecycle record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_backend_lifecycle_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(left, "generated_at")
            .cmp(&string_field(right, "generated_at"))
            .then_with(|| string_field(left, "id").cmp(&string_field(right, "id")))
    });
    Ok(records)
}

fn agentgres_catalog_import_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut records = agentgres_storage_control_records_from_dir(
        request,
        "model-catalog-imports",
        "model_mount_storage_replay_state_dir_required",
        "storage summary projection requires Rust Agentgres state_dir replay",
        "model_mount_storage_replay_read_failed",
        "model_mount_storage_replay_invalid_record",
        "catalog import",
        admitted_catalog_import_record,
    )?;
    records.sort_by(|left, right| string_field(left, "id").cmp(&string_field(right, "id")));
    Ok(records)
}

fn agentgres_storage_control_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut records = agentgres_storage_control_records_from_dir(
        request,
        "model-storage-controls",
        "model_mount_storage_replay_state_dir_required",
        "storage summary projection requires Rust Agentgres state_dir replay",
        "model_mount_storage_replay_read_failed",
        "model_mount_storage_replay_invalid_record",
        "storage control",
        admitted_storage_mutation_record,
    )?;
    records.sort_by(|left, right| string_field(left, "id").cmp(&string_field(right, "id")));
    Ok(records)
}

fn agentgres_storage_control_records_from_dir<F>(
    request: &ModelMountReadProjectionRequest,
    record_dir_name: &'static str,
    state_dir_required_code: &'static str,
    state_dir_required_message: &'static str,
    read_failed_code: &'static str,
    invalid_record_code: &'static str,
    label: &'static str,
    mut admit_record: F,
) -> Result<Vec<Value>, ModelMountReadProjectionError>
where
    F: FnMut(Value) -> Option<Value>,
{
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(state_dir_required_code, state_dir_required_message)
        })?;
    let record_dir = Path::new(state_dir).join(record_dir_name);
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            read_failed_code,
            format!("failed to read {label} records: {error}"),
        )
    })?;
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .map(|path| {
            fs::read_to_string(&path)
                .map_err(|error| {
                    ModelMountReadProjectionError::new(
                        read_failed_code,
                        format!("failed to read {label} record {}: {error}", path.display()),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            invalid_record_code,
                            format!(
                                "failed to decode {label} record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|record| admit_record(record))
        .map(|record| Ok(projected_storage_record(record, record_dir_name)))
        .collect()
}

fn admitted_instance_record(record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    if string_field(&record, "schema_version") != "ioi.model_mount.instance_lifecycle.v1" {
        return None;
    }
    for field in [
        "id",
        "endpoint_id",
        "model_id",
        "provider_id",
        "action",
        "status",
        "execution_backend",
        "provider_lifecycle_hash",
        "instance_lifecycle_hash",
    ] {
        if string_field(&record, field).is_empty() {
            return None;
        }
    }
    if string_field(&record, "execution_backend") != "rust_model_mount_instance_lifecycle" {
        return None;
    }
    let evidence_refs = evidence_refs(&record);
    if !evidence_refs
        .iter()
        .any(|value| value == "rust_model_mount_instance_lifecycle")
    {
        return None;
    }
    if !evidence_refs
        .iter()
        .any(|value| value == "agentgres_model_instance_registry_planned")
    {
        return None;
    }
    Some(record)
}

fn admitted_provider_inventory_record(record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    if string_field(&record, "object") != "ioi.model_mount_provider_inventory" {
        return None;
    }
    if string_field(&record, "schema_version") != "ioi.model_mount.provider_inventory.v1" {
        return None;
    }
    for field in [
        "id",
        "provider_ref",
        "provider_kind",
        "action",
        "operation_kind",
        "status",
        "backend",
        "backend_id",
        "driver",
        "execution_backend",
        "inventory_hash",
        "record_dir",
        "record_id",
        "rust_core_boundary",
        "source",
    ] {
        if string_field(&record, field).is_empty() {
            return None;
        }
    }
    if string_field(&record, "record_dir") != "model-provider-inventory" {
        return None;
    }
    if string_field(&record, "record_id") != string_field(&record, "id") {
        return None;
    }
    if string_field(&record, "rust_core_boundary") != "model_mount.provider_inventory" {
        return None;
    }
    if !matches!(
        string_field(&record, "execution_backend").as_str(),
        "rust_model_mount_fixture_inventory" | "rust_model_mount_native_local_inventory"
    ) {
        return None;
    }
    if !record.get("item_count").and_then(Value::as_u64).is_some() {
        return None;
    }
    let evidence_refs = evidence_refs(&record);
    for required in [
        "rust_model_mount_provider_inventory",
        "agentgres_provider_inventory_truth_required",
    ] {
        if !evidence_refs.iter().any(|value| value == required) {
            return None;
        }
    }
    Some(record)
}

fn admitted_download_record(record: Value) -> Option<Value> {
    if !admitted_storage_control_record(
        &record,
        "ioi.model_mount_download",
        &["model_mount.download.queue", "model_mount.download.cancel"],
    ) {
        return None;
    }
    let details = record.get("details")?;
    if string_field(details, "job_id").is_empty() {
        return None;
    }
    if string_field(&record, "operation_kind") == "model_mount.download.queue"
        && string_field(details, "model_id").is_empty()
    {
        return None;
    }
    let evidence_refs = evidence_refs(&record);
    match string_field(&record, "operation_kind").as_str() {
        "model_mount.download.queue" => {
            for required in [
                "public_catalog_download_js_facade_retired",
                "rust_daemon_core_catalog_download",
                "agentgres_catalog_download_truth_required",
            ] {
                if !evidence_refs.iter().any(|value| value == required) {
                    return None;
                }
            }
        }
        "model_mount.download.cancel" => {
            if !evidence_refs
                .iter()
                .any(|value| value == "rust_daemon_core_model_download_cancel")
            {
                return None;
            }
        }
        _ => return None,
    }
    Some(record)
}

fn admitted_catalog_import_record(record: Value) -> Option<Value> {
    if !admitted_storage_control_record(
        &record,
        "ioi.model_mount_catalog_import",
        &["model_mount.catalog.import_url"],
    ) {
        return None;
    }
    let details = record.get("details")?;
    if string_field(details, "model_id").is_empty()
        || string_field(details, "source_url_hash").is_empty()
    {
        return None;
    }
    let evidence_refs = evidence_refs(&record);
    for required in [
        "public_catalog_download_js_facade_retired",
        "rust_daemon_core_catalog_download",
        "agentgres_catalog_download_truth_required",
    ] {
        if !evidence_refs.iter().any(|value| value == required) {
            return None;
        }
    }
    Some(record)
}

fn admitted_storage_mutation_record(record: Value) -> Option<Value> {
    if !admitted_storage_control_record(
        &record,
        "ioi.model_mount_storage_control",
        &["model_mount.artifact.delete", "model_mount.storage.cleanup"],
    ) {
        return None;
    }
    let evidence_refs = evidence_refs(&record);
    let operation_kind = string_field(&record, "operation_kind");
    let required = match operation_kind.as_str() {
        "model_mount.artifact.delete" => "rust_daemon_core_model_artifact_delete",
        "model_mount.storage.cleanup" => "rust_daemon_core_model_storage_cleanup",
        _ => return None,
    };
    if !evidence_refs.iter().any(|value| value == required) {
        return None;
    }
    Some(record)
}

fn admitted_storage_control_record(record: &Value, object: &str, operation_kinds: &[&str]) -> bool {
    if bool_field(record, "deleted") {
        return false;
    }
    if string_field(record, "schema_version") != "ioi.model_mount.storage_control.v1" {
        return false;
    }
    if string_field(record, "object") != object {
        return false;
    }
    if string_field(record, "rust_core_boundary") != "model_mount.storage_control" {
        return false;
    }
    if !operation_kinds.contains(&string_field(record, "operation_kind").as_str()) {
        return false;
    }
    for field in [
        "id",
        "record_id",
        "status",
        "control_hash",
        "authority_hash",
    ] {
        if string_field(record, field).is_empty() {
            return false;
        }
    }
    if string_field(record, "id") != string_field(record, "record_id") {
        return false;
    }
    if !record.get("details").is_some_and(Value::is_object) {
        return false;
    }
    let evidence_refs = evidence_refs(record);
    for required in [
        "public_model_storage_js_facade_retired",
        "rust_daemon_core_model_storage",
        "agentgres_model_storage_truth_required",
    ] {
        if !evidence_refs.iter().any(|value| value == required) {
            return false;
        }
    }
    true
}

fn projected_storage_record(record: Value, record_dir: &str) -> Value {
    json_object_without_nulls(json!({
        "id": string_field(&record, "id"),
        "record_id": string_field(&record, "record_id"),
        "record_dir": record_dir,
        "object": string_field(&record, "object"),
        "status": string_field(&record, "status"),
        "operation_kind": string_field(&record, "operation_kind"),
        "source": "agentgres_model_mount_storage_control",
        "generated_at": string_field(&record, "generated_at"),
        "rust_core_boundary": string_field(&record, "rust_core_boundary"),
        "storage_projection_boundary": "model_mount.storage_projection",
        "details": record.get("details").cloned().unwrap_or_else(|| json!({})),
        "public_response": record.get("public_response").cloned(),
        "authority": record.get("authority").cloned(),
        "receipt_refs": record.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "evidence_refs": evidence_refs(&record),
        "control_hash": string_field(&record, "control_hash"),
        "authority_hash": string_field(&record, "authority_hash"),
    }))
    .unwrap_or_else(|| json!({}))
}

fn admitted_tokenizer_record(record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    if string_field(&record, "object") != "ioi.model_mount_tokenizer_result" {
        return None;
    }
    for field in [
        "id",
        "status",
        "operation",
        "source",
        "rust_core_boundary",
        "route_selection_boundary",
        "route_id",
        "model",
        "endpoint_id",
        "provider_id",
        "input_hash",
        "control_hash",
    ] {
        if string_field(&record, field).is_empty() {
            return None;
        }
    }
    if string_field(&record, "rust_core_boundary") != "model_mount.tokenizer" {
        return None;
    }
    if string_field(&record, "route_selection_boundary") != "model_mount.route_selection" {
        return None;
    }
    if !matches!(
        string_field(&record, "operation").as_str(),
        "tokenize" | "count_tokens" | "context_fit"
    ) {
        return None;
    }
    if record.get("token_count").and_then(Value::as_u64).is_none() {
        return None;
    }
    let evidence_refs = evidence_refs(&record);
    for required in [
        "model_mount_tokenizer_rust_owned",
        "agentgres_model_tokenizer_truth_required",
    ] {
        if !evidence_refs.iter().any(|value| value == required) {
            return None;
        }
    }
    Some(record)
}

fn admitted_backend_lifecycle_record(record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    if string_field(&record, "schema_version") != MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION
    {
        return None;
    }
    if string_field(&record, "object") != "ioi.model_mount_backend_lifecycle_record" {
        return None;
    }
    if string_field(&record, "rust_core_boundary") != "model_mount.backend_lifecycle" {
        return None;
    }
    if !matches!(
        string_field(&record, "operation_kind").as_str(),
        "model_mount.backend.health"
            | "model_mount.backend.start"
            | "model_mount.backend.stop"
            | "model_mount.backend.logs_read"
    ) {
        return None;
    }
    for field in [
        "id",
        "backend_id",
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
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_backend_lifecycle",
        "agentgres_backend_lifecycle_truth_required",
    ] {
        if !evidence_refs.iter().any(|value| value == required) {
            return None;
        }
    }
    Some(record)
}

fn admitted_route_record(record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    for field in ["id", "role", "status", "updatedAt"] {
        if string_field(&record, field).is_empty() {
            return None;
        }
    }
    if string_array_field(&record, "receiptRefs").is_empty() {
        return None;
    }
    let route_control = record.get("routeControl")?;
    if string_field(route_control, "rust_core_boundary") != "model_mount.route_control" {
        return None;
    }
    let evidence_refs = evidence_refs(route_control);
    for required in [
        "model_mount_route_control_rust_owned",
        "rust_daemon_core_route_control_plan",
        "agentgres_route_truth_required",
    ] {
        if !evidence_refs.iter().any(|value| value == required) {
            return None;
        }
    }
    Some(record)
}

fn catalog_search_result_for_inventory_record(record: &Value, item_ref: &str) -> Value {
    json!({
        "id": format!(
            "catalog_search_{}_{}",
            record_id_segment(&string_field(record, "record_id"), "record"),
            record_id_segment(item_ref, "model")
        ),
        "object": "ioi.model_catalog_search_entry",
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
        "rust_core_boundary": "model_mount.catalog_search",
        "evidence_refs": [
            "rust_daemon_core_catalog_search_projection",
            "agentgres_provider_inventory_truth_required",
            "model_catalog_search_js_orchestrator_retired"
        ],
    })
}

fn artifact_record_for_inventory_record(
    record: &Value,
    item_ref: &str,
    object_kind: &str,
) -> Value {
    json!({
        "id": format!(
            "artifact_{}_{}",
            record_id_segment(&string_field(record, "record_id"), "record"),
            record_id_segment(item_ref, "model")
        ),
        "object": object_kind,
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
        "rust_core_boundary": "model_mount.provider_inventory.materialization",
        "evidence_refs": [
            "rust_daemon_core_provider_inventory_materialization",
            "agentgres_provider_inventory_truth_required",
            "model_mount_topology_js_materialization_retired"
        ],
    })
}

fn runtime_model_catalog_entry_for_inventory_record(record: &Value, item_ref: &str) -> Value {
    json!({
        "id": model_id_from_item_ref(item_ref),
        "object": "ioi.runtime_model_catalog_entry",
        "model_ref": item_ref,
        "provider_ref": string_field(record, "provider_ref"),
        "provider_kind": string_field(record, "provider_kind"),
        "backend": string_field(record, "backend"),
        "backend_id": string_field(record, "backend_id"),
        "driver": string_field(record, "driver"),
        "inventory_record_id": string_field(record, "record_id"),
        "inventory_hash": string_field(record, "inventory_hash"),
        "source": "agentgres_provider_inventory",
        "rust_core_boundary": "model_mount.provider_inventory.materialization",
        "evidence_refs": [
            "rust_daemon_core_provider_inventory_materialization",
            "agentgres_provider_inventory_truth_required",
            "model_mount_runtime_catalog_js_materialization_retired"
        ],
    })
}

fn open_ai_model_record_for_inventory_record(record: &Value, item_ref: &str) -> Value {
    json!({
        "id": model_id_from_item_ref(item_ref),
        "object": "model",
        "owned_by": "ioi",
        "model_ref": item_ref,
        "provider_ref": string_field(record, "provider_ref"),
        "inventory_record_id": string_field(record, "record_id"),
        "inventory_hash": string_field(record, "inventory_hash"),
        "rust_core_boundary": "model_mount.provider_inventory.materialization",
        "evidence_refs": [
            "rust_daemon_core_provider_inventory_materialization",
            "agentgres_provider_inventory_truth_required",
            "openai_model_list_js_materialization_retired"
        ],
    })
}

fn projected_backend_lifecycle_record(record: &Value) -> Value {
    let public_response = record
        .get("public_response")
        .cloned()
        .unwrap_or(Value::Null);
    let backend_status = public_response
        .get("backend_status")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| string_field(record, "status"));
    json_object_without_nulls(json!({
        "id": string_field(record, "backend_id"),
        "object": "ioi.model_mount_backend",
        "backend_id": string_field(record, "backend_id"),
        "backend_kind": string_field(record, "backend_kind"),
        "status": backend_status,
        "lifecycle_status": string_field(record, "status"),
        "source": "agentgres_backend_lifecycle_control",
        "generated_at": string_field(record, "generated_at"),
        "record_dir": "model-backend-lifecycle-controls",
        "record_id": string_field(record, "id"),
        "operation_kind": string_field(record, "operation_kind"),
        "rust_core_boundary": string_field(record, "rust_core_boundary"),
        "backend_lifecycle_projection_boundary": "model_mount.backend_lifecycle_projection",
        "public_response": public_response,
        "receipt_refs": record.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "evidence_refs": projected_backend_lifecycle_evidence_refs(record),
        "control_hash": string_field(record, "control_hash"),
    }))
    .unwrap_or_else(|| json!({}))
}

fn projected_backend_lifecycle_evidence_refs(record: &Value) -> Vec<String> {
    let mut refs = evidence_refs(record);
    for evidence_ref in [
        "rust_daemon_core_backend_lifecycle_projection",
        "agentgres_backend_lifecycle_replay_required",
        "model_mount_backend_list_js_facade_retired",
    ] {
        if !refs.iter().any(|value| value == evidence_ref) {
            refs.push(evidence_ref.to_string());
        }
    }
    refs
}

fn catalog_search_input(state: &Value) -> &Value {
    state.get("catalog_search").unwrap_or(state)
}

fn catalog_search_string(input: &Value, key: &str) -> String {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn catalog_search_limit(input: &Value) -> usize {
    input
        .get("limit")
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str()?.trim().parse().ok())
        })
        .map(|value| value.clamp(1, 100) as usize)
        .unwrap_or(50)
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

fn json_object_without_nulls(value: Value) -> Option<Value> {
    let mut object = value.as_object()?.clone();
    object.retain(|_, value| !value.is_null());
    Some(Value::Object(object))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn string_field_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .map(|key| string_field(value, key))
        .find(|value| !value.is_empty())
}

fn evidence_refs(value: &Value) -> Vec<String> {
    value
        .get("evidence_refs")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::{
        MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION,
        MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
        MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION, MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
        MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION,
    };

    fn request(
        projection_kind: &str,
        state_dir: Option<String>,
    ) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: projection_kind.to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir,
            state: json!({}),
        }
    }

    fn request_with_state(
        projection_kind: &str,
        state_dir: Option<String>,
        state: Value,
    ) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            state,
            ..request(projection_kind, state_dir)
        }
    }

    fn write_provider_inventory_materialization_records(state_dir: &std::path::Path) {
        let provider_inventory_dir = state_dir.join("model-provider-inventory");
        fs::create_dir_all(&provider_inventory_dir).expect("provider inventory dir");
        for record in [
            json!({
                "id": "legacy-js-provider-inventory",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
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
            json!({
                "id": "provider_inventory_fixture_list_models",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
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
                "source": "rust_model_mount_provider_inventory_command",
                "evidence_refs": [
                    "rust_model_mount_provider_inventory",
                    "agentgres_provider_inventory_truth_required",
                    "rust_model_mount_fixture_inventory_backend"
                ]
            }),
            json!({
                "id": "provider_inventory_native_list_loaded",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                "provider_ref": "provider://native",
                "provider_kind": "ioi_native_local",
                "action": "list_loaded",
                "operation_kind": "model_mount.provider.inventory.list_loaded",
                "status": "listed",
                "backend": "autopilot.native_local.fixture",
                "backend_id": "backend.autopilot.native-local.fixture",
                "driver": "native_local",
                "execution_backend": "rust_model_mount_native_local_inventory",
                "item_refs": ["model_instance://native/qwen3"],
                "item_count": 1,
                "inventory_hash": "sha256:native-inventory",
                "record_dir": "model-provider-inventory",
                "record_id": "provider_inventory_native_list_loaded",
                "receipt_refs": [],
                "rust_core_boundary": "model_mount.provider_inventory",
                "source": "rust_model_mount_provider_inventory_command",
                "evidence_refs": [
                    "rust_model_mount_provider_inventory",
                    "agentgres_provider_inventory_truth_required",
                    "rust_model_mount_native_local_inventory_backend"
                ]
            }),
        ] {
            fs::write(
                provider_inventory_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write provider inventory record");
        }
    }

    fn write_storage_records(
        state_dir: &std::path::Path,
        record_dir_name: &str,
        records: &[Value],
    ) {
        let record_dir = state_dir.join(record_dir_name);
        fs::create_dir_all(&record_dir).expect("storage record dir");
        for record in records {
            fs::write(
                record_dir.join(format!("{}.json", string_field(record, "id"))),
                serde_json::to_string_pretty(record).expect("storage record json"),
            )
            .expect("write storage record");
        }
    }

    fn storage_record(
        id: &str,
        object: &str,
        operation_kind: &str,
        status: &str,
        details: Value,
        extra_evidence_refs: &[&str],
    ) -> Value {
        let mut evidence_refs = vec![
            "public_model_storage_js_facade_retired",
            "rust_daemon_core_model_storage",
            "agentgres_model_storage_truth_required",
        ];
        evidence_refs.extend(extra_evidence_refs.iter().copied());
        json!({
            "id": id,
            "record_id": id,
            "schema_version": MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION,
            "object": object,
            "status": status,
            "operation_kind": operation_kind,
            "source": "runtime-daemon.model_mounting.storage_control",
            "generated_at": "2026-06-13T00:00:00.000Z",
            "rust_core_boundary": "model_mount.storage_control",
            "details": details,
            "authority": {
                "wallet_authority_boundary": "wallet.network.model_mount_storage",
                "ctee_custody_boundary": "ctee.model_mount_storage",
                "plaintext_material_returned": false,
            },
            "public_response": {
                "object": object,
                "status": status,
                "id": id,
                "record_id": id,
                "operation_kind": operation_kind,
                "rust_core_boundary": "model_mount.storage_control",
                "js_filesystem_mutation_executed": false,
                "js_network_transfer_executed": false,
            },
            "receipt_refs": ["receipt://storage/test"],
            "evidence_refs": evidence_refs,
            "control_hash": format!("sha256:control:{id}"),
            "authority_hash": format!("sha256:authority:{id}"),
        })
    }

    fn write_backend_lifecycle_records(state_dir: &std::path::Path, records: &[Value]) {
        let record_dir = state_dir.join("model-backend-lifecycle-controls");
        fs::create_dir_all(&record_dir).expect("backend lifecycle record dir");
        for record in records {
            fs::write(
                record_dir.join(format!("{}.json", string_field(record, "id"))),
                serde_json::to_string_pretty(record).expect("backend lifecycle record json"),
            )
            .expect("write backend lifecycle record");
        }
    }

    #[test]
    fn topology_list_defaults_ignore_caller_supplied_js_state() {
        let mut caller_supplied = json!({
            "artifacts": [{"id": "artifact.js"}],
            "product_artifacts": [{"id": "product.js"}],
            "providers": [{"id": "provider.js"}],
            "endpoints": [{"id": "endpoint.js"}],
            "instances": [{"id": "instance.js"}],
            "routes": [{"id": "route.js"}],
            "downloads": [{"id": "download.js"}],
            "backends": [{"id": "backend.js"}],
            "provider_health": [{"id": "provider-health.js"}],
            "runtime_model_catalog": [{"id": "runtime-model.js"}]
        });
        caller_supplied[["model", "capabilities"].join("_")] = json!([{"id": "capability.js"}]);
        let _proof = caller_supplied;

        assert_eq!(model_capabilities(), json!([]));
        let temp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            downloads(&request(
                "downloads",
                Some(temp.path().to_string_lossy().to_string())
            ))
            .expect("download projection"),
            json!([])
        );
        assert_eq!(
            backends(&request(
                "backends",
                Some(temp.path().to_string_lossy().to_string())
            ))
            .expect("backend projection"),
            json!([])
        );
    }

    #[test]
    fn backend_projection_replays_agentgres_lifecycle_records_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_backend_lifecycle_records(
            temp.path(),
            &[
                json!({
                    "id": "legacy-js-backend-lifecycle",
                    "schema_version": MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION,
                    "object": "ioi.model_mount_backend_lifecycle_record",
                    "backend_id": "backend.legacy",
                    "backend_kind": "legacy",
                    "operation_kind": "model_mount.backend.health",
                    "status": "planned",
                    "generated_at": "2026-06-13T00:00:00.000Z",
                    "rust_core_boundary": "daemon_js",
                    "control_hash": "sha256:legacy",
                    "evidence_refs": ["legacy_js_backend_lifecycle"]
                }),
                json!({
                    "id": "backend-lifecycle-control:native-start",
                    "schema_version": MODEL_MOUNT_BACKEND_LIFECYCLE_PLAN_SCHEMA_VERSION,
                    "object": "ioi.model_mount_backend_lifecycle_record",
                    "backend_id": "backend.native",
                    "backend_kind": "native_local",
                    "operation_kind": "model_mount.backend.start",
                    "status": "planned",
                    "source": "runtime-daemon.model_mounting.backend_lifecycle",
                    "generated_at": "2026-06-13T00:00:01.000Z",
                    "rust_core_boundary": "model_mount.backend_lifecycle",
                    "control_hash": "sha256:backend-native-start",
                    "public_response": {
                        "object": "ioi.model_mount_backend_lifecycle",
                        "status": "planned",
                        "backend_id": "backend.native",
                        "backend_kind": "native_local",
                        "operation_kind": "model_mount.backend.start",
                        "rust_core_boundary": "model_mount.backend_lifecycle",
                        "backend_status": "start_planned",
                        "js_backend_registry_read": false,
                        "js_process_control": false,
                        "js_log_read": false,
                        "js_log_write": false
                    },
                    "receipt_refs": ["receipt://backend/native/start", "sha256:backend-native-start"],
                    "evidence_refs": [
                        "public_backend_lifecycle_js_facade_retired",
                        "rust_daemon_core_backend_lifecycle",
                        "agentgres_backend_lifecycle_truth_required"
                    ]
                }),
            ],
        );

        let projection = backends(&request(
            "backends",
            Some(temp.path().to_string_lossy().to_string()),
        ))
        .expect("backend projection");
        let records = projection.as_array().expect("backend records");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["id"], "backend.native");
        assert_eq!(records[0]["status"], "start_planned");
        assert_eq!(
            records[0]["backend_lifecycle_projection_boundary"],
            "model_mount.backend_lifecycle_projection"
        );
        assert!(records[0]["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "agentgres_backend_lifecycle_replay_required"));
    }

    #[test]
    fn storage_download_projections_replay_agentgres_storage_control_records_and_filter_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_storage_records(
            temp.path(),
            "model-downloads",
            &[
                json!({
                    "id": "legacy-js-download",
                    "record_id": "legacy-js-download",
                    "schema_version": MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION,
                    "object": "ioi.model_mount_download",
                    "status": "queued",
                    "operation_kind": "model_mount.download.queue",
                    "rust_core_boundary": "daemon_js",
                    "details": {"job_id": "legacy-js-download", "model_id": "legacy"},
                    "evidence_refs": ["legacy_js_download_truth"],
                    "control_hash": "sha256:legacy",
                    "authority_hash": "sha256:legacy",
                }),
                storage_record(
                    "download.qwen3",
                    "ioi.model_mount_download",
                    "model_mount.download.queue",
                    "queued",
                    json!({
                        "job_id": "download.qwen3",
                        "model_id": "qwen3",
                        "bytes_total": 42,
                        "network_transfer_executed": false,
                        "plaintext_source_url_returned": false,
                    }),
                    &[
                        "public_catalog_download_js_facade_retired",
                        "rust_daemon_core_catalog_download",
                        "agentgres_catalog_download_truth_required",
                    ],
                ),
            ],
        );
        write_storage_records(
            temp.path(),
            "model-catalog-imports",
            &[storage_record(
                "catalog_import.qwen3",
                "ioi.model_mount_catalog_import",
                "model_mount.catalog.import_url",
                "planned",
                json!({
                    "model_id": "qwen3",
                    "source_url_hash": "sha256:source",
                    "network_transfer_executed": false,
                    "plaintext_source_url_returned": false,
                }),
                &[
                    "public_catalog_download_js_facade_retired",
                    "rust_daemon_core_catalog_download",
                    "agentgres_catalog_download_truth_required",
                ],
            )],
        );
        write_storage_records(
            temp.path(),
            "model-storage-controls",
            &[storage_record(
                "storage_cleanup.qwen3",
                "ioi.model_mount_storage_control",
                "model_mount.storage.cleanup",
                "cleanup_planned",
                json!({
                    "remove_orphans": true,
                    "filesystem_mutation_executed": false,
                }),
                &["rust_daemon_core_model_storage_cleanup"],
            )],
        );
        let base_request = request("downloads", Some(temp.path().to_string_lossy().to_string()));

        let download_list = downloads(&base_request).expect("download projection");
        assert_eq!(download_list.as_array().expect("downloads").len(), 1);
        assert_eq!(download_list[0]["id"], "download.qwen3");
        assert_eq!(download_list[0]["record_dir"], "model-downloads");
        assert_eq!(
            download_list[0]["storage_projection_boundary"],
            "model_mount.storage_projection"
        );
        assert_eq!(download_list[0]["details"]["model_id"], "qwen3");

        let mut status_request = request(
            "download_status",
            Some(temp.path().to_string_lossy().to_string()),
        );
        status_request.download_id = Some("download.qwen3".to_string());
        let status = download_status(&status_request).expect("download status projection");
        assert_eq!(status["id"], "download.qwen3");
        assert_eq!(status["details"]["bytes_total"], 42);

        status_request.download_id = Some("missing".to_string());
        let missing = download_status(&status_request).expect_err("missing download");
        assert_eq!(missing.code, "model_mount_download_not_found");

        let summary = storage_summary(&base_request).expect("storage summary projection");
        assert_eq!(
            summary["source"],
            "rust_model_mount_storage_summary_projection"
        );
        assert_eq!(summary["record_counts"]["catalog_imports"], 1);
        assert_eq!(summary["record_counts"]["downloads"], 1);
        assert_eq!(summary["record_counts"]["storage_controls"], 1);
        assert_eq!(summary["filesystem_scanned"], false);
        assert_eq!(summary["total_bytes"], 42);
    }

    #[test]
    fn endpoint_projection_replays_route_control_records_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let endpoint_resolution_dir = temp.path().join("model-route-endpoint-resolutions");
        fs::create_dir_all(&endpoint_resolution_dir).expect("endpoint resolution dir");
        for record in [
            json!({
                "id": "legacy-js-resolution",
                "object": "ioi.model_mount_explicit_model_endpoints",
                "route_id": "route.js",
                "model_id": "model.js",
                "endpoint_ids": ["endpoint.js"],
                "endpoints": [{"id": "endpoint.js", "providerId": "provider.js", "modelId": "model.js"}],
                "rust_core_boundary": "daemon_js",
                "route_selection_boundary": "model_mount.route_selection",
                "evidence_refs": ["legacy_js_endpoint_resolution"]
            }),
            json!({
                "id": "route_endpoint_resolution:route.local-first:test",
                "object": "ioi.model_mount_explicit_model_endpoints",
                "route_id": "route.local-first",
                "model_id": "model.local",
                "endpoint_ids": ["endpoint.local"],
                "endpoints": [{"id": "endpoint.local", "providerId": "provider.local", "modelId": "model.local"}],
                "receipt_refs": ["receipt://route-control/explicit-endpoints"],
                "evidence_refs": [
                    "model_mount_route_control_rust_owned",
                    "rust_daemon_core_route_control_plan",
                    "agentgres_route_truth_required"
                ],
                "rust_core_boundary": "model_mount.route_control",
                "route_selection_boundary": "model_mount.route_selection",
                "source": "runtime-daemon.model_mounting.route_control",
                "resolved_at": "2026-06-13T00:03:00.000Z"
            }),
        ] {
            fs::write(
                endpoint_resolution_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write endpoint resolution record");
        }

        let projection = endpoints(&request(
            "endpoints",
            Some(temp.path().to_string_lossy().to_string()),
        ))
        .expect("endpoint projection");
        let records = projection.as_array().expect("endpoint records");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["id"], "endpoint.local");
        assert_eq!(records[0]["provider_id"], "provider.local");
        assert_eq!(records[0]["model_id"], "model.local");
        assert_eq!(
            records[0]["endpoint_resolution_record_id"],
            "route_endpoint_resolution:route.local-first:test"
        );
        assert!(records[0].get("providerId").is_none());
        assert!(records.iter().all(|record| record["id"] != "endpoint.js"));
    }

    #[test]
    fn endpoint_projection_fails_closed_without_agentgres_state_dir() {
        let error = endpoints(&request("endpoints", None)).expect_err("state dir required");
        assert_eq!(
            error.code,
            "model_mount_route_endpoint_resolution_replay_state_dir_required"
        );
    }

    #[test]
    fn provider_inventory_materialization_replays_agentgres_records_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_provider_inventory_materialization_records(temp.path());
        let state_dir = Some(temp.path().to_string_lossy().to_string());

        let artifact_projection =
            artifacts(&request("artifacts", state_dir.clone())).expect("artifact projection");
        let artifact_records = artifact_projection.as_array().expect("artifact records");
        assert_eq!(artifact_records.len(), 1);
        assert_eq!(artifact_records[0]["model_ref"], "model://fixture/qwen3");
        assert_eq!(
            artifact_records[0]["object"],
            "ioi.model_mount_model_artifact"
        );
        assert_eq!(
            artifact_records[0]["rust_core_boundary"],
            "model_mount.provider_inventory.materialization"
        );

        let product_projection =
            product_artifacts(&request("product_artifacts", state_dir.clone()))
                .expect("product artifact projection");
        assert_eq!(
            product_projection
                .as_array()
                .expect("product artifact records")[0]["object"],
            "ioi.product_model_artifact"
        );

        let provider_projection =
            providers(&request("providers", state_dir.clone())).expect("provider projection");
        let provider_refs = provider_projection
            .as_array()
            .expect("provider records")
            .iter()
            .map(|record| string_field(record, "provider_ref"))
            .collect::<Vec<_>>();
        assert_eq!(
            provider_refs,
            vec![
                "provider://fixture".to_string(),
                "provider://native".to_string()
            ]
        );

        let runtime_projection =
            runtime_model_catalog(&request("runtime_model_catalog", state_dir.clone()))
                .expect("runtime catalog projection");
        let runtime_records = runtime_projection
            .as_array()
            .expect("runtime catalog records");
        assert_eq!(runtime_records.len(), 1);
        assert_eq!(runtime_records[0]["id"], "qwen3");
        assert_eq!(runtime_records[0]["provider_ref"], "provider://fixture");

        let open_ai_projection =
            open_ai_model_list(&request("open_ai_model_list", state_dir)).expect("OpenAI list");
        assert_eq!(open_ai_projection["object"], "list");
        assert_eq!(open_ai_projection["data"][0]["id"], "qwen3");
        assert_eq!(
            open_ai_projection["data"][0]["evidence_refs"][2],
            "openai_model_list_js_materialization_retired"
        );

        assert!(artifact_records
            .iter()
            .all(|record| record["provider_ref"] != "provider://legacy"));
        assert!(runtime_records
            .iter()
            .all(|record| record["provider_ref"] != "provider://native"));
    }

    #[test]
    fn provider_inventory_materialization_fails_closed_without_agentgres_state_dir() {
        let artifact_error =
            artifacts(&request("artifacts", None)).expect_err("state dir required");
        assert_eq!(
            artifact_error.code,
            "model_mount_provider_inventory_replay_state_dir_required"
        );
        let provider_error =
            providers(&request("providers", None)).expect_err("state dir required");
        assert_eq!(
            provider_error.code,
            "model_mount_provider_inventory_replay_state_dir_required"
        );
    }

    #[test]
    fn instance_projection_replays_agentgres_records_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let instance_dir = temp.path().join("model-instances");
        fs::create_dir_all(&instance_dir).expect("instance dir");
        for record in [
            json!({
                "id": "legacy-js-instance",
                "schema_version": MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
                "endpoint_id": "endpoint.local",
                "model_id": "model.local",
                "provider_id": "provider.local",
                "action": "load",
                "status": "loaded",
                "execution_backend": "daemon_js",
                "provider_lifecycle_hash": "sha256:provider",
                "instance_lifecycle_hash": "sha256:legacy"
            }),
            json!({
                "id": "instance.loaded",
                "schema_version": MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
                "endpoint_id": "endpoint.local",
                "model_id": "model.local",
                "provider_id": "provider.local",
                "action": "load",
                "status": "loaded",
                "execution_backend": "rust_model_mount_instance_lifecycle",
                "provider_lifecycle_hash": "sha256:provider",
                "instance_lifecycle_hash": "sha256:loaded",
                "evidence_refs": [
                    "rust_model_mount_instance_lifecycle",
                    "agentgres_model_instance_registry_planned"
                ]
            }),
            json!({
                "id": "instance.old",
                "schema_version": MODEL_MOUNT_INSTANCE_LIFECYCLE_SCHEMA_VERSION,
                "endpoint_id": "endpoint.local",
                "model_id": "model.local",
                "provider_id": "provider.local",
                "action": "evict",
                "status": "evicted",
                "execution_backend": "rust_model_mount_instance_lifecycle",
                "provider_lifecycle_hash": "sha256:provider",
                "instance_lifecycle_hash": "sha256:evicted",
                "evidence_refs": [
                    "rust_model_mount_instance_lifecycle",
                    "agentgres_model_instance_registry_planned"
                ]
            }),
        ] {
            fs::write(
                instance_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write instance record");
        }

        let projection = instances(&request(
            "instances",
            Some(temp.path().to_string_lossy().to_string()),
        ))
        .expect("instance projection");
        let records = projection.as_array().expect("instance records");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["id"], "instance.loaded");
        assert_eq!(records[1]["id"], "instance.old");
        assert!(records
            .iter()
            .all(|record| record["id"] != "legacy-js-instance"));
    }

    #[test]
    fn instance_projection_fails_closed_without_agentgres_state_dir() {
        let error = instances(&request("instances", None)).expect_err("state dir required");
        assert_eq!(error.code, "model_mount_instance_replay_state_dir_required");
    }

    #[test]
    fn provider_inventory_projection_replays_agentgres_records_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let provider_inventory_dir = temp.path().join("model-provider-inventory");
        fs::create_dir_all(&provider_inventory_dir).expect("provider inventory dir");
        for record in [
            json!({
                "id": "legacy-js-provider-inventory",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                "provider_ref": "provider://legacy",
                "provider_kind": "local_folder",
                "action": "list_models",
                "operation_kind": "model_mount.provider.inventory.list_models",
                "status": "listed",
                "backend": "ioi_fixture",
                "backend_id": "backend.fixture",
                "driver": "fixture",
                "execution_backend": "daemon_js",
                "item_refs": ["model://legacy"],
                "item_count": 1,
                "inventory_hash": "sha256:legacy",
                "record_dir": "model-provider-inventory",
                "record_id": "legacy-js-provider-inventory",
                "rust_core_boundary": "daemon_js",
                "source": "runtime-daemon.provider_inventory_js",
                "evidence_refs": ["legacy_js_provider_inventory"]
            }),
            json!({
                "id": "provider_inventory_fixture_list_models",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
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
                "source": "rust_model_mount_provider_inventory_command",
                "evidence_refs": [
                    "rust_model_mount_provider_inventory",
                    "agentgres_provider_inventory_truth_required",
                    "rust_model_mount_fixture_inventory_backend"
                ]
            }),
            json!({
                "id": "provider_inventory_native_list_loaded",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                "provider_ref": "provider://native",
                "provider_kind": "ioi_native_local",
                "action": "list_loaded",
                "operation_kind": "model_mount.provider.inventory.list_loaded",
                "status": "listed",
                "backend": "autopilot.native_local.fixture",
                "backend_id": "backend.autopilot.native-local.fixture",
                "driver": "native_local",
                "execution_backend": "rust_model_mount_native_local_inventory",
                "item_refs": ["model_instance://native/qwen3"],
                "item_count": 1,
                "inventory_hash": "sha256:native-inventory",
                "record_dir": "model-provider-inventory",
                "record_id": "provider_inventory_native_list_loaded",
                "receipt_refs": [],
                "rust_core_boundary": "model_mount.provider_inventory",
                "source": "rust_model_mount_provider_inventory_command",
                "evidence_refs": [
                    "rust_model_mount_provider_inventory",
                    "agentgres_provider_inventory_truth_required",
                    "rust_model_mount_native_local_inventory_backend"
                ]
            }),
        ] {
            fs::write(
                provider_inventory_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write provider inventory record");
        }

        let projection = provider_inventory_records(&request(
            "provider_inventory_records",
            Some(temp.path().to_string_lossy().to_string()),
        ))
        .expect("provider inventory projection");
        let records = projection.as_array().expect("provider inventory records");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["id"], "provider_inventory_fixture_list_models");
        assert_eq!(records[1]["id"], "provider_inventory_native_list_loaded");
        assert!(records
            .iter()
            .all(|record| record["id"] != "legacy-js-provider-inventory"));
    }

    #[test]
    fn provider_inventory_projection_fails_closed_without_agentgres_state_dir() {
        let error = provider_inventory_records(&request("provider_inventory_records", None))
            .expect_err("state dir required");
        assert_eq!(
            error.code,
            "model_mount_provider_inventory_replay_state_dir_required"
        );
    }

    #[test]
    fn catalog_search_replays_provider_inventory_records_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let provider_inventory_dir = temp.path().join("model-provider-inventory");
        fs::create_dir_all(&provider_inventory_dir).expect("provider inventory dir");
        for record in [
            json!({
                "id": "legacy-js-provider-inventory",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
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
            json!({
                "id": "provider_inventory_fixture_list_models",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                "provider_ref": "provider://fixture",
                "provider_kind": "local_folder",
                "action": "list_models",
                "operation_kind": "model_mount.provider.inventory.list_models",
                "status": "listed",
                "backend": "ioi_fixture",
                "backend_id": "backend.fixture",
                "driver": "fixture",
                "execution_backend": "rust_model_mount_fixture_inventory",
                "item_refs": ["model://fixture/qwen3", "model://fixture/llama"],
                "item_count": 2,
                "inventory_hash": "sha256:fixture-inventory",
                "record_dir": "model-provider-inventory",
                "record_id": "provider_inventory_fixture_list_models",
                "receipt_refs": [],
                "rust_core_boundary": "model_mount.provider_inventory",
                "source": "rust_model_mount_provider_inventory_command",
                "evidence_refs": [
                    "rust_model_mount_provider_inventory",
                    "agentgres_provider_inventory_truth_required",
                    "rust_model_mount_fixture_inventory_backend"
                ]
            }),
            json!({
                "id": "provider_inventory_native_list_loaded",
                "object": "ioi.model_mount_provider_inventory",
                "schema_version": MODEL_MOUNT_PROVIDER_INVENTORY_SCHEMA_VERSION,
                "provider_ref": "provider://native",
                "provider_kind": "ioi_native_local",
                "action": "list_loaded",
                "operation_kind": "model_mount.provider.inventory.list_loaded",
                "status": "listed",
                "backend": "autopilot.native_local.fixture",
                "backend_id": "backend.autopilot.native-local.fixture",
                "driver": "native_local",
                "execution_backend": "rust_model_mount_native_local_inventory",
                "item_refs": ["model_instance://native/qwen3"],
                "item_count": 1,
                "inventory_hash": "sha256:native-inventory",
                "record_dir": "model-provider-inventory",
                "record_id": "provider_inventory_native_list_loaded",
                "receipt_refs": [],
                "rust_core_boundary": "model_mount.provider_inventory",
                "source": "rust_model_mount_provider_inventory_command",
                "evidence_refs": [
                    "rust_model_mount_provider_inventory",
                    "agentgres_provider_inventory_truth_required",
                    "rust_model_mount_native_local_inventory_backend"
                ]
            }),
        ] {
            fs::write(
                provider_inventory_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write provider inventory record");
        }

        let projection = catalog_search(&request_with_state(
            "catalog_search",
            Some(temp.path().to_string_lossy().to_string()),
            json!({
                "catalog_search": {
                    "query": "qwen",
                    "provider_ref": "provider://fixture",
                    "limit": 5
                }
            }),
        ))
        .expect("catalog search projection");
        let results = projection["results"].as_array().expect("catalog results");

        assert_eq!(
            projection["source"],
            "rust_model_mount_catalog_search_projection"
        );
        assert_eq!(
            projection["rust_core_boundary"],
            "model_mount.catalog_search"
        );
        assert_eq!(projection["result_count"], 1);
        assert_eq!(results[0]["model_ref"], "model://fixture/qwen3");
        assert_eq!(
            results[0]["inventory_record_id"],
            "provider_inventory_fixture_list_models"
        );
        assert!(results
            .iter()
            .all(|record| record["provider_ref"] != "provider://legacy"));
        assert!(results
            .iter()
            .all(|record| record["provider_ref"] != "provider://native"));
    }

    #[test]
    fn catalog_search_fails_closed_without_agentgres_state_dir() {
        let error = catalog_search(&request_with_state(
            "catalog_search",
            None,
            json!({"catalog_search": {"query": "qwen"}}),
        ))
        .expect_err("state dir required");
        assert_eq!(
            error.code,
            "model_mount_provider_inventory_replay_state_dir_required"
        );
    }

    #[test]
    fn tokenizer_projection_replays_agentgres_records_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let tokenizer_dir = temp.path().join("model-tokenizer-utilities");
        fs::create_dir_all(&tokenizer_dir).expect("tokenizer dir");
        for record in [
            json!({
                "id": "legacy-js-tokenizer",
                "object": "ioi.model_mount_tokenizer_result",
                "status": "planned",
                "operation": "tokenize",
                "source": "runtime-daemon.tokenizer_js",
                "rust_core_boundary": "daemon_js",
                "route_selection_boundary": "model_mount.route_selection",
                "route_id": "route.local-first",
                "model": "model.local",
                "endpoint_id": "endpoint.local",
                "provider_id": "provider.local",
                "input_hash": "sha256:legacy",
                "token_count": 1,
                "control_hash": "sha256:legacy",
                "evidence_refs": ["legacy_js_tokenizer"]
            }),
            json!({
                "id": "model_tokenizer:count_tokens:test",
                "object": "ioi.model_mount_tokenizer_result",
                "status": "planned",
                "operation": "count_tokens",
                "source": "rust_model_mount_tokenizer_command",
                "rust_core_boundary": "model_mount.tokenizer",
                "route_selection_boundary": "model_mount.route_selection",
                "route_id": "route.local-first",
                "model": "model.local",
                "endpoint_id": "endpoint.local",
                "provider_id": "provider.local",
                "input_hash": "sha256:count",
                "tokens": ["hello"],
                "token_count": 1,
                "usage": {"prompt_tokens": 1, "total_tokens": 1},
                "receipt_refs": ["receipt://route-selection"],
                "control_hash": "sha256:count",
                "evidence_refs": [
                    "model_mount_tokenizer_rust_owned",
                    "agentgres_model_tokenizer_truth_required"
                ]
            }),
            json!({
                "id": "model_tokenizer:tokenize:test",
                "object": "ioi.model_mount_tokenizer_result",
                "status": "planned",
                "operation": "tokenize",
                "source": "rust_model_mount_tokenizer_command",
                "rust_core_boundary": "model_mount.tokenizer",
                "route_selection_boundary": "model_mount.route_selection",
                "route_id": "route.local-first",
                "model": "model.local",
                "endpoint_id": "endpoint.local",
                "provider_id": "provider.local",
                "input_hash": "sha256:tokenize",
                "tokens": ["hello", "world"],
                "token_count": 2,
                "usage": {"prompt_tokens": 2, "total_tokens": 2},
                "receipt_refs": ["receipt://route-selection"],
                "control_hash": "sha256:tokenize",
                "evidence_refs": [
                    "model_mount_tokenizer_rust_owned",
                    "agentgres_model_tokenizer_truth_required"
                ]
            }),
        ] {
            fs::write(
                tokenizer_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write tokenizer record");
        }

        let projection = tokenizer_records(&request(
            "model_tokenizer_records",
            Some(temp.path().to_string_lossy().to_string()),
        ))
        .expect("tokenizer projection");
        let records = projection.as_array().expect("tokenizer records");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["id"], "model_tokenizer:count_tokens:test");
        assert_eq!(records[1]["id"], "model_tokenizer:tokenize:test");
        assert!(records
            .iter()
            .all(|record| record["id"] != "legacy-js-tokenizer"));
    }

    #[test]
    fn tokenizer_projection_fails_closed_without_agentgres_state_dir() {
        let error = tokenizer_records(&request("model_tokenizer_records", None))
            .expect_err("state dir required");
        assert_eq!(
            error.code,
            "model_mount_tokenizer_replay_state_dir_required"
        );
    }

    #[test]
    fn route_projection_replays_agentgres_records_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let route_dir = temp.path().join("model-routes");
        fs::create_dir_all(&route_dir).expect("route dir");
        for record in [
            json!({
                "id": "route.js",
                "role": "legacy",
                "status": "active",
                "updatedAt": "2026-06-13T00:00:00.000Z",
                "receiptRefs": ["receipt://legacy"],
                "routeControl": {
                    "rust_core_boundary": "daemon_js",
                    "evidence_refs": ["legacy_js_route_writer"]
                }
            }),
            json!({
                "id": "route.local-first",
                "role": "default",
                "description": "Rust-authored model route.",
                "privacy": "local_or_enterprise",
                "quality": "adaptive",
                "maxCostUsd": 0.25,
                "maxLatencyMs": 30000,
                "providerEligibility": ["local_folder"],
                "fallback": ["endpoint.local"],
                "deniedProviders": [],
                "status": "active",
                "receiptRefs": ["receipt://model-mount/route-control/write"],
                "authorityReceiptRefs": [],
                "updatedAt": "2026-06-13T00:00:00.000Z",
                "routeControl": {
                    "source": "runtime-daemon.model_mounting.route_control",
                    "operation_kind": "model_mount.route.write",
                    "rust_core_boundary": "model_mount.route_control",
                    "evidence_refs": [
                        "model_mount_route_control_rust_owned",
                        "rust_daemon_core_route_control_plan",
                        "agentgres_route_truth_required"
                    ]
                }
            }),
            json!({
                "id": "route.research",
                "role": "research",
                "description": "Rust-authored research route.",
                "privacy": "local_or_enterprise",
                "quality": "adaptive",
                "maxCostUsd": 0.5,
                "maxLatencyMs": 1500,
                "providerEligibility": ["local_folder"],
                "fallback": ["endpoint.research"],
                "deniedProviders": [],
                "status": "active",
                "receiptRefs": ["receipt://model-mount/route-control/research"],
                "authorityReceiptRefs": [],
                "updatedAt": "2026-06-13T00:00:01.000Z",
                "routeControl": {
                    "source": "runtime-daemon.model_mounting.route_control",
                    "operation_kind": "model_mount.route.write",
                    "rust_core_boundary": "model_mount.route_control",
                    "evidence_refs": [
                        "model_mount_route_control_rust_owned",
                        "rust_daemon_core_route_control_plan",
                        "agentgres_route_truth_required"
                    ]
                }
            }),
        ] {
            fs::write(
                route_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write route record");
        }

        let projection = routes(&request(
            "routes",
            Some(temp.path().to_string_lossy().to_string()),
        ))
        .expect("route projection");
        let records = projection.as_array().expect("route records");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["id"], "route.local-first");
        assert_eq!(records[1]["id"], "route.research");
        assert!(records.iter().all(|record| record["id"] != "route.js"));
    }

    #[test]
    fn route_projection_fails_closed_without_agentgres_state_dir() {
        let error = routes(&request("routes", None)).expect_err("state dir required");
        assert_eq!(error.code, "model_mount_route_replay_state_dir_required");
    }
}
