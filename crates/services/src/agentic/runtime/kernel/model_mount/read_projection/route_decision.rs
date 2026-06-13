use std::{fs, path::Path};

use serde_json::{Map, Value};

use super::common::{array_field, json_string_field};
use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn route_decisions(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(route_decision_records(request)?))
}

pub(super) fn endpoint_resolutions(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(route_endpoint_resolution_records(request)?))
}

pub(super) fn route_decision_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let records = read_agentgres_records(
        request,
        "model-route-selections",
        "model_mount_route_decision_replay_state_dir_required",
        "model_mount_route_decision_replay_read_failed",
        "model_mount_route_decision_replay_invalid_record",
        "model route decision projection requires Rust Agentgres state_dir replay",
    )?;
    let mut decisions = records
        .into_iter()
        .filter_map(route_decision_from_selection_record)
        .collect::<Vec<_>>();
    decisions.sort_by(|left, right| {
        json_string_field(left, "route_id")
            .unwrap_or_default()
            .cmp(&json_string_field(right, "route_id").unwrap_or_default())
            .then_with(|| {
                json_string_field(left, "record_id")
                    .unwrap_or_default()
                    .cmp(&json_string_field(right, "record_id").unwrap_or_default())
            })
    });
    Ok(decisions)
}

pub(super) fn route_decision_records_or_empty(
    request: &ModelMountReadProjectionRequest,
) -> Vec<Value> {
    route_decision_records(request).unwrap_or_default()
}

pub(super) fn route_endpoint_resolution_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let records = read_agentgres_records(
        request,
        "model-route-endpoint-resolutions",
        "model_mount_route_endpoint_resolution_replay_state_dir_required",
        "model_mount_route_endpoint_resolution_replay_read_failed",
        "model_mount_route_endpoint_resolution_replay_invalid_record",
        "model route endpoint-resolution projection requires Rust Agentgres state_dir replay",
    )?;
    let mut resolutions = records
        .into_iter()
        .filter_map(admitted_endpoint_resolution_record)
        .collect::<Vec<_>>();
    resolutions.sort_by(|left, right| {
        json_string_field(left, "route_id")
            .unwrap_or_default()
            .cmp(&json_string_field(right, "route_id").unwrap_or_default())
            .then_with(|| {
                json_string_field(left, "model_id")
                    .unwrap_or_default()
                    .cmp(&json_string_field(right, "model_id").unwrap_or_default())
            })
            .then_with(|| {
                json_string_field(left, "id")
                    .unwrap_or_default()
                    .cmp(&json_string_field(right, "id").unwrap_or_default())
            })
    });
    Ok(resolutions)
}

fn route_decision_from_selection_record(record: Value) -> Option<Value> {
    if !admitted_selection_record(&record) {
        return None;
    }
    let mut decision = record
        .get("route_decision")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(Map::new);
    insert_string_if_absent(
        &mut decision,
        "route_id",
        string_field(&record, "route_id")?,
    );
    insert_string_if_absent(
        &mut decision,
        "selected_model",
        string_field(&record, "selected_model")?,
    );
    insert_string_if_absent(
        &mut decision,
        "endpoint_id",
        string_field(&record, "endpoint_id")?,
    );
    insert_string_if_absent(
        &mut decision,
        "provider_id",
        string_field(&record, "provider_id")?,
    );
    insert_optional_string(
        &mut decision,
        "capability",
        string_field(&record, "capability"),
    );
    insert_optional_string(
        &mut decision,
        "policy_hash",
        string_field(&record, "policy_hash"),
    );
    insert_optional_string(
        &mut decision,
        "selected_at",
        string_field(&record, "selected_at"),
    );
    decision.insert(
        "record_dir".to_string(),
        Value::String("model-route-selections".to_string()),
    );
    decision.insert("record_id".to_string(), record.get("id")?.clone());
    decision.insert(
        "receipt_id".to_string(),
        record
            .get("accepted_receipt_record")
            .and_then(|receipt| receipt.get("id"))
            .cloned()
            .or_else(|| first_array_value(&record, "receipt_refs"))
            .unwrap_or(Value::Null),
    );
    decision.insert(
        "receipt_created_at".to_string(),
        record
            .get("accepted_receipt_record")
            .and_then(|receipt| receipt.get("createdAt"))
            .cloned()
            .or_else(|| record.get("selected_at").cloned())
            .unwrap_or(Value::Null),
    );
    decision.insert(
        "receipt_kind".to_string(),
        record
            .get("accepted_receipt_record")
            .and_then(|receipt| receipt.get("kind"))
            .cloned()
            .unwrap_or_else(|| Value::String("model_route_selection".to_string())),
    );
    decision.insert(
        "receipt_refs".to_string(),
        record
            .get("receipt_refs")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![])),
    );
    decision.insert(
        "evidence_refs".to_string(),
        record
            .get("evidence_refs")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![])),
    );
    decision.insert(
        "rust_core_boundary".to_string(),
        record.get("rust_core_boundary")?.clone(),
    );
    decision.insert(
        "route_selection_boundary".to_string(),
        record.get("route_selection_boundary")?.clone(),
    );
    Some(Value::Object(decision))
}

fn admitted_selection_record(record: &Value) -> bool {
    if bool_field(record, "deleted") {
        return false;
    }
    if json_string_field(record, "object").as_deref() != Some("ioi.model_mount_route_selection") {
        return false;
    }
    for field in [
        "id",
        "route_id",
        "selected_model",
        "endpoint_id",
        "provider_id",
    ] {
        if string_field(record, field).is_none() {
            return false;
        }
    }
    if json_string_field(record, "rust_core_boundary").as_deref()
        != Some("model_mount.route_control")
    {
        return false;
    }
    if json_string_field(record, "route_selection_boundary").as_deref()
        != Some("model_mount.route_selection")
    {
        return false;
    }
    required_evidence(record)
}

fn admitted_endpoint_resolution_record(mut record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    if json_string_field(&record, "object").as_deref()
        != Some("ioi.model_mount_explicit_model_endpoints")
    {
        return None;
    }
    for field in ["id", "route_id", "model_id"] {
        string_field(&record, field)?;
    }
    if array_field(&record, "endpoint_ids").is_empty() {
        return None;
    }
    if json_string_field(&record, "rust_core_boundary").as_deref()
        != Some("model_mount.route_control")
    {
        return None;
    }
    if json_string_field(&record, "route_selection_boundary").as_deref()
        != Some("model_mount.route_selection")
    {
        return None;
    }
    if !required_evidence(&record) {
        return None;
    }
    if let Some(map) = record.as_object_mut() {
        map.insert(
            "record_dir".to_string(),
            Value::String("model-route-endpoint-resolutions".to_string()),
        );
    }
    Some(record)
}

fn required_evidence(record: &Value) -> bool {
    let evidence_refs = string_array_field(record, "evidence_refs");
    [
        "model_mount_route_control_rust_owned",
        "rust_daemon_core_route_control_plan",
        "agentgres_route_truth_required",
    ]
    .iter()
    .all(|required| evidence_refs.iter().any(|value| value == required))
}

fn read_agentgres_records(
    request: &ModelMountReadProjectionRequest,
    record_dir_name: &str,
    state_dir_code: &'static str,
    read_failed_code: &'static str,
    invalid_record_code: &'static str,
    state_dir_message: &'static str,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ModelMountReadProjectionError::new(state_dir_code, state_dir_message))?;
    let record_dir = Path::new(state_dir).join(record_dir_name);
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            read_failed_code,
            format!("failed to read {record_dir_name} records: {error}"),
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
                        format!(
                            "failed to read {} record {}: {error}",
                            record_dir_name,
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            invalid_record_code,
                            format!(
                                "failed to decode {} record {}: {error}",
                                record_dir_name,
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect()
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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

fn first_array_value(value: &Value, key: &str) -> Option<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .cloned()
}

fn insert_string_if_absent(target: &mut Map<String, Value>, key: &str, value: String) {
    target
        .entry(key.to_string())
        .or_insert_with(|| Value::String(value));
}

fn insert_optional_string(target: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        target
            .entry(key.to_string())
            .or_insert_with(|| Value::String(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;
    use serde_json::json;

    fn request(state: Value, state_dir: Option<String>) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "model_route_decisions".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir,
            state,
        }
    }

    #[test]
    fn route_decisions_replay_agentgres_selection_records_and_filter_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        let route_selection_dir = temp.path().join("model-route-selections");
        fs::create_dir_all(&route_selection_dir).expect("route selection dir");
        for record in [
            json!({
                "id": "legacy-js-selection",
                "object": "ioi.model_mount_route_selection",
                "route_id": "route.js",
                "selected_model": "model.js",
                "endpoint_id": "endpoint.js",
                "provider_id": "provider.js",
                "rust_core_boundary": "daemon_js",
                "route_selection_boundary": "model_mount.route_selection",
                "evidence_refs": ["legacy_js_route_decision"]
            }),
            json!({
                "id": "route_selection:route.local-first:test",
                "object": "ioi.model_mount_route_selection",
                "route_id": "route.local-first",
                "selected_model": "model.local",
                "endpoint_id": "endpoint.local",
                "provider_id": "provider.local",
                "capability": "chat",
                "policy_hash": "sha256:policy",
                "receipt_refs": ["receipt://route-control/select"],
                "evidence_refs": [
                    "model_mount_route_control_rust_owned",
                    "rust_daemon_core_route_control_plan",
                    "agentgres_route_truth_required"
                ],
                "rust_core_boundary": "model_mount.route_control",
                "route_selection_boundary": "model_mount.route_selection",
                "selected_at": "2026-06-11T00:02:00.000Z",
                "route_decision": {
                    "route_decision_ref": "model_mount://route_decision/route.local-first",
                    "route_ref": "route.local-first",
                    "endpoint_ref": "endpoint.local",
                    "provider_ref": "provider.local",
                    "model_ref": "model.local"
                },
                "accepted_receipt_record": {
                    "id": "receipt-route",
                    "kind": "model_route_selection",
                    "createdAt": "2026-06-11T00:02:00.000Z"
                }
            }),
        ] {
            fs::write(
                route_selection_dir.join(format!("{}.json", string_field(&record, "id").unwrap())),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write route selection record");
        }

        let decisions = route_decisions(&request(
            json!({
                "receipts": [
                    {
                        "id": "receipt-js",
                        "kind": "model_route_selection",
                        "details": {"model_route_decision": {"route_id": "route.js"}}
                    }
                ]
            }),
            Some(temp.path().to_string_lossy().to_string()),
        ))
        .expect("route decisions");

        let decisions = decisions.as_array().expect("route decisions");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["route_id"], "route.local-first");
        assert_eq!(decisions[0]["selected_model"], "model.local");
        assert_eq!(decisions[0]["receipt_id"], "receipt-route");
        assert_eq!(decisions[0]["receipt_kind"], "model_route_selection");
        assert_eq!(
            decisions[0]["record_id"],
            "route_selection:route.local-first:test"
        );
    }

    #[test]
    fn route_decisions_fail_closed_without_agentgres_state_dir() {
        let error = route_decisions(&request(json!({}), None)).expect_err("state dir required");
        assert_eq!(
            error.code,
            "model_mount_route_decision_replay_state_dir_required"
        );
    }

    #[test]
    fn endpoint_resolutions_replay_agentgres_records() {
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
                "endpoints": [{"id": "endpoint.local"}],
                "receipt_refs": ["receipt://route-control/explicit-endpoints"],
                "evidence_refs": [
                    "model_mount_route_control_rust_owned",
                    "rust_daemon_core_route_control_plan",
                    "agentgres_route_truth_required"
                ],
                "rust_core_boundary": "model_mount.route_control",
                "route_selection_boundary": "model_mount.route_selection",
                "source": "runtime-daemon.model_mounting.route_control",
                "resolved_at": "2026-06-11T00:03:00.000Z"
            }),
        ] {
            fs::write(
                endpoint_resolution_dir
                    .join(format!("{}.json", string_field(&record, "id").unwrap())),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write endpoint resolution record");
        }

        let resolutions = endpoint_resolutions(&request(
            json!({"receipts": [{"id": "receipt-js", "kind": "model_route_selection"}]}),
            Some(temp.path().to_string_lossy().to_string()),
        ))
        .expect("endpoint resolutions");
        let resolutions = resolutions.as_array().expect("endpoint resolutions");

        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0]["route_id"], "route.local-first");
        assert_eq!(resolutions[0]["model_id"], "model.local");
        assert_eq!(
            resolutions[0]["record_dir"],
            "model-route-endpoint-resolutions"
        );
    }
}
