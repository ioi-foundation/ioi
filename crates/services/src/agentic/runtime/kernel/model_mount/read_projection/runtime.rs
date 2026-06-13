use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde_json::{json, Value};

use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION;

use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

const RUNTIME_ENGINE_RECORD_DIR: &str = "runtime-engine-controls";
const RUNTIME_ENGINE_PROJECTION_BOUNDARY: &str = "model_mount.runtime_engine_projection";
const RUNTIME_ENGINE_PROJECTION_EVIDENCE_REFS: [&str; 3] = [
    "rust_daemon_core_runtime_engine_projection",
    "agentgres_runtime_engine_replay_required",
    "model_mount_runtime_engine_js_projection_retired",
];

pub(super) fn engines(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(runtime_engine_projection(request)?.engines))
}

pub(super) fn engine_profiles(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(Value::Array(runtime_engine_projection(request)?.profiles))
}

pub(super) fn preference(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    Ok(runtime_engine_projection(request)?
        .preference
        .unwrap_or(Value::Null))
}

pub(super) fn preference_for_endpoint(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    preference(request)
}

pub(super) fn default_load_options(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let engine_id = request
        .engine_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(engine_id) = engine_id else {
        return Ok(Value::Null);
    };
    let projection = runtime_engine_projection(request)?;
    Ok(projection
        .profiles_by_engine
        .get(engine_id)
        .and_then(|profile| profile.get("default_load_options"))
        .cloned()
        .unwrap_or(Value::Null))
}

pub(super) fn engine_detail(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let engine_id = request
        .engine_id
        .as_deref()
        .unwrap_or("unknown_runtime_engine");
    runtime_engine_projection(request)?
        .engines_by_id
        .get(engine_id)
        .cloned()
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_runtime_engine_not_found",
                format!("runtime engine not found: {engine_id}"),
            )
        })
}

struct RuntimeEngineProjection {
    engines: Vec<Value>,
    engines_by_id: BTreeMap<String, Value>,
    profiles: Vec<Value>,
    profiles_by_engine: BTreeMap<String, Value>,
    preference: Option<Value>,
}

fn runtime_engine_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<RuntimeEngineProjection, ModelMountReadProjectionError> {
    let records = agentgres_runtime_engine_records(request)?;
    let mut profiles_by_engine = BTreeMap::new();
    let mut latest_record_by_engine = BTreeMap::new();
    let mut preference = None;

    for record in &records {
        let engine_id = string_field(record, "engine_id");
        latest_record_by_engine.insert(engine_id.clone(), record.clone());
        match string_field(record, "operation_kind").as_str() {
            "model_mount.runtime_preference.write" => {
                preference = Some(runtime_preference_projection(record));
            }
            "model_mount.runtime_engine_profile.write" => {
                profiles_by_engine.insert(engine_id, runtime_profile_projection(record));
            }
            "model_mount.runtime_engine_profile.delete" => {
                profiles_by_engine.remove(&engine_id);
            }
            _ => {}
        }
    }

    let selected_engine_id = preference
        .as_ref()
        .and_then(|value| runtime_json_string_field(value, "selected_engine_id"));
    let mut engine_ids = profiles_by_engine.keys().cloned().collect::<BTreeSet<_>>();
    if let Some(engine_id) = selected_engine_id.clone() {
        engine_ids.insert(engine_id);
    }

    let mut engines_by_id = BTreeMap::new();
    for engine_id in engine_ids {
        let profile = profiles_by_engine.get(&engine_id);
        let latest_record = latest_record_by_engine.get(&engine_id);
        let Some(engine) = runtime_engine_projection_for(
            &engine_id,
            profile,
            preference.as_ref(),
            latest_record,
            selected_engine_id.as_deref(),
        ) else {
            continue;
        };
        engines_by_id.insert(engine_id, engine);
    }

    let engines = engines_by_id.values().cloned().collect::<Vec<_>>();
    let profiles = profiles_by_engine.values().cloned().collect::<Vec<_>>();

    Ok(RuntimeEngineProjection {
        engines,
        engines_by_id,
        profiles,
        profiles_by_engine,
        preference,
    })
}

fn agentgres_runtime_engine_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_runtime_engine_replay_state_dir_required",
                "runtime-engine projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join(RUNTIME_ENGINE_RECORD_DIR);
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_runtime_engine_replay_read_failed",
            format!("failed to read runtime-engine records: {error}"),
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
                        "model_mount_runtime_engine_replay_read_failed",
                        format!(
                            "failed to read runtime-engine record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_runtime_engine_replay_invalid_record",
                            format!(
                                "failed to decode runtime-engine record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(admitted_runtime_engine_record)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        string_field(left, "generated_at")
            .cmp(&string_field(right, "generated_at"))
            .then_with(|| string_field(left, "id").cmp(&string_field(right, "id")))
    });
    Ok(records)
}

fn admitted_runtime_engine_record(record: Value) -> Option<Value> {
    if bool_field(&record, "deleted") {
        return None;
    }
    if string_field(&record, "schema_version") != MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION {
        return None;
    }
    if string_field(&record, "object") != "ioi.model_mount_runtime_engine_record" {
        return None;
    }
    if string_field(&record, "rust_core_boundary") != "model_mount.runtime_engine" {
        return None;
    }
    if !matches!(
        string_field(&record, "operation_kind").as_str(),
        "model_mount.runtime_preference.write"
            | "model_mount.runtime_engine_profile.write"
            | "model_mount.runtime_engine_profile.delete"
    ) {
        return None;
    }
    for field in [
        "id",
        "engine_id",
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
        "public_runtime_engine_js_facade_retired",
        "rust_daemon_core_runtime_engine",
        "agentgres_runtime_engine_truth_required",
    ] {
        if !evidence_refs.iter().any(|value| value == required) {
            return None;
        }
    }
    Some(record)
}

fn runtime_preference_projection(record: &Value) -> Value {
    let selected_engine_id = record
        .get("public_response")
        .and_then(|value| runtime_json_string_field(value, "selected_engine_id"))
        .unwrap_or_else(|| string_field(record, "engine_id"));
    json_object_without_nulls(json!({
        "id": "runtime_preference",
        "object": "ioi.model_mount_runtime_preference",
        "status": string_field(record, "status"),
        "selected_engine_id": selected_engine_id,
        "engine_id": string_field(record, "engine_id"),
        "source": "agentgres_runtime_engine_control",
        "generated_at": string_field(record, "generated_at"),
        "record_dir": RUNTIME_ENGINE_RECORD_DIR,
        "record_id": string_field(record, "id"),
        "operation_kind": string_field(record, "operation_kind"),
        "rust_core_boundary": string_field(record, "rust_core_boundary"),
        "runtime_engine_projection_boundary": RUNTIME_ENGINE_PROJECTION_BOUNDARY,
        "public_response": record.get("public_response").cloned().unwrap_or(Value::Null),
        "receipt_refs": record.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "evidence_refs": projected_evidence_refs(record),
        "control_hash": string_field(record, "control_hash"),
    }))
}

fn runtime_profile_projection(record: &Value) -> Value {
    let public_response = record
        .get("public_response")
        .cloned()
        .unwrap_or(Value::Null);
    json_object_without_nulls(json!({
        "id": string_field(record, "engine_id"),
        "object": "ioi.model_mount_runtime_engine_profile",
        "status": string_field(record, "status"),
        "engine_id": string_field(record, "engine_id"),
        "operator_label": public_response.get("operator_label").cloned().unwrap_or(Value::Null),
        "default_load_options": public_response.get("default_load_options").cloned().unwrap_or(Value::Null),
        "profile_recorded": public_response.get("profile_recorded").cloned().unwrap_or(Value::Null),
        "source": "agentgres_runtime_engine_control",
        "generated_at": string_field(record, "generated_at"),
        "record_dir": RUNTIME_ENGINE_RECORD_DIR,
        "record_id": string_field(record, "id"),
        "operation_kind": string_field(record, "operation_kind"),
        "rust_core_boundary": string_field(record, "rust_core_boundary"),
        "runtime_engine_projection_boundary": RUNTIME_ENGINE_PROJECTION_BOUNDARY,
        "public_response": public_response,
        "receipt_refs": record.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "evidence_refs": projected_evidence_refs(record),
        "control_hash": string_field(record, "control_hash"),
    }))
}

fn runtime_engine_projection_for(
    engine_id: &str,
    profile: Option<&Value>,
    preference: Option<&Value>,
    latest_record: Option<&Value>,
    selected_engine_id: Option<&str>,
) -> Option<Value> {
    let source_record = profile
        .or(preference.filter(|value| {
            runtime_json_string_field(value, "selected_engine_id").as_deref() == Some(engine_id)
        }))
        .or(latest_record)?;
    let selected = selected_engine_id == Some(engine_id);
    let status = if profile.is_some() {
        "configured"
    } else if selected {
        "selected"
    } else {
        "planned"
    };
    let profile_record_id = profile.and_then(|value| runtime_json_string_field(value, "record_id"));
    let preference_record_id = preference
        .filter(|_| selected)
        .and_then(|value| runtime_json_string_field(value, "record_id"));
    Some(json_object_without_nulls(json!({
        "id": engine_id,
        "object": "ioi.model_mount_runtime_engine",
        "engine_id": engine_id,
        "status": status,
        "selected": selected,
        "operator_label": profile.and_then(|value| value.get("operator_label")).cloned().unwrap_or(Value::Null),
        "default_load_options": profile.and_then(|value| value.get("default_load_options")).cloned().unwrap_or(Value::Null),
        "source": "agentgres_runtime_engine_control",
        "record_dir": RUNTIME_ENGINE_RECORD_DIR,
        "record_id": runtime_json_string_field(source_record, "record_id").unwrap_or_else(|| string_field(source_record, "id")),
        "profile_record_id": profile_record_id,
        "preference_record_id": preference_record_id,
        "operation_kind": runtime_json_string_field(source_record, "operation_kind")
            .unwrap_or_else(|| string_field(source_record, "operation_kind")),
        "generated_at": runtime_json_string_field(source_record, "generated_at")
            .unwrap_or_else(|| string_field(source_record, "generated_at")),
        "rust_core_boundary": "model_mount.runtime_engine",
        "runtime_engine_projection_boundary": RUNTIME_ENGINE_PROJECTION_BOUNDARY,
        "receipt_refs": source_record.get("receipt_refs").cloned().unwrap_or_else(|| json!([])),
        "evidence_refs": projected_evidence_refs(source_record),
        "control_hash": runtime_json_string_field(source_record, "control_hash")
            .unwrap_or_else(|| string_field(source_record, "control_hash")),
    })))
}

fn json_object_without_nulls(value: Value) -> Value {
    let Value::Object(mut object) = value else {
        return value;
    };
    object.retain(|_, value| !value.is_null());
    Value::Object(object)
}

fn projected_evidence_refs(record: &Value) -> Vec<String> {
    let mut refs = evidence_refs(record);
    for evidence_ref in RUNTIME_ENGINE_PROJECTION_EVIDENCE_REFS {
        if !refs.iter().any(|value| value == evidence_ref) {
            refs.push(evidence_ref.to_string());
        }
    }
    refs
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn runtime_json_string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn evidence_refs(value: &Value) -> Vec<String> {
    value
        .get("evidence_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;
    use serde_json::json;

    fn request(projection_kind: &str) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: projection_kind.to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: Some("backend.llama-cpp".to_string()),
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: None,
            state: json!({
                "runtime_engines": [
                    {"id": "backend.llama-cpp", "status": "caller_supplied"}
                ],
                "runtime_engine_profiles": [
                    {"engine_id": "backend.llama-cpp", "gpu_layers": 42}
                ],
                "runtime_preference": {"routeId": "route.local-first"},
                "default_load_options": {"gpuLayers": 42},
                "runtime_engine": {"id": "backend.llama-cpp"}
            }),
        }
    }

    #[test]
    fn runtime_projection_replays_agentgres_runtime_engine_controls() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record_dir = temp.path().join(RUNTIME_ENGINE_RECORD_DIR);
        fs::create_dir_all(&record_dir).expect("runtime-engine control dir");
        for record in [
            json!({
                "id": "legacy-js-runtime-engine",
                "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION,
                "object": "ioi.model_mount_runtime_engine_record",
                "engine_id": "backend.legacy",
                "operation_kind": "model_mount.runtime_engine_profile.write",
                "status": "planned",
                "generated_at": "2026-06-10T00:00:00.000Z",
                "rust_core_boundary": "daemon_js",
                "control_hash": "sha256:legacy",
                "evidence_refs": ["legacy_js_runtime_engine"]
            }),
            json!({
                "id": "runtime-engine-control:preference",
                "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION,
                "object": "ioi.model_mount_runtime_engine_record",
                "engine_id": "backend.llama-cpp",
                "operation_kind": "model_mount.runtime_preference.write",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.runtime_engine",
                "generated_at": "2026-06-11T00:00:00.000Z",
                "rust_core_boundary": "model_mount.runtime_engine",
                "control_hash": "sha256:preference",
                "public_response": {
                    "object": "ioi.model_mount_runtime_engine",
                    "status": "planned",
                    "engine_id": "backend.llama-cpp",
                    "rust_core_boundary": "model_mount.runtime_engine",
                    "operation_kind": "model_mount.runtime_preference.write",
                    "selected_engine_id": "backend.llama-cpp",
                    "js_preference_write": false,
                    "js_profile_write": false,
                    "js_projection_write": false
                },
                "receipt_refs": ["receipt://runtime/preference"],
                "evidence_refs": [
                    "public_runtime_engine_js_facade_retired",
                    "rust_daemon_core_runtime_engine",
                    "agentgres_runtime_engine_truth_required"
                ]
            }),
            json!({
                "id": "runtime-engine-control:profile",
                "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION,
                "object": "ioi.model_mount_runtime_engine_record",
                "engine_id": "backend.llama-cpp",
                "operation_kind": "model_mount.runtime_engine_profile.write",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.runtime_engine",
                "generated_at": "2026-06-11T00:00:01.000Z",
                "rust_core_boundary": "model_mount.runtime_engine",
                "control_hash": "sha256:profile",
                "public_response": {
                    "object": "ioi.model_mount_runtime_engine",
                    "status": "planned",
                    "engine_id": "backend.llama-cpp",
                    "rust_core_boundary": "model_mount.runtime_engine",
                    "operation_kind": "model_mount.runtime_engine_profile.write",
                    "profile_recorded": true,
                    "default_load_options": {"gpu_layers": 4},
                    "operator_label": "Native local",
                    "js_preference_write": false,
                    "js_profile_write": false,
                    "js_projection_write": false
                },
                "receipt_refs": ["receipt://runtime/profile"],
                "evidence_refs": [
                    "public_runtime_engine_js_facade_retired",
                    "rust_daemon_core_runtime_engine",
                    "agentgres_runtime_engine_truth_required"
                ]
            }),
            json!({
                "id": "runtime-engine-control:deleted-profile",
                "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION,
                "object": "ioi.model_mount_runtime_engine_record",
                "engine_id": "backend.deleted",
                "operation_kind": "model_mount.runtime_engine_profile.write",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.runtime_engine",
                "generated_at": "2026-06-11T00:00:02.000Z",
                "rust_core_boundary": "model_mount.runtime_engine",
                "control_hash": "sha256:deleted-profile",
                "public_response": {
                    "object": "ioi.model_mount_runtime_engine",
                    "status": "planned",
                    "engine_id": "backend.deleted",
                    "rust_core_boundary": "model_mount.runtime_engine",
                    "operation_kind": "model_mount.runtime_engine_profile.write",
                    "profile_recorded": true
                },
                "evidence_refs": [
                    "public_runtime_engine_js_facade_retired",
                    "rust_daemon_core_runtime_engine",
                    "agentgres_runtime_engine_truth_required"
                ]
            }),
            json!({
                "id": "runtime-engine-control:deleted",
                "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_PLAN_SCHEMA_VERSION,
                "object": "ioi.model_mount_runtime_engine_record",
                "engine_id": "backend.deleted",
                "operation_kind": "model_mount.runtime_engine_profile.delete",
                "status": "planned",
                "source": "runtime-daemon.model_mounting.runtime_engine",
                "generated_at": "2026-06-11T00:00:03.000Z",
                "rust_core_boundary": "model_mount.runtime_engine",
                "control_hash": "sha256:deleted",
                "public_response": {
                    "object": "ioi.model_mount_runtime_engine",
                    "status": "planned",
                    "engine_id": "backend.deleted",
                    "rust_core_boundary": "model_mount.runtime_engine",
                    "operation_kind": "model_mount.runtime_engine_profile.delete",
                    "profile_deleted": true
                },
                "evidence_refs": [
                    "public_runtime_engine_js_facade_retired",
                    "rust_daemon_core_runtime_engine",
                    "agentgres_runtime_engine_truth_required"
                ]
            }),
        ] {
            fs::write(
                record_dir.join(format!("{}.json", string_field(&record, "id"))),
                serde_json::to_string_pretty(&record).expect("record json"),
            )
            .expect("write runtime-engine record");
        }

        let mut request = request("runtime_engines");
        request.state_dir = Some(temp.path().to_string_lossy().to_string());

        let engines = engines(&request).expect("runtime engines");
        assert_eq!(engines.as_array().expect("engines").len(), 1);
        assert_eq!(engines[0]["id"], "backend.llama-cpp");
        assert_eq!(engines[0]["selected"], true);
        assert_eq!(engines[0]["default_load_options"], json!({"gpu_layers": 4}));
        assert_eq!(
            engines[0]["runtime_engine_projection_boundary"],
            RUNTIME_ENGINE_PROJECTION_BOUNDARY
        );
        assert!(engines[0]["evidence_refs"]
            .as_array()
            .expect("evidence")
            .iter()
            .any(|value| value == "agentgres_runtime_engine_replay_required"));
        assert!(engines
            .as_array()
            .expect("engines")
            .iter()
            .all(|record| record["id"] != "backend.legacy" && record["id"] != "backend.deleted"));

        let profiles = engine_profiles(&request).expect("runtime profiles");
        assert_eq!(profiles.as_array().expect("profiles").len(), 1);
        assert_eq!(profiles[0]["operator_label"], "Native local");
        assert_eq!(
            profiles[0]["default_load_options"],
            json!({"gpu_layers": 4})
        );

        let preference = preference(&request).expect("runtime preference");
        assert_eq!(preference["selected_engine_id"], "backend.llama-cpp");
        assert_eq!(preference["record_id"], "runtime-engine-control:preference");

        let default_load_options =
            default_load_options(&request).expect("runtime default load options");
        assert_eq!(default_load_options, json!({"gpu_layers": 4}));

        let detail = engine_detail(&request).expect("runtime engine detail");
        assert_eq!(detail["id"], "backend.llama-cpp");
        assert_eq!(
            detail["profile_record_id"],
            "runtime-engine-control:profile"
        );
        assert_eq!(
            detail["preference_record_id"],
            "runtime-engine-control:preference"
        );
    }

    #[test]
    fn runtime_projection_fails_closed_without_agentgres_state_dir() {
        let error = engines(&request("runtime_engines")).expect_err("state dir required");
        assert_eq!(
            error.code,
            "model_mount_runtime_engine_replay_state_dir_required"
        );
    }

    #[test]
    fn runtime_engine_detail_fails_closed_for_missing_agentgres_record() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut request = request("runtime_engine_detail");
        request.state_dir = Some(temp.path().to_string_lossy().to_string());
        let error =
            engine_detail(&request).expect_err("runtime engine detail requires admitted state");

        assert_eq!(error.code, "model_mount_runtime_engine_not_found");
        assert_eq!(error.message, "runtime engine not found: backend.llama-cpp");
    }
}
