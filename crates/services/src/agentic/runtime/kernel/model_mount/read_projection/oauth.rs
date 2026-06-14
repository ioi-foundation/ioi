use std::{fs, path::Path};

use serde_json::{json, Value};

use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn sessions(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let mut sessions = agentgres_oauth_control_records(request)?
        .into_iter()
        .filter_map(public_oauth_session)
        .collect::<Vec<_>>();
    sessions.sort_by(|left, right| {
        string_field(left, "provider_id")
            .cmp(&string_field(right, "provider_id"))
            .then_with(|| {
                string_field(left, "operation_kind").cmp(&string_field(right, "operation_kind"))
            })
            .then_with(|| string_field(left, "record_id").cmp(&string_field(right, "record_id")))
    });
    Ok(Value::Array(sessions))
}

pub(super) fn states(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let mut states = agentgres_oauth_control_records(request)?
        .into_iter()
        .filter_map(public_oauth_state)
        .collect::<Vec<_>>();
    states.sort_by(|left, right| {
        string_field(left, "provider_id")
            .cmp(&string_field(right, "provider_id"))
            .then_with(|| {
                string_field(left, "operation_kind").cmp(&string_field(right, "operation_kind"))
            })
            .then_with(|| string_field(left, "record_id").cmp(&string_field(right, "record_id")))
    });
    Ok(Value::Array(states))
}

fn agentgres_oauth_control_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_oauth_projection_state_dir_required",
                "OAuth session/state projection requires Rust Agentgres catalog-provider-control state_dir replay",
            )
        })?;
    let record_dir = Path::new(state_dir).join("model-catalog-provider-controls");
    if !record_dir.exists() {
        return Ok(vec![]);
    }
    let entries = fs::read_dir(&record_dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_oauth_projection_read_failed",
            format!("failed to read catalog-provider-control records: {error}"),
        )
    })?;
    let records = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .map(|path| {
            fs::read_to_string(&path)
                .map_err(|error| {
                    ModelMountReadProjectionError::new(
                        "model_mount_oauth_projection_read_failed",
                        format!(
                            "failed to read catalog-provider-control record {}: {error}",
                            path.display()
                        ),
                    )
                })
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents).map_err(|error| {
                        ModelMountReadProjectionError::new(
                            "model_mount_oauth_projection_invalid_record",
                            format!(
                                "failed to decode catalog-provider-control record {}: {error}",
                                path.display()
                            ),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(records
        .into_iter()
        .filter(rust_authored_oauth_control_record)
        .collect())
}

fn rust_authored_oauth_control_record(record: &Value) -> bool {
    string_field(record, "object") == "ioi.model_mount_catalog_provider_control"
        && string_field(record, "rust_core_boundary") == "model_mount.catalog_provider_control"
        && string_field(record, "operation_kind").starts_with("model_mount.catalog_provider_oauth.")
        && string_array(record, "evidence_refs")
            .iter()
            .any(|value| value == "public_catalog_provider_control_js_facade_retired")
}

fn public_oauth_session(record: Value) -> Option<Value> {
    let operation_kind = string_field(&record, "operation_kind");
    if !matches!(
        operation_kind.as_str(),
        "model_mount.catalog_provider_oauth.callback"
            | "model_mount.catalog_provider_oauth.exchange"
            | "model_mount.catalog_provider_oauth.refresh"
            | "model_mount.catalog_provider_oauth.revoke"
    ) {
        return None;
    }
    let provider_id = string_field(&record, "provider_id");
    if provider_id.is_empty() {
        return None;
    }
    let public_response = record.get("public_response").unwrap_or(&Value::Null);
    let session_status = if operation_kind == "model_mount.catalog_provider_oauth.revoke" {
        "revoked"
    } else {
        "active"
    };
    let authority_hash = first_non_empty([
        string_field(public_response, "authority_hash"),
        nested_string_field(&record, "authority", "authority_hash"),
    ]);
    let token_material = first_non_empty([
        string_field(public_response, "token_material"),
        string_field(public_response, "revoked_material"),
    ]);
    Some(json!({
        "object": "ioi.model_catalog_provider_oauth_session",
        "status": "projected",
        "session_status": session_status,
        "provider_id": provider_id,
        "operation_kind": operation_kind,
        "record_id": string_field(&record, "record_id"),
        "record_dir": "model-catalog-provider-controls",
        "control_hash": string_field(&record, "control_hash"),
        "authority_hash": authority_hash,
        "token_material": token_material,
        "private_material_returned": false,
        "plaintext_material_returned": false,
        "ctee_custody_boundary": string_field(&record, "ctee_custody_boundary"),
        "wallet_authority_boundary": string_field(&record, "wallet_authority_boundary"),
        "receipt_refs": string_array(&record, "receipt_refs"),
        "authority_grant_refs": nested_string_array(&record, "authority", "authority_grant_refs"),
        "authority_receipt_refs": nested_string_array(&record, "authority", "authority_receipt_refs"),
        "source": "agentgres_catalog_provider_control",
        "rust_core_boundary": "model_mount.catalog_provider_oauth_projection",
        "evidence_refs": oauth_projection_evidence_refs(),
    }))
}

fn public_oauth_state(record: Value) -> Option<Value> {
    let operation_kind = string_field(&record, "operation_kind");
    if !matches!(
        operation_kind.as_str(),
        "model_mount.catalog_provider_oauth.start" | "model_mount.catalog_provider_oauth.callback"
    ) {
        return None;
    }
    let provider_id = string_field(&record, "provider_id");
    if provider_id.is_empty() {
        return None;
    }
    let public_response = record.get("public_response").unwrap_or(&Value::Null);
    let state_status = if operation_kind == "model_mount.catalog_provider_oauth.callback" {
        "completed"
    } else {
        "pending"
    };
    let authority_hash = first_non_empty([
        string_field(public_response, "authority_hash"),
        nested_string_field(&record, "authority", "authority_hash"),
    ]);
    Some(json!({
        "object": "ioi.model_catalog_provider_oauth_state",
        "status": "projected",
        "state_status": state_status,
        "provider_id": provider_id,
        "operation_kind": operation_kind,
        "record_id": string_field(&record, "record_id"),
        "record_dir": "model-catalog-provider-controls",
        "control_hash": string_field(&record, "control_hash"),
        "state_hash": string_field(&record, "body_hash"),
        "authority_hash": authority_hash,
        "oauth_state_material": string_field(public_response, "oauth_state_material"),
        "authorization_url_material": string_field(public_response, "authorization_url_material"),
        "state_present": public_response
            .get("state_present")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "private_material_returned": false,
        "plaintext_material_returned": false,
        "ctee_custody_boundary": string_field(&record, "ctee_custody_boundary"),
        "wallet_authority_boundary": string_field(&record, "wallet_authority_boundary"),
        "receipt_refs": string_array(&record, "receipt_refs"),
        "authority_grant_refs": nested_string_array(&record, "authority", "authority_grant_refs"),
        "authority_receipt_refs": nested_string_array(&record, "authority", "authority_receipt_refs"),
        "source": "agentgres_catalog_provider_control",
        "rust_core_boundary": "model_mount.catalog_provider_oauth_projection",
        "evidence_refs": oauth_projection_evidence_refs(),
    }))
}

fn oauth_projection_evidence_refs() -> Vec<String> {
    vec![
        "rust_daemon_core_catalog_provider_oauth_projection".to_string(),
        "agentgres_catalog_provider_control_replay_required".to_string(),
        "rust_daemon_core_wallet_ctee_custody_required".to_string(),
        "model_mount_oauth_read_projection_js_facade_retired".to_string(),
    ]
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_default()
}

fn nested_string_field(value: &Value, object_key: &str, key: &str) -> String {
    value
        .get(object_key)
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_default()
}

fn first_non_empty(values: impl IntoIterator<Item = String>) -> String {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn nested_string_array(value: &Value, object_key: &str, key: &str) -> Vec<String> {
    value
        .get(object_key)
        .and_then(|value| value.get(key))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn request(
        state_dir: Option<String>,
        projection_kind: &str,
    ) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: projection_kind.to_string(),
            schema_version: None,
            generated_at: None,
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir,
            state: json!({}),
        }
    }

    fn write_record(state_dir: &std::path::Path, name: &str, record: Value) {
        let record_dir = state_dir.join("model-catalog-provider-controls");
        fs::create_dir_all(&record_dir).expect("record dir");
        fs::write(
            record_dir.join(name),
            serde_json::to_string_pretty(&record).expect("record json"),
        )
        .expect("write record");
    }

    fn oauth_record(id: &str, operation_kind: &str) -> Value {
        json!({
            "id": id,
            "record_id": id,
            "object": "ioi.model_mount_catalog_provider_control",
            "status": "planned",
            "operation_kind": operation_kind,
            "provider_id": "catalog.huggingface",
            "body_hash": format!("sha256:{id}"),
            "rust_core_boundary": "model_mount.catalog_provider_control",
            "wallet_authority_boundary": "wallet.network.catalog_provider_control",
            "ctee_custody_boundary": "ctee.catalog_provider_material",
            "plaintext_material_returned": false,
            "authority": {
                "authority_hash": format!("sha256:authority-{id}"),
                "authority_grant_refs": ["wallet.network://grant/catalog-provider"],
                "authority_receipt_refs": ["receipt://wallet/catalog-provider"]
            },
            "public_response": {
                "status": "accepted",
                "authority_hash": format!("sha256:authority-{id}"),
                "oauth_state_material": "ctee_custody_sealed",
                "authorization_url_material": "ctee_custody_sealed",
                "token_material": "ctee_custody_sealed",
                "revoked_material": "ctee_custody_sealed",
                "state_present": true,
                "private_material_returned": false
            },
            "receipt_refs": ["receipt://catalog-provider-control"],
            "evidence_refs": [
                "rust_daemon_core_catalog_provider_control",
                "agentgres_catalog_provider_control_truth_required",
                "public_catalog_provider_control_js_facade_retired"
            ],
            "control_hash": format!("hash-{id}")
        })
    }

    #[test]
    fn oauth_session_projection_replays_catalog_provider_control_and_filters_js_truth() {
        let temp = tempdir().expect("temp dir");
        write_record(
            temp.path(),
            "legacy.json",
            json!({
                "id": "legacy",
                "object": "ioi.model_mount_catalog_provider_control",
                "operation_kind": "model_mount.catalog_provider_oauth.exchange",
                "provider_id": "catalog.legacy",
                "rust_core_boundary": "daemon_js",
                "evidence_refs": ["legacy_js_oauth_session"]
            }),
        );
        write_record(
            temp.path(),
            "exchange.json",
            oauth_record("exchange", "model_mount.catalog_provider_oauth.exchange"),
        );
        write_record(
            temp.path(),
            "start.json",
            oauth_record("start", "model_mount.catalog_provider_oauth.start"),
        );

        let projection = sessions(&request(
            Some(temp.path().to_string_lossy().to_string()),
            "oauth_sessions",
        ))
        .expect("OAuth sessions");
        let records = projection.as_array().expect("session records");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["provider_id"], "catalog.huggingface");
        assert_eq!(
            records[0]["operation_kind"],
            "model_mount.catalog_provider_oauth.exchange"
        );
        assert_eq!(records[0]["session_status"], "active");
        assert_eq!(records[0]["private_material_returned"], false);
        assert_eq!(records[0]["plaintext_material_returned"], false);
        assert_eq!(
            records[0]["rust_core_boundary"],
            "model_mount.catalog_provider_oauth_projection"
        );
        assert!(records[0]["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .contains(&json!("agentgres_catalog_provider_control_replay_required")));
    }

    #[test]
    fn oauth_state_projection_replays_catalog_provider_control_and_filters_sessions() {
        let temp = tempdir().expect("temp dir");
        write_record(
            temp.path(),
            "start.json",
            oauth_record("start", "model_mount.catalog_provider_oauth.start"),
        );
        write_record(
            temp.path(),
            "exchange.json",
            oauth_record("exchange", "model_mount.catalog_provider_oauth.exchange"),
        );

        let projection = states(&request(
            Some(temp.path().to_string_lossy().to_string()),
            "oauth_states",
        ))
        .expect("OAuth states");
        let records = projection.as_array().expect("state records");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["provider_id"], "catalog.huggingface");
        assert_eq!(
            records[0]["operation_kind"],
            "model_mount.catalog_provider_oauth.start"
        );
        assert_eq!(records[0]["state_status"], "pending");
        assert_eq!(records[0]["state_hash"], "sha256:start");
        assert_eq!(records[0]["private_material_returned"], false);
        assert_eq!(records[0]["plaintext_material_returned"], false);
    }

    #[test]
    fn oauth_projection_fails_closed_without_agentgres_state_dir() {
        let error = sessions(&request(None, "oauth_sessions")).expect_err("state_dir required");

        assert_eq!(
            error.code,
            "model_mount_oauth_projection_state_dir_required"
        );
    }
}
