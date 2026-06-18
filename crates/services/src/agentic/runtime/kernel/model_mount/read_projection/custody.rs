use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use serde_json::{json, Value};

use super::{ModelMountReadProjectionError, ModelMountReadProjectionRequest};

pub(super) fn capability_token_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut active_tokens = BTreeMap::new();
    let mut revoked_tokens = BTreeSet::new();
    for record in custody_records_from_dir(request, "capability-tokens", "capability token")? {
        if !is_admitted_capability_token_record(&record) {
            continue;
        }
        let operation_kind = string_field(&record, "operation_kind");
        let token_id = string_field(&record, "token_id");
        if token_id.is_empty() {
            continue;
        }
        if operation_kind == "model_mount.capability_token.revoke" {
            revoked_tokens.insert(token_id);
            continue;
        }
        if operation_kind != "model_mount.capability_token.create" {
            continue;
        }
        active_tokens.insert(token_id, projected_capability_token_record(&record));
    }
    for token_id in revoked_tokens {
        active_tokens.remove(&token_id);
    }
    Ok(active_tokens.into_values().collect())
}

pub(super) fn vault_ref_records(
    request: &ModelMountReadProjectionRequest,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let mut active_refs = BTreeMap::new();
    let mut removed_refs = BTreeSet::new();
    for record in custody_records_from_dir(request, "vault-refs", "vault ref")? {
        if !is_admitted_vault_ref_record(&record) {
            continue;
        }
        let operation_kind = string_field(&record, "operation_kind");
        let vault_ref_hash = string_field(&record, "vault_ref_hash");
        if vault_ref_hash.is_empty() {
            continue;
        }
        if operation_kind == "model_mount.vault_ref.remove" {
            removed_refs.insert(vault_ref_hash);
            continue;
        }
        if operation_kind != "model_mount.vault_ref.bind" {
            continue;
        }
        active_refs.insert(vault_ref_hash, projected_vault_ref_record(&record));
    }
    for vault_ref_hash in removed_refs {
        active_refs.remove(&vault_ref_hash);
    }
    Ok(active_refs.into_values().collect())
}

fn custody_records_from_dir(
    request: &ModelMountReadProjectionRequest,
    record_dir: &str,
    label: &str,
) -> Result<Vec<Value>, ModelMountReadProjectionError> {
    let state_dir = request
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ModelMountReadProjectionError::new(
                "model_mount_wallet_custody_replay_state_dir_required",
                "wallet authority and vault custody projection requires Rust Agentgres state_dir replay",
            )
        })?;
    let dir = Path::new(state_dir).join(record_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = fs::read_dir(&dir).map_err(|error| {
        ModelMountReadProjectionError::new(
            "model_mount_wallet_custody_replay_read_failed",
            format!("failed to read {label} records: {error}"),
        )
    })?;
    let mut records = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|error| {
            ModelMountReadProjectionError::new(
                "model_mount_wallet_custody_replay_read_failed",
                format!("failed to read {label} record {}: {error}", path.display()),
            )
        })?;
        let record = serde_json::from_slice::<Value>(&bytes).map_err(|error| {
            ModelMountReadProjectionError::new(
                "model_mount_wallet_custody_replay_invalid_record",
                format!(
                    "failed to decode {label} record {}: {error}",
                    path.display()
                ),
            )
        })?;
        records.push(record);
    }
    records.sort_by(|left, right| {
        string_field(left, "planned_at")
            .cmp(&string_field(right, "planned_at"))
            .then_with(|| string_field(left, "record_id").cmp(&string_field(right, "record_id")))
            .then_with(|| string_field(left, "id").cmp(&string_field(right, "id")))
    });
    Ok(records)
}

fn is_admitted_capability_token_record(record: &Value) -> bool {
    string_field(record, "object") == "ioi.model_mount_capability_token_control"
        && string_field(record, "rust_core_boundary") == "model_mount.capability_token"
        && evidence_refs(record)
            .iter()
            .any(|value| value == "agentgres_capability_token_truth_required")
}

fn is_admitted_vault_ref_record(record: &Value) -> bool {
    string_field(record, "object") == "ioi.model_mount_vault_control"
        && string_field(record, "rust_core_boundary") == "model_mount.vault"
        && evidence_refs(record)
            .iter()
            .any(|value| value == "agentgres_vault_truth_required")
}

fn projected_capability_token_record(record: &Value) -> Value {
    let authority = record
        .get("capability_token_authority")
        .unwrap_or(&Value::Null);
    json!({
        "id": string_field(record, "token_id"),
        "token_id": string_field(record, "token_id"),
        "object": "ioi.model_mount_capability_token",
        "status": "active",
        "audience": string_field_any(authority, &["audience"])
            .or_else(|| string_field_any(record.get("public_response").unwrap_or(&Value::Null), &["audience"])),
        "grant_id": string_field_any(authority, &["grant_id"])
            .or_else(|| string_field_any(record.get("public_response").unwrap_or(&Value::Null), &["grant_id"])),
        "created_at": string_field(record, "planned_at"),
        "allowed_scopes": string_array_field(authority, "allowed_scopes"),
        "denied_scopes": string_array_field(authority, "denied_scopes"),
        "token_hash": string_field(record, "token_hash"),
        "token_material_returned_once": true,
        "plaintext_material_persisted": false,
        "record_dir": "capability-tokens",
        "record_id": string_field_any(record, &["record_id", "id"]),
        "operation_kind": string_field(record, "operation_kind"),
        "source": "agentgres_capability_token_control_record",
        "rust_core_boundary": "model_mount.capability_token_projection",
        "capability_token_projection_boundary": "model_mount.capability_token_projection",
        "wallet_authority_boundary": string_field(record, "wallet_authority_boundary"),
        "authority_hash": string_field(authority, "authority_hash"),
        "control_hash": string_field(record, "control_hash"),
        "receipt_refs": json_array_field(record, "receipt_refs"),
        "evidence_refs": custody_projection_evidence_refs(
            record,
            "rust_daemon_core_capability_token_projection",
            "agentgres_capability_token_replay_required",
            "model_mount_capability_token_js_projection_retired",
        ),
    })
}

fn projected_vault_ref_record(record: &Value) -> Value {
    let public_response = record.get("public_response").unwrap_or(&Value::Null);
    let ctee_custody = record.get("ctee_custody").unwrap_or(&Value::Null);
    let vault_authority = record.get("vault_authority").unwrap_or(&Value::Null);
    let vault_ref_hash = string_field(record, "vault_ref_hash");
    let custody_ref = string_field(ctee_custody, "custody_ref");
    let custody_ref = if custody_ref.is_empty() {
        string_field(public_response, "custody_ref")
    } else {
        custody_ref
    };
    json!({
        "id": format!("vault_ref.{vault_ref_hash}"),
        "object": "ioi.model_mount_vault_ref",
        "status": "active",
        "vault_ref_hash": vault_ref_hash,
        "vault_ref": public_response
            .get("vault_ref")
            .cloned()
            .unwrap_or_else(|| json!({"redacted": true, "hash": vault_ref_hash})),
        "label": string_field(public_response, "label"),
        "purpose": string_field(public_response, "purpose"),
        "material_hash": string_field(record, "material_hash"),
        "custody_ref": custody_ref,
        "configured": true,
        "material_bound": true,
        "resolved_material": false,
        "requires_rebind": false,
        "plaintext_material_persisted": false,
        "plaintext_material_returned": false,
        "record_dir": "vault-refs",
        "record_id": string_field_any(record, &["record_id", "id"]),
        "operation_kind": string_field(record, "operation_kind"),
        "source": "agentgres_vault_control_record",
        "rust_core_boundary": "model_mount.vault_projection",
        "vault_projection_boundary": "model_mount.vault_projection",
        "wallet_authority_boundary": string_field(record, "wallet_authority_boundary"),
        "ctee_custody_boundary": string_field(record, "ctee_custody_boundary"),
        "authority_hash": string_field(vault_authority, "authority_hash"),
        "control_hash": string_field(record, "control_hash"),
        "created_at": string_field(record, "planned_at"),
        "updated_at": string_field(record, "planned_at"),
        "receipt_refs": json_array_field(record, "receipt_refs"),
        "evidence_refs": custody_projection_evidence_refs(
            record,
            "rust_daemon_core_vault_ref_projection",
            "agentgres_vault_ref_replay_required",
            "model_mount_vault_ref_js_projection_retired",
        ),
    })
}

fn custody_projection_evidence_refs(
    record: &Value,
    projection_evidence: &str,
    replay_evidence: &str,
    retired_evidence: &str,
) -> Vec<String> {
    let mut refs = evidence_refs(record);
    for required in [projection_evidence, replay_evidence, retired_evidence] {
        if !refs.iter().any(|value| value == required) {
            refs.push(required.to_string());
        }
    }
    refs
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn string_field_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .map(|key| string_field(value, key))
        .find(|value| !value.is_empty())
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
                .collect()
        })
        .unwrap_or_default()
}

fn json_array_field(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(state_dir: Option<String>) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "authority_snapshot".to_string(),
            schema_version: None,
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

    fn write_records(state_dir: &Path, record_dir: &str, records: &[Value]) {
        let dir = state_dir.join(record_dir);
        fs::create_dir_all(&dir).expect("record dir");
        for record in records {
            let id = string_field(record, "id");
            fs::write(
                dir.join(format!("{id}.json")),
                serde_json::to_string_pretty(record).expect("record json"),
            )
            .expect("write record");
        }
    }

    #[test]
    fn custody_projection_replays_tokens_and_vault_refs_and_filters_js_truth() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_records(
            temp.path(),
            "capability-tokens",
            &[
                json!({
                    "id": "legacy-token",
                    "object": "ioi.model_mount_capability_token_control",
                    "operation_kind": "model_mount.capability_token.create",
                    "token_id": "capability_token:legacy",
                    "token_hash": "sha256:legacy",
                    "rust_core_boundary": "daemon_js",
                    "evidence_refs": ["legacy_js_token_truth"]
                }),
                json!({
                    "id": "token-create",
                    "record_id": "token-create",
                    "object": "ioi.model_mount_capability_token_control",
                    "operation_kind": "model_mount.capability_token.create",
                    "token_id": "capability_token:active",
                    "token_hash": "sha256:active",
                    "rust_core_boundary": "model_mount.capability_token",
                    "wallet_authority_boundary": "wallet.network.capability_token",
                    "capability_token_authority": {
                        "authority_hash": "sha256:token-authority",
                        "audience": "hypervisor-session",
                        "grant_id": "grant://wallet/capability",
                        "allowed_scopes": ["model.chat:*"],
                        "denied_scopes": ["shell.exec"]
                    },
                    "public_response": {
                        "object": "ioi.model_mount_capability_token",
                        "status": "issued",
                        "token_id": "capability_token:active",
                        "token": "ioi_mnt_secret"
                    },
                    "receipt_refs": ["receipt://token/create"],
                    "evidence_refs": [
                        "rust_daemon_core_capability_token_control",
                        "wallet_network_capability_token_authority_required",
                        "agentgres_capability_token_truth_required",
                        "public_capability_token_js_facade_retired"
                    ],
                    "control_hash": "sha256:token-control",
                    "planned_at": "2026-06-13T00:00:01.000Z"
                }),
                json!({
                    "id": "token-revoked-create",
                    "record_id": "token-revoked-create",
                    "object": "ioi.model_mount_capability_token_control",
                    "operation_kind": "model_mount.capability_token.create",
                    "token_id": "capability_token:revoked",
                    "token_hash": "sha256:revoked",
                    "rust_core_boundary": "model_mount.capability_token",
                    "capability_token_authority": {},
                    "public_response": {},
                    "evidence_refs": ["agentgres_capability_token_truth_required"],
                    "planned_at": "2026-06-13T00:00:02.000Z"
                }),
                json!({
                    "id": "token-revoke",
                    "record_id": "token-revoke",
                    "object": "ioi.model_mount_capability_token_control",
                    "operation_kind": "model_mount.capability_token.revoke",
                    "token_id": "capability_token:revoked",
                    "rust_core_boundary": "model_mount.capability_token",
                    "evidence_refs": ["agentgres_capability_token_truth_required"],
                    "planned_at": "2026-06-13T00:00:03.000Z"
                }),
            ],
        );
        write_records(
            temp.path(),
            "vault-refs",
            &[
                json!({
                    "id": "legacy-vault",
                    "object": "ioi.model_mount_vault_control",
                    "operation_kind": "model_mount.vault_ref.bind",
                    "vault_ref_hash": "legacy",
                    "rust_core_boundary": "daemon_js",
                    "evidence_refs": ["legacy_js_vault_truth"]
                }),
                json!({
                    "id": "vault-bind",
                    "record_id": "vault-bind",
                    "object": "ioi.model_mount_vault_control",
                    "operation_kind": "model_mount.vault_ref.bind",
                    "vault_ref_hash": "vault-hash-active",
                    "material_hash": "sha256:material",
                    "rust_core_boundary": "model_mount.vault",
                    "wallet_authority_boundary": "wallet.network.vault",
                    "ctee_custody_boundary": "ctee.vault_custody",
                    "vault_authority": {"authority_hash": "sha256:vault-authority"},
                    "ctee_custody": {
                        "custody_ref": "ctee://vault/active",
                        "plaintext_material_persisted": false,
                        "plaintext_material_returned": false
                    },
                    "public_response": {
                        "vault_ref_hash": "vault-hash-active",
                        "label": "Active vault",
                        "purpose": "provider.auth",
                        "vault_ref": {"redacted": true, "hash": "vault-hash-active"}
                    },
                    "receipt_refs": ["receipt://vault/bind"],
                    "evidence_refs": [
                        "rust_daemon_core_vault_control",
                        "wallet_network_vault_authority_required",
                        "ctee_vault_custody_enforced",
                        "agentgres_vault_truth_required",
                        "public_vault_js_facade_retired"
                    ],
                    "control_hash": "sha256:vault-control",
                    "planned_at": "2026-06-13T00:00:04.000Z"
                }),
                json!({
                    "id": "vault-removed-bind",
                    "record_id": "vault-removed-bind",
                    "object": "ioi.model_mount_vault_control",
                    "operation_kind": "model_mount.vault_ref.bind",
                    "vault_ref_hash": "vault-hash-removed",
                    "rust_core_boundary": "model_mount.vault",
                    "public_response": {"vault_ref_hash": "vault-hash-removed"},
                    "evidence_refs": ["agentgres_vault_truth_required"],
                    "planned_at": "2026-06-13T00:00:05.000Z"
                }),
                json!({
                    "id": "vault-remove",
                    "record_id": "vault-remove",
                    "object": "ioi.model_mount_vault_control",
                    "operation_kind": "model_mount.vault_ref.remove",
                    "vault_ref_hash": "vault-hash-removed",
                    "rust_core_boundary": "model_mount.vault",
                    "evidence_refs": ["agentgres_vault_truth_required"],
                    "planned_at": "2026-06-13T00:00:06.000Z"
                }),
            ],
        );

        let request = request(Some(temp.path().to_string_lossy().to_string()));
        let tokens = capability_token_records(&request).expect("capability tokens");
        let vault_refs = vault_ref_records(&request).expect("vault refs");

        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0]["token_id"], "capability_token:active");
        assert_eq!(tokens[0].get("token"), None);
        assert_eq!(
            tokens[0]["capability_token_projection_boundary"],
            "model_mount.capability_token_projection"
        );
        assert!(tokens[0]["evidence_refs"]
            .as_array()
            .expect("token evidence")
            .iter()
            .any(|value| value == "agentgres_capability_token_replay_required"));
        assert_eq!(vault_refs.len(), 1);
        assert_eq!(vault_refs[0]["vault_ref_hash"], "vault-hash-active");
        assert_eq!(vault_refs[0]["plaintext_material_returned"], false);
        assert_eq!(
            vault_refs[0]["vault_projection_boundary"],
            "model_mount.vault_projection"
        );
        assert!(vault_refs[0]["evidence_refs"]
            .as_array()
            .expect("vault evidence")
            .iter()
            .any(|value| value == "agentgres_vault_ref_replay_required"));
    }
}
