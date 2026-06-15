use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, fs, path::Path};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_VAULT_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountVaultControlRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountVaultControlPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub public_response: Value,
    pub receipt_refs: Vec<String>,
    pub authority_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub control_hash: String,
    pub authority_hash: String,
}

#[derive(Debug, Clone)]
struct VaultRefRecord {
    vault_ref_hash: String,
    label: Option<String>,
    purpose: Option<String>,
    material_hash: Option<String>,
    custody_ref: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

impl ModelMountVaultControlRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !vault_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedVaultControlOperation);
        }
        match self.operation_kind.as_str() {
            "model_mount.vault_ref.bind" => {
                option_string(&self.vault_ref, "vault_ref")?;
                option_string(&self.material_hash, "material_hash")?;
            }
            "model_mount.vault_ref.metadata" | "model_mount.vault_ref.remove" => {
                option_string(&self.vault_ref, "vault_ref")?;
            }
            _ => {}
        }
        Ok(())
    }
}

pub(super) fn plan_vault_control(
    request: &ModelMountVaultControlRequest,
) -> Result<ModelMountVaultControlPlan, ModelMountError> {
    request.validate()?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let body = object_or_empty(&request.body);
    let source = source_for(request);
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let existing_refs = load_vault_refs(request.state_dir.as_deref());
    let body_hash = hash_json(&request.body)?;
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let mut vault_ref_hash = request
        .vault_ref
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .map(|value| sha256_hex(value.as_bytes()))
        .transpose()?;
    let mut material_hash = request
        .material_hash
        .as_ref()
        .and_then(|value| non_empty_string(value));
    let mut label = string_field(body, "label");
    let mut purpose = string_field(body, "purpose");
    let mut custody_ref = request
        .custody_ref
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| string_field(body, "custody_ref"));
    let public_response: Value;

    match operation_kind.as_str() {
        "model_mount.vault_ref.bind" => {
            let vault_ref = option_string(&request.vault_ref, "vault_ref")?;
            vault_ref_hash = Some(sha256_hex(vault_ref.as_bytes())?);
            material_hash = Some(option_string(&request.material_hash, "material_hash")?);
            purpose = purpose.or_else(|| Some("operator_provider_auth_binding".to_string()));
            custody_ref = custody_ref.or_else(|| {
                Some(format!(
                    "ctee://vault-ref/{}",
                    vault_ref_hash.as_deref().unwrap_or("unknown")
                ))
            });
            public_response = public_vault_ref_response(json!({
                "status": "bound",
                "vault_ref_hash": vault_ref_hash,
                "label": label,
                "purpose": purpose,
                "material_hash": material_hash,
                "custody_ref": custody_ref,
                "configured": true,
                "material_bound": true,
                "resolved_material": false,
                "requires_rebind": false,
                "created_at": generated_at,
                "updated_at": generated_at,
            }));
        }
        "model_mount.vault_ref.list" => {
            public_response = json!({
                "object": "ioi.model_mount_vault_ref_list",
                "status": "projected",
                "vault_refs": public_vault_ref_list(&existing_refs),
                "count": existing_refs.len(),
                "plaintext_material_persisted": false,
                "plaintext_material_returned": false,
            });
        }
        "model_mount.vault_ref.metadata" => {
            let vault_ref = option_string(&request.vault_ref, "vault_ref")?;
            let hash = sha256_hex(vault_ref.as_bytes())?;
            vault_ref_hash = Some(hash.clone());
            let existing = existing_refs
                .iter()
                .find(|record| record.vault_ref_hash == hash);
            if let Some(existing) = existing {
                label = existing.label.clone();
                purpose = existing.purpose.clone();
                material_hash = existing.material_hash.clone();
                custody_ref = existing.custody_ref.clone();
                public_response = public_vault_ref_response(json!({
                    "status": "projected",
                    "vault_ref_hash": existing.vault_ref_hash,
                    "label": existing.label,
                    "purpose": existing.purpose,
                    "material_hash": existing.material_hash,
                    "custody_ref": existing.custody_ref,
                    "configured": true,
                    "material_bound": true,
                    "resolved_material": false,
                    "requires_rebind": false,
                    "created_at": existing.created_at,
                    "updated_at": existing.updated_at,
                }));
            } else {
                public_response = public_vault_ref_response(json!({
                    "status": "missing",
                    "vault_ref_hash": hash,
                    "label": null,
                    "purpose": "lookup",
                    "material_hash": null,
                    "custody_ref": null,
                    "configured": false,
                    "material_bound": false,
                    "resolved_material": false,
                    "requires_rebind": false,
                    "created_at": null,
                    "updated_at": generated_at,
                }));
            }
        }
        "model_mount.vault.status" => {
            public_response = json!({
                "object": "ioi.model_mount_vault_status",
                "status": "available",
                "implementation": "rust_daemon_core_vault_control",
                "configured": true,
                "record_count": existing_refs.len(),
                "storage_backend": "agentgres_model_mount_record_state",
                "plaintext_material_persisted": false,
                "plaintext_material_returned": false,
                "wallet_authority_boundary": "wallet.network.vault",
                "ctee_custody_boundary": "ctee.vault_custody",
            });
        }
        "model_mount.vault.health" => {
            public_response = json!({
                "object": "ioi.model_mount_vault_health",
                "status": "healthy",
                "read_available": request.state_dir.as_ref().and_then(|value| non_empty_string(value)).is_some(),
                "write_available": true,
                "record_count": existing_refs.len(),
                "plaintext_material_persisted": false,
                "plaintext_material_returned": false,
                "checked_at": generated_at,
                "wallet_authority_boundary": "wallet.network.vault",
                "ctee_custody_boundary": "ctee.vault_custody",
            });
        }
        "model_mount.vault_ref.remove" => {
            let vault_ref = option_string(&request.vault_ref, "vault_ref")?;
            let hash = sha256_hex(vault_ref.as_bytes())?;
            vault_ref_hash = Some(hash.clone());
            let existing = existing_refs
                .iter()
                .find(|record| record.vault_ref_hash == hash);
            label = existing.and_then(|record| record.label.clone()).or(label);
            purpose = purpose
                .or_else(|| existing.and_then(|record| record.purpose.clone()))
                .or_else(|| Some("operator_provider_auth_remove".to_string()));
            material_hash = existing.and_then(|record| record.material_hash.clone());
            custody_ref = existing.and_then(|record| record.custody_ref.clone());
            public_response = public_vault_ref_response(json!({
                "status": "removed",
                "vault_ref_hash": hash,
                "label": label,
                "purpose": purpose,
                "material_hash": material_hash,
                "custody_ref": custody_ref,
                "configured": false,
                "material_bound": false,
                "resolved_material": false,
                "requires_rebind": false,
                "created_at": existing.and_then(|record| record.created_at.clone()),
                "updated_at": generated_at,
            }));
        }
        _ => return Err(ModelMountError::UnsupportedVaultControlOperation),
    }

    let authority_seed = json!({
        "operation_kind": operation_kind,
        "vault_ref_hash": vault_ref_hash,
        "label": label,
        "material_hash": material_hash,
        "custody_ref": custody_ref,
        "body_hash": body_hash,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
    });
    let authority_hash = format!("sha256:{}", hash_json(&authority_seed)?);
    let control_seed = json!({
        "schema_version": request.schema_version,
        "operation_kind": operation_kind,
        "vault_ref_hash": vault_ref_hash,
        "material_hash": material_hash,
        "source": source,
        "body_hash": body_hash,
        "authority_hash": authority_hash,
    });
    let control_hash = hash_json(&control_seed)?;
    let record_id = format!(
        "vault_control:{}:{}",
        safe_segment(vault_ref_hash.as_deref().unwrap_or("all")),
        &control_hash[..16]
    );
    let mut receipt_refs = receipt_refs_for(request);
    push_unique_ref(
        &mut receipt_refs,
        format!("receipt://model_mount/vault/{record_id}").as_str(),
    );
    let evidence_refs = vault_control_evidence_refs();
    let record = json!({
        "id": record_id,
        "record_id": record_id,
        "schema_version": MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION,
        "object": "ioi.model_mount_vault_control",
        "status": "planned",
        "operation_kind": operation_kind,
        "source": source,
        "vault_ref_hash": vault_ref_hash,
        "material_hash": material_hash,
        "body_hash": format!("sha256:{body_hash}"),
        "request_field_count": body.len(),
        "rust_core_boundary": "model_mount.vault",
        "wallet_authority_boundary": "wallet.network.vault",
        "ctee_custody_boundary": "ctee.vault_custody",
        "vault_authority": {
            "authority_hash": authority_hash,
            "vault_ref_hash": vault_ref_hash,
            "label": label,
            "material_hash": material_hash,
            "purpose": purpose,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
        },
        "ctee_custody": {
            "custody_ref": custody_ref,
            "plaintext_material_persisted": false,
            "plaintext_material_returned": false,
            "material_hash": material_hash,
        },
        "public_response": public_response,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "planned_at": generated_at,
    });
    Ok(ModelMountVaultControlPlan {
        schema_version: MODEL_MOUNT_VAULT_CONTROL_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_vault_control_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.vault".to_string(),
        operation_kind,
        source,
        record_dir: "vault-refs".to_string(),
        record_id,
        record,
        public_response,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        control_hash,
        authority_hash,
    })
}

fn vault_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.vault_ref.bind"
            | "model_mount.vault_ref.list"
            | "model_mount.vault_ref.metadata"
            | "model_mount.vault.status"
            | "model_mount.vault.health"
            | "model_mount.vault_ref.remove"
    )
}

fn vault_control_evidence_refs() -> Vec<String> {
    vec![
        "rust_daemon_core_vault_control".to_string(),
        "wallet_network_vault_authority_required".to_string(),
        "ctee_vault_custody_enforced".to_string(),
        "agentgres_vault_truth_required".to_string(),
        "public_vault_js_facade_retired".to_string(),
    ]
}

fn load_vault_refs(state_dir: Option<&str>) -> Vec<VaultRefRecord> {
    let Some(state_dir) = state_dir.and_then(non_empty_string) else {
        return Vec::new();
    };
    let dir = Path::new(&state_dir).join("vault-refs");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut bound = BTreeMap::new();
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if value.get("rust_core_boundary").and_then(Value::as_str) != Some("model_mount.vault") {
            continue;
        }
        let operation = value.get("operation_kind").and_then(Value::as_str);
        let vault_ref_hash = value
            .get("vault_ref_hash")
            .and_then(Value::as_str)
            .and_then(non_empty_string);
        if operation == Some("model_mount.vault_ref.remove") {
            if let Some(vault_ref_hash) = vault_ref_hash {
                removed.push(vault_ref_hash);
            }
            continue;
        }
        if operation != Some("model_mount.vault_ref.bind") {
            continue;
        }
        let Some(vault_ref_hash) = vault_ref_hash else {
            continue;
        };
        let response = if let Some(map) = value.get("public_response").and_then(Value::as_object) {
            map
        } else {
            empty_map()
        };
        let ctee = value.get("ctee_custody").and_then(Value::as_object);
        bound.insert(
            vault_ref_hash.clone(),
            VaultRefRecord {
                vault_ref_hash,
                label: string_field(response, "label"),
                purpose: string_field(response, "purpose"),
                material_hash: value
                    .get("material_hash")
                    .and_then(Value::as_str)
                    .and_then(non_empty_string),
                custody_ref: ctee
                    .and_then(|map| string_field(map, "custody_ref"))
                    .or_else(|| string_field(response, "custody_ref")),
                created_at: value
                    .get("planned_at")
                    .and_then(Value::as_str)
                    .and_then(non_empty_string),
                updated_at: value
                    .get("planned_at")
                    .and_then(Value::as_str)
                    .and_then(non_empty_string),
            },
        );
    }
    for vault_ref_hash in removed {
        bound.remove(&vault_ref_hash);
    }
    bound.into_values().collect()
}

fn public_vault_ref_list(records: &[VaultRefRecord]) -> Vec<Value> {
    records
        .iter()
        .map(|record| {
            public_vault_ref_response(json!({
                "status": "active",
                "vault_ref_hash": record.vault_ref_hash,
                "label": record.label,
                "purpose": record.purpose,
                "material_hash": record.material_hash,
                "custody_ref": record.custody_ref,
                "configured": true,
                "material_bound": true,
                "resolved_material": false,
                "requires_rebind": false,
                "created_at": record.created_at,
                "updated_at": record.updated_at,
            }))
        })
        .collect()
}

fn public_vault_ref_response(mut value: Value) -> Value {
    let object = value.as_object_mut().expect("vault response is object");
    let vault_ref_hash = object
        .get("vault_ref_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    object.insert(
        "object".to_string(),
        Value::String("ioi.model_mount_vault_ref".to_string()),
    );
    object.insert(
        "id".to_string(),
        Value::String(format!("vault_ref.{vault_ref_hash}")),
    );
    object.insert(
        "vault_ref".to_string(),
        json!({ "redacted": true, "hash": vault_ref_hash }),
    );
    object.insert(
        "plaintext_material_persisted".to_string(),
        Value::Bool(false),
    );
    object.insert(
        "plaintext_material_returned".to_string(),
        Value::Bool(false),
    );
    value
}

fn source_for(request: &ModelMountVaultControlRequest) -> String {
    request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "runtime-daemon.model_mounting.vault_control".to_string())
}

fn receipt_refs_for(request: &ModelMountVaultControlRequest) -> Vec<String> {
    let mut refs = Vec::new();
    for value in &request.receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    for value in &request.authority_receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    refs
}

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| non_empty_string(value))
        .collect()
}

fn option_string(value: &Option<String>, field: &'static str) -> Result<String, ModelMountError> {
    value
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .ok_or(ModelMountError::MissingField(field))
}

fn object_or_empty(value: &Value) -> &Map<String, Value> {
    if let Some(map) = value.as_object() {
        map
    } else {
        empty_map()
    }
}

fn empty_map() -> &'static Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

fn string_field(map: &Map<String, Value>, field: &str) -> Option<String> {
    map.get(field)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn safe_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    sha256_hex(
        &serde_json::to_vec(value)
            .map_err(|error| ModelMountError::HashFailed(error.to_string()))?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation_kind: &str) -> ModelMountVaultControlRequest {
        ModelMountVaultControlRequest {
            schema_version: MODEL_MOUNT_VAULT_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: operation_kind.to_string(),
            vault_ref: Some("vault://provider/custom/api-key".to_string()),
            material_hash: Some("sha256:material".to_string()),
            custody_ref: Some("ctee://vault/custom".to_string()),
            source: Some("test.vault_control".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
            state_dir: None,
            body: json!({
                "label": "Custom auth",
                "purpose": "provider.auth:custom",
                "custody_ref": "ctee://vault/custom"
            }),
            receipt_refs: vec![],
            authority_grant_refs: vec!["grant://wallet/vault".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/vault".to_string()],
        }
    }

    #[test]
    fn rust_core_plans_vault_control_direct_api() {
        let plan =
            plan_vault_control(&request("model_mount.vault_ref.bind")).expect("vault control plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_VAULT_CONTROL_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.record_dir, "vault-refs");
        assert_eq!(plan.rust_core_boundary, "model_mount.vault");
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_vault_control".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"ctee_vault_custody_enforced".to_string()));
        assert_eq!(
            plan.record["public_response"]["plaintext_material_persisted"],
            false
        );
        assert_eq!(
            plan.record["ctee_custody"]["plaintext_material_returned"],
            false
        );
        assert_eq!(plan.record["public_response"].get("material"), None);
        assert_eq!(plan.public_response.get("material"), None);
        assert_eq!(plan.record["public_response"]["status"], "bound");
        assert_eq!(plan.record["public_response"]["label"], "Custom auth");
    }

    #[test]
    fn rust_core_rejects_vault_bind_without_material_hash() {
        let mut invalid = request("model_mount.vault_ref.bind");
        invalid.material_hash = None;

        assert_eq!(
            plan_vault_control(&invalid).unwrap_err(),
            ModelMountError::MissingField("material_hash")
        );
    }
}
