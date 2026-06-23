use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{fs, path::Path};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountCapabilityTokenControlRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,
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
pub struct ModelMountCapabilityTokenControlPlan {
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
struct CapabilityTokenRecord {
    token_id: String,
    token_hash: String,
    audience: Option<String>,
    grant_id: Option<String>,
    created_at: Option<String>,
    allowed_scopes: Vec<String>,
    denied_scopes: Vec<String>,
    revoked: bool,
}

impl ModelMountCapabilityTokenControlRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !capability_token_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedCapabilityTokenControlOperation);
        }
        option_string(&self.state_dir, "state_dir")?;
        match self.operation_kind.as_str() {
            "model_mount.capability_token.authorize" => {
                option_string(&self.token_hash, "token_hash")?;
                option_string(&self.required_scope, "required_scope")?;
            }
            "model_mount.capability_token.revoke" => {
                option_string(&self.token_id, "token_id")?;
            }
            "model_mount.capability_token.list" => {}
            _ => {}
        }
        Ok(())
    }
}

pub(super) fn plan_capability_token_control(
    request: &ModelMountCapabilityTokenControlRequest,
) -> Result<ModelMountCapabilityTokenControlPlan, ModelMountError> {
    request.validate()?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let body = object_or_empty(&request.body);
    let source = source_for(request);
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let existing_tokens = load_capability_tokens(request.state_dir.as_deref())?;
    let body_hash = hash_json(&request.body)?;
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let mut token_id = request
        .token_id
        .as_ref()
        .and_then(|value| non_empty_string(value));
    let token_hash = request
        .token_hash
        .as_ref()
        .and_then(|value| non_empty_string(value));
    let (record_public_response, response_public_response): (Value, Value);
    let mut allowed_scopes = Vec::new();
    let mut denied_scopes = Vec::new();
    let mut grant_id = None;
    let mut audience = None;
    let mut minted_token_hash = token_hash.clone();

    match operation_kind.as_str() {
        "model_mount.capability_token.create" => {
            audience = string_field(body, "audience");
            grant_id = string_field(body, "grant_id");
            allowed_scopes = string_array_field(body, "allowed")
                .into_iter()
                .chain(string_array_field(body, "allowed_scopes"))
                .collect();
            denied_scopes = string_array_field(body, "denied")
                .into_iter()
                .chain(string_array_field(body, "denied_scopes"))
                .collect();
            let create_seed = json!({
                "operation_kind": operation_kind,
                "body_hash": body_hash,
                "source": source,
                "generated_at": generated_at,
                "authority_grant_refs": authority_grant_refs,
                "authority_receipt_refs": authority_receipt_refs,
            });
            let create_hash = hash_json(&create_seed)?;
            let minted = format!("ioi_mnt_{}", &create_hash[..32]);
            token_id = Some(format!("capability_token:{}", &create_hash[..16]));
            minted_token_hash = Some(sha256_hex(minted.as_bytes())?);
            record_public_response = json!({
                "object": "ioi.model_mount_capability_token",
                "status": "issued",
                "token_id": token_id,
                "token_material_returned_once": true,
                "plaintext_material_persisted": false,
                "token_hash": minted_token_hash,
                "audience": audience,
                "grant_id": grant_id,
                "allowed_scopes": allowed_scopes,
                "denied_scopes": denied_scopes,
            });
            response_public_response = json!({
                "object": "ioi.model_mount_capability_token",
                "status": "issued",
                "token_id": token_id,
                "token": minted,
                "token_material_returned_once": true,
                "token_hash": minted_token_hash,
                "audience": audience,
                "grant_id": grant_id,
                "allowed_scopes": allowed_scopes,
                "denied_scopes": denied_scopes,
            });
        }
        "model_mount.capability_token.list" => {
            let tokens = public_token_list(&existing_tokens);
            record_public_response = json!({
                "object": "ioi.model_mount_capability_token_list",
                "status": "projected",
                "plaintext_material_persisted": false,
                "tokens": tokens,
            });
            response_public_response = record_public_response.clone();
        }
        "model_mount.capability_token.authorize" => {
            let token = existing_tokens
                .iter()
                .find(|candidate| {
                    !candidate.revoked
                        && Some(candidate.token_hash.as_str()) == token_hash.as_deref()
                })
                .ok_or(ModelMountError::CapabilityTokenUnauthorized)?;
            let required_scope = option_string(&request.required_scope, "required_scope")?;
            if !scope_authorized(&required_scope, &token.allowed_scopes, &token.denied_scopes) {
                return Err(ModelMountError::CapabilityTokenUnauthorized);
            }
            token_id = Some(token.token_id.clone());
            grant_id = token.grant_id.clone();
            audience = token.audience.clone();
            allowed_scopes = token.allowed_scopes.clone();
            denied_scopes = token.denied_scopes.clone();
            record_public_response = json!({
                "object": "ioi.model_mount_capability_token_authorization",
                "status": "authorized",
                "token_id": token.token_id,
                "required_scope": required_scope,
                "grant_id": token.grant_id,
                "audience": token.audience,
                "plaintext_material_persisted": false,
            });
            response_public_response = record_public_response.clone();
        }
        "model_mount.capability_token.revoke" => {
            let requested_token_id = option_string(&request.token_id, "token_id")?;
            let token = existing_tokens
                .iter()
                .find(|candidate| !candidate.revoked && candidate.token_id == requested_token_id)
                .ok_or(ModelMountError::CapabilityTokenNotFound)?;
            token_id = Some(token.token_id.clone());
            minted_token_hash = Some(token.token_hash.clone());
            grant_id = token.grant_id.clone();
            audience = token.audience.clone();
            allowed_scopes = token.allowed_scopes.clone();
            denied_scopes = token.denied_scopes.clone();
            record_public_response = json!({
                "object": "ioi.model_mount_capability_token_revocation",
                "status": "revoked",
                "token_id": token.token_id,
                "grant_id": token.grant_id,
                "plaintext_material_persisted": false,
            });
            response_public_response = record_public_response.clone();
        }
        _ => return Err(ModelMountError::UnsupportedCapabilityTokenControlOperation),
    }

    let authority_seed = json!({
        "operation_kind": operation_kind,
        "token_id": token_id,
        "token_hash": minted_token_hash,
        "required_scope": request.required_scope,
        "body_hash": body_hash,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
    });
    let authority_hash = format!("sha256:{}", hash_json(&authority_seed)?);
    let control_seed = json!({
        "schema_version": request.schema_version,
        "operation_kind": operation_kind,
        "token_id": token_id,
        "token_hash": minted_token_hash,
        "required_scope": request.required_scope,
        "source": source,
        "body_hash": body_hash,
        "authority_hash": authority_hash,
    });
    let control_hash = hash_json(&control_seed)?;
    let record_id = format!(
        "capability_token_control:{}:{}",
        safe_segment(token_id.as_deref().unwrap_or("all")),
        &control_hash[..16]
    );
    let mut receipt_refs = receipt_refs_for(request);
    push_unique_ref(
        &mut receipt_refs,
        format!("receipt://model_mount/capability_token/{record_id}").as_str(),
    );
    let evidence_refs = capability_token_control_evidence_refs();
    let record = json!({
        "id": record_id,
        "record_id": record_id,
        "schema_version": MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
        "object": "ioi.model_mount_capability_token_control",
        "status": "planned",
        "operation_kind": operation_kind,
        "source": source,
        "token_id": token_id,
        "token_hash": minted_token_hash,
        "body_hash": format!("sha256:{body_hash}"),
        "request_field_count": body.len(),
        "rust_core_boundary": "model_mount.capability_token",
        "authority_boundary": "wallet.network.capability_token",
        "authority_provider_ref": "wallet.network",
        "wallet_authority_boundary": "wallet.network.capability_token",
        "capability_token_authority": {
            "authority_hash": authority_hash,
            "grant_id": grant_id,
            "audience": audience,
            "required_scope": request.required_scope,
            "allowed_scopes": allowed_scopes,
            "denied_scopes": denied_scopes,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
        },
        "public_response": record_public_response,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "planned_at": generated_at,
    });
    Ok(ModelMountCapabilityTokenControlPlan {
        schema_version: MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_capability_token_control_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.capability_token".to_string(),
        operation_kind,
        source,
        record_dir: "capability-tokens".to_string(),
        record_id,
        record,
        public_response: response_public_response,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        control_hash,
        authority_hash,
    })
}

fn capability_token_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.capability_token.create"
            | "model_mount.capability_token.list"
            | "model_mount.capability_token.authorize"
            | "model_mount.capability_token.revoke"
    )
}

fn capability_token_control_evidence_refs() -> Vec<String> {
    vec![
        "rust_daemon_core_capability_token_control".to_string(),
        "wallet_network_capability_token_authority_required".to_string(),
        "agentgres_capability_token_truth_required".to_string(),
        "public_capability_token_js_facade_retired".to_string(),
    ]
}

fn load_capability_tokens(
    state_dir: Option<&str>,
) -> Result<Vec<CapabilityTokenRecord>, ModelMountError> {
    let Some(state_dir) = state_dir.and_then(non_empty_string) else {
        return Ok(Vec::new());
    };
    let dir = Path::new(&state_dir).join("capability-tokens");
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut creates = Vec::new();
    let mut revoked = Vec::new();
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
        if value.get("rust_core_boundary").and_then(Value::as_str)
            != Some("model_mount.capability_token")
        {
            continue;
        }
        let operation = value.get("operation_kind").and_then(Value::as_str);
        let token_id = value
            .get("token_id")
            .and_then(Value::as_str)
            .and_then(non_empty_string);
        if operation == Some("model_mount.capability_token.revoke") {
            if let Some(token_id) = token_id {
                revoked.push(token_id);
            }
            continue;
        }
        if operation != Some("model_mount.capability_token.create") {
            continue;
        }
        let Some(token_id) = token_id else {
            continue;
        };
        let Some(token_hash) = value
            .get("token_hash")
            .and_then(Value::as_str)
            .and_then(non_empty_string)
        else {
            continue;
        };
        let authority = value
            .get("capability_token_authority")
            .and_then(Value::as_object);
        creates.push(CapabilityTokenRecord {
            token_id,
            token_hash,
            audience: authority
                .and_then(|map| string_field(map, "audience"))
                .or_else(|| string_field(value.as_object().unwrap_or(empty_map()), "audience")),
            grant_id: authority.and_then(|map| string_field(map, "grant_id")),
            created_at: value
                .get("planned_at")
                .and_then(Value::as_str)
                .and_then(non_empty_string),
            allowed_scopes: authority
                .map(|map| string_array_field(map, "allowed_scopes"))
                .unwrap_or_default(),
            denied_scopes: authority
                .map(|map| string_array_field(map, "denied_scopes"))
                .unwrap_or_default(),
            revoked: false,
        });
    }
    for token in &mut creates {
        token.revoked = revoked.iter().any(|token_id| token_id == &token.token_id);
    }
    Ok(creates)
}

fn public_token_list(tokens: &[CapabilityTokenRecord]) -> Vec<Value> {
    let mut values = tokens
        .iter()
        .filter(|token| !token.revoked)
        .map(|token| {
            json!({
                "id": token.token_id,
                "token_id": token.token_id,
                "object": "ioi.model_mount_capability_token",
                "status": "active",
                "audience": token.audience,
                "grant_id": token.grant_id,
                "created_at": token.created_at,
                "allowed_scopes": token.allowed_scopes,
                "denied_scopes": token.denied_scopes,
                "token_hash": token.token_hash,
            })
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| {
        left.get("token_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(
                right
                    .get("token_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
    });
    values
}

fn scope_authorized(required_scope: &str, allowed: &[String], denied: &[String]) -> bool {
    if denied
        .iter()
        .any(|pattern| scope_matches(required_scope, pattern.as_str()))
    {
        return false;
    }
    allowed
        .iter()
        .any(|pattern| scope_matches(required_scope, pattern.as_str()))
}

fn scope_matches(scope: &str, pattern: &str) -> bool {
    if pattern == scope {
        return true;
    }
    pattern
        .strip_suffix('*')
        .is_some_and(|prefix| scope.starts_with(prefix))
}

fn source_for(request: &ModelMountCapabilityTokenControlRequest) -> String {
    request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "runtime-daemon.model_mounting.capability_token_control".to_string())
}

fn receipt_refs_for(request: &ModelMountCapabilityTokenControlRequest) -> Vec<String> {
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

fn string_array_field(map: &Map<String, Value>, field: &str) -> Vec<String> {
    map.get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(non_empty_string)
                .collect()
        })
        .unwrap_or_default()
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

    fn request(operation_kind: &str) -> ModelMountCapabilityTokenControlRequest {
        ModelMountCapabilityTokenControlRequest {
            schema_version: MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: operation_kind.to_string(),
            token_id: None,
            token_hash: None,
            required_scope: None,
            source: Some("test.capability_token_control".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
            state_dir: Some("/tmp/ioi-model-mount-state".to_string()),
            body: json!({
                "audience": "hypervisor-session",
                "allowed": ["model.chat:*"],
                "denied": ["shell.exec"],
                "grant_id": "grant://wallet/capability"
            }),
            receipt_refs: vec![],
            authority_grant_refs: vec!["grant://wallet/capability".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/capability".to_string()],
        }
    }

    #[test]
    fn rust_core_plans_capability_token_control_direct_api() {
        let plan = plan_capability_token_control(&request("model_mount.capability_token.create"))
            .expect("capability token plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.record_dir, "capability-tokens");
        assert_eq!(plan.rust_core_boundary, "model_mount.capability_token");
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_capability_token_control".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"wallet_network_capability_token_authority_required".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_capability_token_truth_required".to_string()));
        assert_eq!(
            plan.receipt_refs,
            vec![
                "receipt://wallet/capability".to_string(),
                format!("receipt://model_mount/capability_token/{}", plan.record_id)
            ]
        );
        assert_eq!(plan.record["public_response"]["status"], "issued");
        assert_eq!(
            plan.record["public_response"]["plaintext_material_persisted"],
            false
        );
        assert_eq!(
            plan.record["capability_token_authority"]["allowed_scopes"][0],
            "model.chat:*"
        );
        assert_eq!(plan.record["public_response"].get("token"), None);
        assert!(plan.public_response["token"]
            .as_str()
            .unwrap()
            .starts_with("ioi_mnt_"));
    }

    #[test]
    fn rust_core_rejects_capability_token_control_without_state_dir() {
        let mut invalid = request("model_mount.capability_token.create");
        invalid.state_dir = None;

        assert_eq!(
            plan_capability_token_control(&invalid).unwrap_err(),
            ModelMountError::MissingField("state_dir")
        );
    }
}
