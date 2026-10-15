use rand::{rngs::OsRng, RngCore};
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

/// Marks a token record minted from the OS RNG. Records without it were derived and are not honoured.
const CAPABILITY_TOKEN_ENTROPY: &str = "os_rng_256_v1";

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Equality that reads every byte of both sides whatever the first difference.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
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
            // The token is 256 bits from the OS RNG and nothing else; the public token_id is drawn
            // separately, so the id discloses nothing of the token.
            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            let minted = format!("ioi_mnt_{}", hex_lower(&secret));
            let mut id_material = [0u8; 16];
            OsRng.fill_bytes(&mut id_material);
            token_id = Some(format!("capability_token:{}", hex_lower(&id_material)));
            minted_token_hash = Some(sha256_hex(minted.as_bytes())?);
            record_public_response = json!({
                "object": "ioi.model_mount_capability_token",
                "status": "issued",
                "token_id": token_id,
                "token_material_returned_once": true,
                "plaintext_material_persisted": false,
                "token_entropy": CAPABILITY_TOKEN_ENTROPY,
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
            // Every stored hash is compared in constant time and the scan never exits early, so the
            // time taken says nothing about which stored token a presented value is close to.
            let presented = token_hash.as_deref().unwrap_or_default().as_bytes();
            let mut matched: Option<&CapabilityTokenRecord> = None;
            for candidate in &existing_tokens {
                let equal = constant_time_eq(candidate.token_hash.as_bytes(), presented);
                if equal & !candidate.revoked & matched.is_none() {
                    matched = Some(candidate);
                }
            }
            let token = matched.ok_or(ModelMountError::CapabilityTokenUnauthorized)?;
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
        "token_entropy": if operation_kind == "model_mount.capability_token.create" { json!(CAPABILITY_TOKEN_ENTROPY) } else { Value::Null },
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
        // A token minted before tokens were random (derived from non-secret inputs) is not honoured.
        if value.get("token_entropy").and_then(Value::as_str) != Some(CAPABILITY_TOKEN_ENTROPY) {
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

    fn scratch_state() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ioi-capability-token-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(dir.join("capability-tokens")).unwrap();
        dir
    }

    fn create_in(state: &Path) -> ModelMountCapabilityTokenControlPlan {
        let mut create = request("model_mount.capability_token.create");
        create.state_dir = Some(state.to_string_lossy().to_string());
        let plan = plan_capability_token_control(&create).expect("create");
        fs::write(
            state
                .join("capability-tokens")
                .join(format!("{}.json", plan.record_id.replace(':', "_"))),
            serde_json::to_vec(&plan.record).unwrap(),
        )
        .unwrap();
        plan
    }

    fn authorize_in(
        state: &Path,
        token: &str,
    ) -> Result<ModelMountCapabilityTokenControlPlan, ModelMountError> {
        let mut authorize = request("model_mount.capability_token.authorize");
        authorize.state_dir = Some(state.to_string_lossy().to_string());
        authorize.token_hash = Some(sha256_hex(token.as_bytes()).unwrap());
        authorize.required_scope = Some("model.chat:hello".to_string());
        plan_capability_token_control(&authorize)
    }

    #[test]
    fn two_creates_with_identical_inputs_mint_different_tokens_and_ids() {
        let state = scratch_state();
        let first = create_in(&state);
        let second = create_in(&state);
        assert_ne!(
            first.public_response["token"],
            second.public_response["token"]
        );
        assert_ne!(
            first.public_response["token_id"],
            second.public_response["token_id"]
        );
        // And neither is the old derivation of its inputs.
        let seed = json!({
            "operation_kind": "model_mount.capability_token.create",
            "body_hash": hash_json(&request("x").body).unwrap(),
            "source": "test.capability_token_control",
            "generated_at": "2026-06-13T12:00:00.000Z",
            "authority_grant_refs": ["grant://wallet/capability"],
            "authority_receipt_refs": ["receipt://wallet/capability"],
        });
        let derived = format!("ioi_mnt_{}", &hash_json(&seed).unwrap()[..32]);
        assert_ne!(first.public_response["token"].as_str().unwrap(), derived);
    }

    #[test]
    fn the_token_is_256_random_bits_and_its_id_is_independent_of_it() {
        let state = scratch_state();
        let plan = create_in(&state);
        let token = plan.public_response["token"].as_str().unwrap();
        let hex = token.strip_prefix("ioi_mnt_").unwrap();
        assert_eq!(hex.len(), 64);
        let id = plan.public_response["token_id"].as_str().unwrap();
        let id_hex = id.strip_prefix("capability_token:").unwrap();
        assert!(!id_hex.is_empty());
        assert!(
            !hex.starts_with(id_hex),
            "the public id is not a prefix of the token"
        );
        assert!(!hex.contains(&id_hex[..id_hex.len().min(16)]));
    }

    #[test]
    fn only_the_exact_token_authorizes() {
        let state = scratch_state();
        let first = create_in(&state);
        let second = create_in(&state);
        for plan in [&first, &second] {
            let token = plan.public_response["token"].as_str().unwrap();
            let granted = authorize_in(&state, token).expect("its own token authorizes");
            assert_eq!(granted.record["token_id"], plan.public_response["token_id"]);
        }
        let mut wrong = first.public_response["token"].as_str().unwrap().to_string();
        let last = wrong.pop().unwrap();
        wrong.push(if last == '0' { '1' } else { '0' });
        assert_eq!(
            authorize_in(&state, &wrong).unwrap_err(),
            ModelMountError::CapabilityTokenUnauthorized
        );
    }

    #[test]
    fn a_token_minted_by_the_old_derivation_does_not_authorize() {
        let state = scratch_state();
        let legacy = "ioi_mnt_00112233445566778899aabbccddeeff";
        let record = json!({
            "operation_kind": "model_mount.capability_token.create",
            "rust_core_boundary": "model_mount.capability_token",
            "token_id": "capability_token:0011223344556677",
            "token_hash": sha256_hex(legacy.as_bytes()).unwrap(),
            "capability_token_authority": {
                "allowed_scopes": ["model.chat:*"], "denied_scopes": [], "audience": "a", "grant_id": "g"
            },
            "planned_at": "2026-06-13T12:00:00.000Z",
        });
        fs::write(
            state.join("capability-tokens").join("legacy.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert_eq!(
            authorize_in(&state, legacy).unwrap_err(),
            ModelMountError::CapabilityTokenUnauthorized
        );
    }

    #[test]
    fn the_list_projection_is_an_explicit_metadata_field_list() {
        let state = scratch_state();
        create_in(&state);
        create_in(&state);
        let mut list = request("model_mount.capability_token.list");
        list.state_dir = Some(state.to_string_lossy().to_string());
        let plan = plan_capability_token_control(&list).expect("list");
        let tokens = plan.public_response["tokens"].as_array().expect("tokens");
        assert_eq!(tokens.len(), 2);
        for token in tokens {
            let mut keys: Vec<&str> = token
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "allowed_scopes",
                    "audience",
                    "created_at",
                    "denied_scopes",
                    "grant_id",
                    "id",
                    "object",
                    "status",
                    "token_id"
                ]
            );
        }
    }

    #[test]
    fn a_revoked_token_is_absent_from_the_list() {
        let state = scratch_state();
        let first = create_in(&state);
        let second = create_in(&state);
        let mut revoke = request("model_mount.capability_token.revoke");
        revoke.state_dir = Some(state.to_string_lossy().to_string());
        revoke.token_id = first.public_response["token_id"]
            .as_str()
            .map(str::to_string);
        let plan = plan_capability_token_control(&revoke).expect("revoke");
        fs::write(
            state
                .join("capability-tokens")
                .join(format!("{}.json", plan.record_id.replace(':', "_"))),
            serde_json::to_vec(&plan.record).unwrap(),
        )
        .unwrap();
        let mut list = request("model_mount.capability_token.list");
        list.state_dir = Some(state.to_string_lossy().to_string());
        let listed = plan_capability_token_control(&list).expect("list");
        let ids: Vec<&str> = listed.public_response["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["token_id"].as_str())
            .collect();
        assert_eq!(
            ids,
            vec![second.public_response["token_id"].as_str().unwrap()]
        );
    }

    #[test]
    fn constant_time_eq_is_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
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

    // BUILD-DELTA #21(c): a token's issue record (issued-at, expiry, audience) is written in the same
    // durable record as the token, and every authorize reads its expiry back from disk. The clock is an
    // explicit input (`now_unix_secs`), so these tests choose the instant. Requests are built from JSON.

    const T0: i64 = 1_760_000_000;

    fn rfc3339(unix_secs: i64) -> String {
        time::OffsetDateTime::from_unix_timestamp(unix_secs)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    fn request_from(fields: Value) -> ModelMountCapabilityTokenControlRequest {
        let mut request = json!({
            "schema_version": MODEL_MOUNT_CAPABILITY_TOKEN_CONTROL_SCHEMA_VERSION,
            "source": "test.capability_token_control",
            "body": {
                "audience": "hypervisor-session",
                "allowed_scopes": ["model.chat:*"],
                "grant_id": "grant://wallet/capability"
            },
            "authority_grant_refs": ["grant://wallet/capability"],
        });
        for (key, value) in fields.as_object().unwrap() {
            request[key] = value.clone();
        }
        serde_json::from_value(request).expect("a token control request")
    }

    fn create_at(
        state: &Path,
        now: Option<i64>,
        expires_at: Option<&str>,
    ) -> Result<ModelMountCapabilityTokenControlPlan, ModelMountError> {
        let mut fields = json!({
            "operation_kind": "model_mount.capability_token.create",
            "state_dir": state.to_string_lossy(),
        });
        if let Some(now) = now {
            fields["now_unix_secs"] = json!(now);
        }
        if let Some(expires_at) = expires_at {
            fields["body"] = json!({
                "audience": "hypervisor-session",
                "allowed_scopes": ["model.chat:*"],
                "grant_id": "grant://wallet/capability",
                "expiresAt": expires_at,
            });
        }
        plan_capability_token_control(&request_from(fields))
    }

    fn persist_in(state: &Path, plan: &ModelMountCapabilityTokenControlPlan) {
        fs::write(
            state
                .join("capability-tokens")
                .join(format!("{}.json", plan.record_id.replace(':', "_"))),
            serde_json::to_vec(&plan.record).unwrap(),
        )
        .unwrap();
    }

    fn authorize_at(
        state: &Path,
        token: &str,
        now: Option<i64>,
    ) -> Result<ModelMountCapabilityTokenControlPlan, ModelMountError> {
        let mut fields = json!({
            "operation_kind": "model_mount.capability_token.authorize",
            "state_dir": state.to_string_lossy(),
            "token_hash": sha256_hex(token.as_bytes()).unwrap(),
            "required_scope": "model.chat:hello",
        });
        if let Some(now) = now {
            fields["now_unix_secs"] = json!(now);
        }
        plan_capability_token_control(&request_from(fields))
    }

    #[test]
    fn a_create_writes_its_issue_record_into_the_durable_token_record() {
        let state = scratch_state();
        let plan = create_at(&state, Some(T0), Some(&rfc3339(T0 + 60))).expect("create");
        assert_eq!(
            plan.record["issue_record"],
            json!({
                "schema_version": "ioi.model_mount.capability_token_issue.v1",
                "issued_at_unix_secs": T0,
                "expires_at_unix_secs": T0 + 60,
                "ttl_secs": 60,
                "audience": "hypervisor-session",
                "run_session_ref": null,
            }),
            "the issue record is part of the record the daemon persists: {}",
            plan.record
        );
        let token = plan.public_response["token"].as_str().unwrap();
        assert!(
            !plan.record.to_string().contains(token),
            "the plaintext token is not in the durable record"
        );
    }

    #[test]
    fn authorize_refuses_a_token_at_its_persisted_expiry() {
        let state = scratch_state();
        let plan = create_at(&state, Some(T0), Some(&rfc3339(T0 + 60))).expect("create");
        persist_in(&state, &plan);
        let token = plan.public_response["token"].as_str().unwrap();
        assert!(
            authorize_at(&state, token, Some(T0 + 59)).is_ok(),
            "valid one second before its expiry"
        );
        let refused = authorize_at(&state, token, Some(T0 + 60));
        assert!(
            format!("{refused:?}").contains("CapabilityTokenExpired"),
            "refused at its expiry, read from the persisted record: {refused:?}"
        );
        assert!(
            format!("{:?}", authorize_at(&state, token, Some(T0 + 86_400)))
                .contains("CapabilityTokenExpired"),
            "and at every use after it"
        );
    }

    #[test]
    fn a_token_record_without_an_issue_record_is_refused() {
        let state = scratch_state();
        let token = "ioi_mnt_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        // The shape a create wrote before issue records existed: random, hashed, no durable expiry.
        let record = json!({
            "operation_kind": "model_mount.capability_token.create",
            "rust_core_boundary": "model_mount.capability_token",
            "token_id": "capability_token:00112233445566778899aabbccddeeff",
            "token_hash": sha256_hex(token.as_bytes()).unwrap(),
            "token_entropy": "os_rng_256_v1",
            "capability_token_authority": {
                "allowed_scopes": ["model.chat:*"], "denied_scopes": [], "audience": "a", "grant_id": "g"
            },
            "planned_at": "rust_model_mount_core",
        });
        fs::write(
            state.join("capability-tokens").join("no-issue-record.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let refused = authorize_at(&state, token, Some(T0));
        assert!(
            format!("{refused:?}").contains("CapabilityTokenIssueRecordAbsent"),
            "a token that cannot prove its expiry from disk is refused: {refused:?}"
        );
    }

    #[test]
    fn authorize_without_a_clock_is_refused() {
        let state = scratch_state();
        let plan = create_at(&state, Some(T0), None).expect("create");
        persist_in(&state, &plan);
        let token = plan.public_response["token"].as_str().unwrap();
        assert!(authorize_at(&state, token, Some(T0)).is_ok());
        assert_eq!(
            format!("{:?}", authorize_at(&state, token, None).map(|_| ())),
            format!(
                "{:?}",
                Err::<(), _>(ModelMountError::MissingField("now_unix_secs"))
            ),
            "an authorize that names no instant is refused"
        );
    }

    #[test]
    fn a_create_whose_requested_expiry_is_unreadable_or_not_after_now_is_refused() {
        let state = scratch_state();
        for expires_at in [rfc3339(T0), rfc3339(T0 - 1), "tomorrow".to_string()] {
            let refused = create_at(&state, Some(T0), Some(&expires_at));
            assert!(
                format!("{refused:?}").contains("CapabilityTokenExpiryInvalid"),
                "expiresAt {expires_at:?} is refused, never read as no expiry: {refused:?}"
            );
        }
        assert_eq!(
            format!(
                "{:?}",
                create_at(&state, None, Some(&rfc3339(T0 + 60))).map(|_| ())
            ),
            format!(
                "{:?}",
                Err::<(), _>(ModelMountError::MissingField("now_unix_secs"))
            ),
            "a create that names no instant is refused"
        );
    }
}
