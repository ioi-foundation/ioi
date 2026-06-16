use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountProviderAuthMaterializationRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_header_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_ref_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,
    #[serde(default)]
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountProviderAuthMaterializationPlan {
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
    pub materialization_hash: String,
    pub authority_hash: String,
}

impl ModelMountProviderAuthMaterializationRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.operation_kind != "model_mount.provider_auth.materialize" {
            return Err(ModelMountError::UnsupportedProviderAuthMaterializationOperation);
        }
        require_non_empty("provider_id", &provider_id_for_request(self)?)?;
        require_non_empty("provider_ref", &provider_ref_for_request(self)?)?;
        if self
            .vault_ref
            .as_ref()
            .and_then(|value| non_empty_string(value))
            .is_none()
            && self
                .vault_ref_hash
                .as_ref()
                .and_then(|value| non_empty_string(value))
                .is_none()
        {
            return Err(ModelMountError::MissingField("vault_ref"));
        }
        if let Some(body) = self.body.as_object() {
            if body.keys().any(|key| is_plaintext_provider_secret_key(key)) {
                return Err(ModelMountError::ProviderAuthMaterializationPlaintextMaterial);
            }
        }
        Ok(())
    }
}

pub(super) fn plan_provider_auth_materialization(
    request: &ModelMountProviderAuthMaterializationRequest,
) -> Result<ModelMountProviderAuthMaterializationPlan, ModelMountError> {
    request.validate()?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let provider_id = provider_id_for_request(request)?;
    let provider_ref = provider_ref_for_request(request)?;
    let provider_kind =
        option_string(&request.provider_kind).unwrap_or_else(|| "hosted_provider".to_string());
    let source = source_for(request);
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let vault_ref_hash = if let Some(vault_ref) = option_string(&request.vault_ref) {
        format!("sha256:{}", sha256_hex(vault_ref.as_bytes())?)
    } else {
        option_string(&request.vault_ref_hash)
            .ok_or(ModelMountError::MissingField("vault_ref_hash"))?
    };
    let auth_scheme =
        option_string(&request.auth_scheme).unwrap_or_else(|| default_auth_scheme(&provider_kind));
    let auth_header_name = option_string(&request.auth_header_name)
        .unwrap_or_else(|| default_auth_header_name(&provider_kind));
    let auth_header_name_hash = format!("sha256:{}", sha256_hex(auth_header_name.as_bytes())?);
    let material_hash = option_string(&request.material_hash);
    let receipt_refs = receipt_refs_for(request);
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let evidence_refs = provider_auth_materialization_evidence_refs();
    let authority_seed = json!({
        "operation_kind": operation_kind,
        "provider_id": provider_id,
        "provider_ref": provider_ref,
        "provider_kind": provider_kind,
        "vault_ref_hash": vault_ref_hash,
        "auth_header_name_hash": auth_header_name_hash,
        "required_scope": request.required_scope,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "custody_ref": request.custody_ref,
        "containment_ref": request.containment_ref,
    });
    let authority_hash = format!("sha256:{}", hash_json(&authority_seed)?);
    let materialization_seed = json!({
        "schema_version": request.schema_version,
        "operation_kind": operation_kind,
        "provider_id": provider_id,
        "provider_ref": provider_ref,
        "vault_ref_hash": vault_ref_hash,
        "auth_scheme": auth_scheme,
        "auth_header_name_hash": auth_header_name_hash,
        "authority_hash": authority_hash,
        "receipt_refs": receipt_refs,
    });
    let materialization_hash = hash_json(&materialization_seed)?;
    let record_id = format!("{}_auth_header", safe_segment(&provider_id));
    let outbound_header_binding_ref =
        format!("provider_auth_header://{record_id}#sha256:{materialization_hash}");
    let provider_auth_materialization_ref =
        format!("agentgres://model-mounting/model-provider-auth-materializations/{record_id}");
    let public_response = json!({
        "object": "ioi.model_mount_provider_auth_materialization",
        "id": record_id,
        "provider_id": provider_id,
        "provider_ref": provider_ref,
        "provider_kind": provider_kind,
        "auth_scheme": auth_scheme,
        "auth_header_name": auth_header_name,
        "auth_header_name_hash": auth_header_name_hash,
        "vault_ref": { "redacted": true, "hash": vault_ref_hash },
        "vault_ref_hash": vault_ref_hash,
        "material_hash": material_hash,
        "auth_header_materialization_status": "rust_ctee_outbound_header_bound",
        "outbound_header_binding_ref": outbound_header_binding_ref,
        "provider_auth_materialization_ref": provider_auth_materialization_ref,
        "plaintext_secret_material_returned": false,
        "auth_header_value_returned": false,
        "auth_header_value_persisted": false,
        "authority_hash": authority_hash,
        "materialization_hash": format!("sha256:{materialization_hash}"),
    });
    let record = json!({
        "id": record_id,
        "record_id": record_id,
        "schema_version": MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_SCHEMA_VERSION,
        "object": "ioi.model_mount_provider_auth_materialization",
        "status": "materialized",
        "operation_kind": operation_kind,
        "source": source,
        "provider_id": provider_id,
        "provider_ref": provider_ref,
        "provider_kind": provider_kind,
        "auth_scheme": auth_scheme,
        "auth_header_name": auth_header_name,
        "auth_header_name_hash": auth_header_name_hash,
        "vault_ref": { "redacted": true, "hash": vault_ref_hash },
        "vault_ref_hash": vault_ref_hash,
        "material_hash": material_hash,
        "auth_header_materialization_status": "rust_ctee_outbound_header_bound",
        "outbound_header_binding_ref": outbound_header_binding_ref,
        "provider_auth_materialization_ref": provider_auth_materialization_ref,
        "rust_core_boundary": "model_mount.provider_auth_materialization",
        "wallet_authority_boundary": "wallet.network.provider_auth",
        "ctee_custody_boundary": "ctee.provider_auth_header",
        "plaintext_secret_material_returned": false,
        "auth_header_value_returned": false,
        "auth_header_value_persisted": false,
        "custody_policy": {
            "no_plaintext_custody": true,
            "private_material_resolved_by": "rust_daemon_core_ctee",
            "outbound_header_materialized_by": "rust_daemon_core.model_mount.provider_auth_materialization",
            "js_private_material_readback_retired": true,
            "custody_ref": request.custody_ref,
            "containment_ref": request.containment_ref,
        },
        "authority": {
            "authority_hash": authority_hash,
            "required_scope": request.required_scope,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
        },
        "public_response": public_response,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "materialization_hash": materialization_hash,
        "planned_at": generated_at,
    });

    Ok(ModelMountProviderAuthMaterializationPlan {
        schema_version: MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_provider_auth_materialization_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.provider_auth_materialization".to_string(),
        operation_kind,
        source,
        record_dir: "model-provider-auth-materializations".to_string(),
        record_id,
        record,
        public_response,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        materialization_hash,
        authority_hash,
    })
}

fn provider_id_for_request(
    request: &ModelMountProviderAuthMaterializationRequest,
) -> Result<String, ModelMountError> {
    request
        .provider_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| string_field(object_or_empty(&request.body), "provider_id"))
        .or_else(|| string_field(object_or_empty(&request.body), "id"))
        .ok_or(ModelMountError::MissingField("provider_id"))
}

fn provider_ref_for_request(
    request: &ModelMountProviderAuthMaterializationRequest,
) -> Result<String, ModelMountError> {
    request
        .provider_ref
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| string_field(object_or_empty(&request.body), "provider_ref"))
        .or_else(|| {
            provider_id_for_request(request)
                .ok()
                .map(|id| format!("provider://{id}"))
        })
        .ok_or(ModelMountError::MissingField("provider_ref"))
}

fn source_for(request: &ModelMountProviderAuthMaterializationRequest) -> String {
    request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| {
            "runtime-daemon.model_mounting.provider_auth_materialization".to_string()
        })
}

fn receipt_refs_for(request: &ModelMountProviderAuthMaterializationRequest) -> Vec<String> {
    let mut refs = Vec::new();
    for value in &request.receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    for value in &request.authority_receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    refs
}

fn provider_auth_materialization_evidence_refs() -> Vec<String> {
    vec![
        "rust_daemon_core_provider_auth_materialization".to_string(),
        "rust_provider_auth_materialization_bound".to_string(),
        "wallet_network_provider_vault_ref_bound".to_string(),
        "ctee_provider_auth_header_custody_enforced".to_string(),
        "hosted_provider_auth_header_materialized_by_rust".to_string(),
        "hosted_provider_plaintext_secret_not_returned".to_string(),
        "agentgres_provider_auth_materialization_truth_required".to_string(),
        "public_provider_auth_header_js_facade_retired".to_string(),
    ]
}

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| non_empty_string(value))
        .collect()
}

fn option_string(value: &Option<String>) -> Option<String> {
    value.as_ref().and_then(|value| non_empty_string(value))
}

fn string_field(map: &Map<String, Value>, field: &str) -> Option<String> {
    map.get(field)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
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

fn default_auth_scheme(provider_kind: &str) -> String {
    match provider_kind {
        "anthropic" | "gemini" | "custom_http" => "api_key".to_string(),
        _ => "bearer".to_string(),
    }
}

fn default_auth_header_name(provider_kind: &str) -> String {
    match provider_kind {
        "anthropic" => "x-api-key".to_string(),
        _ => "authorization".to_string(),
    }
}

fn is_plaintext_provider_secret_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|ch| !matches!(ch, '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "apikey"
            | "authorization"
            | "auth"
            | "header"
            | "headers"
            | "bearertoken"
            | "accesstoken"
            | "providerkey"
            | "material"
            | "secret"
    )
}

fn safe_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
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

    fn request() -> ModelMountProviderAuthMaterializationRequest {
        ModelMountProviderAuthMaterializationRequest {
            schema_version: MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.provider_auth.materialize".to_string(),
            provider_id: Some("provider.openai".to_string()),
            provider_ref: Some("provider://provider.openai".to_string()),
            provider_kind: Some("openai".to_string()),
            auth_scheme: Some("bearer".to_string()),
            auth_header_name: Some("authorization".to_string()),
            vault_ref: Some("vault://provider/openai".to_string()),
            vault_ref_hash: None,
            material_hash: Some("sha256:material".to_string()),
            source: Some("test.provider_auth_materialization".to_string()),
            generated_at: Some("2026-06-16T12:00:00.000Z".to_string()),
            receipt_refs: vec!["receipt://provider-control".to_string()],
            authority_grant_refs: vec!["grant://wallet/provider-auth".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/provider-auth".to_string()],
            custody_ref: Some("ctee://provider/openai".to_string()),
            containment_ref: Some("ctee://workspace/private".to_string()),
            required_scope: Some("provider.auth:provider.openai".to_string()),
            body: Value::Null,
        }
    }

    #[test]
    fn rust_core_plans_provider_auth_materialization_direct_api() {
        let plan = plan_provider_auth_materialization(&request()).expect("provider auth plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_PROVIDER_AUTH_MATERIALIZATION_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.record_dir, "model-provider-auth-materializations");
        assert_eq!(
            plan.rust_core_boundary,
            "model_mount.provider_auth_materialization"
        );
        assert_eq!(
            plan.record["object"],
            "ioi.model_mount_provider_auth_materialization"
        );
        assert_eq!(
            plan.record["auth_header_materialization_status"],
            "rust_ctee_outbound_header_bound"
        );
        assert_eq!(plan.record["plaintext_secret_material_returned"], false);
        assert_eq!(plan.record["auth_header_value_returned"], false);
        assert_eq!(plan.record["auth_header_value_persisted"], false);
        assert_eq!(plan.public_response["auth_header_value_returned"], false);
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_provider_auth_materialization".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"rust_provider_auth_materialization_bound".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"ctee_provider_auth_header_custody_enforced".to_string()));
        assert!(plan.record["outbound_header_binding_ref"]
            .as_str()
            .unwrap()
            .starts_with("provider_auth_header://provider.openai_auth_header#sha256:"));
    }

    #[test]
    fn rust_core_rejects_provider_auth_materialization_without_vault_ref() {
        let mut invalid = request();
        invalid.vault_ref = None;
        invalid.vault_ref_hash = None;

        assert_eq!(
            plan_provider_auth_materialization(&invalid).unwrap_err(),
            ModelMountError::MissingField("vault_ref")
        );
    }

    #[test]
    fn rust_core_rejects_plaintext_provider_auth_materialization() {
        let mut invalid = request();
        invalid.body = json!({ "api_key": "sk-plaintext" });

        assert_eq!(
            plan_provider_auth_materialization(&invalid).unwrap_err(),
            ModelMountError::ProviderAuthMaterializationPlaintextMaterial
        );
    }
}
