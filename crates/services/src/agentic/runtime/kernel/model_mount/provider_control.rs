use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION,
};

const RETIRED_PROVIDER_CONTROL_ALIASES: &[&str] = &[
    "authScheme",
    "authHeaderName",
    "apiFormat",
    "baseUrl",
    "privacyClass",
    "evidenceRefs",
    "secretRef",
    "authVaultRef",
    "apiKeyVaultRef",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountProviderControlRequest {
    pub schema_version: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub body: Value,
    #[serde(default)]
    pub receipt_refs: Vec<String>,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountProviderControlPlan {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub rust_core_boundary: String,
    pub operation_kind: String,
    pub source: String,
    pub record_dir: String,
    pub record_id: String,
    pub record: Value,
    pub receipt_refs: Vec<String>,
    pub authority_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub control_hash: String,
    pub authority_hash: String,
}

impl ModelMountProviderControlRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if self.operation_kind != "model_mount.provider.write" {
            return Err(ModelMountError::UnsupportedProviderControlOperation);
        }
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        let body = object_or_empty(&self.body);
        if body
            .keys()
            .any(|key| RETIRED_PROVIDER_CONTROL_ALIASES.contains(&key.as_str()))
        {
            return Err(ModelMountError::ProviderControlRetiredAlias);
        }
        if body.keys().any(|key| is_plaintext_provider_secret_key(key)) {
            return Err(ModelMountError::ProviderControlPlaintextMaterial);
        }
        let provider_id = provider_id_for_request(self)?;
        require_non_empty("provider_id", &provider_id)?;
        let kind = string_field(body, "kind").ok_or(ModelMountError::MissingField("kind"))?;
        if provider_requires_vault_secret(&kind) && provider_secret_ref(body).is_none() {
            return Err(ModelMountError::MissingField("secret_ref"));
        }
        Ok(())
    }
}

pub(super) fn plan_provider_control(
    request: &ModelMountProviderControlRequest,
) -> Result<ModelMountProviderControlPlan, ModelMountError> {
    request.validate()?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let body = object_or_empty(&request.body);
    let provider_id = provider_id_for_request(request)?;
    let record_id = safe_segment(&provider_id);
    let provider_ref =
        string_field(body, "provider_ref").unwrap_or_else(|| format!("provider://{provider_id}"));
    let kind = string_field(body, "kind").ok_or(ModelMountError::MissingField("kind"))?;
    let label = string_field(body, "label").unwrap_or_else(|| provider_id.clone());
    let api_format = string_field(body, "api_format").unwrap_or_else(|| kind.clone());
    let driver = string_field(body, "driver").unwrap_or_else(|| default_driver(&kind, &api_format));
    let secret_ref = provider_secret_ref(body);
    let status = string_field(body, "status").unwrap_or_else(|| {
        if secret_ref.is_some() {
            "configured"
        } else {
            "available"
        }
        .to_string()
    });
    let privacy_class =
        string_field(body, "privacy_class").unwrap_or_else(|| "workspace".to_string());
    let base_url = string_field(body, "base_url");
    let auth_scheme = string_field(body, "auth_scheme");
    let auth_header_name = string_field(body, "auth_header_name");
    let provider_auth_materialization_ref = string_field(body, "provider_auth_materialization_ref");
    let outbound_header_binding_ref = string_field(body, "outbound_header_binding_ref");
    let auth_header_materialization_status =
        string_field(body, "auth_header_materialization_status");
    let ctee_egress_resolver_ref = string_field(body, "ctee_egress_resolver_ref");
    let ctee_egress_resolver_hash = string_field(body, "ctee_egress_resolver_hash");
    let ctee_egress_resolution_status = string_field(body, "ctee_egress_resolution_status");
    let capabilities = string_array_field(body, "capabilities");
    let request_evidence_refs = string_array_field(body, "evidence_refs");
    let source = source_for(request);
    let generated_at = request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string());
    let body_hash = hash_json(&request.body)?;
    let receipt_refs = receipt_refs_for(request);
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let evidence_refs = provider_control_evidence_refs();
    let authority_seed = json!({
        "operation_kind": operation_kind,
        "provider_id": provider_id,
        "provider_ref": provider_ref,
        "secret_ref": secret_ref,
        "body_hash": body_hash,
        "required_scope": request.required_scope,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "custody_ref": request.custody_ref,
    });
    let authority_hash = format!("sha256:{}", hash_json(&authority_seed)?);
    let control_seed = json!({
        "schema_version": request.schema_version,
        "operation_kind": operation_kind,
        "provider_id": provider_id,
        "provider_ref": provider_ref,
        "source": source,
        "body_hash": body_hash,
        "authority_hash": authority_hash,
        "receipt_refs": receipt_refs,
    });
    let control_hash = hash_json(&control_seed)?;
    let public_response = json!({
        "object": "ioi.model_mount_provider",
        "id": provider_id,
        "provider_id": provider_id,
        "provider_ref": provider_ref,
        "kind": kind,
        "label": label,
        "status": status,
        "api_format": api_format,
        "driver": driver,
        "base_url": base_url,
        "privacy_class": privacy_class,
        "capabilities": capabilities,
        "auth_scheme": auth_scheme,
        "auth_header_name": auth_header_name,
        "secret_ref": secret_ref,
        "provider_auth_materialization_ref": provider_auth_materialization_ref,
        "outbound_header_binding_ref": outbound_header_binding_ref,
        "auth_header_materialization_status": auth_header_materialization_status,
        "ctee_egress_resolver_ref": ctee_egress_resolver_ref,
        "ctee_egress_resolver_hash": ctee_egress_resolver_hash,
        "ctee_egress_resolution_status": ctee_egress_resolution_status,
        "auth_material_status": if auth_header_materialization_status.is_some() {
            "rust_ctee_outbound_header_bound"
        } else if secret_ref.is_some() { "wallet_vault_ref_bound" } else { "not_required" },
        "private_material_returned": false,
        "plaintext_material_persisted": false,
        "authority_hash": authority_hash,
        "control_hash": format!("sha256:{control_hash}"),
    });
    let record = json!({
        "id": record_id,
        "record_id": record_id,
        "schema_version": MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION,
        "object": "ioi.model_mount_provider",
        "status": status,
        "operation_kind": operation_kind,
        "source": source,
        "provider_id": provider_id,
        "provider_ref": provider_ref,
        "kind": kind,
        "label": label,
        "api_format": api_format,
        "driver": driver,
        "base_url": base_url,
        "privacy_class": privacy_class,
        "capabilities": capabilities,
        "auth_scheme": auth_scheme,
        "auth_header_name": auth_header_name,
        "secret_ref": secret_ref,
        "provider_auth_materialization_ref": provider_auth_materialization_ref,
        "outbound_header_binding_ref": outbound_header_binding_ref,
        "auth_header_materialization_status": auth_header_materialization_status,
        "ctee_egress_resolver_ref": ctee_egress_resolver_ref,
        "ctee_egress_resolver_hash": ctee_egress_resolver_hash,
        "ctee_egress_resolution_status": ctee_egress_resolution_status,
        "body_hash": format!("sha256:{body_hash}"),
        "request_field_count": body.len(),
        "rust_core_boundary": "model_mount.provider_control",
        "wallet_authority_boundary": "wallet.network.provider_control",
        "ctee_custody_boundary": "ctee.provider_material",
        "plaintext_material_returned": false,
        "custody_policy": {
            "no_plaintext_custody": true,
            "private_material_resolved_by": "rust_daemon_core_ctee",
            "js_private_material_readback_retired": true,
            "custody_ref": request.custody_ref,
        },
        "authority": {
            "authority_hash": authority_hash,
            "required_scope": request.required_scope,
            "authority_grant_refs": authority_grant_refs,
            "authority_receipt_refs": authority_receipt_refs,
        },
        "public_response": public_response,
        "request_evidence_refs": request_evidence_refs,
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "planned_at": generated_at,
    });
    Ok(ModelMountProviderControlPlan {
        schema_version: MODEL_MOUNT_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_provider_control_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.provider_control".to_string(),
        operation_kind,
        source,
        record_dir: "model-providers".to_string(),
        record_id,
        record,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        control_hash,
        authority_hash,
    })
}

fn provider_id_for_request(
    request: &ModelMountProviderControlRequest,
) -> Result<String, ModelMountError> {
    request
        .provider_id
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .or_else(|| string_field(object_or_empty(&request.body), "id"))
        .ok_or(ModelMountError::MissingField("provider_id"))
}

fn provider_secret_ref(body: &Map<String, Value>) -> Option<String> {
    string_field(body, "secret_ref")
        .or_else(|| string_field(body, "api_key_vault_ref"))
        .or_else(|| string_field(body, "auth_vault_ref"))
}

fn provider_requires_vault_secret(kind: &str) -> bool {
    matches!(kind, "openai" | "anthropic" | "gemini" | "custom_http")
}

fn default_driver(kind: &str, api_format: &str) -> String {
    match (kind, api_format) {
        ("ioi_native_local", _) | (_, "ioi_native") => "native_local".to_string(),
        ("local_folder", _) | (_, "ioi_fixture") | (_, "fixture") => "fixture".to_string(),
        ("ollama", _) => "ollama".to_string(),
        ("vllm", _) => "vllm".to_string(),
        ("llama_cpp", _) => "llama_cpp".to_string(),
        ("lm_studio", _) => "lm_studio".to_string(),
        _ => "hosted_provider".to_string(),
    }
}

fn provider_control_evidence_refs() -> Vec<String> {
    vec![
        "rust_daemon_core_provider_control".to_string(),
        "wallet_network_provider_control_authority_required".to_string(),
        "wallet_network_vault_authority_required".to_string(),
        "ctee_provider_custody_enforced".to_string(),
        "agentgres_provider_control_truth_required".to_string(),
        "public_provider_control_js_facade_retired".to_string(),
    ]
}

fn source_for(request: &ModelMountProviderControlRequest) -> String {
    request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "runtime-daemon.model_mounting.provider_control".to_string())
}

fn receipt_refs_for(request: &ModelMountProviderControlRequest) -> Vec<String> {
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

    fn request() -> ModelMountProviderControlRequest {
        ModelMountProviderControlRequest {
            schema_version: MODEL_MOUNT_PROVIDER_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: "model_mount.provider.write".to_string(),
            provider_id: Some("provider.openai".to_string()),
            source: Some("test.provider_control".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
            body: json!({
                "id": "provider.openai",
                "kind": "openai",
                "label": "OpenAI",
                "api_key_vault_ref": "vault://provider/openai",
                "auth_header_name": "authorization",
                "provider_auth_materialization_ref": "agentgres://model-mounting/model-provider-auth-materializations/provider.openai_auth_header",
                "outbound_header_binding_ref": "provider_auth_header://provider.openai_auth_header#sha256:provider-auth",
                "auth_header_materialization_status": "rust_ctee_outbound_header_bound",
                "api_format": "openai",
                "base_url": "https://api.openai.example/v1",
                "privacy_class": "hosted_private",
                "capabilities": ["chat", "responses"],
                "evidence_refs": ["operator_provider_config"]
            }),
            receipt_refs: vec!["receipt://provider-control".to_string()],
            authority_grant_refs: vec!["grant://wallet/provider-write".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/provider-write".to_string()],
            custody_ref: Some("ctee://provider/openai".to_string()),
            required_scope: Some("provider.write:provider.openai".to_string()),
        }
    }

    #[test]
    fn rust_core_plans_provider_control_direct_api() {
        let plan = plan_provider_control(&request()).expect("provider control plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.record_dir, "model-providers");
        assert_eq!(plan.record_id, "provider.openai");
        assert_eq!(plan.rust_core_boundary, "model_mount.provider_control");
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_provider_control".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_provider_control_truth_required".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"ctee_provider_custody_enforced".to_string()));
        assert_eq!(
            plan.receipt_refs,
            vec![
                "receipt://provider-control",
                "receipt://wallet/provider-write"
            ]
        );
        assert_eq!(plan.record["object"], "ioi.model_mount_provider");
        assert_eq!(
            plan.record["rust_core_boundary"],
            "model_mount.provider_control"
        );
        assert_eq!(plan.record["plaintext_material_returned"], false);
        assert_eq!(
            plan.record["public_response"]["private_material_returned"],
            false
        );
        assert_eq!(
            plan.record["public_response"]["plaintext_material_persisted"],
            false
        );
        assert_eq!(
            plan.record["public_response"]["auth_header_materialization_status"],
            "rust_ctee_outbound_header_bound"
        );
        assert_eq!(
            plan.record["provider_auth_materialization_ref"],
            "agentgres://model-mounting/model-provider-auth-materializations/provider.openai_auth_header"
        );
    }

    #[test]
    fn rust_core_rejects_plaintext_provider_material() {
        let mut invalid = request();
        invalid.body.as_object_mut().unwrap().insert(
            "api_key".to_string(),
            Value::String("sk-plaintext".to_string()),
        );

        assert_eq!(
            plan_provider_control(&invalid).unwrap_err(),
            ModelMountError::ProviderControlPlaintextMaterial
        );
    }

    #[test]
    fn rust_core_rejects_retired_provider_aliases() {
        let mut invalid = request();
        invalid
            .body
            .as_object_mut()
            .unwrap()
            .insert("apiFormat".to_string(), Value::String("openai".to_string()));

        assert_eq!(
            plan_provider_control(&invalid).unwrap_err(),
            ModelMountError::ProviderControlRetiredAlias
        );
    }
}
