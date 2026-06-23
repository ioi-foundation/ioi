use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, trimmed_string,
    ModelMountError, MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION,
};

const CONFIGURABLE_CATALOG_PROVIDER_IDS: &[&str] = &[
    "catalog.local_manifest",
    "catalog.custom_http",
    "catalog.huggingface",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountCatalogProviderControlRequest {
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
pub struct ModelMountCatalogProviderControlPlan {
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

impl ModelMountCatalogProviderControlRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if provider_id_required(&self.operation_kind) {
            let provider_id = option_string(&self.provider_id, "provider_id")?;
            if !CONFIGURABLE_CATALOG_PROVIDER_IDS.contains(&provider_id.as_str()) {
                return Err(ModelMountError::CatalogProviderNotConfigurable);
            }
        }
        if self.operation_kind == "model_mount.catalog_provider_oauth.callback" {
            let body = object_or_empty(&self.body);
            trimmed_string(
                string_field(body, "state").unwrap_or_default().as_str(),
                "state",
            )?;
        }
        if !catalog_provider_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedCatalogProviderControlOperation);
        }
        Ok(())
    }
}

pub(super) fn plan_catalog_provider_control(
    request: &ModelMountCatalogProviderControlRequest,
) -> Result<ModelMountCatalogProviderControlPlan, ModelMountError> {
    request.validate()?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let provider_id = request
        .provider_id
        .as_ref()
        .and_then(|value| non_empty_string(value));
    let body = object_or_empty(&request.body);
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
    let evidence_refs = catalog_provider_control_evidence_refs();
    let authority_seed = json!({
        "operation_kind": operation_kind,
        "provider_id": provider_id,
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
        "source": source,
        "body_hash": body_hash,
        "authority_hash": authority_hash,
        "receipt_refs": receipt_refs,
    });
    let control_hash = hash_json(&control_seed)?;
    let record_id = format!(
        "catalog_provider_control:{}:{}",
        safe_segment(provider_id.as_deref().unwrap_or("all")),
        &control_hash[..16]
    );
    let public_response = public_response_for(
        &operation_kind,
        provider_id.as_deref(),
        body,
        &body_hash,
        &authority_hash,
    );
    let record = json!({
        "id": record_id,
        "record_id": record_id,
        "schema_version": MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION,
        "object": "ioi.model_mount_catalog_provider_control",
        "status": "planned",
        "operation_kind": operation_kind,
        "source": source,
        "provider_id": provider_id,
        "body_hash": format!("sha256:{body_hash}"),
        "request_field_count": body.len(),
        "rust_core_boundary": "model_mount.catalog_provider_control",
        "authority_boundary": "wallet.network.catalog_provider_control",
        "authority_provider_ref": "wallet.network",
        "wallet_authority_boundary": "wallet.network.catalog_provider_control",
        "ctee_custody_boundary": "ctee.catalog_provider_material",
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
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "planned_at": generated_at,
    });
    Ok(ModelMountCatalogProviderControlPlan {
        schema_version: MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_catalog_provider_control_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.catalog_provider_control".to_string(),
        operation_kind,
        source,
        record_dir: "model-catalog-provider-controls".to_string(),
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

fn public_response_for(
    operation_kind: &str,
    provider_id: Option<&str>,
    body: &Map<String, Value>,
    body_hash: &str,
    authority_hash: &str,
) -> Value {
    match operation_kind {
        "model_mount.catalog_provider_configuration.list" => json!({
            "object": "ioi.model_catalog_provider_config_list",
            "rust_core_boundary": "model_mount.catalog_provider_control",
            "providers": CONFIGURABLE_CATALOG_PROVIDER_IDS
                .iter()
                .map(|provider_id| {
                    json!({
                        "id": provider_id,
                        "provider_id": provider_id,
                        "object": "ioi.model_catalog_provider_config",
                        "status": "rust_controlled",
                        "configured_status": "agentgres_catalog_provider_controlled",
                        "plaintext_material_returned": false,
                    })
                })
                .collect::<Vec<_>>(),
        }),
        "model_mount.catalog_provider_configuration.get"
        | "model_mount.catalog_provider_configuration.read_private" => json!({
            "object": "ioi.model_catalog_provider_config",
            "provider_id": provider_id,
            "status": "rust_controlled",
            "configured_status": "agentgres_catalog_provider_controlled",
            "private_material_returned": false,
            "auth_material_status": "ctee_custody_required",
            "authority_hash": authority_hash,
        }),
        "model_mount.catalog_provider_configuration.write" => json!({
            "object": "ioi.model_catalog_provider_config_write",
            "provider_id": provider_id,
            "status": "accepted",
            "body_hash": format!("sha256:{body_hash}"),
            "request_field_count": body.len(),
            "private_material_returned": false,
            "auth_material_status": "ctee_custody_sealed",
            "authority_hash": authority_hash,
        }),
        "model_mount.catalog_provider_oauth.start" => json!({
            "object": "ioi.model_catalog_provider_oauth_start",
            "provider_id": provider_id,
            "status": "accepted",
            "oauth_state_material": "ctee_custody_sealed",
            "authorization_url_material": "ctee_custody_sealed",
            "private_material_returned": false,
            "authority_hash": authority_hash,
        }),
        "model_mount.catalog_provider_oauth.callback" => json!({
            "object": "ioi.model_catalog_provider_oauth_callback",
            "provider_id": provider_id,
            "status": "accepted",
            "state_present": true,
            "token_material": "ctee_custody_sealed",
            "private_material_returned": false,
            "authority_hash": authority_hash,
        }),
        "model_mount.catalog_provider_oauth.exchange" => json!({
            "object": "ioi.model_catalog_provider_oauth_exchange",
            "provider_id": provider_id,
            "status": "accepted",
            "token_material": "ctee_custody_sealed",
            "private_material_returned": false,
            "authority_hash": authority_hash,
        }),
        "model_mount.catalog_provider_oauth.refresh" => json!({
            "object": "ioi.model_catalog_provider_oauth_refresh",
            "provider_id": provider_id,
            "status": "accepted",
            "token_material": "ctee_custody_sealed",
            "private_material_returned": false,
            "authority_hash": authority_hash,
        }),
        "model_mount.catalog_provider_oauth.revoke" => json!({
            "object": "ioi.model_catalog_provider_oauth_revoke",
            "provider_id": provider_id,
            "status": "accepted",
            "revoked_material": "ctee_custody_sealed",
            "private_material_returned": false,
            "authority_hash": authority_hash,
        }),
        "model_mount.catalog_provider_runtime_material.resolve" => json!({
            "object": "ioi.model_catalog_provider_runtime_material",
            "provider_id": provider_id,
            "status": "ctee_custody_sealed",
            "runtime_material_status": "rust_ctee_custody_required",
            "plaintext_material_returned": false,
            "authority_hash": authority_hash,
        }),
        _ => Value::Null,
    }
}

fn catalog_provider_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.catalog_provider_configuration.list"
            | "model_mount.catalog_provider_configuration.get"
            | "model_mount.catalog_provider_configuration.write"
            | "model_mount.catalog_provider_oauth.start"
            | "model_mount.catalog_provider_oauth.callback"
            | "model_mount.catalog_provider_oauth.exchange"
            | "model_mount.catalog_provider_oauth.refresh"
            | "model_mount.catalog_provider_oauth.revoke"
            | "model_mount.catalog_provider_configuration.read_private"
            | "model_mount.catalog_provider_runtime_material.resolve"
    )
}

fn provider_id_required(operation_kind: &str) -> bool {
    operation_kind != "model_mount.catalog_provider_configuration.list"
}

fn catalog_provider_control_evidence_refs() -> Vec<String> {
    vec![
        "rust_daemon_core_catalog_provider_control".to_string(),
        "wallet_network_catalog_provider_authority_required".to_string(),
        "ctee_catalog_provider_custody_enforced".to_string(),
        "agentgres_catalog_provider_control_truth_required".to_string(),
        "public_catalog_provider_control_js_facade_retired".to_string(),
    ]
}

fn source_for(request: &ModelMountCatalogProviderControlRequest) -> String {
    request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "runtime-daemon.model_mounting.catalog_provider_control".to_string())
}

fn receipt_refs_for(request: &ModelMountCatalogProviderControlRequest) -> Vec<String> {
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

    fn request(operation_kind: &str) -> ModelMountCatalogProviderControlRequest {
        ModelMountCatalogProviderControlRequest {
            schema_version: MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: operation_kind.to_string(),
            provider_id: Some("catalog.huggingface".to_string()),
            source: Some("test.catalog_provider_control".to_string()),
            generated_at: Some("2026-06-13T12:00:00.000Z".to_string()),
            body: json!({
                "auth_header_name": "authorization",
                "state": "oauth-state"
            }),
            receipt_refs: vec!["receipt://catalog-provider-control".to_string()],
            authority_grant_refs: vec!["grant://wallet/provider-write".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/provider-write".to_string()],
            custody_ref: Some("ctee://catalog-provider/huggingface".to_string()),
            required_scope: Some("provider.write:catalog.huggingface".to_string()),
        }
    }

    #[test]
    fn rust_core_plans_catalog_provider_control_direct_api() {
        let plan = plan_catalog_provider_control(&request(
            "model_mount.catalog_provider_configuration.write",
        ))
        .expect("catalog provider control plan");

        assert_eq!(
            plan.schema_version,
            MODEL_MOUNT_CATALOG_PROVIDER_CONTROL_PLAN_SCHEMA_VERSION
        );
        assert_eq!(plan.record_dir, "model-catalog-provider-controls");
        assert_eq!(
            plan.rust_core_boundary,
            "model_mount.catalog_provider_control"
        );
        assert!(plan
            .evidence_refs
            .contains(&"ctee_catalog_provider_custody_enforced".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_catalog_provider_control_truth_required".to_string()));
        assert_eq!(
            plan.receipt_refs,
            vec![
                "receipt://catalog-provider-control",
                "receipt://wallet/provider-write"
            ]
        );
        assert_eq!(
            plan.authority_grant_refs,
            vec!["grant://wallet/provider-write"]
        );
        assert_eq!(
            plan.authority_receipt_refs,
            vec!["receipt://wallet/provider-write"]
        );
        assert_eq!(plan.record["plaintext_material_returned"], false);
        assert_eq!(
            plan.record["public_response"]["auth_material_status"],
            "ctee_custody_sealed"
        );
    }

    #[test]
    fn rust_core_rejects_unconfigured_catalog_provider() {
        let mut invalid = request("model_mount.catalog_provider_oauth.start");
        invalid.provider_id = Some("catalog.fixture".to_string());

        assert_eq!(
            plan_catalog_provider_control(&invalid).unwrap_err(),
            ModelMountError::CatalogProviderNotConfigurable
        );
    }
}
