use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, ModelMountError,
    MODEL_MOUNT_ARTIFACT_ENDPOINT_PLAN_SCHEMA_VERSION,
    MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountArtifactEndpointRequest {
    pub schema_version: String,
    pub operation_kind: String,
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
pub struct ModelMountArtifactEndpointPlan {
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

#[derive(Debug, Deserialize)]
pub struct ModelMountArtifactEndpointBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountArtifactEndpointRequest,
}

impl ModelMountArtifactEndpointRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !artifact_endpoint_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedArtifactEndpointOperation);
        }
        let body = object_or_empty(&self.body);
        match self.operation_kind.as_str() {
            "model_mount.artifact.import" | "model_mount.endpoint.mount" => {
                string_field(body, "model_id").ok_or(ModelMountError::MissingField("model_id"))?;
            }
            "model_mount.endpoint.unmount" => {
                string_field(body, "endpoint_id")
                    .ok_or(ModelMountError::MissingField("endpoint_id"))?;
            }
            _ => {}
        }
        Ok(())
    }
}

pub fn plan_model_mount_artifact_endpoint_response(
    request: ModelMountArtifactEndpointBridgeRequest,
) -> Result<Value, ModelMountError> {
    let plan = plan_artifact_endpoint(&request.request)?;
    let record_dir = plan.record_dir.clone();
    let record_id = plan.record_id.clone();
    let record = plan.record.clone();
    let public_response = plan.public_response.clone();
    let receipt_refs = plan.receipt_refs.clone();
    let authority_grant_refs = plan.authority_grant_refs.clone();
    let authority_receipt_refs = plan.authority_receipt_refs.clone();
    let evidence_refs = plan.evidence_refs.clone();
    let control_hash = plan.control_hash.clone();
    let authority_hash = plan.authority_hash.clone();
    let operation_kind = plan.operation_kind.clone();
    let rust_core_boundary = plan.rust_core_boundary.clone();
    Ok(json!({
        "source": "rust_model_mount_artifact_endpoint_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_artifact_endpoint".to_string()),
        "plan": plan,
        "record_dir": record_dir,
        "record_id": record_id,
        "record": record,
        "public_response": public_response,
        "receipt_refs": receipt_refs,
        "authority_grant_refs": authority_grant_refs,
        "authority_receipt_refs": authority_receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "authority_hash": authority_hash,
        "operation_kind": operation_kind,
        "rust_core_boundary": rust_core_boundary,
    }))
}

pub(super) fn plan_artifact_endpoint(
    request: &ModelMountArtifactEndpointRequest,
) -> Result<ModelMountArtifactEndpointPlan, ModelMountError> {
    request.validate()?;
    match request.operation_kind.as_str() {
        "model_mount.artifact.import" => plan_artifact_import(request),
        "model_mount.endpoint.mount" => plan_endpoint_mount(request),
        "model_mount.endpoint.unmount" => plan_endpoint_unmount(request),
        _ => Err(ModelMountError::UnsupportedArtifactEndpointOperation),
    }
}

fn plan_artifact_import(
    request: &ModelMountArtifactEndpointRequest,
) -> Result<ModelMountArtifactEndpointPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let model_id = required_body_string(body, "model_id")?;
    let provider_id =
        string_field(body, "provider_id").unwrap_or_else(|| "provider.local.folder".to_string());
    let artifact_id = string_field(body, "artifact_id")
        .unwrap_or_else(|| format!("artifact.{}", safe_segment(&model_id)));
    let source = source_for(request);
    let generated_at = generated_at_for(request);
    let body_hash = hash_json(&request.body)?;
    let authority_hash = authority_hash_for(request, &body_hash)?;
    let control_hash = control_hash_for(request, &artifact_id, &body_hash, &authority_hash)?;
    let receipt_refs = receipt_refs_for(request);
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let evidence_refs = evidence_refs_for("artifact_import");
    let source_path_hash = string_field(body, "source_path")
        .map(|value| sha256_hex(value.as_bytes()))
        .transpose()?
        .map(|hash| format!("sha256:{hash}"));
    let display_name = string_field(body, "display_name").unwrap_or_else(|| model_id.clone());
    let capabilities = array_field(body, "capabilities").unwrap_or_else(|| {
        vec![
            Value::String("chat".to_string()),
            Value::String("responses".to_string()),
        ]
    });
    let public_response = json!({
        "object": "ioi.model_mount_model_artifact",
        "status": "imported",
        "id": artifact_id.clone(),
        "artifact_id": artifact_id.clone(),
        "model_id": model_id.clone(),
        "provider_id": provider_id.clone(),
        "display_name": display_name.clone(),
        "plaintext_source_path_returned": false,
    });
    let record = json!({
        "id": artifact_id.clone(),
        "record_id": artifact_id.clone(),
        "schema_version": MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
        "object": "ioi.model_mount_model_artifact",
        "status": "imported",
        "state": "installed",
        "operation_kind": request.operation_kind,
        "source": source,
        "rust_core_boundary": "model_mount.artifact_endpoint",
        "model_id": model_id.clone(),
        "provider_id": provider_id.clone(),
        "display_name": display_name,
        "family": string_field(body, "family").unwrap_or_else(|| "operator_import".to_string()),
        "quantization": string_field(body, "quantization").unwrap_or_else(|| "unknown".to_string()),
        "size_bytes": integer_field(body, "size_bytes"),
        "context_window": integer_field(body, "context_window").unwrap_or(8192),
        "capabilities": capabilities.clone(),
        "privacy_class": string_field(body, "privacy_class").unwrap_or_else(|| "local_private".to_string()),
        "source_path_hash": source_path_hash,
        "plaintext_source_path_returned": false,
        "custody_ref": request.custody_ref,
        "authority": authority_record(request, &authority_hash),
        "public_response": public_response.clone(),
        "receipt_refs": receipt_refs.clone(),
        "evidence_refs": evidence_refs.clone(),
        "control_hash": control_hash.clone(),
        "authority_hash": authority_hash.clone(),
        "imported_at": generated_at,
    });
    artifact_endpoint_plan(
        request,
        "model-artifacts",
        &artifact_id,
        record,
        public_response,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        control_hash,
        authority_hash,
    )
}

fn plan_endpoint_mount(
    request: &ModelMountArtifactEndpointRequest,
) -> Result<ModelMountArtifactEndpointPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let model_id = required_body_string(body, "model_id")?;
    let provider_id =
        string_field(body, "provider_id").unwrap_or_else(|| "provider.local.folder".to_string());
    let endpoint_id = string_field(body, "endpoint_id").unwrap_or_else(|| {
        format!(
            "endpoint.{}.{}",
            safe_segment(&provider_id),
            safe_segment(&model_id)
        )
    });
    let source = source_for(request);
    let generated_at = generated_at_for(request);
    let body_hash = hash_json(&request.body)?;
    let authority_hash = authority_hash_for(request, &body_hash)?;
    let control_hash = control_hash_for(request, &endpoint_id, &body_hash, &authority_hash)?;
    let receipt_refs = receipt_refs_for(request);
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let evidence_refs = evidence_refs_for("endpoint_mount");
    let load_policy = load_policy_for(body);
    let capabilities = array_field(body, "capabilities").unwrap_or_else(|| {
        vec![
            Value::String("chat".to_string()),
            Value::String("responses".to_string()),
        ]
    });
    let api_format = string_field(body, "api_format").unwrap_or_else(|| "ioi_fixture".to_string());
    let driver = string_field(body, "driver").unwrap_or_else(|| "fixture".to_string());
    let provider_kind = string_field(body, "provider_kind").unwrap_or_else(|| {
        if provider_id == "provider.local.folder" {
            "local_folder".to_string()
        } else {
            "operator_configured".to_string()
        }
    });
    let backend_id =
        string_field(body, "backend_id").unwrap_or_else(|| "backend.fixture".to_string());
    let privacy_class =
        string_field(body, "privacy_class").unwrap_or_else(|| "local_private".to_string());
    let base_url_hash = string_field(body, "base_url")
        .map(|value| sha256_hex(value.as_bytes()))
        .transpose()?
        .map(|hash| format!("sha256:{hash}"));
    let public_response = json!({
        "object": "ioi.model_mount_endpoint",
        "status": "mounted",
        "id": endpoint_id.clone(),
        "endpoint_id": endpoint_id.clone(),
        "model_id": model_id.clone(),
        "provider_id": provider_id.clone(),
        "provider_kind": provider_kind.clone(),
        "api_format": api_format.clone(),
        "driver": driver.clone(),
        "backend_id": backend_id.clone(),
        "capabilities": capabilities.clone(),
        "privacy_class": privacy_class.clone(),
        "load_policy": load_policy.clone(),
        "plaintext_transport_material_returned": false,
    });
    let record = json!({
        "id": endpoint_id.clone(),
        "record_id": endpoint_id.clone(),
        "schema_version": MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
        "object": "ioi.model_mount_endpoint",
        "status": "mounted",
        "operation_kind": request.operation_kind,
        "source": source,
        "rust_core_boundary": "model_mount.artifact_endpoint",
        "endpoint_id": endpoint_id.clone(),
        "model_id": model_id.clone(),
        "provider_id": provider_id.clone(),
        "provider_kind": provider_kind,
        "api_format": api_format,
        "driver": driver,
        "backend_id": backend_id,
        "base_url_hash": base_url_hash,
        "plaintext_transport_material_returned": false,
        "capabilities": capabilities,
        "privacy_class": privacy_class,
        "load_policy": load_policy,
        "custody_ref": request.custody_ref,
        "authority": authority_record(request, &authority_hash),
        "public_response": public_response.clone(),
        "receipt_refs": receipt_refs.clone(),
        "evidence_refs": evidence_refs.clone(),
        "control_hash": control_hash.clone(),
        "authority_hash": authority_hash.clone(),
        "mounted_at": generated_at,
    });
    artifact_endpoint_plan(
        request,
        "model-endpoints",
        &endpoint_id,
        record,
        public_response,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        control_hash,
        authority_hash,
    )
}

fn plan_endpoint_unmount(
    request: &ModelMountArtifactEndpointRequest,
) -> Result<ModelMountArtifactEndpointPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let endpoint_id = required_body_string(body, "endpoint_id")?;
    let source = source_for(request);
    let generated_at = generated_at_for(request);
    let body_hash = hash_json(&request.body)?;
    let authority_hash = authority_hash_for(request, &body_hash)?;
    let control_hash = control_hash_for(request, &endpoint_id, &body_hash, &authority_hash)?;
    let receipt_refs = receipt_refs_for(request);
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let evidence_refs = evidence_refs_for("endpoint_unmount");
    let public_response = json!({
        "object": "ioi.model_mount_endpoint",
        "status": "unmounted",
        "id": endpoint_id.clone(),
        "endpoint_id": endpoint_id.clone(),
        "plaintext_transport_material_returned": false,
    });
    let record = json!({
        "id": endpoint_id.clone(),
        "record_id": endpoint_id.clone(),
        "schema_version": MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION,
        "object": "ioi.model_mount_endpoint",
        "status": "unmounted",
        "operation_kind": request.operation_kind,
        "source": source,
        "rust_core_boundary": "model_mount.artifact_endpoint",
        "endpoint_id": endpoint_id.clone(),
        "model_id": string_field(body, "model_id"),
        "provider_id": string_field(body, "provider_id"),
        "plaintext_transport_material_returned": false,
        "authority": authority_record(request, &authority_hash),
        "public_response": public_response.clone(),
        "receipt_refs": receipt_refs.clone(),
        "evidence_refs": evidence_refs.clone(),
        "control_hash": control_hash.clone(),
        "authority_hash": authority_hash.clone(),
        "unmounted_at": generated_at,
    });
    artifact_endpoint_plan(
        request,
        "model-endpoints",
        &endpoint_id,
        record,
        public_response,
        receipt_refs,
        authority_grant_refs,
        authority_receipt_refs,
        evidence_refs,
        control_hash,
        authority_hash,
    )
}

#[allow(clippy::too_many_arguments)]
fn artifact_endpoint_plan(
    request: &ModelMountArtifactEndpointRequest,
    record_dir: &str,
    record_id: &str,
    record: Value,
    public_response: Value,
    receipt_refs: Vec<String>,
    authority_grant_refs: Vec<String>,
    authority_receipt_refs: Vec<String>,
    evidence_refs: Vec<String>,
    control_hash: String,
    authority_hash: String,
) -> Result<ModelMountArtifactEndpointPlan, ModelMountError> {
    Ok(ModelMountArtifactEndpointPlan {
        schema_version: MODEL_MOUNT_ARTIFACT_ENDPOINT_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_artifact_endpoint_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.artifact_endpoint".to_string(),
        operation_kind: request.operation_kind.clone(),
        source: source_for(request),
        record_dir: record_dir.to_string(),
        record_id: record_id.to_string(),
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

fn artifact_endpoint_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.artifact.import"
            | "model_mount.endpoint.mount"
            | "model_mount.endpoint.unmount"
    )
}

fn evidence_refs_for(operation: &str) -> Vec<String> {
    let mut refs = vec![
        "public_artifact_endpoint_js_facade_retired".to_string(),
        "rust_daemon_core_artifact_endpoint".to_string(),
        "agentgres_artifact_endpoint_truth_required".to_string(),
    ];
    match operation {
        "artifact_import" => refs.push("rust_daemon_core_model_artifact_import".to_string()),
        "endpoint_mount" => refs.push("rust_daemon_core_model_endpoint_mount".to_string()),
        "endpoint_unmount" => refs.push("rust_daemon_core_model_endpoint_unmount".to_string()),
        _ => {}
    }
    refs
}

fn authority_record(request: &ModelMountArtifactEndpointRequest, authority_hash: &str) -> Value {
    json!({
        "authority_hash": authority_hash,
        "required_scope": request.required_scope,
        "authority_grant_refs": non_empty_vec(&request.authority_grant_refs),
        "authority_receipt_refs": non_empty_vec(&request.authority_receipt_refs),
        "custody_ref": request.custody_ref,
        "wallet_authority_boundary": "wallet.network.model_mount_artifact_endpoint",
        "ctee_custody_boundary": "ctee.model_mount_artifact_endpoint",
        "plaintext_private_material_returned": false,
    })
}

fn authority_hash_for(
    request: &ModelMountArtifactEndpointRequest,
    body_hash: &str,
) -> Result<String, ModelMountError> {
    let seed = json!({
        "operation_kind": request.operation_kind,
        "body_hash": body_hash,
        "required_scope": request.required_scope,
        "authority_grant_refs": non_empty_vec(&request.authority_grant_refs),
        "authority_receipt_refs": non_empty_vec(&request.authority_receipt_refs),
        "custody_ref": request.custody_ref,
    });
    Ok(format!("sha256:{}", hash_json(&seed)?))
}

fn control_hash_for(
    request: &ModelMountArtifactEndpointRequest,
    subject_id: &str,
    body_hash: &str,
    authority_hash: &str,
) -> Result<String, ModelMountError> {
    let seed = json!({
        "operation_kind": request.operation_kind,
        "subject_id": subject_id,
        "body_hash": body_hash,
        "authority_hash": authority_hash,
        "receipt_refs": receipt_refs_for(request),
        "source": source_for(request),
    });
    hash_json(&seed)
}

fn load_policy_for(body: &Map<String, Value>) -> Value {
    let candidate = body
        .get("load_policy")
        .and_then(|value| value.as_object())
        .cloned()
        .unwrap_or_default();
    json!({
        "mode": candidate
            .get("mode")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("on_demand"),
        "idle_ttl_seconds": candidate
            .get("idle_ttl_seconds")
            .and_then(Value::as_u64)
            .or_else(|| candidate.get("ttl_seconds").and_then(Value::as_u64))
            .unwrap_or(900),
        "auto_evict": candidate
            .get("auto_evict")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    })
}

fn source_for(request: &ModelMountArtifactEndpointRequest) -> String {
    request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string())
}

fn generated_at_for(request: &ModelMountArtifactEndpointRequest) -> String {
    request
        .generated_at
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_core".to_string())
}

fn receipt_refs_for(request: &ModelMountArtifactEndpointRequest) -> Vec<String> {
    let mut refs = Vec::new();
    for receipt_ref in &request.receipt_refs {
        push_unique_ref(&mut refs, receipt_ref);
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
    value.as_object().expect("validated object body")
}

fn required_body_string(
    body: &Map<String, Value>,
    field: &'static str,
) -> Result<String, ModelMountError> {
    string_field(body, field).ok_or(ModelMountError::MissingField(field))
}

fn string_field(body: &Map<String, Value>, field: &str) -> Option<String> {
    body.get(field)
        .and_then(Value::as_str)
        .and_then(non_empty_string)
}

fn array_field(body: &Map<String, Value>, field: &str) -> Option<Vec<Value>> {
    body.get(field).and_then(Value::as_array).cloned()
}

fn integer_field(body: &Map<String, Value>, field: &str) -> Option<u64> {
    body.get(field).and_then(Value::as_u64)
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    sha256_hex(
        &serde_json::to_vec(value)
            .map_err(|error| ModelMountError::HashFailed(error.to_string()))?,
    )
}

fn safe_segment(value: &str) -> String {
    let mut segment = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            segment.push(character.to_ascii_lowercase());
        } else if matches!(character, '.' | '-' | '_') {
            segment.push(character);
        } else if !segment.ends_with('.') {
            segment.push('.');
        }
    }
    let trimmed = segment.trim_matches('.').to_string();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation_kind: &str, body: Value) -> ModelMountArtifactEndpointRequest {
        ModelMountArtifactEndpointRequest {
            schema_version: MODEL_MOUNT_ARTIFACT_ENDPOINT_SCHEMA_VERSION.to_string(),
            operation_kind: operation_kind.to_string(),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            body,
            receipt_refs: vec!["receipt://artifact-endpoint".to_string()],
            authority_grant_refs: vec!["grant://wallet/model-mount".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/model-mount".to_string()],
            custody_ref: Some("ctee://workspace/private-models".to_string()),
            required_scope: Some("model.endpoint:write".to_string()),
        }
    }

    #[test]
    fn plans_artifact_import_record() {
        let plan = plan_artifact_endpoint(&request(
            "model_mount.artifact.import",
            json!({
                "model_id": "local:test",
                "provider_id": "provider.local.folder",
                "source_path": "/private/models/test.gguf",
            }),
        ))
        .expect("artifact import plan");

        assert_eq!(plan.record_dir, "model-artifacts");
        assert_eq!(plan.rust_core_boundary, "model_mount.artifact_endpoint");
        assert_eq!(plan.record["object"], "ioi.model_mount_model_artifact");
        assert_eq!(plan.record["model_id"], "local:test");
        assert_eq!(plan.record["plaintext_source_path_returned"], false);
        assert!(plan
            .evidence_refs
            .contains(&"agentgres_artifact_endpoint_truth_required".to_string()));
        assert_eq!(plan.public_response["status"], "imported");
    }

    #[test]
    fn plans_endpoint_mount_record() {
        let plan = plan_artifact_endpoint(&request(
            "model_mount.endpoint.mount",
            json!({
                "model_id": "local:test",
                "provider_id": "provider.local.folder",
                "load_policy": {"mode": "resident", "idle_ttl_seconds": 0, "auto_evict": false},
            }),
        ))
        .expect("endpoint mount plan");

        assert_eq!(plan.record_dir, "model-endpoints");
        assert_eq!(plan.record["object"], "ioi.model_mount_endpoint");
        assert_eq!(plan.record["status"], "mounted");
        assert_eq!(plan.record["model_id"], "local:test");
        assert_eq!(plan.record["load_policy"]["mode"], "resident");
        assert_eq!(plan.public_response["provider_id"], "provider.local.folder");
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_model_endpoint_mount".to_string()));
    }

    #[test]
    fn plans_endpoint_unmount_record() {
        let plan = plan_artifact_endpoint(&request(
            "model_mount.endpoint.unmount",
            json!({"endpoint_id": "endpoint.local.test"}),
        ))
        .expect("endpoint unmount plan");

        assert_eq!(plan.record_dir, "model-endpoints");
        assert_eq!(plan.record_id, "endpoint.local.test");
        assert_eq!(plan.record["status"], "unmounted");
        assert_eq!(plan.public_response["endpoint_id"], "endpoint.local.test");
    }

    #[test]
    fn rejects_missing_endpoint_subjects() {
        let error = plan_artifact_endpoint(&request("model_mount.endpoint.mount", json!({})))
            .expect_err("missing model id");
        assert_eq!(error, ModelMountError::MissingField("model_id"));
    }
}
