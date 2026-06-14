use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    non_empty_string, push_unique_ref, require_non_empty, sha256_hex, ModelMountError,
    MODEL_MOUNT_STORAGE_CONTROL_PLAN_SCHEMA_VERSION, MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountStorageControlRequest {
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
pub struct ModelMountStorageControlPlan {
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

impl ModelMountStorageControlRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.body.is_null() && !self.body.is_object() {
            return Err(ModelMountError::MissingField("body"));
        }
        if !storage_control_operation_supported(&self.operation_kind) {
            return Err(ModelMountError::UnsupportedStorageControlOperation);
        }
        let body = object_or_empty(&self.body);
        match self.operation_kind.as_str() {
            "model_mount.catalog.import_url" => {
                string_field(body, "source_url")
                    .ok_or(ModelMountError::MissingField("source_url"))?;
            }
            "model_mount.download.queue" => {
                string_field(body, "model_id").ok_or(ModelMountError::MissingField("model_id"))?;
            }
            "model_mount.download.cancel" => {
                string_field(body, "job_id").ok_or(ModelMountError::MissingField("job_id"))?;
            }
            "model_mount.artifact.delete" => {
                string_field(body, "artifact_id")
                    .ok_or(ModelMountError::MissingField("artifact_id"))?;
            }
            "model_mount.storage.cleanup" => {}
            _ => return Err(ModelMountError::UnsupportedStorageControlOperation),
        }
        Ok(())
    }
}

pub(super) fn plan_storage_control(
    request: &ModelMountStorageControlRequest,
) -> Result<ModelMountStorageControlPlan, ModelMountError> {
    request.validate()?;
    match request.operation_kind.as_str() {
        "model_mount.catalog.import_url" => plan_catalog_import_url(request),
        "model_mount.download.queue" => plan_download_queue(request),
        "model_mount.download.cancel" => plan_download_cancel(request),
        "model_mount.artifact.delete" => plan_artifact_delete(request),
        "model_mount.storage.cleanup" => plan_storage_cleanup(request),
        _ => Err(ModelMountError::UnsupportedStorageControlOperation),
    }
}

fn plan_catalog_import_url(
    request: &ModelMountStorageControlRequest,
) -> Result<ModelMountStorageControlPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let source_url = required_body_string(body, "source_url")?;
    let source_url_hash = hash_text(&source_url)?;
    let model_id = string_field(body, "model_id").unwrap_or_else(|| {
        format!(
            "catalog-import-{}",
            &source_url_hash.trim_start_matches("sha256:")[0..12]
        )
    });
    let record_id = string_field(body, "import_id")
        .unwrap_or_else(|| format!("catalog_import.{}", safe_segment(&model_id)));
    storage_plan(
        request,
        "model-catalog-imports",
        &record_id,
        "ioi.model_mount_catalog_import",
        "planned",
        json!({
            "model_id": model_id,
            "provider_id": string_field(body, "provider_id"),
            "source_url_hash": source_url_hash,
            "file_name": string_field(body, "file_name"),
            "fixture_content_hash": string_field(body, "fixture_content").map(|value| hash_text(&value)).transpose()?,
            "transfer_approved": bool_field(body, "transfer_approved").unwrap_or(false),
            "plaintext_source_url_returned": false,
            "network_transfer_executed": false,
        }),
    )
}

fn plan_download_queue(
    request: &ModelMountStorageControlRequest,
) -> Result<ModelMountStorageControlPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let model_id = required_body_string(body, "model_id")?;
    let record_id = string_field(body, "download_id")
        .or_else(|| string_field(body, "job_id"))
        .unwrap_or_else(|| format!("download.{}", safe_segment(&model_id)));
    storage_plan(
        request,
        "model-downloads",
        &record_id,
        "ioi.model_mount_download",
        "queued",
        json!({
            "job_id": record_id.clone(),
            "model_id": model_id,
            "provider_id": string_field(body, "provider_id"),
            "catalog_provider_id": string_field(body, "catalog_provider_id"),
            "source_url_hash": string_field(body, "source_url").map(|value| hash_text(&value)).transpose()?,
            "source_label": string_field(body, "source_label"),
            "file_name": string_field(body, "file_name"),
            "bytes_total": integer_field(body, "bytes_total"),
            "max_bytes": integer_field(body, "max_bytes"),
            "expected_checksum_hash": string_field(body, "expected_checksum").map(|value| hash_text(&value)).transpose()?,
            "display_name": string_field(body, "display_name"),
            "context_window": integer_field(body, "context_window"),
            "privacy_class": string_field(body, "privacy_class"),
            "queued_only": bool_field(body, "queued_only").unwrap_or(true),
            "network_transfer_executed": false,
            "plaintext_source_url_returned": false,
        }),
    )
}

fn plan_download_cancel(
    request: &ModelMountStorageControlRequest,
) -> Result<ModelMountStorageControlPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let job_id = required_body_string(body, "job_id")?;
    storage_plan(
        request,
        "model-downloads",
        &job_id,
        "ioi.model_mount_download",
        "cancelled",
        json!({
            "job_id": job_id,
            "cleanup_partial": bool_field(body, "cleanup_partial").unwrap_or(false),
            "filesystem_mutation_executed": false,
        }),
    )
}

fn plan_artifact_delete(
    request: &ModelMountStorageControlRequest,
) -> Result<ModelMountStorageControlPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let artifact_id = required_body_string(body, "artifact_id")?;
    let record_id = format!("artifact_delete.{}", safe_segment(&artifact_id));
    storage_plan(
        request,
        "model-storage-controls",
        &record_id,
        "ioi.model_mount_storage_control",
        "delete_planned",
        json!({
            "artifact_id": artifact_id,
            "dry_run": bool_field(body, "dry_run").unwrap_or(false),
            "filesystem_mutation_executed": false,
        }),
    )
}

fn plan_storage_cleanup(
    request: &ModelMountStorageControlRequest,
) -> Result<ModelMountStorageControlPlan, ModelMountError> {
    let body = object_or_empty(&request.body);
    let body_hash = hash_json(&request.body)?;
    let record_id = format!(
        "storage_cleanup.{}",
        &body_hash.trim_start_matches("sha256:")[0..12]
    );
    storage_plan(
        request,
        "model-storage-controls",
        &record_id,
        "ioi.model_mount_storage_control",
        "cleanup_planned",
        json!({
            "remove_orphans": bool_field(body, "remove_orphans").unwrap_or(false),
            "dry_run": bool_field(body, "dry_run").unwrap_or(false),
            "filesystem_mutation_executed": false,
        }),
    )
}

fn storage_plan(
    request: &ModelMountStorageControlRequest,
    record_dir: &str,
    record_id: &str,
    object: &str,
    status: &str,
    details: Value,
) -> Result<ModelMountStorageControlPlan, ModelMountError> {
    let body_hash = hash_json(&request.body)?;
    let authority_hash = authority_hash_for(request, &body_hash)?;
    let control_hash = control_hash_for(request, record_id, &body_hash, &authority_hash)?;
    let source = request
        .source
        .as_deref()
        .and_then(non_empty_string)
        .unwrap_or_else(|| "runtime-daemon.model_mounting.storage_control".to_string());
    let generated_at = request
        .generated_at
        .as_deref()
        .and_then(non_empty_string)
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string());
    let receipt_refs = receipt_refs_for(request);
    let authority_grant_refs = non_empty_vec(&request.authority_grant_refs);
    let authority_receipt_refs = non_empty_vec(&request.authority_receipt_refs);
    let evidence_refs = evidence_refs_for(&request.operation_kind);
    let public_response = json!({
        "object": object,
        "status": status,
        "id": record_id,
        "record_id": record_id,
        "record_dir": record_dir,
        "operation_kind": request.operation_kind,
        "rust_core_boundary": "model_mount.storage_control",
        "details": details.clone(),
        "js_filesystem_mutation_executed": false,
        "js_network_transfer_executed": false,
    });
    let record = json!({
        "id": record_id,
        "record_id": record_id,
        "schema_version": MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION,
        "object": object,
        "status": status,
        "operation_kind": request.operation_kind,
        "source": source,
        "generated_at": generated_at,
        "rust_core_boundary": "model_mount.storage_control",
        "details": details,
        "custody_ref": request.custody_ref,
        "authority": authority_record(request, &authority_hash),
        "public_response": public_response.clone(),
        "receipt_refs": receipt_refs,
        "evidence_refs": evidence_refs,
        "control_hash": control_hash,
        "authority_hash": authority_hash,
    });
    Ok(ModelMountStorageControlPlan {
        schema_version: MODEL_MOUNT_STORAGE_CONTROL_PLAN_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_storage_control_plan".to_string(),
        status: "planned".to_string(),
        rust_core_boundary: "model_mount.storage_control".to_string(),
        operation_kind: request.operation_kind.clone(),
        source: record["source"].as_str().unwrap_or_default().to_string(),
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

fn storage_control_operation_supported(operation_kind: &str) -> bool {
    matches!(
        operation_kind,
        "model_mount.catalog.import_url"
            | "model_mount.download.queue"
            | "model_mount.download.cancel"
            | "model_mount.artifact.delete"
            | "model_mount.storage.cleanup"
    )
}

fn evidence_refs_for(operation_kind: &str) -> Vec<String> {
    let mut refs = vec![
        "public_model_storage_js_facade_retired".to_string(),
        "rust_daemon_core_model_storage".to_string(),
        "agentgres_model_storage_truth_required".to_string(),
    ];
    match operation_kind {
        "model_mount.catalog.import_url" | "model_mount.download.queue" => {
            refs.push("public_catalog_download_js_facade_retired".to_string());
            refs.push("rust_daemon_core_catalog_download".to_string());
            refs.push("agentgres_catalog_download_truth_required".to_string());
        }
        "model_mount.download.cancel" => {
            refs.push("rust_daemon_core_model_download_cancel".to_string());
        }
        "model_mount.artifact.delete" => {
            refs.push("rust_daemon_core_model_artifact_delete".to_string());
        }
        "model_mount.storage.cleanup" => {
            refs.push("rust_daemon_core_model_storage_cleanup".to_string());
        }
        _ => {}
    }
    refs
}

fn authority_record(request: &ModelMountStorageControlRequest, authority_hash: &str) -> Value {
    json!({
        "authority_hash": authority_hash,
        "required_scope": request.required_scope,
        "authority_grant_refs": non_empty_vec(&request.authority_grant_refs),
        "authority_receipt_refs": non_empty_vec(&request.authority_receipt_refs),
        "wallet_authority_boundary": "wallet.network.model_mount_storage",
        "ctee_custody_boundary": "ctee.model_mount_storage",
        "plaintext_material_returned": false,
    })
}

fn receipt_refs_for(request: &ModelMountStorageControlRequest) -> Vec<String> {
    let mut refs = Vec::new();
    for value in &request.receipt_refs {
        push_unique_ref(&mut refs, value);
    }
    refs
}

fn authority_hash_for(
    request: &ModelMountStorageControlRequest,
    body_hash: &str,
) -> Result<String, ModelMountError> {
    hash_json(&json!({
        "operation_kind": request.operation_kind,
        "required_scope": request.required_scope,
        "authority_grant_refs": non_empty_vec(&request.authority_grant_refs),
        "authority_receipt_refs": non_empty_vec(&request.authority_receipt_refs),
        "custody_ref": request.custody_ref,
        "body_hash": body_hash,
    }))
}

fn control_hash_for(
    request: &ModelMountStorageControlRequest,
    record_id: &str,
    body_hash: &str,
    authority_hash: &str,
) -> Result<String, ModelMountError> {
    hash_json(&json!({
        "schema_version": request.schema_version,
        "operation_kind": request.operation_kind,
        "record_id": record_id,
        "body_hash": body_hash,
        "authority_hash": authority_hash,
        "receipt_refs": non_empty_vec(&request.receipt_refs),
    }))
}

fn hash_json(value: &Value) -> Result<String, ModelMountError> {
    serde_json::to_vec(value)
        .map_err(|error| ModelMountError::HashFailed(error.to_string()))
        .and_then(|bytes| sha256_hex(&bytes))
        .map(|hash| format!("sha256:{hash}"))
}

fn hash_text(value: &str) -> Result<String, ModelMountError> {
    sha256_hex(value.as_bytes()).map(|hash| format!("sha256:{hash}"))
}

fn object_or_empty(value: &Value) -> &Map<String, Value> {
    value.as_object().unwrap_or_else(|| empty_object())
}

fn empty_object() -> &'static Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

fn string_field(body: &Map<String, Value>, field: &str) -> Option<String> {
    body.get(field)?.as_str().and_then(non_empty_string)
}

fn required_body_string(
    body: &Map<String, Value>,
    field: &'static str,
) -> Result<String, ModelMountError> {
    string_field(body, field).ok_or(ModelMountError::MissingField(field))
}

fn integer_field(body: &Map<String, Value>, field: &str) -> Option<i64> {
    body.get(field)?.as_i64()
}

fn bool_field(body: &Map<String, Value>, field: &str) -> Option<bool> {
    body.get(field)?.as_bool()
}

fn non_empty_vec(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|value| non_empty_string(value))
        .collect()
}

fn safe_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn request(operation_kind: &str, body: Value) -> ModelMountStorageControlRequest {
        ModelMountStorageControlRequest {
            schema_version: MODEL_MOUNT_STORAGE_CONTROL_SCHEMA_VERSION.to_string(),
            operation_kind: operation_kind.to_string(),
            source: Some("test".to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            body,
            receipt_refs: vec!["receipt://storage".to_string()],
            authority_grant_refs: vec!["grant://wallet/storage".to_string()],
            authority_receipt_refs: vec!["receipt://wallet/storage".to_string()],
            custody_ref: Some("ctee://storage".to_string()),
            required_scope: Some("model.storage:test".to_string()),
        }
    }

    #[test]
    fn plans_catalog_import_without_plaintext_url() {
        let plan = plan_storage_control(&request(
            "model_mount.catalog.import_url",
            json!({"source_url": "https://example.test/model.gguf", "model_id": "qwen-test"}),
        ))
        .expect("catalog import plan");

        assert_eq!(plan.record_dir, "model-catalog-imports");
        assert_eq!(plan.record["details"]["model_id"], "qwen-test");
        assert!(plan.record["details"]["source_url_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(plan
            .evidence_refs
            .contains(&"rust_daemon_core_catalog_download".to_string()));
        assert_eq!(
            plan.public_response["details"]["network_transfer_executed"],
            false
        );
    }

    #[test]
    fn plans_download_queue_and_cancel_records() {
        let queued = plan_storage_control(&request(
            "model_mount.download.queue",
            json!({"model_id": "llama-test", "source_url": "fixture://llama"}),
        ))
        .expect("download queue plan");
        assert_eq!(queued.record_dir, "model-downloads");
        assert_eq!(queued.record["status"], "queued");

        let cancelled = plan_storage_control(&request(
            "model_mount.download.cancel",
            json!({"job_id": queued.record_id, "cleanup_partial": true}),
        ))
        .expect("download cancel plan");
        assert_eq!(cancelled.record_dir, "model-downloads");
        assert_eq!(cancelled.record["status"], "cancelled");
        assert_eq!(cancelled.record["details"]["cleanup_partial"], true);
    }

    #[test]
    fn plans_artifact_delete_and_cleanup_records() {
        let delete = plan_storage_control(&request(
            "model_mount.artifact.delete",
            json!({"artifact_id": "artifact.llama", "dry_run": true}),
        ))
        .expect("artifact delete plan");
        assert_eq!(delete.record_dir, "model-storage-controls");
        assert_eq!(delete.record["status"], "delete_planned");

        let cleanup = plan_storage_control(&request(
            "model_mount.storage.cleanup",
            json!({"remove_orphans": true}),
        ))
        .expect("storage cleanup plan");
        assert_eq!(cleanup.record_dir, "model-storage-controls");
        assert_eq!(cleanup.record["status"], "cleanup_planned");
        assert_eq!(cleanup.record["details"]["remove_orphans"], true);
    }

    #[test]
    fn rejects_missing_required_storage_fields() {
        let error = plan_storage_control(&request("model_mount.download.queue", json!({})))
            .expect_err("missing model id");
        assert_eq!(error, ModelMountError::MissingField("model_id"));
    }
}
