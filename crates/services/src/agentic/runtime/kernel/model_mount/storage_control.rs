use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::time::Duration;

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
    let materialization = hosted_download_materialization(body, &record_id)?;
    let status = if materialization.is_some() {
        "completed"
    } else {
        "queued"
    };
    let mut details = json!({
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
    });
    if let Some(materialization) = materialization {
        if let Some(details) = details.as_object_mut() {
            for (key, value) in materialization {
                details.insert(key, value);
            }
        }
    }
    storage_plan(
        request,
        "model-downloads",
        &record_id,
        "ioi.model_mount_download",
        status,
        details,
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

fn hosted_download_materialization(
    body: &Map<String, Value>,
    record_id: &str,
) -> Result<Option<Map<String, Value>>, ModelMountError> {
    if !hosted_download_materialization_requested(body) {
        return Ok(None);
    }
    let source_url = required_body_string(body, "source_url")?;
    if !source_url.starts_with("https://") && !source_url.starts_with("http://") {
        return Err(ModelMountError::HostedProviderTransportExecutionFailed(
            "hosted download materialization requires http(s) source_url".to_string(),
        ));
    }
    let max_bytes = integer_field(body, "max_bytes")
        .filter(|value| *value > 0)
        .ok_or(ModelMountError::MissingField("max_bytes"))? as usize;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::limited(8))
        .build()
        .map_err(|error| {
            ModelMountError::HostedProviderTransportExecutionFailed(error.to_string())
        })?;
    let request_ref = format!(
        "model_mount://hosted_download_transport_request/{}",
        safe_segment(record_id)
    );
    let ctee_egress_resolver_ref = string_field(body, "ctee_egress_resolver_ref");
    let ctee_egress_resolver_hash = string_field(body, "ctee_egress_resolver_hash");
    let ctee_egress_resolution_status = string_field(body, "ctee_egress_resolution_status");
    let source_url_hash = hash_text(&source_url)?;
    let request_hash = hash_json(&json!({
        "schema": "ioi.model_mount.hosted_download_request.v1",
        "method": "GET",
        "record_id": record_id,
        "source_url_hash": source_url_hash,
        "provider_auth_materialization_ref": string_field(body, "provider_auth_materialization_ref"),
        "outbound_header_binding_ref": string_field(body, "outbound_header_binding_ref"),
        "auth_header_materialization_status": string_field(body, "auth_header_materialization_status"),
        "ctee_egress_resolver_ref": ctee_egress_resolver_ref,
        "ctee_egress_resolver_hash": ctee_egress_resolver_hash,
        "ctee_egress_resolution_status": ctee_egress_resolution_status,
        "plaintext_source_url_returned": false,
    }))?;
    let response = client.get(&source_url).send().map_err(|error| {
        ModelMountError::HostedProviderTransportExecutionFailed(error.to_string())
    })?;
    let status_code = response.status().as_u16();
    let response_bytes = response.bytes().map_err(|error| {
        ModelMountError::HostedProviderTransportExecutionFailed(error.to_string())
    })?;
    if response_bytes.len() > max_bytes {
        return Err(ModelMountError::HostedProviderTransportExecutionFailed(
            "hosted download response exceeded max_bytes".to_string(),
        ));
    }
    if !(200..300).contains(&status_code) {
        return Err(ModelMountError::HostedProviderTransportExecutionFailed(
            format!("hosted download returned HTTP {status_code}"),
        ));
    }
    let download_content_hash = format!("sha256:{}", sha256_hex(response_bytes.as_ref())?);
    if let Some(expected_checksum) = string_field(body, "expected_checksum") {
        if expected_checksum.starts_with("sha256:") && expected_checksum != download_content_hash {
            return Err(ModelMountError::HostedProviderTransportExecutionFailed(
                "hosted download checksum mismatch".to_string(),
            ));
        }
    }
    let response_hash = hash_json(&json!({
        "schema": "ioi.model_mount.hosted_download_response.v1",
        "request_hash": request_hash,
        "status_code": status_code,
        "bytes_downloaded": response_bytes.len(),
        "download_content_hash": download_content_hash,
        "plaintext_payload_returned": false,
    }))?;
    let mut materialization = Map::new();
    materialization.insert(
        "download_materialization_kind".to_string(),
        json!("hosted_download"),
    );
    materialization.insert(
        "download_materialization_status".to_string(),
        json!("rust_hosted_download_materialized"),
    );
    materialization.insert(
        "download_materialization_owner".to_string(),
        json!("rust_daemon_core.model_mount.storage_control"),
    );
    materialization.insert(
        "transport_execution_owner".to_string(),
        json!("rust_daemon_core.model_mount.storage_control.hosted_download"),
    );
    materialization.insert("network_transfer_executed".to_string(), json!(true));
    materialization.insert("queued_only".to_string(), json!(false));
    materialization.insert("bytes_downloaded".to_string(), json!(response_bytes.len()));
    materialization.insert("bytes_total".to_string(), json!(response_bytes.len()));
    materialization.insert(
        "download_content_hash".to_string(),
        json!(download_content_hash),
    );
    materialization.insert(
        "hosted_download_transport_request_ref".to_string(),
        json!(request_ref),
    );
    materialization.insert(
        "hosted_download_transport_request_hash".to_string(),
        json!(request_hash),
    );
    materialization.insert(
        "hosted_download_transport_response_hash".to_string(),
        json!(response_hash),
    );
    materialization.insert(
        "hosted_download_transport_status".to_string(),
        json!("rust_hosted_download_transport_response_bound"),
    );
    materialization.insert(
        "hosted_download_http_status".to_string(),
        json!(status_code),
    );
    materialization.insert("plaintext_payload_returned".to_string(), json!(false));
    materialization.insert("artifact_bytes_returned".to_string(), json!(false));
    materialization.insert(
        "provider_auth_materialization_ref".to_string(),
        json!(string_field(body, "provider_auth_materialization_ref")),
    );
    materialization.insert(
        "outbound_header_binding_ref".to_string(),
        json!(string_field(body, "outbound_header_binding_ref")),
    );
    materialization.insert(
        "auth_header_materialization_status".to_string(),
        json!(string_field(body, "auth_header_materialization_status")),
    );
    materialization.insert(
        "ctee_egress_resolver_ref".to_string(),
        json!(ctee_egress_resolver_ref),
    );
    materialization.insert(
        "ctee_egress_resolver_hash".to_string(),
        json!(ctee_egress_resolver_hash),
    );
    materialization.insert(
        "ctee_egress_resolution_status".to_string(),
        json!(ctee_egress_resolution_status),
    );
    materialization.insert(
        "custody_policy".to_string(),
        json!({
            "no_plaintext_custody": true,
            "download_bytes_returned_to_js": false,
            "private_material_resolved_by": "rust_daemon_core_ctee",
            "download_materialized_by": "rust_daemon_core.model_mount.storage_control",
        }),
    );
    Ok(Some(materialization))
}

fn hosted_download_materialization_requested(body: &Map<String, Value>) -> bool {
    if bool_field(body, "hosted_download_materialization").unwrap_or(false) {
        return true;
    }
    if bool_field(body, "materialize_now").unwrap_or(false) {
        return true;
    }
    if string_field(body, "download_materialization_kind").as_deref() == Some("hosted_download") {
        return true;
    }
    if string_field(body, "materialization_kind").as_deref() == Some("hosted_download") {
        return true;
    }
    bool_field(body, "queued_only") == Some(false)
        && string_field(body, "source_url")
            .map(|value| value.starts_with("https://") || value.starts_with("http://"))
            .unwrap_or(false)
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
    let evidence_refs = evidence_refs_for(&request.operation_kind, &details);
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

fn evidence_refs_for(operation_kind: &str, details: &Value) -> Vec<String> {
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
            if string_field(object_or_empty(details), "download_materialization_kind").as_deref()
                == Some("hosted_download")
            {
                for evidence_ref in [
                    "rust_hosted_download_materialized",
                    "rust_hosted_download_transport_executor_owned",
                    "rust_hosted_download_transport_request_bound",
                    "rust_hosted_download_transport_response_bound",
                    "ctee_hosted_download_no_plaintext_custody",
                ] {
                    push_unique_ref(&mut refs, evidence_ref);
                }
                if string_field(object_or_empty(details), "ctee_egress_resolver_ref").is_some() {
                    push_unique_ref(&mut refs, "rust_ctee_egress_resolver_bound");
                }
            }
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
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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

    fn hosted_download_fixture_url(bytes: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind hosted download fixture");
        let address = listener.local_addr().expect("fixture address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("fixture accept");
            let mut request_bytes = [0_u8; 1024];
            let _ = stream.read(&mut request_bytes);
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            stream
                .write_all(headers.as_bytes())
                .expect("fixture response headers");
            stream.write_all(&bytes).expect("fixture response body");
        });
        format!("http://{address}/models/qwen-test.gguf")
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
    fn materializes_hosted_download_transport_in_rust() {
        let payload = b"hosted model bytes".to_vec();
        let source_url = hosted_download_fixture_url(payload.clone());
        let expected_checksum = format!("sha256:{}", sha256_hex(&payload).expect("payload hash"));
        let plan = plan_storage_control(&request(
            "model_mount.download.queue",
            json!({
                "model_id": "hosted-qwen",
                "provider_id": "provider.openai",
                "source_url": source_url,
                "max_bytes": 1024,
                "expected_checksum": expected_checksum,
                "download_materialization_kind": "hosted_download",
                "provider_auth_materialization_ref": "agentgres://model-mounting/model-provider-auth-materializations/provider_openai_auth_header",
                "outbound_header_binding_ref": "provider_auth_header://provider_openai_auth_header#sha256:auth",
                "auth_header_materialization_status": "rust_ctee_outbound_header_bound",
                "ctee_egress_resolver_ref": "ctee://model-mount/egress-resolver/provider_openai_auth_header#sha256:egress",
                "ctee_egress_resolver_hash": "sha256:egress",
                "ctee_egress_resolution_status": "rust_ctee_outbound_egress_resolved",
            }),
        ))
        .expect("hosted download plan");

        assert_eq!(plan.record_dir, "model-downloads");
        assert_eq!(plan.record["status"], "completed");
        assert_eq!(
            plan.record["details"]["download_materialization_status"],
            "rust_hosted_download_materialized"
        );
        assert_eq!(plan.record["details"]["network_transfer_executed"], true);
        assert_eq!(plan.record["details"]["plaintext_payload_returned"], false);
        assert_eq!(plan.record["details"]["artifact_bytes_returned"], false);
        assert_eq!(
            plan.record["details"]["hosted_download_transport_status"],
            "rust_hosted_download_transport_response_bound"
        );
        assert_eq!(
            plan.record["details"]["download_content_hash"],
            expected_checksum
        );
        assert!(
            plan.record["details"]["hosted_download_transport_request_hash"]
                .as_str()
                .expect("request hash")
                .starts_with("sha256:")
        );
        assert!(plan
            .evidence_refs
            .contains(&"rust_hosted_download_materialized".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"ctee_hosted_download_no_plaintext_custody".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"rust_ctee_egress_resolver_bound".to_string()));
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
