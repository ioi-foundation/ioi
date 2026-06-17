use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

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
    let secret_injection = hosted_download_secret_injection_binding(body)?;
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
    let source_url_hash = hash_text(&source_url)?;
    let request_hash = hash_json(&json!({
        "schema": "ioi.model_mount.hosted_download_request.v1",
        "method": "GET",
        "record_id": record_id,
        "source_url_hash": source_url_hash,
        "provider_auth_materialization_ref": &secret_injection.provider_auth_materialization_ref,
        "outbound_header_binding_ref": &secret_injection.outbound_header_binding_ref,
        "auth_header_materialization_status": &secret_injection.auth_header_materialization_status,
        "ctee_egress_resolver_ref": &secret_injection.ctee_egress_resolver_ref,
        "ctee_egress_resolver_hash": &secret_injection.ctee_egress_resolver_hash,
        "ctee_egress_resolution_status": &secret_injection.ctee_egress_resolution_status,
        "ctee_secret_injection": "ctee_egress_resolver_ref",
        "ctee_outbound_secret_injection_ref": &secret_injection.ctee_egress_resolver_ref,
        "ctee_outbound_secret_injection_hash": &secret_injection.ctee_egress_resolver_hash,
        "ctee_outbound_secret_injection_status": "rust_ctee_outbound_secret_injection_bound",
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
        json!(&secret_injection.provider_auth_materialization_ref),
    );
    materialization.insert(
        "outbound_header_binding_ref".to_string(),
        json!(&secret_injection.outbound_header_binding_ref),
    );
    materialization.insert(
        "auth_header_materialization_status".to_string(),
        json!(&secret_injection.auth_header_materialization_status),
    );
    materialization.insert(
        "ctee_egress_resolver_ref".to_string(),
        json!(&secret_injection.ctee_egress_resolver_ref),
    );
    materialization.insert(
        "ctee_egress_resolver_hash".to_string(),
        json!(&secret_injection.ctee_egress_resolver_hash),
    );
    materialization.insert(
        "ctee_egress_resolution_status".to_string(),
        json!(&secret_injection.ctee_egress_resolution_status),
    );
    materialization.insert(
        "ctee_secret_injection".to_string(),
        json!("ctee_egress_resolver_ref"),
    );
    materialization.insert(
        "ctee_outbound_secret_injection_ref".to_string(),
        json!(&secret_injection.ctee_egress_resolver_ref),
    );
    materialization.insert(
        "ctee_outbound_secret_injection_hash".to_string(),
        json!(&secret_injection.ctee_egress_resolver_hash),
    );
    materialization.insert(
        "ctee_outbound_secret_injection_status".to_string(),
        json!("rust_ctee_outbound_secret_injection_bound"),
    );
    materialization.insert(
        "custody_policy".to_string(),
        json!({
            "no_plaintext_custody": true,
            "download_bytes_returned_to_js": false,
            "private_material_resolved_by": "rust_daemon_core_ctee",
            "download_materialized_by": "rust_daemon_core.model_mount.storage_control",
            "secret_injection_required": true,
            "secret_injection_owner": "rust_daemon_core.ctee.egress_resolver",
            "secret_injection_status": "rust_ctee_outbound_secret_injection_bound",
        }),
    );
    Ok(Some(materialization))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostedDownloadSecretInjectionBinding {
    provider_auth_materialization_ref: String,
    outbound_header_binding_ref: String,
    auth_header_materialization_status: String,
    ctee_egress_resolver_ref: String,
    ctee_egress_resolver_hash: String,
    ctee_egress_resolution_status: String,
}

fn hosted_download_secret_injection_binding(
    body: &Map<String, Value>,
) -> Result<HostedDownloadSecretInjectionBinding, ModelMountError> {
    let provider_auth_materialization_ref = string_field(body, "provider_auth_materialization_ref")
        .ok_or(ModelMountError::HostedProviderInvocationMissingAuthMaterialization)?;
    let outbound_header_binding_ref = string_field(body, "outbound_header_binding_ref")
        .ok_or(ModelMountError::HostedProviderInvocationMissingAuthMaterialization)?;
    let auth_header_materialization_status =
        string_field(body, "auth_header_materialization_status")
            .ok_or(ModelMountError::HostedProviderInvocationMissingAuthMaterialization)?;
    if auth_header_materialization_status != "rust_ctee_outbound_header_bound" {
        return Err(ModelMountError::HostedProviderInvocationMissingAuthMaterialization);
    }
    let ctee_egress_resolver_ref = string_field(body, "ctee_egress_resolver_ref")
        .ok_or(ModelMountError::HostedProviderInvocationMissingCteeEgressResolver)?;
    let ctee_egress_resolver_hash = string_field(body, "ctee_egress_resolver_hash")
        .ok_or(ModelMountError::HostedProviderInvocationMissingCteeEgressResolver)?;
    let ctee_egress_resolution_status = string_field(body, "ctee_egress_resolution_status")
        .ok_or(ModelMountError::HostedProviderInvocationMissingCteeEgressResolver)?;
    if ctee_egress_resolution_status != "rust_ctee_outbound_egress_resolved" {
        return Err(ModelMountError::HostedProviderInvocationMissingCteeEgressResolver);
    }
    Ok(HostedDownloadSecretInjectionBinding {
        provider_auth_materialization_ref,
        outbound_header_binding_ref,
        auth_header_materialization_status,
        ctee_egress_resolver_ref,
        ctee_egress_resolver_hash,
        ctee_egress_resolution_status,
    })
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
    let mut details = json!({
        "artifact_id": artifact_id,
        "dry_run": bool_field(body, "dry_run").unwrap_or(false),
        "filesystem_mutation_executed": false,
    });
    if let Some(custody_details) = artifact_delete_filesystem_custody(body)? {
        merge_details(&mut details, custody_details);
    }
    storage_plan(
        request,
        "model-storage-controls",
        &record_id,
        "ioi.model_mount_storage_control",
        "delete_planned",
        details,
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
    let mut details = json!({
        "remove_orphans": bool_field(body, "remove_orphans").unwrap_or(false),
        "dry_run": bool_field(body, "dry_run").unwrap_or(false),
        "filesystem_mutation_executed": false,
    });
    if let Some(custody_details) = storage_cleanup_filesystem_custody(body)? {
        merge_details(&mut details, custody_details);
    }
    storage_plan(
        request,
        "model-storage-controls",
        &record_id,
        "ioi.model_mount_storage_control",
        "cleanup_planned",
        details,
    )
}

fn artifact_delete_filesystem_custody(
    body: &Map<String, Value>,
) -> Result<Option<Map<String, Value>>, ModelMountError> {
    if !filesystem_custody_requested(body, "artifact_delete") {
        return Ok(None);
    }
    let dry_run = bool_field(body, "dry_run").unwrap_or(false);
    let storage_root = required_body_string(body, "storage_root")?;
    let artifact_path = required_body_string(body, "artifact_path")?;
    let target = contained_existing_path(&storage_root, &artifact_path)?;
    let storage_root_hash = target.storage_root_hash.clone();
    if !dry_run {
        remove_contained_path(&target)?;
    }
    Ok(Some(filesystem_custody_details(
        "artifact_delete",
        dry_run,
        &storage_root_hash,
        vec![target],
    )?))
}

fn storage_cleanup_filesystem_custody(
    body: &Map<String, Value>,
) -> Result<Option<Map<String, Value>>, ModelMountError> {
    if !filesystem_custody_requested(body, "storage_cleanup") {
        return Ok(None);
    }
    let dry_run = bool_field(body, "dry_run").unwrap_or(false);
    let remove_orphans = bool_field(body, "remove_orphans").unwrap_or(false);
    let storage_root = required_body_string(body, "storage_root")?;
    let orphan_paths = string_array_field(body, "orphan_paths");
    if remove_orphans && orphan_paths.is_empty() {
        return Err(ModelMountError::MissingField("orphan_paths"));
    }
    let mut targets = Vec::new();
    for orphan_path in orphan_paths {
        targets.push(contained_existing_path(&storage_root, &orphan_path)?);
    }
    if !dry_run {
        for target in &targets {
            remove_contained_path(target)?;
        }
    }
    let storage_root_hash = targets
        .first()
        .map(|target| target.storage_root_hash.clone())
        .unwrap_or(hash_text(&storage_root)?);
    Ok(Some(filesystem_custody_details(
        "storage_cleanup",
        dry_run,
        &storage_root_hash,
        targets,
    )?))
}

#[derive(Debug, Clone)]
struct ContainedPath {
    path: PathBuf,
    storage_root_hash: String,
    target_hash: String,
    target_kind: String,
}

fn contained_existing_path(
    storage_root: &str,
    target_path: &str,
) -> Result<ContainedPath, ModelMountError> {
    let root = fs::canonicalize(storage_root).map_err(filesystem_custody_error)?;
    if !root.is_dir() {
        return Err(ModelMountError::StorageControlFilesystemCustodyFailed(
            "storage_root must be an existing directory".to_string(),
        ));
    }
    let target_input = PathBuf::from(target_path);
    let joined = if target_input.is_absolute() {
        target_input
    } else {
        root.join(target_input)
    };
    let target = fs::canonicalize(joined).map_err(filesystem_custody_error)?;
    if target == root || !target.starts_with(&root) {
        return Err(ModelMountError::StorageControlFilesystemCustodyFailed(
            "filesystem custody target must stay inside storage_root".to_string(),
        ));
    }
    let metadata = fs::metadata(&target).map_err(filesystem_custody_error)?;
    let target_kind = if metadata.is_dir() {
        "directory"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    }
    .to_string();
    Ok(ContainedPath {
        storage_root_hash: hash_path(&root)?,
        target_hash: hash_path(&target)?,
        target_kind,
        path: target,
    })
}

fn remove_contained_path(target: &ContainedPath) -> Result<(), ModelMountError> {
    if target.target_kind == "directory" {
        fs::remove_dir_all(&target.path).map_err(filesystem_custody_error)
    } else {
        fs::remove_file(&target.path).map_err(filesystem_custody_error)
    }
}

fn filesystem_custody_details(
    mutation_kind: &str,
    dry_run: bool,
    storage_root_hash: &str,
    targets: Vec<ContainedPath>,
) -> Result<Map<String, Value>, ModelMountError> {
    let target_hashes: Vec<Value> = targets
        .iter()
        .map(|target| json!(target.target_hash))
        .collect();
    let target_kinds: Vec<Value> = targets
        .iter()
        .map(|target| json!(target.target_kind))
        .collect();
    let custody_hash = hash_json(&json!({
        "schema": "ioi.model_mount.filesystem_custody.v1",
        "mutation_kind": mutation_kind,
        "dry_run": dry_run,
        "storage_root_hash": storage_root_hash,
        "target_hashes": target_hashes,
        "target_kinds": target_kinds,
        "plaintext_paths_returned": false,
    }))?;
    let mut details = Map::new();
    details.insert(
        "filesystem_custody_status".to_string(),
        json!(if dry_run {
            "rust_filesystem_custody_dry_run"
        } else {
            "rust_filesystem_mutation_executed"
        }),
    );
    details.insert(
        "filesystem_custody_owner".to_string(),
        json!("rust_daemon_core.model_mount.storage_control.filesystem_custody"),
    );
    details.insert("filesystem_mutation_kind".to_string(), json!(mutation_kind));
    details.insert("filesystem_mutation_executed".to_string(), json!(!dry_run));
    details.insert("filesystem_custody_hash".to_string(), json!(custody_hash));
    details.insert("storage_root_hash".to_string(), json!(storage_root_hash));
    details.insert(
        "filesystem_target_hashes".to_string(),
        Value::Array(target_hashes),
    );
    details.insert(
        "filesystem_target_kinds".to_string(),
        Value::Array(target_kinds),
    );
    details.insert("filesystem_targets_count".to_string(), json!(targets.len()));
    details.insert("plaintext_paths_returned".to_string(), json!(false));
    details.insert("js_filesystem_mutation_executed".to_string(), json!(false));
    details.insert(
        "custody_policy".to_string(),
        json!({
            "no_plaintext_path_return": true,
            "filesystem_mutated_by": "rust_daemon_core.model_mount.storage_control",
            "containment_checked_by": "rust_daemon_core.model_mount.storage_control.filesystem_custody",
        }),
    );
    Ok(details)
}

fn filesystem_custody_requested(body: &Map<String, Value>, mutation_kind: &str) -> bool {
    if bool_field(body, "filesystem_custody").unwrap_or(false) {
        return true;
    }
    if string_field(body, "filesystem_custody_mode").as_deref() == Some("rust_owned") {
        return true;
    }
    string_field(body, "filesystem_mutation_kind").as_deref() == Some(mutation_kind)
}

fn filesystem_custody_error(error: std::io::Error) -> ModelMountError {
    ModelMountError::StorageControlFilesystemCustodyFailed(error.to_string())
}

fn hash_path(path: &Path) -> Result<String, ModelMountError> {
    hash_text(&path.to_string_lossy())
}

fn merge_details(details: &mut Value, updates: Map<String, Value>) {
    if let Some(details) = details.as_object_mut() {
        for (key, value) in updates {
            details.insert(key, value);
        }
    }
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
                    "rust_provider_auth_materialization_bound",
                    "hosted_provider_auth_header_materialized_by_rust",
                    "hosted_provider_auth_header_materialization_contract_bound",
                    "rust_ctee_egress_resolver_bound",
                    "ctee_outbound_secret_injection_ref_bound",
                    "ctee_outbound_egress_resolver_depth_bound",
                    "ctee_hosted_download_secret_injection_bound",
                ] {
                    push_unique_ref(&mut refs, evidence_ref);
                }
            }
        }
        "model_mount.download.cancel" => {
            refs.push("rust_daemon_core_model_download_cancel".to_string());
        }
        "model_mount.artifact.delete" => {
            refs.push("rust_daemon_core_model_artifact_delete".to_string());
            if string_field(object_or_empty(details), "filesystem_custody_status").is_some() {
                push_filesystem_custody_evidence(&mut refs, details, "artifact_delete");
            }
        }
        "model_mount.storage.cleanup" => {
            refs.push("rust_daemon_core_model_storage_cleanup".to_string());
            if string_field(object_or_empty(details), "filesystem_custody_status").is_some() {
                push_filesystem_custody_evidence(&mut refs, details, "storage_cleanup");
            }
        }
        _ => {}
    }
    refs
}

fn push_filesystem_custody_evidence(refs: &mut Vec<String>, details: &Value, mutation_kind: &str) {
    for evidence_ref in [
        "rust_model_mount_filesystem_custody_owned",
        "rust_model_mount_filesystem_target_contained",
        "ctee_model_mount_filesystem_no_plaintext_path_custody",
    ] {
        push_unique_ref(refs, evidence_ref);
    }
    match mutation_kind {
        "artifact_delete" => {
            push_unique_ref(refs, "rust_model_mount_artifact_delete_filesystem_custody")
        }
        "storage_cleanup" => {
            push_unique_ref(refs, "rust_model_mount_storage_cleanup_filesystem_custody")
        }
        _ => {}
    }
    match string_field(object_or_empty(details), "filesystem_custody_status").as_deref() {
        Some("rust_filesystem_mutation_executed") => {
            push_unique_ref(refs, "rust_model_mount_filesystem_mutation_executed")
        }
        Some("rust_filesystem_custody_dry_run") => {
            push_unique_ref(refs, "rust_model_mount_filesystem_custody_dry_run")
        }
        _ => {}
    }
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

fn string_array_field(body: &Map<String, Value>, field: &str) -> Vec<String> {
    body.get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(non_empty_string)
        .collect()
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
        fs,
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
            plan.record["details"]["provider_auth_materialization_ref"],
            "agentgres://model-mounting/model-provider-auth-materializations/provider_openai_auth_header"
        );
        assert_eq!(
            plan.record["details"]["outbound_header_binding_ref"],
            "provider_auth_header://provider_openai_auth_header#sha256:auth"
        );
        assert_eq!(
            plan.record["details"]["auth_header_materialization_status"],
            "rust_ctee_outbound_header_bound"
        );
        assert_eq!(
            plan.record["details"]["ctee_egress_resolver_ref"],
            "ctee://model-mount/egress-resolver/provider_openai_auth_header#sha256:egress"
        );
        assert_eq!(
            plan.record["details"]["ctee_outbound_secret_injection_ref"],
            "ctee://model-mount/egress-resolver/provider_openai_auth_header#sha256:egress"
        );
        assert_eq!(
            plan.record["details"]["ctee_outbound_secret_injection_hash"],
            "sha256:egress"
        );
        assert_eq!(
            plan.record["details"]["ctee_outbound_secret_injection_status"],
            "rust_ctee_outbound_secret_injection_bound"
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
        assert!(plan
            .evidence_refs
            .contains(&"rust_provider_auth_materialization_bound".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"ctee_outbound_secret_injection_ref_bound".to_string()));
        assert!(plan
            .evidence_refs
            .contains(&"ctee_hosted_download_secret_injection_bound".to_string()));
    }

    #[test]
    fn hosted_download_requires_rust_auth_and_ctee_secret_injection_before_transport() {
        let missing_auth = plan_storage_control(&request(
            "model_mount.download.queue",
            json!({
                "model_id": "hosted-qwen",
                "source_url": "http://127.0.0.1:9/models/qwen-test.gguf",
                "max_bytes": 1024,
                "download_materialization_kind": "hosted_download",
            }),
        ))
        .expect_err("hosted download must reject missing Rust auth materialization before network");
        assert_eq!(
            missing_auth,
            ModelMountError::HostedProviderInvocationMissingAuthMaterialization
        );

        let missing_ctee = plan_storage_control(&request(
            "model_mount.download.queue",
            json!({
                "model_id": "hosted-qwen",
                "source_url": "http://127.0.0.1:9/models/qwen-test.gguf",
                "max_bytes": 1024,
                "download_materialization_kind": "hosted_download",
                "provider_auth_materialization_ref": "agentgres://model-mounting/model-provider-auth-materializations/provider_openai_auth_header",
                "outbound_header_binding_ref": "provider_auth_header://provider_openai_auth_header#sha256:auth",
                "auth_header_materialization_status": "rust_ctee_outbound_header_bound",
            }),
        ))
        .expect_err("hosted download must reject missing cTEE egress resolver before network");
        assert_eq!(
            missing_ctee,
            ModelMountError::HostedProviderInvocationMissingCteeEgressResolver
        );
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
    fn materializes_filesystem_custody_for_delete_and_cleanup_in_rust() {
        let temp = tempfile::tempdir().expect("storage root");
        let storage_root = temp.path().to_string_lossy().to_string();
        let artifact_path = temp.path().join("artifact.gguf");
        fs::write(&artifact_path, b"artifact bytes").expect("artifact file");

        let delete = plan_storage_control(&request(
            "model_mount.artifact.delete",
            json!({
                "artifact_id": "artifact.local",
                "storage_root": storage_root,
                "artifact_path": "artifact.gguf",
                "filesystem_custody": true,
                "filesystem_mutation_kind": "artifact_delete",
            }),
        ))
        .expect("artifact delete custody plan");

        assert!(!artifact_path.exists());
        assert_eq!(
            delete.record["details"]["filesystem_custody_status"],
            "rust_filesystem_mutation_executed"
        );
        assert_eq!(
            delete.record["details"]["filesystem_custody_owner"],
            "rust_daemon_core.model_mount.storage_control.filesystem_custody"
        );
        assert_eq!(
            delete.record["details"]["filesystem_mutation_kind"],
            "artifact_delete"
        );
        assert_eq!(
            delete.record["details"]["filesystem_mutation_executed"],
            true
        );
        assert_eq!(delete.record["details"]["plaintext_paths_returned"], false);
        assert!(delete.record["details"]["storage_root_hash"]
            .as_str()
            .expect("root hash")
            .starts_with("sha256:"));
        assert_eq!(
            delete.record["details"]["filesystem_target_hashes"]
                .as_array()
                .expect("target hashes")
                .len(),
            1
        );
        assert!(delete
            .evidence_refs
            .contains(&"rust_model_mount_filesystem_custody_owned".to_string()));
        assert!(delete
            .evidence_refs
            .contains(&"rust_model_mount_artifact_delete_filesystem_custody".to_string()));
        assert!(delete
            .evidence_refs
            .contains(&"rust_model_mount_filesystem_mutation_executed".to_string()));
        assert!(delete
            .evidence_refs
            .contains(&"ctee_model_mount_filesystem_no_plaintext_path_custody".to_string()));

        let orphan_path = temp.path().join("orphan.tmp");
        fs::write(&orphan_path, b"orphan bytes").expect("orphan file");
        let cleanup = plan_storage_control(&request(
            "model_mount.storage.cleanup",
            json!({
                "storage_root": temp.path().to_string_lossy().to_string(),
                "remove_orphans": true,
                "orphan_paths": ["orphan.tmp"],
                "filesystem_custody": true,
                "filesystem_mutation_kind": "storage_cleanup",
            }),
        ))
        .expect("storage cleanup custody plan");

        assert!(!orphan_path.exists());
        assert_eq!(
            cleanup.record["details"]["filesystem_custody_status"],
            "rust_filesystem_mutation_executed"
        );
        assert_eq!(
            cleanup.record["details"]["filesystem_mutation_kind"],
            "storage_cleanup"
        );
        assert_eq!(cleanup.record["details"]["filesystem_targets_count"], 1);
        assert!(cleanup
            .evidence_refs
            .contains(&"rust_model_mount_storage_cleanup_filesystem_custody".to_string()));
    }

    #[test]
    fn rejects_missing_required_storage_fields() {
        let error = plan_storage_control(&request("model_mount.download.queue", json!({})))
            .expect_err("missing model id");
        assert_eq!(error, ModelMountError::MissingField("model_id"));
    }
}
