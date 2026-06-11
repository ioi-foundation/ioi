use serde::{Deserialize, Serialize};

use super::super::{
    non_empty_string, require_non_empty, trimmed_string, ModelMountError,
    MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountBackendLifecycleRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    pub backend_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountBackendLifecycleRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub backend_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_kind: Option<String>,
    pub source: String,
    pub evidence_refs: Vec<String>,
    pub details: serde_json::Value,
    pub generated_at: String,
}

impl ModelMountBackendLifecycleRequiredRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        require_non_empty("backend_id", &self.backend_id)?;
        Ok(())
    }
}

pub(super) fn plan_backend_lifecycle_required(
    request: &ModelMountBackendLifecycleRequiredRequest,
) -> Result<ModelMountBackendLifecycleRequiredRecord, ModelMountError> {
    request.validate()?;
    let operation = trimmed_string(&request.operation, "operation")?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let backend_id = trimmed_string(&request.backend_id, "backend_id")?;
    let backend_kind = request
        .backend_kind
        .as_ref()
        .and_then(|value| non_empty_string(value));
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_backend_lifecycle_required_command".to_string());
    let evidence_refs = if request.evidence_refs.is_empty() {
        vec![
            "public_backend_lifecycle_js_facade_retired".to_string(),
            "rust_daemon_core_lifecycle_required".to_string(),
            "agentgres_backend_lifecycle_truth_required".to_string(),
        ]
    } else {
        request.evidence_refs.clone()
    };
    let details = serde_json::json!({
        "backend_id": backend_id.clone(),
        "backend_kind": backend_kind.clone(),
        "operation": operation.clone(),
        "operation_kind": operation_kind.clone(),
        "rust_core_boundary": "model_mount.backend_lifecycle",
        "source": source.clone(),
        "evidence_refs": evidence_refs.clone(),
    });
    Ok(ModelMountBackendLifecycleRequiredRecord {
        schema_version: MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_backend_lifecycle_required".to_string(),
        status: "rust_core_required".to_string(),
        status_code: 501,
        code: "model_mount_backend_lifecycle_rust_core_required".to_string(),
        message: "Backend lifecycle facade control requires Rust daemon-core model_mount lifecycle ownership.".to_string(),
        rust_core_boundary: "model_mount.backend_lifecycle".to_string(),
        operation,
        operation_kind,
        backend_id,
        backend_kind,
        source,
        evidence_refs,
        details,
        generated_at: "rust_model_mount_core".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_lifecycle_required_is_planned_in_rust_model_mount() {
        let record = plan_backend_lifecycle_required(&ModelMountBackendLifecycleRequiredRequest {
            schema_version: MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION
                .to_string(),
            operation: "model_mount.backend_lifecycle".to_string(),
            operation_kind: "model_mount.backend.start".to_string(),
            backend_id: "backend.llama_cpp".to_string(),
            backend_kind: None,
            source: Some("runtime-daemon.model_mounting.backend_lifecycle".to_string()),
            evidence_refs: vec![],
        })
        .expect("backend lifecycle required record");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.model_mount_backend_lifecycle_required");
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(
            record.code,
            "model_mount_backend_lifecycle_rust_core_required"
        );
        assert_eq!(record.backend_id, "backend.llama_cpp");
        assert_eq!(record.backend_kind, None);
        assert_eq!(record.operation_kind, "model_mount.backend.start");
        assert_eq!(record.rust_core_boundary, "model_mount.backend_lifecycle");
        assert_eq!(record.details["backend_id"], "backend.llama_cpp");
        assert_eq!(record.details["backend_kind"], serde_json::Value::Null);
        assert_eq!(
            record.details["operation_kind"],
            "model_mount.backend.start"
        );
        assert!(record
            .evidence_refs
            .contains(&"public_backend_lifecycle_js_facade_retired".to_string()));
        assert!(record.details.get("backendId").is_none());
        assert!(record.details.get("operationKind").is_none());
    }
}
