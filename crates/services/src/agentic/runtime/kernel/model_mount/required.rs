use serde::{Deserialize, Serialize};

use super::{
    non_empty_string, require_non_empty, trimmed_string, ModelMountError,
    MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_SERVER_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_SERVER_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION,
    MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_TOKENIZER_REQUIRED_RESULT_SCHEMA_VERSION,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountServerControlRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountServerControlRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub source: String,
    pub evidence_refs: Vec<String>,
    pub details: serde_json::Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountRuntimeEngineRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountRuntimeEngineRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    pub source: String,
    pub evidence_refs: Vec<String>,
    pub details: serde_json::Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountTokenizerRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountTokenizerRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub source: String,
    pub evidence_refs: Vec<String>,
    pub details: serde_json::Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountRouteControlRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMountRouteControlRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
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

impl ModelMountServerControlRequiredRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_SERVER_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_SERVER_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.details.is_null() && !self.details.is_object() {
            return Err(ModelMountError::MissingField("details"));
        }
        Ok(())
    }
}

impl ModelMountRuntimeEngineRequiredRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.details.is_null() && !self.details.is_object() {
            return Err(ModelMountError::MissingField("details"));
        }
        Ok(())
    }
}

impl ModelMountTokenizerRequiredRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        if !self.details.is_null() && !self.details.is_object() {
            return Err(ModelMountError::MissingField("details"));
        }
        Ok(())
    }
}

impl ModelMountRouteControlRequiredRequest {
    pub fn validate(&self) -> Result<(), ModelMountError> {
        if self.schema_version != MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(ModelMountError::InvalidSchemaVersion {
                expected: MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("operation", &self.operation)?;
        require_non_empty("operation_kind", &self.operation_kind)?;
        if !self.details.is_null() && !self.details.is_object() {
            return Err(ModelMountError::MissingField("details"));
        }
        Ok(())
    }
}

pub fn plan_backend_lifecycle_required(
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

pub fn plan_server_control_required(
    request: &ModelMountServerControlRequiredRequest,
) -> Result<ModelMountServerControlRequiredRecord, ModelMountError> {
    request.validate()?;
    let operation = trimmed_string(&request.operation, "operation")?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_server_control_required_command".to_string());
    let evidence_refs = if request.evidence_refs.is_empty() {
        vec![
            "public_server_control_js_facade_retired".to_string(),
            "rust_daemon_core_server_control_required".to_string(),
            "agentgres_server_control_truth_required".to_string(),
        ]
    } else {
        request.evidence_refs.clone()
    };
    let mut details = serde_json::Map::new();
    if let Some(request_details) = request.details.as_object() {
        details.extend(request_details.clone());
    }
    details
        .entry("operation".to_string())
        .or_insert_with(|| serde_json::Value::String(operation.clone()));
    details.insert(
        "operation_kind".to_string(),
        serde_json::Value::String(operation_kind.clone()),
    );
    details.insert(
        "rust_core_boundary".to_string(),
        serde_json::Value::String("model_mount.server_control".to_string()),
    );
    details.insert(
        "source".to_string(),
        serde_json::Value::String(source.clone()),
    );
    details.insert(
        "evidence_refs".to_string(),
        serde_json::Value::Array(
            evidence_refs
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    Ok(ModelMountServerControlRequiredRecord {
        schema_version: MODEL_MOUNT_SERVER_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_server_control_required".to_string(),
        status: "rust_core_required".to_string(),
        status_code: 501,
        code: "model_mount_server_control_rust_core_required".to_string(),
        message:
            "Server-control facade requires Rust daemon-core model_mount server-control ownership."
                .to_string(),
        rust_core_boundary: "model_mount.server_control".to_string(),
        operation,
        operation_kind,
        source,
        evidence_refs,
        details: serde_json::Value::Object(details),
        generated_at: "rust_model_mount_core".to_string(),
    })
}

pub fn plan_runtime_engine_required(
    request: &ModelMountRuntimeEngineRequiredRequest,
) -> Result<ModelMountRuntimeEngineRequiredRecord, ModelMountError> {
    request.validate()?;
    let operation = trimmed_string(&request.operation, "operation")?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_runtime_engine_required_command".to_string());
    let evidence_refs = if request.evidence_refs.is_empty() {
        vec![
            "public_runtime_engine_js_facade_retired".to_string(),
            "rust_daemon_core_runtime_engine_required".to_string(),
            "agentgres_runtime_engine_truth_required".to_string(),
        ]
    } else {
        request.evidence_refs.clone()
    };
    let mut details = serde_json::Map::new();
    if let Some(request_details) = request.details.as_object() {
        details.extend(request_details.clone());
    }
    details
        .entry("operation".to_string())
        .or_insert_with(|| serde_json::Value::String(operation.clone()));
    details.insert(
        "operation_kind".to_string(),
        serde_json::Value::String(operation_kind.clone()),
    );
    details.insert(
        "rust_core_boundary".to_string(),
        serde_json::Value::String("model_mount.runtime_engine".to_string()),
    );
    details.insert(
        "source".to_string(),
        serde_json::Value::String(source.clone()),
    );
    details.insert(
        "evidence_refs".to_string(),
        serde_json::Value::Array(
            evidence_refs
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    Ok(ModelMountRuntimeEngineRequiredRecord {
        schema_version: MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_runtime_engine_required".to_string(),
        status: "rust_core_required".to_string(),
        status_code: 501,
        code: "model_mount_runtime_engine_rust_core_required".to_string(),
        message:
            "Runtime-engine mutation facade requires Rust daemon-core model_mount runtime-engine ownership."
                .to_string(),
        rust_core_boundary: "model_mount.runtime_engine".to_string(),
        operation,
        operation_kind,
        source,
        evidence_refs,
        details: serde_json::Value::Object(details),
        generated_at: "rust_model_mount_core".to_string(),
    })
}

pub fn plan_tokenizer_required(
    request: &ModelMountTokenizerRequiredRequest,
) -> Result<ModelMountTokenizerRequiredRecord, ModelMountError> {
    request.validate()?;
    let operation = trimmed_string(&request.operation, "operation")?;
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_tokenizer_required_command".to_string());
    let evidence_refs = if request.evidence_refs.is_empty() {
        vec![
            "model_mount_tokenizer_js_facade_retired".to_string(),
            "model_mount_context_fit_js_facade_retired".to_string(),
            "rust_daemon_core_model_tokenizer_required".to_string(),
            "rust_daemon_core_model_context_fit_required".to_string(),
            "agentgres_model_tokenizer_truth_required".to_string(),
        ]
    } else {
        request.evidence_refs.clone()
    };
    let mut details = serde_json::Map::new();
    if let Some(request_details) = request.details.as_object() {
        details.extend(request_details.clone());
    }
    details
        .entry("operation".to_string())
        .or_insert_with(|| serde_json::Value::String(operation.clone()));
    details.insert(
        "rust_core_boundary".to_string(),
        serde_json::Value::String("model_mount.tokenizer".to_string()),
    );
    details.insert(
        "source".to_string(),
        serde_json::Value::String(source.clone()),
    );
    details.insert(
        "evidence_refs".to_string(),
        serde_json::Value::Array(
            evidence_refs
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    Ok(ModelMountTokenizerRequiredRecord {
        schema_version: MODEL_MOUNT_TOKENIZER_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_tokenizer_required".to_string(),
        status: "rust_core_required".to_string(),
        status_code: 501,
        code: "model_mount_tokenizer_rust_core_required".to_string(),
        message:
            "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection."
                .to_string(),
        rust_core_boundary: "model_mount.tokenizer".to_string(),
        operation,
        source,
        evidence_refs,
        details: serde_json::Value::Object(details),
        generated_at: "rust_model_mount_core".to_string(),
    })
}

pub fn plan_route_control_required(
    request: &ModelMountRouteControlRequiredRequest,
) -> Result<ModelMountRouteControlRequiredRecord, ModelMountError> {
    request.validate()?;
    let operation = trimmed_string(&request.operation, "operation")?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_model_mount_route_control_required_command".to_string());
    let evidence_refs = if request.evidence_refs.is_empty() {
        vec![
            "model_mount_route_control_js_facade_retired".to_string(),
            "rust_daemon_core_route_control_required".to_string(),
            "agentgres_route_truth_required".to_string(),
        ]
    } else {
        request.evidence_refs.clone()
    };
    let mut details = serde_json::Map::new();
    if let Some(request_details) = request.details.as_object() {
        details.extend(request_details.clone());
    }
    details
        .entry("operation".to_string())
        .or_insert_with(|| serde_json::Value::String(operation.clone()));
    details.insert(
        "operation_kind".to_string(),
        serde_json::Value::String(operation_kind.clone()),
    );
    details.insert(
        "rust_core_boundary".to_string(),
        serde_json::Value::String("model_mount.route_control".to_string()),
    );
    details.insert(
        "source".to_string(),
        serde_json::Value::String(source.clone()),
    );
    details.insert(
        "evidence_refs".to_string(),
        serde_json::Value::Array(
            evidence_refs
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    Ok(ModelMountRouteControlRequiredRecord {
        schema_version: MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION.to_string(),
        object: "ioi.model_mount_route_control_required".to_string(),
        status: "rust_core_required".to_string(),
        status_code: 501,
        code: "model_mount_route_control_rust_core_required".to_string(),
        message: "Model route control requires Rust daemon-core ownership.".to_string(),
        rust_core_boundary: "model_mount.route_control".to_string(),
        operation,
        operation_kind,
        source,
        evidence_refs,
        details: serde_json::Value::Object(details),
        generated_at: "rust_model_mount_core".to_string(),
    })
}
