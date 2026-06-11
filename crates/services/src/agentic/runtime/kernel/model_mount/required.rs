mod backend_lifecycle;
mod route_control;
mod runtime_engine;
mod server_control;
mod tokenizer;

use serde::Deserialize;
use serde_json::{json, Value};

pub use backend_lifecycle::{
    ModelMountBackendLifecycleRequiredRecord, ModelMountBackendLifecycleRequiredRequest,
};
pub use route_control::{
    ModelMountRouteControlRequiredRecord, ModelMountRouteControlRequiredRequest,
};
pub use runtime_engine::{
    ModelMountRuntimeEngineRequiredRecord, ModelMountRuntimeEngineRequiredRequest,
};
pub use server_control::{
    ModelMountServerControlRequiredRecord, ModelMountServerControlRequiredRequest,
};
pub use tokenizer::{ModelMountTokenizerRequiredRecord, ModelMountTokenizerRequiredRequest};

use super::ModelMountError;

#[derive(Debug, Deserialize)]
pub struct ModelMountBackendLifecycleRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountBackendLifecycleRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountServerControlRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountServerControlRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountRuntimeEngineRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountRuntimeEngineRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountTokenizerRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountTokenizerRequiredRequest,
}

#[derive(Debug, Deserialize)]
pub struct ModelMountRouteControlRequiredBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountRouteControlRequiredRequest,
}

pub fn plan_backend_lifecycle_required(
    request: &ModelMountBackendLifecycleRequiredRequest,
) -> Result<ModelMountBackendLifecycleRequiredRecord, ModelMountError> {
    backend_lifecycle::plan_backend_lifecycle_required(request)
}

pub fn plan_server_control_required(
    request: &ModelMountServerControlRequiredRequest,
) -> Result<ModelMountServerControlRequiredRecord, ModelMountError> {
    server_control::plan_server_control_required(request)
}

pub fn plan_runtime_engine_required(
    request: &ModelMountRuntimeEngineRequiredRequest,
) -> Result<ModelMountRuntimeEngineRequiredRecord, ModelMountError> {
    runtime_engine::plan_runtime_engine_required(request)
}

pub fn plan_tokenizer_required(
    request: &ModelMountTokenizerRequiredRequest,
) -> Result<ModelMountTokenizerRequiredRecord, ModelMountError> {
    tokenizer::plan_tokenizer_required(request)
}

pub fn plan_route_control_required(
    request: &ModelMountRouteControlRequiredRequest,
) -> Result<ModelMountRouteControlRequiredRecord, ModelMountError> {
    route_control::plan_route_control_required(request)
}

pub fn plan_model_mount_backend_lifecycle_required_response(
    request: ModelMountBackendLifecycleRequiredBridgeRequest,
) -> Result<Value, ModelMountError> {
    let record = plan_backend_lifecycle_required(&request.request)?;
    Ok(json!({
        "source": "rust_model_mount_backend_lifecycle_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_backend_lifecycle_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation_kind": record.operation_kind,
        "details": record.details,
    }))
}

pub fn plan_model_mount_server_control_required_response(
    request: ModelMountServerControlRequiredBridgeRequest,
) -> Result<Value, ModelMountError> {
    let record = plan_server_control_required(&request.request)?;
    Ok(json!({
        "source": "rust_model_mount_server_control_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_server_control_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation_kind": record.operation_kind,
        "details": record.details,
    }))
}

pub fn plan_model_mount_runtime_engine_required_response(
    request: ModelMountRuntimeEngineRequiredBridgeRequest,
) -> Result<Value, ModelMountError> {
    let record = plan_runtime_engine_required(&request.request)?;
    Ok(json!({
        "source": "rust_model_mount_runtime_engine_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_runtime_engine_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation_kind": record.operation_kind,
        "details": record.details,
    }))
}

pub fn plan_model_mount_tokenizer_required_response(
    request: ModelMountTokenizerRequiredBridgeRequest,
) -> Result<Value, ModelMountError> {
    let record = plan_tokenizer_required(&request.request)?;
    Ok(json!({
        "source": "rust_model_mount_tokenizer_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_tokenizer_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation": record.operation,
        "details": record.details,
    }))
}

pub fn plan_model_mount_route_control_required_response(
    request: ModelMountRouteControlRequiredBridgeRequest,
) -> Result<Value, ModelMountError> {
    let record = plan_route_control_required(&request.request)?;
    Ok(json!({
        "source": "rust_model_mount_route_control_required_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_route_control_required".to_string()),
        "record": record.clone(),
        "status": record.status,
        "status_code": record.status_code,
        "code": record.code,
        "message": record.message,
        "rust_core_boundary": record.rust_core_boundary,
        "operation": record.operation,
        "operation_kind": record.operation_kind,
        "details": record.details,
    }))
}
