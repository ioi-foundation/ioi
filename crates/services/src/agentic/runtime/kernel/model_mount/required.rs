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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::command_protocol::DAEMON_CORE_COMMAND_SCHEMA_VERSION;
    use crate::agentic::runtime::kernel::model_mount::{
        MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION,
        MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
        MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_REQUEST_SCHEMA_VERSION,
        MODEL_MOUNT_SERVER_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
        MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION,
    };

    #[test]
    fn rust_core_shapes_model_mount_backend_lifecycle_required_command_response() {
        let request: ModelMountBackendLifecycleRequiredBridgeRequest =
            serde_json::from_value(json!({
                "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
                "operation": "plan_model_mount_backend_lifecycle_required",
                "backend": "rust_model_mount_backend_lifecycle_required",
                "request": {
                    "schema_version": MODEL_MOUNT_BACKEND_LIFECYCLE_REQUIRED_REQUEST_SCHEMA_VERSION,
                    "operation": "model_mount.backend_lifecycle",
                    "operation_kind": "model_mount.backend.start",
                    "backend_id": "backend.llama_cpp",
                    "source": "runtime-daemon.model_mounting.backend_lifecycle"
                }
            }))
            .expect("backend lifecycle required command request");

        let response = plan_model_mount_backend_lifecycle_required_response(request)
            .expect("backend lifecycle required planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_backend_lifecycle_required_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_backend_lifecycle_required"
        );
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "model_mount_backend_lifecycle_rust_core_required"
        );
        assert_eq!(response["operation_kind"], "model_mount.backend.start");
        assert_eq!(
            response["rust_core_boundary"],
            "model_mount.backend_lifecycle"
        );
        assert_eq!(response["details"]["backend_id"], "backend.llama_cpp");
        assert_eq!(response["details"]["backend_kind"], Value::Null);
        assert!(response["details"].get("backendId").is_none());
        assert!(response["details"].get("operationKind").is_none());
    }

    #[test]
    fn rust_core_shapes_model_mount_server_control_required_command_response() {
        let request: ModelMountServerControlRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_server_control_required",
            "backend": "rust_model_mount_server_control_required",
            "request": {
                "schema_version": MODEL_MOUNT_SERVER_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
                "operation": "model_mount.server_control",
                "operation_kind": "model_mount.server_control.record_operation",
                "source": "runtime-daemon.model_mounting.server_control",
                "details": {
                    "base_url": "http://daemon.test",
                    "reason": "test",
                    "server_control_id": "server-control.default"
                }
            }
        }))
        .expect("server control required command request");

        let response = plan_model_mount_server_control_required_response(request)
            .expect("server control required planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_server_control_required_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_server_control_required"
        );
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "model_mount_server_control_rust_core_required"
        );
        assert_eq!(
            response["operation_kind"],
            "model_mount.server_control.record_operation"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.server_control");
        assert_eq!(response["details"]["base_url"], "http://daemon.test");
        assert_eq!(
            response["details"]["server_control_id"],
            "server-control.default"
        );
        assert!(response["details"].get("operationKind").is_none());
        assert!(response["details"].get("serverControlId").is_none());
    }

    #[test]
    fn rust_core_shapes_model_mount_runtime_engine_required_command_response() {
        let request: ModelMountRuntimeEngineRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_runtime_engine_required",
            "backend": "rust_model_mount_runtime_engine_required",
            "request": {
                "schema_version": MODEL_MOUNT_RUNTIME_ENGINE_REQUIRED_REQUEST_SCHEMA_VERSION,
                "operation": "model_mount.runtime_engine",
                "operation_kind": "model_mount.runtime_engine_profile.write",
                "source": "runtime-daemon.model_mounting.runtime_engine",
                "details": {
                    "engine_id": "backend.llama-cpp"
                }
            }
        }))
        .expect("runtime engine required command request");

        let response = plan_model_mount_runtime_engine_required_response(request)
            .expect("runtime engine required planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_runtime_engine_required_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_runtime_engine_required"
        );
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "model_mount_runtime_engine_rust_core_required"
        );
        assert_eq!(
            response["operation_kind"],
            "model_mount.runtime_engine_profile.write"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.runtime_engine");
        assert_eq!(response["details"]["engine_id"], "backend.llama-cpp");
        assert!(response["details"].get("engineId").is_none());
        assert!(response["details"].get("operationKind").is_none());
    }

    #[test]
    fn rust_core_shapes_model_mount_tokenizer_required_command_response() {
        let request: ModelMountTokenizerRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_tokenizer_required",
            "backend": "rust_model_mount_tokenizer_required",
            "request": {
                "schema_version": MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION,
                "operation": "context_fit",
                "source": "runtime-daemon.model_mounting.tokenizer",
                "details": {
                    "model": "llama-test",
                    "route_id": "route.local-first",
                    "requested_scope": "model.context:*"
                }
            }
        }))
        .expect("tokenizer required command request");

        let response = plan_model_mount_tokenizer_required_response(request)
            .expect("tokenizer required planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_tokenizer_required_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_tokenizer_required");
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(response["code"], "model_mount_tokenizer_rust_core_required");
        assert_eq!(response["operation"], "context_fit");
        assert_eq!(response["rust_core_boundary"], "model_mount.tokenizer");
        assert_eq!(response["details"]["model"], "llama-test");
        assert_eq!(response["details"]["route_id"], "route.local-first");
        assert_eq!(response["details"]["requested_scope"], "model.context:*");
        assert!(response["details"].get("routeId").is_none());
        assert!(response["details"].get("requestedScope").is_none());
    }

    #[test]
    fn rust_core_shapes_model_mount_route_control_required_command_response() {
        let request: ModelMountRouteControlRequiredBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_route_control_required",
            "backend": "rust_model_mount_route_control_required",
            "request": {
                "schema_version": MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
                "operation": "model_mount.route_control",
                "operation_kind": "model_mount.route.selection_update",
                "source": "runtime-daemon.model_mounting.route_control",
                "details": {
                    "route_id": "route.local-first",
                    "selected_model": "model.local",
                    "receipt_id": "receipt-route-test",
                    "route_selection_boundary": "model_mount.route_selection"
                }
            }
        }))
        .expect("route control required command request");

        let response = plan_model_mount_route_control_required_response(request)
            .expect("route control required planned");

        assert_eq!(
            response["source"],
            "rust_model_mount_route_control_required_command"
        );
        assert_eq!(
            response["backend"],
            "rust_model_mount_route_control_required"
        );
        assert_eq!(response["status"], "rust_core_required");
        assert_eq!(response["status_code"], 501);
        assert_eq!(
            response["code"],
            "model_mount_route_control_rust_core_required"
        );
        assert_eq!(response["operation"], "model_mount.route_control");
        assert_eq!(
            response["operation_kind"],
            "model_mount.route.selection_update"
        );
        assert_eq!(response["rust_core_boundary"], "model_mount.route_control");
        assert_eq!(response["details"]["route_id"], "route.local-first");
        assert_eq!(response["details"]["selected_model"], "model.local");
        assert_eq!(response["details"]["receipt_id"], "receipt-route-test");
        assert!(response["details"].get("routeId").is_none());
        assert!(response["details"].get("selectedModel").is_none());
        assert!(response["details"].get("receiptId").is_none());
    }
}
