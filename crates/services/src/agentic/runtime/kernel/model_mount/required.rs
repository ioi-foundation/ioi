mod route_control;
mod tokenizer;

use serde::Deserialize;
use serde_json::{json, Value};

pub use route_control::{
    ModelMountRouteControlRequiredRecord, ModelMountRouteControlRequiredRequest,
};
pub use tokenizer::{ModelMountTokenizerRequiredRecord, ModelMountTokenizerRequiredRequest};

use super::ModelMountError;

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
        MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
        MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION,
    };

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
