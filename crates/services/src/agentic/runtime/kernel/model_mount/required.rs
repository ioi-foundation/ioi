mod route_control;
mod tokenizer;

use serde_json::{json, Value};

pub use route_control::{
    ModelMountRouteControlRequiredRecord, ModelMountRouteControlRequiredRequest,
};
pub use tokenizer::{ModelMountTokenizerRequiredRecord, ModelMountTokenizerRequiredRequest};

use super::ModelMountError;

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

pub fn plan_model_mount_tokenizer_required(
    request: &ModelMountTokenizerRequiredRequest,
) -> Result<Value, ModelMountError> {
    let record = plan_tokenizer_required(request)?;
    Ok(json!({
        "source": "rust_daemon_core.model_mount.tokenizer_required",
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

pub fn plan_model_mount_route_control_required(
    request: &ModelMountRouteControlRequiredRequest,
) -> Result<Value, ModelMountError> {
    let record = plan_route_control_required(request)?;
    Ok(json!({
        "source": "rust_daemon_core.model_mount.route_control_required",
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
    use crate::agentic::runtime::kernel::model_mount::{
        MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
        MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION,
    };

    #[test]
    fn rust_core_plans_model_mount_tokenizer_required_direct_api() {
        let request = ModelMountTokenizerRequiredRequest {
            schema_version: MODEL_MOUNT_TOKENIZER_REQUIRED_REQUEST_SCHEMA_VERSION.to_string(),
            operation: "context_fit".to_string(),
            source: Some("runtime-daemon.model_mounting.tokenizer".to_string()),
            details: json!({
                "model": "llama-test",
                "route_id": "route.local-first",
                "requested_scope": "model.context:*"
            }),
            evidence_refs: vec![],
        };

        let response =
            plan_model_mount_tokenizer_required(&request).expect("tokenizer required planned");

        assert_eq!(
            response["source"],
            "rust_daemon_core.model_mount.tokenizer_required"
        );
        assert!(response.get("backend").is_none());
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
    fn rust_core_plans_model_mount_route_control_required_direct_api() {
        let request = ModelMountRouteControlRequiredRequest {
            schema_version: MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION.to_string(),
            operation: "model_mount.route_control".to_string(),
            operation_kind: "model_mount.route.selection_update".to_string(),
            source: Some("runtime-daemon.model_mounting.route_control".to_string()),
            details: json!({
                "route_id": "route.local-first",
                "selected_model": "model.local",
                "receipt_id": "receipt-route-test",
                "route_selection_boundary": "model_mount.route_selection"
            }),
            evidence_refs: vec![],
        };

        let response = plan_model_mount_route_control_required(&request)
            .expect("route control required planned");

        assert_eq!(
            response["source"],
            "rust_daemon_core.model_mount.route_control_required"
        );
        assert!(response.get("backend").is_none());
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
