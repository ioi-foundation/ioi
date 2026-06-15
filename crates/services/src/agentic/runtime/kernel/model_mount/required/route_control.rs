use serde::{Deserialize, Serialize};

use super::super::{
    non_empty_string, require_non_empty, trimmed_string, ModelMountError,
    MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION,
    MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION,
};

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

pub(super) fn plan_route_control_required(
    request: &ModelMountRouteControlRequiredRequest,
) -> Result<ModelMountRouteControlRequiredRecord, ModelMountError> {
    request.validate()?;
    let operation = trimmed_string(&request.operation, "operation")?;
    let operation_kind = trimmed_string(&request.operation_kind, "operation_kind")?;
    let source = request
        .source
        .as_ref()
        .and_then(|value| non_empty_string(value))
        .unwrap_or_else(|| "rust_daemon_core.model_mount.route_control_required".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_control_required_is_planned_in_rust_model_mount() {
        let record = plan_route_control_required(&ModelMountRouteControlRequiredRequest {
            schema_version: MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_REQUEST_SCHEMA_VERSION.to_string(),
            operation: "model_mount.route_control".to_string(),
            operation_kind: "model_mount.route.selection_update".to_string(),
            source: Some("runtime-daemon.model_mounting.route_control".to_string()),
            evidence_refs: vec![],
            details: serde_json::json!({
                "route_id": "route.local-first",
                "selected_model": "model.local",
                "receipt_id": "receipt-route-test",
                "route_selection_boundary": "model_mount.route_selection",
            }),
        })
        .expect("route control required record");

        assert_eq!(
            record.schema_version,
            MODEL_MOUNT_ROUTE_CONTROL_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.object, "ioi.model_mount_route_control_required");
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "model_mount_route_control_rust_core_required");
        assert_eq!(record.operation, "model_mount.route_control");
        assert_eq!(record.operation_kind, "model_mount.route.selection_update");
        assert_eq!(record.rust_core_boundary, "model_mount.route_control");
        assert_eq!(record.details["route_id"], "route.local-first");
        assert_eq!(record.details["selected_model"], "model.local");
        assert_eq!(record.details["receipt_id"], "receipt-route-test");
        assert_eq!(
            record.details["route_selection_boundary"],
            "model_mount.route_selection"
        );
        assert!(record
            .evidence_refs
            .contains(&"model_mount_route_control_js_facade_retired".to_string()));
        assert!(record
            .evidence_refs
            .contains(&"agentgres_route_truth_required".to_string()));
        assert!(record.details.get("routeId").is_none());
        assert!(record.details.get("selectedModel").is_none());
        assert!(record.details.get("receiptId").is_none());
    }
}
