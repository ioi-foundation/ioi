use serde::{Deserialize, Serialize};
use serde_json::Value;

mod adapter_boundary;
mod aggregate;
mod authority;
mod catalog;
mod common;
mod oauth;
mod receipt;
mod runtime;
mod status;
mod topology;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReadProjectionRequest {
    pub projection_kind: String,
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub engine_id: Option<String>,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    pub state: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReadProjectionPlan {
    pub projection_kind: String,
    pub projection: Value,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelMountReadProjectionError {
    pub code: &'static str,
    pub message: String,
}

impl ModelMountReadProjectionError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub(super) fn plan_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<ModelMountReadProjectionPlan, ModelMountReadProjectionError> {
    let projection = model_mount_read_projection(request)?;
    Ok(ModelMountReadProjectionPlan {
        projection_kind: request.projection_kind.clone(),
        projection,
        evidence_refs: vec![
            "rust_daemon_core_model_mount_projection".to_string(),
            "agentgres_model_mount_read_truth".to_string(),
            "model_mount_js_read_projection_authoring_retired".to_string(),
        ],
    })
}

pub(super) fn model_mount_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    match request.projection_kind.as_str() {
        "snapshot" => Ok(aggregate::snapshot(request)),
        "projection" => Ok(aggregate::projection(request)),
        "projection_summary" => Ok(receipt::projection_summary(request)),
        "receipt_replay" => receipt::receipt_replay(request),
        "model_route_decisions" => Ok(receipt::route_decisions(request)),
        "authority_snapshot" => Ok(authority::authority_snapshot(request)),
        "server_status" => Ok(status::server_status(request)),
        "artifacts" => Ok(topology::artifacts()),
        "product_artifacts" => Ok(topology::product_artifacts()),
        "providers" => Ok(topology::providers()),
        "endpoints" => Ok(topology::endpoints()),
        "instances" => Ok(topology::instances()),
        "routes" => Ok(topology::routes()),
        "model_capabilities" => Ok(topology::model_capabilities()),
        "downloads" => Ok(topology::downloads()),
        "backends" => Ok(topology::backends()),
        "oauth_sessions" => oauth::sessions(),
        "oauth_states" => oauth::states(),
        "provider_health" => Ok(topology::provider_health()),
        "workflow_bindings" => Ok(adapter_boundary::workflow_bindings()),
        "adapter_boundaries" => Ok(adapter_boundary::adapter_boundaries(&request.state)),
        "runtime_engines" => Ok(runtime::engines()),
        "runtime_engine_profiles" => Ok(runtime::engine_profiles()),
        "runtime_preference" => Ok(runtime::preference()),
        "runtime_preference_for_endpoint" => Ok(runtime::preference_for_endpoint()),
        "runtime_default_load_options" => Ok(runtime::default_load_options()),
        "runtime_engine_detail" => runtime::engine_detail(request),
        "runtime_model_catalog" => Ok(topology::runtime_model_catalog()),
        "open_ai_model_list" => Ok(topology::open_ai_model_list()),
        "latest_provider_health" => receipt::latest_provider_health(request),
        "latest_vault_health" => receipt::latest_vault_health(request),
        "latest_runtime_survey" => Ok(receipt::latest_runtime_survey(request)),
        "catalog_status" => catalog::status(),
        other => Err(ModelMountReadProjectionError::new(
            "model_mount_read_projection_kind_unsupported",
            format!("unsupported model_mount read projection kind {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::super::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;
    use super::*;

    #[test]
    fn read_projection_is_planned_in_rust_model_mount_core() {
        let plan = plan_read_projection(&ModelMountReadProjectionRequest {
            projection_kind: "projection_summary".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            base_url: None,
            state: serde_json::json!({
                "receipts": [
                    {"id": "receipt_1", "kind": "model_route_selection", "details": {}}
                ]
            }),
        })
        .expect("read projection planned in Rust model_mount core");

        assert_eq!(plan.projection_kind, "projection_summary");
        assert_eq!(
            plan.projection["schemaVersion"],
            MODEL_MOUNT_RUNTIME_SCHEMA_VERSION
        );
        assert_eq!(
            plan.projection["source"],
            "agentgres_model_mounting_projection"
        );
        assert_eq!(plan.projection["watermark"], 1);
        assert_eq!(plan.projection["receiptCount"], 1);
        assert_eq!(
            plan.evidence_refs,
            vec![
                "rust_daemon_core_model_mount_projection",
                "agentgres_model_mount_read_truth",
                "model_mount_js_read_projection_authoring_retired",
            ],
        );
    }
}
