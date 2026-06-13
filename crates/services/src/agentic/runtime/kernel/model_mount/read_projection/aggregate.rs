use serde_json::{json, Value};

use super::common::{
    array_field, model_mount_projection_generated_at, model_mount_projection_schema_version,
    receipts_by_kind,
};
use super::{
    adapter_boundary, conversation, health, receipt, route_decision, status, topology,
    ModelMountReadProjectionRequest,
};

pub(super) fn snapshot(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let receipts = array_field(state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "server": status::server_status_or_default(request),
        "catalog": status::catalog_status_or_default(request),
        "oauthSessions": [],
        "oauthStates": [],
        "artifacts": topology::artifact_records(request),
        "productArtifacts": topology::product_artifact_records(request),
        "backends": topology::backend_records(request).unwrap_or_default(),
        "backendProcesses": [],
        "endpoints": topology::endpoint_records(request),
        "instances": topology::instance_records(request),
        "providers": topology::provider_records(request),
        "routes": topology::route_records(request),
        "modelCapabilities": [],
        "runtimeModelCatalog": topology::runtime_model_catalog_records(request).unwrap_or_default(),
        "openAiModelList": topology::open_ai_model_list_value(request),
        "downloads": topology::download_records(request),
        "providerHealth": [],
        "runtimeEngines": [],
        "runtimeEngineProfiles": [],
        "runtimePreference": Value::Null,
        "runtimeSurvey": health::latest_runtime_survey(request),
        "tokens": array_field(state, "grants"),
        "vaultRefs": array_field(state, "vault_refs"),
        "mcpServers": [],
        "conversationStates": conversation::conversation_state_records(request),
        "workflowNodes": adapter_boundary::workflow_bindings(),
        "receipts": receipts.into_iter().rev().take(25).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>(),
        "projection": receipt::projection_summary(request),
        "adapterBoundaries": adapter_boundary::adapter_boundaries(state),
    })
}

pub(super) fn projection(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let receipts = array_field(state, "receipts");
    json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "source": "agentgres_model_mounting_projection",
        "generatedAt": model_mount_projection_generated_at(request),
        "watermark": receipts.len(),
        "artifacts": topology::artifact_records(request),
        "productArtifacts": topology::product_artifact_records(request),
        "endpoints": topology::endpoint_records(request),
        "instances": topology::instance_records(request),
        "routes": topology::route_records(request),
        "modelCapabilities": [],
        "runtimeModelCatalog": topology::runtime_model_catalog_records(request).unwrap_or_default(),
        "openAiModelList": topology::open_ai_model_list_value(request),
        "backends": topology::backend_records(request).unwrap_or_default(),
        "backendProcesses": [],
        "providers": topology::provider_records(request),
        "catalog": status::catalog_status_or_default(request),
        "oauthSessions": [],
        "oauthStates": [],
        "downloads": topology::download_records(request),
        "providerHealth": [],
        "runtimeEngines": [],
        "runtimeEngineProfiles": [],
        "runtimePreference": Value::Null,
        "runtimeSurvey": health::latest_runtime_survey(request),
        "grants": array_field(state, "grants"),
        "vaultRefs": array_field(state, "vault_refs"),
        "mcpServers": [],
        "conversationStates": conversation::conversation_state_records(request),
        "workflowBindings": adapter_boundary::workflow_bindings(),
        "adapterBoundaries": adapter_boundary::adapter_boundaries(state),
        "lifecycleEvents": receipts_by_kind(&receipts, "model_lifecycle"),
        "routeReceipts": receipts_by_kind(&receipts, "model_route_selection"),
        "routeDecisions": route_decision::route_decision_records_or_empty(request),
        "providerHealthReceipts": receipts_by_kind(&receipts, "provider_health"),
        "runtimeSurveyReceipts": receipts_by_kind(&receipts, "runtime_survey"),
        "invocationReceipts": receipts_by_kind(&receipts, "model_invocation"),
        "toolReceipts": receipts_by_kind(&receipts, "mcp_tool_invocation"),
        "receipts": receipts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;

    fn request(state: Value) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "projection".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: Some("http://127.0.0.1:9444".to_string()),
            state_dir: None,
            state,
        }
    }

    #[test]
    fn aggregate_projection_is_planned_from_admitted_receipts() {
        let projection = projection(&request(json!({
            "receipts": [
                {
                    "id": "receipt.route",
                    "kind": "model_route_selection",
                    "details": {
                        "model_route_decision": {
                            "route_id": "route.local",
                            "selected_model": "qwen3"
                        }
                    }
                },
                {
                    "id": "receipt.health",
                    "kind": "provider_health",
                    "details": {
                        "provider_id": "provider.local",
                        "status": "healthy"
                    }
                }
            ],
            "grants": ["grant://wallet/model-chat"],
            "vault_refs": ["vault://model/provider.local"]
        })));

        assert_eq!(projection["source"], "agentgres_model_mounting_projection");
        assert_eq!(projection["watermark"], 2);
        assert_eq!(projection["routeReceipts"].as_array().unwrap().len(), 1);
        assert_eq!(projection["routeDecisions"], json!([]));
        assert_eq!(
            projection["providerHealthReceipts"][0]["id"],
            "receipt.health"
        );
        assert_eq!(projection["routes"], json!([]));
        assert_eq!(projection["providers"], json!([]));
    }

    #[test]
    fn aggregate_snapshot_is_planned_from_projection_summary_and_recent_receipts() {
        let snapshot = snapshot(&request(json!({
            "receipts": (0..30)
                .map(|index| json!({
                    "id": format!("receipt.{index}"),
                    "kind": "model_route_selection",
                    "details": {}
                }))
                .collect::<Vec<_>>(),
            "grants": ["grant://wallet/model-chat"],
            "vault_refs": ["vault://model/provider.local"]
        })));

        assert_eq!(
            snapshot["schemaVersion"],
            MODEL_MOUNT_RUNTIME_SCHEMA_VERSION
        );
        assert_eq!(snapshot["projection"]["watermark"], 30);
        assert_eq!(snapshot["receipts"].as_array().unwrap().len(), 25);
        assert_eq!(snapshot["receipts"][0]["id"], "receipt.5");
        assert_eq!(snapshot["workflowNodes"].as_array().unwrap().len(), 10);
        assert_eq!(snapshot["runtimeModelCatalog"], json!([]));
        assert_eq!(snapshot["openAiModelList"]["data"], json!([]));
    }
}
