use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

mod adapter_boundary;
mod aggregate;
mod authority;
mod common;
mod conversation;
mod health;
mod mcp;
mod oauth;
mod receipt;
mod route_decision;
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
    pub download_id: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub state_dir: Option<String>,
    pub state: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMountReadProjectionPlan {
    pub projection_kind: String,
    pub projection: Value,
    pub evidence_refs: Vec<String>,
}

pub(super) const MODEL_MOUNT_CONVERSATION_PROJECTION_KIND: &str = "model_conversation_states";
pub(super) const MODEL_MOUNT_INSTANCES_PROJECTION_KIND: &str = "instances";
pub(super) const MODEL_MOUNT_PROVIDER_INVENTORY_PROJECTION_KIND: &str =
    "provider_inventory_records";
pub(super) const MODEL_MOUNT_CATALOG_SEARCH_PROJECTION_KIND: &str = "catalog_search";
pub(super) const MODEL_MOUNT_CATALOG_STATUS_PROJECTION_KIND: &str = "catalog_status";
pub(super) const MODEL_MOUNT_PROVIDER_MATERIALIZATION_PROJECTION_KINDS: [&str; 5] = [
    "artifacts",
    "product_artifacts",
    "providers",
    "runtime_model_catalog",
    "open_ai_model_list",
];
pub(super) const MODEL_MOUNT_ENDPOINTS_PROJECTION_KIND: &str = "endpoints";
pub(super) const MODEL_MOUNT_ROUTES_PROJECTION_KIND: &str = "routes";
pub(super) const MODEL_MOUNT_MODEL_CAPABILITIES_PROJECTION_KIND: &str = "model_capabilities";
pub(super) const MODEL_MOUNT_ROUTE_DECISIONS_PROJECTION_KIND: &str = "model_route_decisions";
pub(super) const MODEL_MOUNT_ROUTE_ENDPOINT_RESOLUTIONS_PROJECTION_KIND: &str =
    "model_route_endpoint_resolutions";
pub(super) const MODEL_MOUNT_TOKENIZER_RECORDS_PROJECTION_KIND: &str = "model_tokenizer_records";
pub(super) const MODEL_MOUNT_DOWNLOADS_PROJECTION_KIND: &str = "downloads";
pub(super) const MODEL_MOUNT_DOWNLOAD_STATUS_PROJECTION_KIND: &str = "download_status";
pub(super) const MODEL_MOUNT_STORAGE_SUMMARY_PROJECTION_KIND: &str = "storage_summary";
pub(super) const MODEL_MOUNT_BACKENDS_PROJECTION_KIND: &str = "backends";
pub(super) const MODEL_MOUNT_BACKEND_LOGS_PROJECTION_KIND: &str = "backend_logs";
pub(super) const MODEL_MOUNT_SERVER_STATUS_PROJECTION_KIND: &str = "server_status";
pub(super) const MODEL_MOUNT_SERVER_LOGS_PROJECTION_KIND: &str = "server_logs";
pub(super) const MODEL_MOUNT_SERVER_EVENTS_PROJECTION_KIND: &str = "server_events";
pub(super) const MODEL_MOUNT_SERVER_LOG_RECORDS_PROJECTION_KIND: &str = "server_log_records";
pub(super) const MODEL_MOUNT_MCP_SERVERS_PROJECTION_KIND: &str = "mcp_servers";
pub(super) const MODEL_MOUNT_PROVIDER_HEALTH_PROJECTION_KIND: &str = "provider_health";
pub(super) const MODEL_MOUNT_RECEIPT_REPLAY_PROJECTION_KINDS: [&str; 9] = [
    "snapshot",
    "projection",
    "projection_summary",
    "receipt_replay",
    "authority_snapshot",
    MODEL_MOUNT_PROVIDER_HEALTH_PROJECTION_KIND,
    "latest_provider_health",
    "latest_vault_health",
    "latest_runtime_survey",
];
pub(super) const MODEL_MOUNT_RUNTIME_ENGINE_PROJECTION_KINDS: [&str; 6] = [
    "runtime_engines",
    "runtime_engine_profiles",
    "runtime_preference",
    "runtime_preference_for_endpoint",
    "runtime_default_load_options",
    "runtime_engine_detail",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelMountReadProjectionError {
    pub code: &'static str,
    pub message: String,
}

impl ModelMountReadProjectionError {
    pub(super) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ModelMountReadProjectionBridgeRequest {
    #[serde(default)]
    backend: Option<String>,
    request: ModelMountReadProjectionRequest,
}

pub fn plan_model_mount_read_projection_response(
    request: ModelMountReadProjectionBridgeRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let plan = plan_read_projection(&request.request)?;
    Ok(json!({
        "source": "rust_model_mount_read_projection_command",
        "backend": request.backend.unwrap_or_else(|| "rust_model_mount_read_projection".to_string()),
        "projection_kind": plan.projection_kind,
        "projection": plan.projection,
        "evidence_refs": plan.evidence_refs,
    }))
}

pub(super) fn plan_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<ModelMountReadProjectionPlan, ModelMountReadProjectionError> {
    let projection = model_mount_read_projection(request)?;
    let mut evidence_refs = vec![
        "rust_daemon_core_model_mount_projection".to_string(),
        "agentgres_model_mount_read_truth".to_string(),
        "model_mount_js_read_projection_authoring_retired".to_string(),
    ];
    if request.projection_kind == MODEL_MOUNT_CONVERSATION_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_conversation_projection".to_string(),
            "agentgres_model_conversation_replay_required".to_string(),
            "model_mount_conversation_list_js_facade_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_INSTANCES_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_instance_projection".to_string(),
            "agentgres_model_instance_replay_required".to_string(),
            "model_mount_instance_list_js_facade_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_PROVIDER_INVENTORY_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_provider_inventory_projection".to_string(),
            "agentgres_provider_inventory_replay_required".to_string(),
            "model_mount_provider_inventory_js_projection_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_CATALOG_SEARCH_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_catalog_search_projection".to_string(),
            "agentgres_catalog_search_replay_required".to_string(),
            "model_catalog_search_js_orchestrator_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_CATALOG_STATUS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_catalog_status_projection".to_string(),
            "agentgres_catalog_status_replay_required".to_string(),
            "agentgres_provider_inventory_truth_required".to_string(),
            "model_catalog_status_js_readback_retired".to_string(),
        ]);
    }
    if MODEL_MOUNT_PROVIDER_MATERIALIZATION_PROJECTION_KINDS
        .contains(&request.projection_kind.as_str())
    {
        evidence_refs.extend([
            "rust_daemon_core_provider_inventory_materialization".to_string(),
            "agentgres_provider_inventory_materialization_required".to_string(),
            "model_mount_topology_js_materialization_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_ENDPOINTS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_endpoint_projection".to_string(),
            "agentgres_model_route_endpoint_resolution_replay_required".to_string(),
            "model_mount_endpoint_list_js_facade_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_ROUTES_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_route_projection".to_string(),
            "agentgres_model_route_replay_required".to_string(),
            "model_mount_route_list_js_facade_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_MODEL_CAPABILITIES_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_capability_projection".to_string(),
            "agentgres_model_capability_replay_required".to_string(),
            "model_mount_model_capability_js_projection_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_ROUTE_DECISIONS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_route_decision_projection".to_string(),
            "agentgres_model_route_selection_replay_required".to_string(),
            "model_mount_route_decision_js_receipt_projection_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_ROUTE_ENDPOINT_RESOLUTIONS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_route_endpoint_resolution_projection".to_string(),
            "agentgres_model_route_endpoint_resolution_replay_required".to_string(),
            "model_mount_route_endpoint_resolution_js_projection_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_TOKENIZER_RECORDS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_tokenizer_projection".to_string(),
            "agentgres_model_tokenizer_replay_required".to_string(),
            "model_mount_tokenizer_js_projection_retired".to_string(),
        ]);
    }
    if matches!(
        request.projection_kind.as_str(),
        MODEL_MOUNT_DOWNLOADS_PROJECTION_KIND
            | MODEL_MOUNT_DOWNLOAD_STATUS_PROJECTION_KIND
            | MODEL_MOUNT_STORAGE_SUMMARY_PROJECTION_KIND
    ) {
        evidence_refs.extend([
            "rust_daemon_core_model_storage_projection".to_string(),
            "agentgres_model_storage_replay_required".to_string(),
            "model_mount_storage_summary_js_facade_retired".to_string(),
            "model_mount_download_status_js_map_retired".to_string(),
        ]);
    }
    if MODEL_MOUNT_RUNTIME_ENGINE_PROJECTION_KINDS.contains(&request.projection_kind.as_str()) {
        evidence_refs.extend([
            "rust_daemon_core_runtime_engine_projection".to_string(),
            "agentgres_runtime_engine_replay_required".to_string(),
            "model_mount_runtime_engine_js_projection_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_BACKENDS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_backend_lifecycle_projection".to_string(),
            "agentgres_backend_lifecycle_replay_required".to_string(),
            "model_mount_backend_list_js_facade_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_BACKEND_LOGS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_backend_lifecycle_log_projection".to_string(),
            "agentgres_backend_lifecycle_log_replay_required".to_string(),
            "model_mount_backend_log_read_js_control_path_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_SERVER_STATUS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_server_control_projection".to_string(),
            "agentgres_server_control_replay_required".to_string(),
            "model_mount_server_status_js_projection_retired".to_string(),
        ]);
    }
    if matches!(
        request.projection_kind.as_str(),
        MODEL_MOUNT_SERVER_LOGS_PROJECTION_KIND
            | MODEL_MOUNT_SERVER_EVENTS_PROJECTION_KIND
            | MODEL_MOUNT_SERVER_LOG_RECORDS_PROJECTION_KIND
    ) {
        evidence_refs.extend([
            "rust_daemon_core_server_control_log_projection".to_string(),
            "agentgres_server_control_log_replay_required".to_string(),
            "model_mount_server_log_read_js_control_path_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_MCP_SERVERS_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_model_mount_mcp_projection".to_string(),
            "agentgres_mcp_projection_truth_required".to_string(),
            "model_mount_mcp_server_js_projection_retired".to_string(),
        ]);
    }
    if request.projection_kind == MODEL_MOUNT_PROVIDER_HEALTH_PROJECTION_KIND {
        evidence_refs.extend([
            "rust_daemon_core_provider_health_projection".to_string(),
            "agentgres_provider_health_replay_required".to_string(),
            "model_mount_provider_health_js_projection_retired".to_string(),
        ]);
    }
    if MODEL_MOUNT_RECEIPT_REPLAY_PROJECTION_KINDS.contains(&request.projection_kind.as_str()) {
        evidence_refs.extend([
            "rust_daemon_core_model_mount_receipt_replay_projection".to_string(),
            "agentgres_model_mount_receipt_replay_required".to_string(),
            "model_mount_js_receipt_list_projection_transport_retired".to_string(),
        ]);
    }
    Ok(ModelMountReadProjectionPlan {
        projection_kind: request.projection_kind.clone(),
        projection,
        evidence_refs,
    })
}

pub(super) fn model_mount_read_projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    match request.projection_kind.as_str() {
        "snapshot" => aggregate::snapshot(request),
        "projection" => aggregate::projection(request),
        "projection_summary" => receipt::projection_summary(request),
        "receipt_replay" => receipt::receipt_replay(request),
        MODEL_MOUNT_ROUTE_DECISIONS_PROJECTION_KIND => route_decision::route_decisions(request),
        MODEL_MOUNT_ROUTE_ENDPOINT_RESOLUTIONS_PROJECTION_KIND => {
            route_decision::endpoint_resolutions(request)
        }
        MODEL_MOUNT_CONVERSATION_PROJECTION_KIND => conversation::conversation_states(request),
        "authority_snapshot" => authority::authority_snapshot(request),
        MODEL_MOUNT_SERVER_STATUS_PROJECTION_KIND => status::server_status(request),
        MODEL_MOUNT_SERVER_LOGS_PROJECTION_KIND => status::server_logs(request),
        MODEL_MOUNT_SERVER_EVENTS_PROJECTION_KIND => status::server_events(request),
        MODEL_MOUNT_SERVER_LOG_RECORDS_PROJECTION_KIND => status::server_log_records(request),
        "artifacts" => topology::artifacts(request),
        "product_artifacts" => topology::product_artifacts(request),
        "providers" => topology::providers(request),
        MODEL_MOUNT_ENDPOINTS_PROJECTION_KIND => topology::endpoints(request),
        MODEL_MOUNT_INSTANCES_PROJECTION_KIND => topology::instances(request),
        MODEL_MOUNT_PROVIDER_INVENTORY_PROJECTION_KIND => {
            topology::provider_inventory_records(request)
        }
        MODEL_MOUNT_CATALOG_SEARCH_PROJECTION_KIND => topology::catalog_search(request),
        MODEL_MOUNT_ROUTES_PROJECTION_KIND => topology::routes(request),
        MODEL_MOUNT_TOKENIZER_RECORDS_PROJECTION_KIND => topology::tokenizer_records(request),
        MODEL_MOUNT_MODEL_CAPABILITIES_PROJECTION_KIND => topology::model_capabilities(request),
        MODEL_MOUNT_DOWNLOADS_PROJECTION_KIND => topology::downloads(request),
        MODEL_MOUNT_DOWNLOAD_STATUS_PROJECTION_KIND => topology::download_status(request),
        MODEL_MOUNT_STORAGE_SUMMARY_PROJECTION_KIND => topology::storage_summary(request),
        MODEL_MOUNT_BACKENDS_PROJECTION_KIND => topology::backends(request),
        MODEL_MOUNT_BACKEND_LOGS_PROJECTION_KIND => topology::backend_logs(request),
        MODEL_MOUNT_MCP_SERVERS_PROJECTION_KIND => mcp::mcp_servers(request),
        "oauth_sessions" => oauth::sessions(),
        "oauth_states" => oauth::states(),
        MODEL_MOUNT_PROVIDER_HEALTH_PROJECTION_KIND => health::provider_health(request),
        "workflow_bindings" => Ok(adapter_boundary::workflow_bindings()),
        "adapter_boundaries" => Ok(adapter_boundary::adapter_boundaries(&request.state)),
        "runtime_engines" => runtime::engines(request),
        "runtime_engine_profiles" => runtime::engine_profiles(request),
        "runtime_preference" => runtime::preference(request),
        "runtime_preference_for_endpoint" => runtime::preference_for_endpoint(request),
        "runtime_default_load_options" => runtime::default_load_options(request),
        "runtime_engine_detail" => runtime::engine_detail(request),
        "runtime_model_catalog" => topology::runtime_model_catalog(request),
        "open_ai_model_list" => topology::open_ai_model_list(request),
        "latest_provider_health" => health::latest_provider_health(request),
        "latest_vault_health" => health::latest_vault_health(request),
        "latest_runtime_survey" => health::latest_runtime_survey(request),
        MODEL_MOUNT_CATALOG_STATUS_PROJECTION_KIND => status::catalog_status(request),
        other => Err(ModelMountReadProjectionError::new(
            "model_mount_read_projection_kind_unsupported",
            format!("unsupported model_mount read projection kind {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::agentic::runtime::kernel::command_protocol::DAEMON_CORE_COMMAND_SCHEMA_VERSION;

    use super::super::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;
    use super::*;

    fn write_receipts(state_dir: &std::path::Path, receipts: &[Value]) {
        let receipt_dir = state_dir.join("receipts");
        std::fs::create_dir_all(&receipt_dir).expect("receipt dir");
        for receipt in receipts {
            let receipt_id = receipt
                .get("id")
                .and_then(Value::as_str)
                .expect("receipt id");
            std::fs::write(
                receipt_dir.join(format!("{receipt_id}.json")),
                serde_json::to_string_pretty(receipt).expect("receipt json"),
            )
            .expect("write receipt");
        }
    }

    #[test]
    fn read_projection_is_planned_in_rust_model_mount_core() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_receipts(
            temp.path(),
            &[json!({"id": "receipt_1", "kind": "model_route_selection", "details": {}})],
        );
        let plan = plan_read_projection(&ModelMountReadProjectionRequest {
            projection_kind: "projection_summary".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            state: serde_json::json!({
                "receipts": [
                    {"id": "receipt_js", "kind": "model_route_selection", "details": {}}
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
                "rust_daemon_core_model_mount_receipt_replay_projection",
                "agentgres_model_mount_receipt_replay_required",
                "model_mount_js_receipt_list_projection_transport_retired",
            ],
        );
    }

    #[test]
    fn rust_core_shapes_model_mount_read_projection_command_response() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().to_string_lossy().to_string();
        write_receipts(
            temp.path(),
            &[json!({
                "id": "receipt-route",
                "kind": "model_route_selection",
                "createdAt": "2026-06-08T00:00:00.000Z",
                "details": {
                    "model_route_decision": {
                        "schema_version": "ioi.model-route-decision.v1",
                        "route_id": "route.local-first",
                        "selected_model": "model.local"
                    },
                    "route_id": "route.local-first",
                    "endpoint_id": "endpoint.local",
                    "provider_id": "provider.local"
                }
            })],
        );
        let request: ModelMountReadProjectionBridgeRequest = serde_json::from_value(json!({
            "schema_version": DAEMON_CORE_COMMAND_SCHEMA_VERSION,
            "operation": "plan_model_mount_read_projection",
            "backend": "rust_model_mount_read_projection",
            "request": {
                "projection_kind": "projection",
                "schema_version": MODEL_MOUNT_RUNTIME_SCHEMA_VERSION,
                "generated_at": "2026-06-08T00:00:00.000Z",
                "state_dir": state_dir,
                "state": {
                    "wallet": {"port": "WalletAuthorityPort"},
                    "vault": {"port": "VaultPort"},
                    "agentgres_store": {"port": "AgentgresStorePort"},
                    "receipts": [{
                        "id": "receipt-js",
                        "kind": "model_route_selection",
                        "createdAt": "2026-06-08T00:00:00.000Z",
                        "details": {
                            "model_route_decision": {
                                "schema_version": "ioi.model-route-decision.v1",
                                "route_id": "route.local-first",
                                "selected_model": "model.local"
                            },
                            "route_id": "route.local-first",
                            "endpoint_id": "endpoint.local",
                            "provider_id": "provider.local"
                        }
                    }]
                }
            }
        }))
        .expect("read projection command request");

        let response =
            plan_model_mount_read_projection_response(request).expect("read projection response");

        assert_eq!(
            response["source"],
            "rust_model_mount_read_projection_command"
        );
        assert_eq!(response["backend"], "rust_model_mount_read_projection");
        assert_eq!(response["projection_kind"], "projection");
        assert_eq!(
            response["projection"]["source"],
            "agentgres_model_mounting_projection"
        );
        assert_eq!(response["projection"]["watermark"], 1);
        assert_eq!(response["projection"]["routeDecisions"], json!([]));
        assert_eq!(
            response["projection"]["adapterBoundaries"]["agentgres"]["port"],
            "AgentgresStorePort"
        );
        assert!(response["projection"].get("route_decisions").is_none());
        assert!(response["evidence_refs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .any(|value| value == "model_mount_js_read_projection_authoring_retired"));
    }

    #[test]
    fn read_projection_plans_model_conversation_states_from_agentgres_with_conversation_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let conversation_dir = temp.path().join("model-conversations");
        std::fs::create_dir_all(&conversation_dir).expect("conversation dir");
        std::fs::write(
            conversation_dir.join("resp-rust.json"),
            serde_json::to_string_pretty(&json!({
                "id": "resp-rust",
                "object": "ioi.model_mount_conversation_state",
                "created_at": "2026-06-13T00:00:00.000Z",
                "rust_core_boundary": "model_mount.conversation",
                "conversation_hash": "sha256:conversation",
                "evidence_refs": [
                    "model_mount_conversation_state_rust_owned",
                    "agentgres_model_conversation_truth_required"
                ]
            }))
            .expect("record json"),
        )
        .expect("write conversation record");
        let plan = plan_read_projection(&ModelMountReadProjectionRequest {
            projection_kind: MODEL_MOUNT_CONVERSATION_PROJECTION_KIND.to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-13T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            state: serde_json::json!({}),
        })
        .expect("conversation state projection planned");

        assert_eq!(
            plan.projection_kind,
            MODEL_MOUNT_CONVERSATION_PROJECTION_KIND
        );
        assert_eq!(plan.projection.as_array().expect("records").len(), 1);
        assert!(plan
            .evidence_refs
            .iter()
            .any(|value| value == "rust_daemon_core_model_conversation_projection"));
        assert!(plan
            .evidence_refs
            .iter()
            .any(|value| value == "model_mount_conversation_list_js_facade_retired"));
    }
}
