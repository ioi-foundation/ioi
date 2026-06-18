use serde_json::{json, Value};

use super::common::{
    model_mount_projection_generated_at, model_mount_projection_schema_version, receipts_by_kind,
};
use super::{
    adapter_boundary, conversation, custody, health, oauth, receipt, route_decision, status,
    topology, ModelMountReadProjectionError, ModelMountReadProjectionRequest,
};

pub(super) fn snapshot(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let receipts = receipt::receipt_records(request)?;
    let tokens = custody::capability_token_records(request)?;
    let vault_refs = custody::vault_ref_records(request)?;
    Ok(json!({
        "schemaVersion": model_mount_projection_schema_version(request),
        "server": status::server_status_or_default(request),
        "catalog": status::catalog_status_or_default(request),
        "oauthSessions": oauth::sessions(request)?,
        "oauthStates": oauth::states(request)?,
        "artifacts": topology::artifact_records(request),
        "productArtifacts": topology::product_artifact_records(request),
        "backends": topology::backend_records(request).unwrap_or_default(),
        "endpoints": topology::endpoint_records(request),
        "instances": topology::instance_records(request),
        "providers": topology::provider_records(request),
        "routes": topology::route_records(request),
        "modelCapabilities": [],
        "runtimeModelCatalog": topology::runtime_model_catalog_records(request).unwrap_or_default(),
        "openAiModelList": topology::open_ai_model_list_value(request),
        "downloads": topology::download_records(request),
        "providerHealth": health::provider_health(request)?,
        "runtimeEngines": [],
        "runtimeEngineProfiles": [],
        "runtimePreference": Value::Null,
        "runtimeSurvey": health::latest_runtime_survey(request)?,
        "tokens": tokens,
        "vaultRefs": vault_refs,
        "mcpServers": [],
        "conversationStates": conversation::conversation_state_records(request),
        "workflowNodes": adapter_boundary::workflow_bindings(),
        "receipts": receipts.into_iter().rev().take(25).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>(),
        "projection": receipt::projection_summary(request)?,
        "adapterBoundaries": adapter_boundary::adapter_boundaries(&request.state),
    }))
}

pub(super) fn projection(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let receipts = receipt::receipt_records(request)?;
    let tokens = custody::capability_token_records(request)?;
    let vault_refs = custody::vault_ref_records(request)?;
    Ok(json!({
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
        "providers": topology::provider_records(request),
        "catalog": status::catalog_status_or_default(request),
        "oauthSessions": oauth::sessions(request)?,
        "oauthStates": oauth::states(request)?,
        "downloads": topology::download_records(request),
        "providerHealth": health::provider_health(request)?,
        "runtimeEngines": [],
        "runtimeEngineProfiles": [],
        "runtimePreference": Value::Null,
        "runtimeSurvey": health::latest_runtime_survey(request)?,
        "grants": tokens,
        "vaultRefs": vault_refs,
        "mcpServers": [],
        "conversationStates": conversation::conversation_state_records(request),
        "workflowBindings": adapter_boundary::workflow_bindings(),
        "adapterBoundaries": adapter_boundary::adapter_boundaries(&request.state),
        "lifecycleEvents": receipts_by_kind(&receipts, "model_lifecycle"),
        "routeReceipts": receipts_by_kind(&receipts, "model_route_selection"),
        "routeDecisions": route_decision::route_decision_records_or_empty(request),
        "providerLifecycleRecords": health::provider_lifecycle_records_or_empty(request),
        "runtimeSurveyReceipts": receipts_by_kind(&receipts, "runtime_survey"),
        "invocationReceipts": receipts_by_kind(&receipts, "model_invocation"),
        "toolReceipts": receipts_by_kind(&receipts, "mcp_tool_invocation"),
        "receipts": receipts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::kernel::model_mount::MODEL_MOUNT_RUNTIME_SCHEMA_VERSION;

    fn request(state_dir: Option<String>, state: Value) -> ModelMountReadProjectionRequest {
        ModelMountReadProjectionRequest {
            projection_kind: "projection".to_string(),
            schema_version: Some(MODEL_MOUNT_RUNTIME_SCHEMA_VERSION.to_string()),
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: Some("http://127.0.0.1:9444".to_string()),
            state_dir,
            state,
        }
    }

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

    fn write_provider_lifecycle_records(state_dir: &std::path::Path, records: &[Value]) {
        let record_dir = state_dir.join("model-provider-lifecycle-controls");
        std::fs::create_dir_all(&record_dir).expect("provider lifecycle dir");
        for record in records {
            let record_id = record
                .get("id")
                .and_then(Value::as_str)
                .expect("provider lifecycle record id");
            std::fs::write(
                record_dir.join(format!("{record_id}.json")),
                serde_json::to_string_pretty(record).expect("provider lifecycle json"),
            )
            .expect("write provider lifecycle");
        }
    }

    fn write_records(state_dir: &std::path::Path, record_dir: &str, records: &[Value]) {
        let dir = state_dir.join(record_dir);
        std::fs::create_dir_all(&dir).expect("record dir");
        for record in records {
            let record_id = record.get("id").and_then(Value::as_str).expect("record id");
            std::fs::write(
                dir.join(format!("{record_id}.json")),
                serde_json::to_string_pretty(record).expect("record json"),
            )
            .expect("write record");
        }
    }

    #[test]
    fn aggregate_projection_is_planned_from_admitted_receipts() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_receipts(
            temp.path(),
            &[
                json!({
                    "id": "receipt.route",
                    "kind": "model_route_selection",
                    "details": {
                        "model_route_decision": {
                            "route_id": "route.local",
                            "selected_model": "qwen3"
                        }
                    }
                }),
                json!({
                    "id": "receipt.health",
                    "kind": "provider_health",
                    "details": {
                        "provider_id": "provider.local",
                        "status": "healthy"
                    }
                }),
            ],
        );
        write_provider_lifecycle_records(
            temp.path(),
            &[json!({
                "id": "provider-lifecycle-health",
                "record_id": "provider-lifecycle-health",
                "object": "ioi.model_mount_provider_lifecycle",
                "schema_version": "ioi.model_mount.provider_lifecycle_plan.v1",
                "provider_ref": "provider://provider.local",
                "provider_kind": "ioi_native_local",
                "action": "health",
                "operation_kind": "model_mount.provider.health",
                "status": "available",
                "backend": "hypervisor.native_local.fixture",
                "backend_id": "backend.hypervisor.native-local.fixture",
                "driver": "native_local",
                "execution_backend": "rust_model_mount_native_local_lifecycle",
                "lifecycle_hash": "sha256:provider-lifecycle-health",
                "record_dir": "model-provider-lifecycle-controls",
                "rust_core_boundary": "model_mount.provider_lifecycle",
                "generated_at": "2026-06-11T00:00:01.000Z",
                "evidence_refs": [
                    "rust_model_mount_provider_lifecycle",
                    "agentgres_provider_lifecycle_truth_required"
                ]
            })],
        );
        write_records(
            temp.path(),
            "capability-tokens",
            &[json!({
                "id": "token-create",
                "record_id": "token-create",
                "object": "ioi.model_mount_capability_token_control",
                "operation_kind": "model_mount.capability_token.create",
                "token_id": "capability_token:aggregate",
                "token_hash": "sha256:aggregate",
                "rust_core_boundary": "model_mount.capability_token",
                "wallet_authority_boundary": "wallet.network.capability_token",
                "capability_token_authority": {
                    "authority_hash": "sha256:token-authority",
                    "audience": "hypervisor-session",
                    "grant_id": "grant://wallet/capability",
                    "allowed_scopes": ["model.chat:*"],
                    "denied_scopes": []
                },
                "public_response": {"token": "ioi_mnt_secret"},
                "evidence_refs": [
                    "rust_daemon_core_capability_token_control",
                    "agentgres_capability_token_truth_required",
                    "public_capability_token_js_facade_retired"
                ],
                "planned_at": "2026-06-11T00:00:02.000Z"
            })],
        );
        write_records(
            temp.path(),
            "vault-refs",
            &[json!({
                "id": "vault-bind",
                "record_id": "vault-bind",
                "object": "ioi.model_mount_vault_control",
                "operation_kind": "model_mount.vault_ref.bind",
                "vault_ref_hash": "vault-hash",
                "material_hash": "sha256:material",
                "rust_core_boundary": "model_mount.vault",
                "wallet_authority_boundary": "wallet.network.vault",
                "ctee_custody_boundary": "ctee.vault_custody",
                "vault_authority": {"authority_hash": "sha256:vault-authority"},
                "ctee_custody": {
                    "custody_ref": "ctee://vault/hash",
                    "plaintext_material_persisted": false,
                    "plaintext_material_returned": false
                },
                "public_response": {
                    "vault_ref_hash": "vault-hash",
                    "vault_ref": {"redacted": true, "hash": "vault-hash"},
                    "label": "Provider key",
                    "purpose": "provider.auth"
                },
                "evidence_refs": [
                    "rust_daemon_core_vault_control",
                    "agentgres_vault_truth_required",
                    "public_vault_js_facade_retired"
                ],
                "planned_at": "2026-06-11T00:00:03.000Z"
            })],
        );
        write_records(
            temp.path(),
            "model-catalog-provider-controls",
            &[
                json!({
                    "id": "oauth-exchange",
                    "record_id": "oauth-exchange",
                    "object": "ioi.model_mount_catalog_provider_control",
                    "operation_kind": "model_mount.catalog_provider_oauth.exchange",
                    "provider_id": "catalog.huggingface",
                    "body_hash": "sha256:oauth-exchange",
                    "control_hash": "hash-oauth-exchange",
                    "rust_core_boundary": "model_mount.catalog_provider_control",
                    "wallet_authority_boundary": "wallet.network.catalog_provider_control",
                    "ctee_custody_boundary": "ctee.catalog_provider_material",
                    "authority": {
                        "authority_hash": "sha256:oauth-exchange-authority",
                        "authority_grant_refs": ["wallet.network://grant/catalog-provider"],
                        "authority_receipt_refs": ["receipt://wallet/catalog-provider"]
                    },
                    "public_response": {
                        "authority_hash": "sha256:oauth-exchange-authority",
                        "token_material": "ctee_custody_sealed"
                    },
                    "receipt_refs": ["receipt://catalog-provider-control"],
                    "evidence_refs": [
                        "rust_daemon_core_catalog_provider_control",
                        "agentgres_catalog_provider_control_truth_required",
                        "public_catalog_provider_control_js_facade_retired"
                    ]
                }),
                json!({
                    "id": "oauth-start",
                    "record_id": "oauth-start",
                    "object": "ioi.model_mount_catalog_provider_control",
                    "operation_kind": "model_mount.catalog_provider_oauth.start",
                    "provider_id": "catalog.huggingface",
                    "body_hash": "sha256:oauth-start",
                    "control_hash": "hash-oauth-start",
                    "rust_core_boundary": "model_mount.catalog_provider_control",
                    "wallet_authority_boundary": "wallet.network.catalog_provider_control",
                    "ctee_custody_boundary": "ctee.catalog_provider_material",
                    "authority": {"authority_hash": "sha256:oauth-start-authority"},
                    "public_response": {
                        "authority_hash": "sha256:oauth-start-authority",
                        "oauth_state_material": "ctee_custody_sealed",
                        "authorization_url_material": "ctee_custody_sealed",
                        "state_present": true
                    },
                    "receipt_refs": ["receipt://catalog-provider-control"],
                    "evidence_refs": [
                        "rust_daemon_core_catalog_provider_control",
                        "agentgres_catalog_provider_control_truth_required",
                        "public_catalog_provider_control_js_facade_retired"
                    ]
                }),
            ],
        );
        let projection = projection(&request(
            Some(temp.path().to_string_lossy().to_string()),
            json!({
                "receipts": [
                    {"id": "receipt.js", "kind": "provider_health", "details": {"status": "js"}}
                ],
                "grants": ["grant://wallet/model-chat"],
                "vault_refs": ["vault://model/provider.local"]
            }),
        ))
        .expect("aggregate projection");

        assert_eq!(projection["source"], "agentgres_model_mounting_projection");
        assert_eq!(projection["watermark"], 2);
        assert_eq!(projection["routeReceipts"].as_array().unwrap().len(), 1);
        assert_eq!(projection["routeDecisions"], json!([]));
        assert_eq!(
            projection["providerHealth"][0]["record"]["id"],
            "provider-lifecycle-health"
        );
        assert_eq!(
            projection["providerLifecycleRecords"][0]["id"],
            "provider-lifecycle-health"
        );
        assert_eq!(projection["grants"].as_array().unwrap().len(), 1);
        assert_eq!(
            projection["grants"][0]["token_id"],
            "capability_token:aggregate"
        );
        assert_eq!(projection["grants"][0].get("token"), None);
        assert_eq!(projection["vaultRefs"].as_array().unwrap().len(), 1);
        assert_eq!(projection["vaultRefs"][0]["vault_ref_hash"], "vault-hash");
        assert_eq!(projection["oauthSessions"].as_array().unwrap().len(), 1);
        assert_eq!(
            projection["oauthSessions"][0]["record_id"],
            "oauth-exchange"
        );
        assert_eq!(projection["oauthStates"].as_array().unwrap().len(), 1);
        assert_eq!(projection["oauthStates"][0]["record_id"], "oauth-start");
        assert_eq!(projection.get("providerHealthReceipts"), None);
        assert_eq!(projection["routes"], json!([]));
        assert_eq!(projection["providers"], json!([]));
    }

    #[test]
    fn aggregate_snapshot_is_planned_from_projection_summary_and_recent_receipts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let receipts = (0..30)
            .map(|index| {
                json!({
                    "id": format!("receipt.{index}"),
                    "kind": "model_route_selection",
                    "createdAt": format!("2026-06-11T00:00:{index:02}.000Z"),
                    "details": {}
                })
            })
            .collect::<Vec<_>>();
        write_receipts(temp.path(), &receipts);
        write_records(
            temp.path(),
            "capability-tokens",
            &[json!({
                "id": "snapshot-token",
                "record_id": "snapshot-token",
                "object": "ioi.model_mount_capability_token_control",
                "operation_kind": "model_mount.capability_token.create",
                "token_id": "capability_token:snapshot",
                "token_hash": "sha256:snapshot",
                "rust_core_boundary": "model_mount.capability_token",
                "capability_token_authority": {"allowed_scopes": ["model.chat:*"], "denied_scopes": []},
                "evidence_refs": ["agentgres_capability_token_truth_required"],
                "planned_at": "2026-06-11T00:00:31.000Z"
            })],
        );
        write_records(
            temp.path(),
            "vault-refs",
            &[json!({
                "id": "snapshot-vault",
                "record_id": "snapshot-vault",
                "object": "ioi.model_mount_vault_control",
                "operation_kind": "model_mount.vault_ref.bind",
                "vault_ref_hash": "vault-snapshot",
                "rust_core_boundary": "model_mount.vault",
                "public_response": {"vault_ref_hash": "vault-snapshot"},
                "evidence_refs": ["agentgres_vault_truth_required"],
                "planned_at": "2026-06-11T00:00:32.000Z"
            })],
        );
        write_records(
            temp.path(),
            "model-catalog-provider-controls",
            &[json!({
                "id": "snapshot-oauth-start",
                "record_id": "snapshot-oauth-start",
                "object": "ioi.model_mount_catalog_provider_control",
                "operation_kind": "model_mount.catalog_provider_oauth.start",
                "provider_id": "catalog.snapshot",
                "body_hash": "sha256:snapshot-oauth-start",
                "control_hash": "hash-snapshot-oauth-start",
                "rust_core_boundary": "model_mount.catalog_provider_control",
                "wallet_authority_boundary": "wallet.network.catalog_provider_control",
                "ctee_custody_boundary": "ctee.catalog_provider_material",
                "authority": {"authority_hash": "sha256:snapshot-oauth-authority"},
                "public_response": {
                    "authority_hash": "sha256:snapshot-oauth-authority",
                    "oauth_state_material": "ctee_custody_sealed",
                    "authorization_url_material": "ctee_custody_sealed",
                    "state_present": true
                },
                "evidence_refs": [
                    "rust_daemon_core_catalog_provider_control",
                    "agentgres_catalog_provider_control_truth_required",
                    "public_catalog_provider_control_js_facade_retired"
                ]
            })],
        );
        let snapshot = snapshot(&request(
            Some(temp.path().to_string_lossy().to_string()),
            json!({
                "receipts": [{"id": "receipt.js", "kind": "model_route_selection"}],
                "grants": ["grant://wallet/model-chat"],
                "vault_refs": ["vault://model/provider.local"]
            }),
        ))
        .expect("aggregate snapshot");

        assert_eq!(
            snapshot["schemaVersion"],
            MODEL_MOUNT_RUNTIME_SCHEMA_VERSION
        );
        assert_eq!(snapshot["projection"]["watermark"], 30);
        assert_eq!(snapshot["receipts"].as_array().unwrap().len(), 25);
        assert_eq!(snapshot["receipts"][0]["id"], "receipt.5");
        assert_eq!(snapshot["tokens"].as_array().unwrap().len(), 1);
        assert_eq!(
            snapshot["tokens"][0]["token_id"],
            "capability_token:snapshot"
        );
        assert_eq!(snapshot["vaultRefs"].as_array().unwrap().len(), 1);
        assert_eq!(snapshot["vaultRefs"][0]["vault_ref_hash"], "vault-snapshot");
        assert_eq!(snapshot["oauthSessions"], json!([]));
        assert_eq!(snapshot["oauthStates"].as_array().unwrap().len(), 1);
        assert_eq!(
            snapshot["oauthStates"][0]["record_id"],
            "snapshot-oauth-start"
        );
        assert_eq!(snapshot["workflowNodes"].as_array().unwrap().len(), 10);
        assert_eq!(snapshot["runtimeModelCatalog"], json!([]));
        assert_eq!(snapshot["openAiModelList"]["data"], json!([]));
    }

    #[test]
    fn aggregate_projection_rejects_js_receipt_transport_without_state_dir() {
        let error = projection(&request(
            None,
            json!({"receipts": [{"id": "receipt.js", "kind": "model_route_selection"}]}),
        ))
        .expect_err("state_dir is required");

        assert_eq!(error.code, "model_mount_receipt_replay_state_dir_required");
    }
}
