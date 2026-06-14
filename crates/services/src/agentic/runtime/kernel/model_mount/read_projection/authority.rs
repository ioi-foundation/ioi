use serde_json::{json, Value};

use super::common::{json_string_field, model_mount_projection_generated_at, object_or_null};
use super::{
    custody, receipt, status, ModelMountReadProjectionError, ModelMountReadProjectionRequest,
};

pub(super) fn authority_snapshot(
    request: &ModelMountReadProjectionRequest,
) -> Result<Value, ModelMountReadProjectionError> {
    let state = &request.state;
    let grants = custody::capability_token_records(request)?;
    let vault_refs = custody::vault_ref_records(request)?;
    let authority_receipts = receipt::receipt_records(request)?
        .into_iter()
        .filter(|receipt| {
            matches!(
                json_string_field(receipt, "kind").as_deref(),
                Some("permission_token")
                    | Some("permission_token_revocation")
                    | Some("vault_ref_binding")
                    | Some("vault_ref_removal")
                    | Some("vault_adapter_health")
            )
        })
        .rev()
        .take(25)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let wallet = object_or_null(state.get("wallet"));
    let active_grants = grants.len();
    let revoked_grants = grants.len().saturating_sub(active_grants);
    let vault_ref_count = vault_refs.len();
    let authority_receipt_count = authority_receipts.len();
    let remote_wallet_configured = wallet
        .get("remoteAdapter")
        .and_then(|remote| remote.get("configured"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(json!({
        "schemaVersion": "ioi.wallet-core-lite.authority.v1",
        "source": "agentgres_wallet_authority_projection",
        "generatedAt": model_mount_projection_generated_at(request),
        "server": status::server_status_or_default(request),
        "wallet": wallet,
        "vault": object_or_null(state.get("vault")),
        "grants": grants,
        "vaultRefs": vault_refs,
        "approvals": [],
        "approvalQueue": {
            "status": "not_configured",
            "pendingCount": 0,
            "evidenceRefs": ["wallet.network.approval_queue.pending_runtime_adapter"],
        },
        "receipts": authority_receipts,
        "summary": {
            "activeGrants": active_grants,
            "revokedGrants": revoked_grants,
            "vaultRefs": vault_ref_count,
            "pendingApprovals": 0,
            "receiptCount": authority_receipt_count,
            "remoteWalletConfigured": remote_wallet_configured,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_receipts(state_dir: &std::path::Path, receipts: &[Value]) {
        let receipt_dir = state_dir.join("receipts");
        std::fs::create_dir_all(&receipt_dir).expect("receipt dir");
        for receipt in receipts {
            let receipt_id = json_string_field(receipt, "id").expect("receipt id");
            std::fs::write(
                receipt_dir.join(format!("{receipt_id}.json")),
                serde_json::to_string_pretty(receipt).expect("receipt json"),
            )
            .expect("write receipt");
        }
    }

    fn write_records(state_dir: &std::path::Path, record_dir: &str, records: &[Value]) {
        let dir = state_dir.join(record_dir);
        std::fs::create_dir_all(&dir).expect("record dir");
        for record in records {
            let record_id = json_string_field(record, "id").expect("record id");
            std::fs::write(
                dir.join(format!("{record_id}.json")),
                serde_json::to_string_pretty(record).expect("record json"),
            )
            .expect("write record");
        }
    }

    #[test]
    fn authority_snapshot_is_planned_in_rust_model_mount_projection() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_receipts(
            temp.path(),
            &[
                json!({"id": "receipt-route", "kind": "model_route_selection"}),
                json!({"id": "receipt-token", "kind": "permission_token"}),
                json!({"id": "receipt-vault", "kind": "vault_adapter_health"}),
            ],
        );
        write_records(
            temp.path(),
            "capability-tokens",
            &[json!({
                "id": "token-create",
                "record_id": "token-create",
                "object": "ioi.model_mount_capability_token_control",
                "operation_kind": "model_mount.capability_token.create",
                "token_id": "capability_token:rust",
                "token_hash": "sha256:token",
                "rust_core_boundary": "model_mount.capability_token",
                "wallet_authority_boundary": "wallet.network.capability_token",
                "capability_token_authority": {
                    "authority_hash": "sha256:authority",
                    "audience": "agent-studio",
                    "grant_id": "grant://wallet/capability",
                    "allowed_scopes": ["model.chat:*"],
                    "denied_scopes": ["shell.exec"]
                },
                "public_response": {
                    "token": "ioi_mnt_secret"
                },
                "evidence_refs": [
                    "rust_daemon_core_capability_token_control",
                    "agentgres_capability_token_truth_required",
                    "public_capability_token_js_facade_retired"
                ],
                "planned_at": "2026-06-11T00:00:00.000Z"
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
                "planned_at": "2026-06-11T00:00:00.000Z"
            })],
        );
        let snapshot = authority_snapshot(&ModelMountReadProjectionRequest {
            projection_kind: "authority_snapshot".to_string(),
            schema_version: None,
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: Some("http://127.0.0.1:3200".to_string()),
            state_dir: Some(temp.path().to_string_lossy().to_string()),
            state: json!({
                "wallet": {"remoteAdapter": {"configured": true}},
                "vault": {"status": "ready"},
                "grants": [
                    {"id": "grant-active"},
                    {"id": "grant-revoked", "revokedAt": "2026-06-11T00:01:00.000Z"}
                ],
                "vault_refs": [{"id": "vault-ref"}],
                "receipts": [{"id": "receipt-js", "kind": "permission_token"}]
            }),
        })
        .expect("authority snapshot");

        assert_eq!(snapshot["source"], "agentgres_wallet_authority_projection");
        assert_eq!(snapshot["generatedAt"], "2026-06-11T00:00:00.000Z");
        assert_eq!(snapshot["summary"]["activeGrants"], 1);
        assert_eq!(snapshot["summary"]["revokedGrants"], 0);
        assert_eq!(snapshot["summary"]["vaultRefs"], 1);
        assert_eq!(snapshot["summary"]["receiptCount"], 2);
        assert_eq!(snapshot["summary"]["remoteWalletConfigured"], true);
        assert_eq!(snapshot["grants"].as_array().expect("grants").len(), 1);
        assert_eq!(snapshot["grants"][0]["token_id"], "capability_token:rust");
        assert_eq!(snapshot["grants"][0].get("token"), None);
        assert_eq!(
            snapshot["grants"][0]["capability_token_projection_boundary"],
            "model_mount.capability_token_projection"
        );
        assert_eq!(
            snapshot["vaultRefs"].as_array().expect("vault refs").len(),
            1
        );
        assert_eq!(snapshot["vaultRefs"][0]["vault_ref_hash"], "vault-hash");
        assert_eq!(
            snapshot["vaultRefs"][0]["vault_projection_boundary"],
            "model_mount.vault_projection"
        );
        assert_eq!(
            snapshot["server"]["nativeBaseUrl"],
            "http://127.0.0.1:3200/api/v1"
        );
        assert_eq!(snapshot["receipts"].as_array().expect("receipts").len(), 2);
    }

    #[test]
    fn authority_snapshot_rejects_missing_custody_replay_state_dir() {
        let error = authority_snapshot(&ModelMountReadProjectionRequest {
            projection_kind: "authority_snapshot".to_string(),
            schema_version: None,
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            download_id: None,
            base_url: None,
            state_dir: None,
            state: json!({
                "receipts": [{"id": "receipt-token", "kind": "permission_token"}]
            }),
        })
        .expect_err("state_dir is required");

        assert_eq!(
            error.code,
            "model_mount_wallet_custody_replay_state_dir_required"
        );
    }
}
