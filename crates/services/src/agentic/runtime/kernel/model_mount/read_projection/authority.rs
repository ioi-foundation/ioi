use serde_json::{json, Value};

use super::common::{
    array_field, json_string_field, model_mount_projection_generated_at, object_or_null,
};
use super::{status, ModelMountReadProjectionRequest};

pub(super) fn authority_snapshot(request: &ModelMountReadProjectionRequest) -> Value {
    let state = &request.state;
    let grants = array_field(state, "grants");
    let vault_refs = array_field(state, "vault_refs");
    let authority_receipts = array_field(state, "receipts")
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
    let active_grants = grants
        .iter()
        .filter(|grant| grant.get("revokedAt").is_none())
        .count();
    let revoked_grants = grants.len().saturating_sub(active_grants);
    let vault_ref_count = vault_refs.len();
    let authority_receipt_count = authority_receipts.len();
    let remote_wallet_configured = wallet
        .get("remoteAdapter")
        .and_then(|remote| remote.get("configured"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "schemaVersion": "ioi.wallet-core-lite.authority.v1",
        "source": "agentgres_wallet_authority_projection",
        "generatedAt": model_mount_projection_generated_at(request),
        "server": status::server_status(request),
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_snapshot_is_planned_in_rust_model_mount_projection() {
        let snapshot = authority_snapshot(&ModelMountReadProjectionRequest {
            projection_kind: "authority_snapshot".to_string(),
            schema_version: None,
            generated_at: Some("2026-06-11T00:00:00.000Z".to_string()),
            receipt_id: None,
            engine_id: None,
            provider_id: None,
            base_url: Some("http://127.0.0.1:3200".to_string()),
            state: json!({
                "wallet": {"remoteAdapter": {"configured": true}},
                "vault": {"status": "ready"},
                "grants": [
                    {"id": "grant-active"},
                    {"id": "grant-revoked", "revokedAt": "2026-06-11T00:01:00.000Z"}
                ],
                "vault_refs": [{"id": "vault-ref"}],
                "receipts": [
                    {"id": "receipt-route", "kind": "model_route_selection"},
                    {"id": "receipt-token", "kind": "permission_token"},
                    {"id": "receipt-vault", "kind": "vault_adapter_health"}
                ]
            }),
        });

        assert_eq!(snapshot["source"], "agentgres_wallet_authority_projection");
        assert_eq!(snapshot["generatedAt"], "2026-06-11T00:00:00.000Z");
        assert_eq!(snapshot["summary"]["activeGrants"], 1);
        assert_eq!(snapshot["summary"]["revokedGrants"], 1);
        assert_eq!(snapshot["summary"]["vaultRefs"], 1);
        assert_eq!(snapshot["summary"]["receiptCount"], 2);
        assert_eq!(snapshot["summary"]["remoteWalletConfigured"], true);
        assert_eq!(
            snapshot["server"]["nativeBaseUrl"],
            "http://127.0.0.1:3200/api/v1"
        );
        assert_eq!(snapshot["receipts"].as_array().expect("receipts").len(), 2);
    }
}
