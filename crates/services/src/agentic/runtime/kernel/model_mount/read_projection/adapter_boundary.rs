use serde_json::{json, Value};

pub(super) fn adapter_boundaries(state: &Value) -> Value {
    let _ = state;
    json!({
        "wallet": {
            "port": "WalletAuthorityPort",
            "implementation": "wallet_network_authority",
            "methods": ["authorizeCapabilityExit", "listTokens", "revokeToken", "adapterStatus"],
            "evidenceRefs": [
                "wallet.network.authority_boundary",
                "rust_daemon_core_wallet_authority_projection_required"
            ],
        },
        "vault": {
            "port": "VaultPort",
            "implementation": "ctee_private_workspace_vault",
            "methods": ["bindVaultRef", "resolveVaultRef", "listVaultRefs", "removeVaultRef", "adapterStatus"],
            "plaintextPersistence": false,
            "evidenceRefs": [
                "ctee_no_plaintext_custody_boundary",
                "rust_daemon_core_vault_projection_required"
            ],
        },
        "oauth": {
            "port": "OAuthCredentialProvider",
            "implementation": "agentgres_vault_oauth_session",
            "methods": [
                "startAuthorization",
                "completeAuthorization",
                "exchangeAuthorizationCode",
                "refreshAccessToken",
                "revokeSession",
                "resolveAccessHeader",
            ],
            "plaintextPersistence": false,
            "evidenceRefs": [
                "OAuthCredentialProvider",
                "VaultOAuthAuthorizationState",
                "VaultOAuthSession",
                "oauth_tokens_not_persisted",
            ],
        },
        "agentgres": {
            "port": "AgentgresStorePort",
            "implementation": "agentgres_admitted_model_mounting_store",
            "methods": ["appendAcceptedReceipt", "recordState", "expectedHeads", "adapterStatus"],
            "evidenceRefs": [
                "agentgres_model_mount_read_truth_required",
                "rust_daemon_core_agentgres_projection_required"
            ],
        },
    })
}

pub(super) fn workflow_bindings() -> Value {
    Value::Array(
        [
            ("Model Call", "chat"),
            ("Structured Output", "responses"),
            ("Verifier", "chat"),
            ("Planner", "chat"),
            ("Embedding", "embeddings"),
            ("Reranker", "rerank"),
            ("Vision", "vision"),
            ("Local Tool/MCP", "mcp"),
            ("Model Router", "chat"),
            ("Receipt Gate", "receipt_gate"),
        ]
        .into_iter()
        .map(|(node, capability)| {
            json!({
                "node": node,
                "modelId": Value::Null,
                "supportsExplicitModelId": true,
                "supportsModelPolicy": true,
                "capability": capability,
                "receiptRequired": true,
                "routeId": "route.local-first",
                "daemonApi": if node == "Receipt Gate" {
                    "/v1/model-mount/workflows/receipt-gate"
                } else {
                    "/v1/model-mount/workflows/nodes/execute"
                },
            })
        })
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_boundaries_are_planned_in_rust_model_mount_projection() {
        let boundaries = adapter_boundaries(&json!({
            "wallet": {"status": "retired-js-input"},
            "agentgres_store": {"status": "retired-js-input"}
        }));

        assert_eq!(boundaries["wallet"]["port"], "WalletAuthorityPort");
        assert_eq!(
            boundaries["wallet"]["implementation"],
            "wallet_network_authority"
        );
        assert_eq!(
            boundaries["vault"]["plaintextPersistence"],
            Value::Bool(false)
        );
        assert_eq!(boundaries["agentgres"]["port"], "AgentgresStorePort");
        assert!(boundaries["agentgres"]["evidenceRefs"]
            .as_array()
            .expect("evidence refs")
            .contains(&Value::String(
                "agentgres_model_mount_read_truth_required".to_string()
            )));
        assert!(!boundaries
            .as_object()
            .expect("boundaries")
            .contains_key("agentgres_store"));
    }

    #[test]
    fn workflow_bindings_are_planned_in_rust_model_mount_projection() {
        let bindings = workflow_bindings();
        let bindings = bindings.as_array().expect("workflow bindings");

        assert_eq!(bindings.len(), 10);
        assert_eq!(bindings[0]["node"], "Model Call");
        assert_eq!(bindings[4]["capability"], "embeddings");
        assert_eq!(bindings[9]["node"], "Receipt Gate");
        assert_eq!(
            bindings[9]["daemonApi"],
            "/v1/model-mount/workflows/receipt-gate"
        );
        assert_eq!(
            bindings[0]["daemonApi"],
            "/v1/model-mount/workflows/nodes/execute"
        );
    }
}
