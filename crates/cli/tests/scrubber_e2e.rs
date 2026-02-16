// Path: crates/cli/tests/scrubber_e2e.rs
#![cfg(all(
    feature = "consensus-admft",
    feature = "vm-wasm",
    feature = "state-iavl"
))]

use anyhow::Result;
use ioi_cli::testing::{build_test_artifacts, submit_transaction, wait_for_height, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, SignHeader,
        SignatureProof, SignatureSuite, SystemPayload, SystemTransaction, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1,
    },
    config::{InitialServiceConfig, ValidatorRole},
    keys::active_service_key, // Added import
    service_configs::{ActiveServiceMeta, Capabilities, MethodPermission, MigrationConfig}, // Added imports
};
use std::collections::BTreeMap; // Added import
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn test_pii_firewall_blocks_raw_egress_and_allows_clean_payload() -> Result<()> {
    // 1. Setup
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_role(0, ValidatorRole::Consensus) // Scrubber runs on Consensus/Orchestrator
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        // Use a genesis modifier to ensure the validator has the right permissions/role
        .with_genesis_modifier(|builder, keys| {
            let key = &keys[0];
            let account_id = builder.add_identity(key);

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::ED25519,
                            public_key_hash: account_id.0,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            };
            builder.set_validators(&vs);

            // [FIX] Register dummy "agentic" service meta so PolicyEngine passes
            let mut methods = BTreeMap::new();
            methods.insert("execute_task@v1".to_string(), MethodPermission::User);

            let meta = ActiveServiceMeta {
                id: "agentic".to_string(),
                abi_version: 1,
                state_schema: "v1".to_string(),
                caps: Capabilities::empty(),
                artifact_hash: [0u8; 32],
                activated_at: 0,
                methods,
                allowed_system_prefixes: vec![],
                generation_id: 0,
                parent_hash: None,
                author: None,
                context_filter: None,
            };

            let key = active_service_key("agentic");
            builder.insert_typed(key, &meta);
        })
        .build()
        .await?;

    // ... rest of the test remains the same
    let node = &cluster.validators[0];
    let rpc_addr = &node.validator().rpc_addr;
    let keypair = &node.validator().keypair;

    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // 2. Craft a Transaction with PII
    // The MockBitNet is configured to flag "sk_live_" as PII.
    let sensitive_payload = b"Execute trade using key sk_live_1234567890abcd";

    // We send this to the 'agentic' service which triggers the scrubber in `enforce_firewall`.
    let sys_payload = SystemPayload::CallService {
        service_id: "agentic".to_string(),
        method: "execute_task@v1".to_string(), // Dummy method
        params: sensitive_payload.to_vec(),
    };

    let pk = keypair.public().encode_protobuf();
    let account_id = AccountId(account_id_from_key_material(SignatureSuite::ED25519, &pk)?);

    let mut sys_tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce: 0,
            chain_id: 1.into(),
            tx_version: 1,
            session_auth: None,
        },
        payload: sys_payload,
        signature_proof: SignatureProof::default(),
    };

    let sign_bytes = sys_tx.to_sign_bytes().unwrap();
    sys_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: pk,
        signature: keypair.sign(&sign_bytes)?,
    };

    let tx = ChainTransaction::System(Box::new(sys_tx));

    // 3. Submit and Expect Rejection
    // In Phase 2.2 implementation of `enforce_firewall`, if PII is detected, it returns an Error.
    // So `submit_transaction` should fail.

    let result = submit_transaction(rpc_addr, &tx).await;

    assert!(
        result.is_err(),
        "Transaction with PII should be rejected by firewall"
    );

    let err_msg = result.unwrap_err().to_string();
    println!("Firewall correctly rejected tx: {}", err_msg);
    assert!(
        err_msg.contains("PII detected")
            || err_msg.contains("Blocked by Safety Firewall")
            || err_msg.contains("PII firewall denied raw egress")
    );

    // 4. Submit Clean Transaction
    // "Safe" payload should pass
    let safe_payload = b"Execute trade using public_key pk_test_123";
    let sys_payload_safe = SystemPayload::CallService {
        service_id: "agentic".to_string(),
        method: "execute_task@v1".to_string(),
        params: safe_payload.to_vec(),
    };

    let mut sys_tx_safe = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce: 0, // Reuse nonce 0 since previous tx failed
            chain_id: 1.into(),
            tx_version: 1,
            session_auth: None,
        },
        payload: sys_payload_safe,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes_safe = sys_tx_safe.to_sign_bytes().unwrap();
    sys_tx_safe.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: keypair.public().encode_protobuf(),
        signature: keypair.sign(&sign_bytes_safe)?,
    };
    let tx_safe = ChainTransaction::System(Box::new(sys_tx_safe));

    // This should succeed (or fail later in execution if method doesn't exist, but pass firewall)
    // The mempool acceptance confirms firewall passage.
    let submission_result =
        ioi_cli::testing::rpc::submit_transaction_no_wait(rpc_addr, &tx_safe).await;
    assert!(
        submission_result.is_ok(),
        "Safe transaction should be accepted by firewall"
    );

    cluster.shutdown().await?;
    Ok(())
}
