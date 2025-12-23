// Path: crates/forge/tests/state_iavl_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-iavl",
    feature = "commitment-hash"
))]

use anyhow::{anyhow, Result};
use ioi_forge::testing::{build_test_artifacts, rpc::query_state_key, TestCluster};
use ioi_types::{
    app::{
        ActiveKeyRecord, ChainStatus, SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    keys::STATUS_KEY,
};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_iavl_tree_e2e() -> Result<()> {
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_commitment_scheme("Hash")
        // --- UPDATED: Using GenesisBuilder API ---
        .with_genesis_modifier(|builder, keys| {
            let key = &keys[0];

            // 1. Register Identity
            // Returns AccountId, which we need for the validator set
            let account_id = builder.add_identity(key);
            let acct_hash = account_id.0;

            // 2. Validator Set
            let validator_set = ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        // FIX: Use ED25519 constant
                        suite: SignatureSuite::ED25519,
                        public_key_hash: acct_hash,
                        since_height: 0,
                    },
                }],
            };

            let vs = ValidatorSetsV1 {
                current: validator_set,
                next: None,
            };
            builder.set_validators(&vs);
        })
        .build()
        .await?;

    let node_guard = &cluster.validators[0];
    let rpc_addr = &node_guard.validator().rpc_addr;
    let mut ok = false;
    for _ in 0..20 {
        sleep(Duration::from_secs(2)).await;
        if let Some(bytes) = query_state_key(rpc_addr, STATUS_KEY).await? {
            let status: ChainStatus =
                codec::from_bytes_canonical(&bytes).map_err(anyhow::Error::msg)?;
            if status.height >= 1 {
                ok = true;
                break;
            }
        }
    }
    if !ok {
        anyhow::bail!("Node did not produce block #1 in time");
    }

    println!("--- IAVL Tree E2E Test Passed ---");

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    Ok(())
}
