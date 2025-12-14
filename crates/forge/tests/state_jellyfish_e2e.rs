// Path: crates/forge/tests/state_jellyfish_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-jellyfish",
    feature = "commitment-hash"
))]

use anyhow::{anyhow, Result};
use ioi_forge::testing::{build_test_artifacts, rpc::query_state_key, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, ActiveKeyRecord, ChainStatus, SignatureSuite,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    keys::{STATUS_KEY, VALIDATOR_SET_KEY},
};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_jellyfish_merkle_tree_e2e() -> Result<()> {
    // 1. Build test artifacts (contracts, services)
    build_test_artifacts();

    // 2. Launch Cluster with Jellyfish config
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("Jellyfish") // Use new JMT backend
        .with_commitment_scheme("Hash")
        .with_genesis_modifier(|builder, keys| {
            let key = &keys[0];

            // 1. Register Identity
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
                        suite: SignatureSuite::Ed25519,
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

    // 3. Verify Liveness
    // If the node starts producing blocks, it means the JMT backend is successfully
    // processing state updates (Apply Batch) and computing roots.
    let node_guard = &cluster.validators[0];
    let rpc_addr = &node_guard.validator().rpc_addr;
    
    println!("Waiting for block production...");
    let mut ok = false;
    for _ in 0..20 {
        sleep(Duration::from_secs(2)).await;
        // Check if the chain status key exists in the JMT and has updated
        if let Some(bytes) = query_state_key(rpc_addr, STATUS_KEY).await? {
            let status: ChainStatus =
                codec::from_bytes_canonical(&bytes).map_err(anyhow::Error::msg)?;
            println!("Chain Height: {}", status.height);
            if status.height >= 2 {
                ok = true;
                break;
            }
        }
    }

    if !ok {
        anyhow::bail!("Node did not produce blocks with Jellyfish backend in time");
    }

    println!("--- Jellyfish Merkle Tree E2E Test Passed ---");

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    Ok(())
}