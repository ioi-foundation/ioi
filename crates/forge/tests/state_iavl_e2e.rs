// Path: crates/forge/tests/state_iavl_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-iavl",
    feature = "commitment-hash"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{add_genesis_identity, build_test_artifacts, TestCluster}; // [+] Import
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainStatus, SignatureSuite,
        ValidatorSetBlob, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    keys::{STATUS_KEY, VALIDATOR_SET_KEY},
};
use reqwest::Client;
use serde_json::json;
use tokio::time::{sleep, Duration};

async fn query_state_key(rpc_addr: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let client = Client::new();
    let request_body = serde_json::json!({
        "jsonrpc":"2.0","method":"query_state","params":[hex::encode(key)],"id":1
    });
    let url = format!("http://{}/rpc", rpc_addr);
    let resp: serde_json::Value = client
        .post(&url)
        .json(&request_body)
        .send()
        .await?
        .json()
        .await?;
    if let Some(err) = resp.get("error") {
        if !err.is_null() {
            return Err(anyhow!("RPC error: {}", err));
        }
    }
    match resp["result"].as_str() {
        Some(hex_val) if !hex_val.is_empty() => Ok(Some(hex::decode(hex_val)?)),
        _ => Ok(None),
    }
}

#[tokio::test]
async fn test_iavl_tree_e2e() -> Result<()> {
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_commitment_scheme("Hash")
        .with_genesis_modifier(|genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let key = &keys[0];

            // [+] Use shared helper
            let account_id = add_genesis_identity(genesis_state, key);
            let acct_hash = account_id.0;

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

            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: validator_set,
                    next: None,
                },
            };
            let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

            // [-] REMOVED: Manual identity record insertion
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
