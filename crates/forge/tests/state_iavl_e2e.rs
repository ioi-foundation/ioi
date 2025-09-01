// Path: crates/forge/tests/state_iavl_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{build_test_artifacts, TestCluster};
use depin_sdk_types::{
    app::{account_id_from_key_material, AccountId, ActiveKeyRecord, ChainStatus, SignatureSuite},
    codec,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, AUTHORITY_SET_KEY, STATUS_KEY},
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
    // 1. Build binaries with the specific IAVL feature enabled
    build_test_artifacts("consensus-poa,vm-wasm,tree-iavl,primitive-hash");

    // 2. Launch a cluster configured to use the IAVLTree
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_commitment_scheme("Hash")
        .with_genesis_modifier(|genesis, keys| {
            let suite = SignatureSuite::Ed25519;
            let pk = keys[0].public().encode_protobuf();
            let acct = AccountId(account_id_from_key_material(suite, &pk).unwrap());

            // 1) PoA authority set: Vec<AccountId>, canonical-encoded
            let auth_bytes = codec::to_bytes_canonical(&vec![acct]);
            genesis["genesis_state"][std::str::from_utf8(AUTHORITY_SET_KEY).unwrap()] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&auth_bytes)));

            // 2) ActiveKeyRecord for the authority (helps PoA checks)
            let record = ActiveKeyRecord {
                suite,
                pubkey_hash: acct.0,
                since_height: 0,
            };
            let record_key = [b"identity::key_record::", acct.as_ref()].concat();
            let record_bytes = codec::to_bytes_canonical(&record);
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes)));

            // 3) AccountId -> PublicKey map (used to derive header validator_set)
            let map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct.as_ref()].concat();
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&map_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&pk)));
        })
        .build()
        .await?;

    // 3. Assert that the node can produce a block by polling its state.
    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let mut ok = false;
    for _ in 0..20 {
        sleep(Duration::from_secs(2)).await;
        if let Some(bytes) = query_state_key(rpc_addr, STATUS_KEY).await? {
            let status: ChainStatus = serde_json::from_slice(&bytes)?;
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
    Ok(())
}
