// Path: crates/forge/tests/ibc_golden_e2e.rs

//! End-to-End Test: IBC Golden File Verification
//!
//! This test launches a node with a specific, hardcoded genesis state, queries
//! known IBC paths via the HTTP gateway, and asserts that the returned values
//! and proofs match pre-computed "golden" files.
//!
//! This serves as a critical regression test to ensure that any changes to state
//! serialization, hashing, or proof generation do not break compatibility with
//! existing IBC standards and clients.

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-iavl",
    feature = "commitment-hash",
    feature = "ibc-deps"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ioi_forge::testing::{build_test_artifacts, poll::wait_for_height, TestCluster};
use ibc_core_host_types::{
    identifiers::ClientId,
    path::{ClientConsensusStatePath, ClientStatePath},
};
use ibc_proto::google::protobuf::Any;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, Credential, SignatureSuite,
        ValidatorSetBlob, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use prost::Message;
use reqwest::Client;
use serde_json::{json, Value};
use std::{env, fs, path::PathBuf, str::FromStr, time::Duration};

fn add_full_identity(
    genesis: &mut serde_json::Map<String, serde_json::Value>,
    kp: &Keypair,
) -> AccountId {
    let suite = SignatureSuite::Ed25519;
    let pk = kp.public().encode_protobuf();
    let id_hash = account_id_from_key_material(suite, &pk).unwrap();
    let account_id = AccountId(id_hash);
    // creds
    let cred = Credential {
        suite,
        public_key_hash: id_hash,
        activation_height: 0,
        l2_location: None,
    };
    let arr: [Option<Credential>; 2] = [Some(cred), None];
    let key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
    genesis.insert(
        format!("b64:{}", BASE64.encode(&key)),
        json!(format!(
            "b64:{}",
            BASE64.encode(codec::to_bytes_canonical(&arr).unwrap())
        )),
    );
    // pubkey map
    let map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
    genesis.insert(
        format!("b64:{}", BASE64.encode(&map_key)),
        json!(format!("b64:{}", BASE64.encode(&pk))),
    );
    account_id
}

fn golden_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("goldens");
    p
}

async fn query_b64(
    client: &Client,
    gw: &str,
    path: &str,
) -> Result<(String, Option<String>, String)> {
    let resp: serde_json::Value = client
        .post(format!("http://{gw}/v1/ibc/query"))
        .json(&json!({ "path": path, "latest": true }))
        .send()
        .await?
        .json()
        .await?;
    let val = resp["value_pb"]
        .as_str()
        .ok_or_else(|| anyhow!("missing value_pb"))?
        .to_string();
    let proof = resp["proof_pb"].as_str().map(|s| s.to_string());
    let h = resp["height"].as_str().unwrap_or("0").to_string();
    Ok((val, proof, h))
}

#[tokio::test(flavor = "multi_thread")]
async fn ibc_golden_paths_match_fixtures() -> Result<()> {
    build_test_artifacts();

    let client_id = "07-tendermint-0";
    let gateway_addr = "127.0.0.1:9911";

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_chain_id(33)
        .with_ibc_gateway(gateway_addr)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 33,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Ibc(ioi_types::config::IbcConfig {
            enabled_clients: vec!["07-tendermint".into(), "tendermint-v0.34".into()],
        }))
        .with_genesis_modifier(move |genesis, keys| {
            let gs = genesis["genesis_state"].as_object_mut().unwrap();
            let kp = &keys[0];
            let val_id = add_full_identity(gs, kp);

            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1,
                        validators: vec![ValidatorV1 {
                            account_id: val_id,
                            weight: 1,
                            consensus_key: ActiveKeyRecord {
                                suite: SignatureSuite::Ed25519,
                                public_key_hash: val_id.0,
                                since_height: 0,
                            },
                        }],
                    },
                    next: None,
                },
            };
            let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();
            gs.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64.encode(vs_bytes))),
            );

            // Re-create the exact genesis state that generated the golden files
            let client_type_path = format!("clients/{}/clientType", client_id);
            let client_state_path =
                ClientStatePath::new(ClientId::from_str(client_id).unwrap()).to_string();
            let consensus_state_path =
                ClientConsensusStatePath::new(ClientId::from_str(client_id).unwrap(), 0, 1)
                    .to_string();

            gs.insert(
                client_type_path,
                json!(format!("b64:{}", BASE64.encode("07-tendermint"))),
            );

            let client_state_b64 =
                fs::read_to_string(golden_dir().join("clientState.value_pb.b64"))
                    .expect("read clientState.value_pb.b64");
            let client_state_bytes = BASE64
                .decode(client_state_b64.trim())
                .expect("base64 decode clientState.value_pb.b64");
            let client_state_any =
                Any::decode(&client_state_bytes[..]).expect("prost Any decode for clientState");
            gs.insert(
                client_state_path,
                json!(format!(
                    "b64:{}",
                    BASE64.encode(client_state_any.encode_to_vec())
                )),
            );

            let consensus_state_b64 =
                fs::read_to_string(golden_dir().join("consensusState-0-1.value_pb.b64"))
                    .expect("read consensusState-0-1.value_pb.b64");
            let consensus_state_bytes = BASE64
                .decode(consensus_state_b64.trim())
                .expect("base64 decode consensusState-0-1.value_pb.b64");
            let consensus_state_any = Any::decode(&consensus_state_bytes[..])
                .expect("prost Any decode for consensusState");
            gs.insert(
                consensus_state_path,
                json!(format!(
                    "b64:{}",
                    BASE64.encode(consensus_state_any.encode_to_vec())
                )),
            );
        })
        .build()
        .await?;

    let node = &cluster.validators[0];
    wait_for_height(&node.rpc_addr, 1, Duration::from_secs(20)).await?;

    let http = Client::new();
    let dir = golden_dir();

    let update_goldens = env::var("UPDATE_GOLDENS").is_ok();

    let cases = [
        (
            format!("clients/{}/clientType", client_id),
            "clientType.value_pb.b64",
            "clientType.proof_pb.b64",
        ),
        (
            ClientStatePath::new(ClientId::from_str(client_id)?).to_string(),
            "clientState.value_pb.b64",
            "clientState.proof_pb.b64",
        ),
        (
            ClientConsensusStatePath::new(ClientId::from_str(client_id)?, 0, 1).to_string(),
            "consensusState-0-1.value_pb.b64",
            "consensusState-0-1.proof_pb.b64",
        ),
    ];

    for (path, val_file, proof_file) in cases {
        let (val_b64, proof_b64_opt, _h) = query_b64(&http, gateway_addr, &path).await?;
        let proof_b64 = proof_b64_opt.ok_or_else(|| anyhow!("missing proof_pb for {}", path))?;

        if update_goldens {
            fs::write(dir.join(val_file), &val_b64)?;
            fs::write(dir.join(proof_file), &proof_b64)?;
            println!("Updated golden file: {}", val_file);
            println!("Updated golden file: {}", proof_file);
        } else {
            let expected_val = fs::read_to_string(dir.join(val_file))?.trim().to_string();
            let expected_proof = fs::read_to_string(dir.join(proof_file))?.trim().to_string();

            assert_eq!(val_b64, expected_val, "value_pb mismatch for {}", path);
            assert_eq!(proof_b64, expected_proof, "proof_pb mismatch for {}", path);
        }
    }

    Ok(())
}
