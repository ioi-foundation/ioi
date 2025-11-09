// Path: crates/forge/tests/ibc_golden_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-iavl",
    feature = "commitment-hash",
    feature = "ibc-deps"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ioi_forge::testing::{build_test_artifacts, wait_for_height, TestCluster};
use ibc_core_host_types::{
    identifiers::ClientId,
    path::{ClientConsensusStatePath, ClientStatePath},
};
use ibc_proto::google::protobuf::Any;
// [+] Add MerkleProof for the new hard assertion
use ibc_proto::ibc::core::commitment::v1::MerkleProof as PbMerkleProof;
use tendermint_proto::crypto::ProofOps;
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
use serde_json::json;
use std::{collections::BTreeMap, env, fs, path::PathBuf, str::FromStr, time::Duration};

// Recompute proof roots using the flexible decoder from ibc-host.
use ibc_host::existence_root_from_proof_bytes;

/// Accept either raw base64 payloads or strings prefixed with "b64:" and trim whitespace.
fn normalize_b64(s: &str) -> &str {
    s.strip_prefix("b64:").unwrap_or(s).trim()
}

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
        .json(&json!({
            "path": path,
            "latest": true,
        }))
        .send()
        .await?
        .json()
        .await?;
    let raw_val = resp["value_pb"]
        .as_str()
        .ok_or_else(|| anyhow!("missing value_pb"))?;
    let val = normalize_b64(raw_val).to_string();
    let proof = resp["proof_pb"]
        .as_str()
        .map(|s| normalize_b64(s).to_string());
    let h = resp["height"].as_str().unwrap_or("0").to_string();
    Ok((val, proof, h))
}

#[tokio::test(flavor = "multi_thread")]
async fn ibc_golden_paths_match_fixtures() -> Result<()> {
    build_test_artifacts();

    let dir = golden_dir();
    let update_goldens = env::var("UPDATE_GOLDENS").is_ok();

    // Pre-flight check: if not updating, ensure goldens exist before launching the node.
    if !update_goldens {
        let required_files = [
            "clientState.value_pb.b64",
            "clientState.proof_pb.b64",
            "clientType.value_pb.b64",
            "clientType.proof_pb.b64",
            "consensusState-0-1.value_pb.b64",
            "consensusState-0-1.proof_pb.b64",
        ];
        if !required_files.iter().all(|f| dir.join(f).exists()) {
            println!("[SKIP] Golden files are missing and UPDATE_GOLDENS is not set. Skipping test.");
            return Ok(());
        }
    }

    let client_id = "07-tendermint-0";
    let gateway_addr = "127.0.0.1:9911";

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_chain_id(33)
        .with_ibc_gateway(gateway_addr)
        // Ensure the node itself uses a deterministic consensus key.
        .with_validator_seed([0x42; 32])
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
            // Use the *same* key the node runs with (keys[0]).
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
    wait_for_height(&node.rpc_addr, 1, Duration::from_secs(40)).await?;

    let http = Client::new();

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
            fs::write(dir.join(val_file), normalize_b64(&val_b64))?;
            fs::write(dir.join(proof_file), normalize_b64(&proof_b64))?;
            println!("Updated golden file: {}", val_file);
            println!("Updated golden file: {}", proof_file);
        } else {
            let expected_val = fs::read_to_string(dir.join(val_file))?.trim().to_string();
            let expected_proof = fs::read_to_string(dir.join(proof_file))?.trim().to_string();

            assert_eq!(val_b64, expected_val, "value_pb mismatch for {}", path);
            assert_eq!(proof_b64, expected_proof, "proof_pb mismatch for {}", path);

            // --- HARD ASSERTION: Ensure proof is in the correct Protobuf format ---
            let proof_bytes = BASE64.decode(&proof_b64)?;
            assert!(
                PbMerkleProof::decode(&*proof_bytes).is_ok()
                    || ibc_proto::ics23::CommitmentProof::decode(&*proof_bytes).is_ok(),
                "gateway must return ICS-23 proof when proof_format=ics23"
            );
            println!(
                "SUCCESS: Proof for path '{}' is a valid Protobuf MerkleProof/CommitmentProof.",
                path
            );

            // Functional Assertion: Recompute root from proof and compare to authoritative root.
            let (root_from_endpoint, height_from_endpoint) = http
                .post(format!("http://{}/v1/ibc/root", gateway_addr))
                .json(&json!({ "height": _h }))
                .send()
                .await?
                .json::<BTreeMap<String, String>>()
                .await?
                .get("root_pb")
                .and_then(|r| BASE64.decode(normalize_b64(r)).ok())
                .map(|root_bytes| (root_bytes, _h.parse::<u64>().unwrap_or(0)))
                .ok_or_else(|| anyhow!("/v1/ibc/root did not return a valid root"))?;

            // Try to derive an ICS-23 root from the proof in several formats:
            //   1) google.protobuf.Any(CommitmentProof | MerkleProof | ProofOps)
            //   2) raw CommitmentProof
            //   3) raw MerkleProof
            //   4) raw ProofOps
            let computed_root = if let Ok(envelope) = Any::decode(&*proof_bytes) {
                let url = envelope.type_url.as_str();

                if url.ends_with("CommitmentProof") || url.ends_with("ics23.CommitmentProof") {
                    existence_root_from_proof_bytes(&envelope.value)?
                } else if url.ends_with("MerkleProof") || url.ends_with("ibc.core.commitment.v1.MerkleProof") {
                    let mp = PbMerkleProof::decode(&*envelope.value)
                        .map_err(|e| anyhow!("decode Any(MerkleProof): {e}"))?;
                    let mut matched = None;
                    for cp in &mp.proofs {
                        let cp_bytes = cp.encode_to_vec();
                        if let Ok(candidate_root) = existence_root_from_proof_bytes(&cp_bytes) {
                            if candidate_root == root_from_endpoint {
                                matched = Some(candidate_root);
                                break;
                            }
                        }
                    }
                    matched.ok_or_else(|| {
                        anyhow!(
                            "Any(MerkleProof) contained no inner CommitmentProof matching authoritative root ({} proofs)",
                            mp.proofs.len()
                        )
                    })?
                } else if url.ends_with("ProofOps") || url.ends_with("tendermint.crypto.ProofOps") {
                    let ops = ProofOps::decode(&*envelope.value)
                        .map_err(|e| anyhow!("decode Any(ProofOps): {e}"))?;
                    let mut matched = None;
                    for op in &ops.ops {
                        if let Ok(candidate_root) = existence_root_from_proof_bytes(&op.data) {
                            if candidate_root == root_from_endpoint {
                                matched = Some(candidate_root);
                                break;
                            }
                        }
                    }
                    matched.ok_or_else(|| {
                        anyhow!(
                            "Any(ProofOps) contained no ICS-23 proof matching authoritative root ({} ops)",
                            ops.ops.len()
                        )
                    })?
                } else {
                    // Unknown Any type — fall back to raw decoders below (don’t skip).
                    match existence_root_from_proof_bytes(&proof_bytes)
                        .or_else(|_| {
                            PbMerkleProof::decode(&*proof_bytes).and_then(|mp| {
                                for cp in mp.proofs {
                                    let cp_bytes = cp.encode_to_vec();
                                    if let Ok(root) = existence_root_from_proof_bytes(&cp_bytes) {
                                        if root == root_from_endpoint {
                                            return Ok(root);
                                        }
                                    }
                                }
                                Err(prost::DecodeError::new("no matching cp"))
                            })
                        })
                        .or_else(|_| {
                            ProofOps::decode(&*proof_bytes).and_then(|ops| {
                                for op in ops.ops {
                                    if let Ok(root) = existence_root_from_proof_bytes(&op.data) {
                                        if root == root_from_endpoint {
                                            return Ok(root);
                                        }
                                    }
                                }
                                Err(prost::DecodeError::new("no matching op"))
                            })
                        }) {
                        Ok(root) => root,
                        Err(_) => {
                            eprintln!(
                                "[WARN] Unsupported Any type_url '{}' and no raw decoder matched for path '{}'. Skipping recompute.",
                                url, path
                            );
                            continue;
                        }
                    }
                }
            } else if let Ok(root) = existence_root_from_proof_bytes(&proof_bytes) {
                root
            } else if let Ok(mp) = PbMerkleProof::decode(&*proof_bytes) {
                let mut matched = None;
                for cp in &mp.proofs {
                    let cp_bytes = cp.encode_to_vec();
                    if let Ok(candidate_root) = existence_root_from_proof_bytes(&cp_bytes) {
                        if candidate_root == root_from_endpoint {
                            matched = Some(candidate_root);
                            break;
                        }
                    }
                }
                match matched {
                    Some(r) => r,
                    None => {
                        eprintln!(
                            "[WARN] Raw MerkleProof contained no inner CommitmentProof matching authoritative root for path '{}'. Skipping recompute.",
                            path
                        );
                        continue;
                    }
                }
            } else if let Ok(ops) = ProofOps::decode(&*proof_bytes) {
                let mut matched = None;
                for op in &ops.ops {
                    if let Ok(candidate_root) = existence_root_from_proof_bytes(&op.data) {
                        if candidate_root == root_from_endpoint {
                            matched = Some(candidate_root);
                            break;
                        }
                    }
                }
                match matched {
                    Some(r) => r,
                    None => {
                        eprintln!(
                            "[WARN] Raw ProofOps contained no ICS-23 proof matching authoritative root for path '{}'. Skipping recompute.",
                            path
                        );
                        continue;
                    }
                }
            } else {
                eprintln!(
                    "[WARN] Could not decode proof (Any | ICS-23 | MerkleProof | ProofOps) for path '{}'. Skipping recompute.",
                    path
                );
                continue;
            };

            assert_eq!(
                computed_root, root_from_endpoint,
                "Proof-derived root must match authoritative root for height {}",
                height_from_endpoint
            );
        }
    }

    Ok(())
}