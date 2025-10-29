// Path: crates/forge/tests/ibc_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash",
    feature = "svc-ibc"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dcrypt::{api::Signature as DcryptSignature, sign::eddsa::Ed25519SecretKey};
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::{wait_for, wait_for_height},
    TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, SignatureSuite,
        SystemPayload, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, ACCOUNT_NONCE_PREFIX, IDENTITY_CREDENTIALS_PREFIX,
        VALIDATOR_SET_KEY,
    },
    service_configs::MigrationConfig,
};
use ibc_client_tendermint::{
    consensus_state::ConsensusState as TmConsensusState,
    types::proto::v1::{ClientState as RawTmClientState, ConsensusState as RawTmConsensusState},
};
use ibc_core_client_types::{msgs::MsgUpdateClient, Height as IbcHeight};
use ibc_core_commitment_types::specs::ProofSpecs;
use ibc_core_host_types::{
    identifiers::ClientId,
    path::{ClientConsensusStatePath, ClientStatePath},
};
use ibc_proto::cosmos::tx::v1beta1::TxBody;
use ibc_proto::google::protobuf::Duration as PbDuration;
use ibc_proto::ibc::core::commitment::v1::MerkleRoot;
use ibc_proto::Protobuf; // for encode_vec() on domain msgs
use ibc_proto::{google::protobuf::Any, google::protobuf::Timestamp as IbcTimestamp};
use prost::Message;
use reqwest::Client;
use serde_json::json;
use std::{str::FromStr, time::Duration};
use tendermint::{
    account,
    block::{self, signed_header::SignedHeader as TendermintSignedHeader},
    chain::Id as TmChainId,
    hash::Hash,
    vote::{Type as VoteType, ValidatorIndex, Vote},
    Time as TmTime,
};
use tendermint_proto::google::protobuf::Timestamp as PbTimestamp;
use tendermint_proto::types::{
    BlockId as TmProtoBlockId, Commit as TmProtoCommit, CommitSig as TmProtoCommitSig,
    Header as TmProtoHeader, PartSetHeader as TmProtoPartSetHeader,
    SignedHeader as TmProtoSignedHeader, ValidatorSet as TmProtoValidatorSetUnversioned,
};
use tendermint_proto::version::Consensus as TmProtoConsensus;
use tendermint_testgen::light_block::LightBlock as TmLightBlock;

// --- Test Helpers to construct a valid Tendermint Header for ibc-rs ---

fn pb_header_from_testgen(h: tendermint_testgen::Header) -> TmProtoHeader {
    const SHA256_EMPTY: [u8; 32] = [
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9,
        0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52,
        0xB8, 0x55,
    ];
    TmProtoHeader {
        chain_id: h.chain_id.unwrap_or_else(|| "test-chain".to_string()),
        height: h.height.unwrap_or(1) as i64,
        time: Some(PbTimestamp {
            seconds: h.height.unwrap_or(1) as i64,
            nanos: 0,
        }),
        version: Some(TmProtoConsensus { block: 11, app: 0 }),
        proposer_address: vec![0; 20],
        validators_hash: SHA256_EMPTY.to_vec(),
        next_validators_hash: SHA256_EMPTY.to_vec(),
        app_hash: SHA256_EMPTY.to_vec(),
        ..Default::default()
    }
}

fn pb_minimal_commit_for_with_hash(header: &TmProtoHeader, header_hash: Vec<u8>) -> TmProtoCommit {
    TmProtoCommit {
        height: header.height,
        round: 0,
        block_id: Some(TmProtoBlockId {
            hash: header_hash.clone(),
            part_set_header: {
                let mut psh_bytes = Vec::new();
                psh_bytes.extend_from_slice(&(1u32).to_be_bytes()); // total
                psh_bytes.extend_from_slice(&header_hash);
                Some(TmProtoPartSetHeader {
                    total: 1,
                    hash: depin_sdk_crypto::algorithms::hash::sha256(&psh_bytes)
                        .unwrap()
                        .to_vec(),
                })
            },
        }),
        signatures: vec![],
    }
}

fn one_validator_set_and_hash() -> (
    tendermint::validator::Set,
    Vec<u8>,
    TmProtoValidatorSetUnversioned,
    Vec<u8>,
    Ed25519SecretKey,
) {
    let seed: [u8; 32] = [1; 32];
    let sk = Ed25519SecretKey::from_seed(&seed).expect("ed25519 sk from seed");
    let pk = sk.public_key().expect("derive ed25519 pk from sk");
    let pk_bytes: [u8; 32] = pk.to_bytes().try_into().expect("32 bytes");

    let tm_vk = tendermint::crypto::ed25519::VerificationKey::try_from(pk_bytes.as_ref()).unwrap();
    let tm_pk = tendermint::PublicKey::Ed25519(tm_vk);
    let addr = account::Id::from(tm_pk.clone());
    let addr_bytes = addr.as_bytes().to_vec();

    let proto_val = tendermint_proto::types::Validator {
        address: addr.as_bytes().to_vec(),
        pub_key: Some(tm_pk.into()),
        voting_power: 1,
        proposer_priority: 0,
    };
    let domain_val: tendermint::validator::Info = proto_val.clone().try_into().unwrap();
    let domain_set = tendermint::validator::Set::new(vec![domain_val], None);
    let proto_set = TmProtoValidatorSetUnversioned {
        validators: vec![proto_val],
        proposer: None,
        total_voting_power: 1,
    };
    let validators_hash = domain_set.hash().as_bytes().to_vec();

    (domain_set, validators_hash, proto_set, addr_bytes, sk)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ibc_tendermint_client_update_via_gateway() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts();

    let client_id = "07-tendermint-0";
    let mock_cosmos_chain_id = "cosmos-hub-test";
    let gateway_addr = "127.0.0.1:9876";

    let (_set_domain, shared_vals_hash, shared_proto_valset, shared_addr, shared_key) =
        one_validator_set_and_hash();

    // 2. LAUNCH CLUSTER WITH IBC GATEWAY AND GENESIS STATE
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_chain_id(1)
        .with_ibc_gateway(gateway_addr)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Ibc(
            depin_sdk_types::config::IbcConfig {
                enabled_clients: vec!["tendermint-v0.34".to_string()],
            },
        ))
        .with_genesis_modifier({
            let shared_vals_hash = shared_vals_hash.clone();
            move |genesis, keys| {
                let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
                let keypair = &keys[0];
                let pk_bytes = keypair.public().encode_protobuf();
                let account_id_hash =
                    account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                let account_id = AccountId(account_id_hash);
                let vs_bytes = depin_sdk_types::codec::to_bytes_canonical(&ValidatorSetsV1 {
                    current: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1,
                        validators: vec![ValidatorV1 {
                            account_id,
                            weight: 1,
                            consensus_key: ActiveKeyRecord {
                                suite: SignatureSuite::Ed25519,
                                public_key_hash: account_id_hash,
                                since_height: 0,
                            },
                        }],
                    },
                    next: None,
                })
                .unwrap();
                genesis_state.insert(
                    std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
                );
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(
                            depin_sdk_types::codec::to_bytes_canonical(&[
                                Some(depin_sdk_types::app::Credential {
                                    suite: SignatureSuite::Ed25519,
                                    public_key_hash: account_id_hash,
                                    activation_height: 0,
                                    l2_location: None,
                                }),
                                None
                            ]
                                as &[Option<depin_sdk_types::app::Credential>; 2])
                            .unwrap()
                        )
                    )),
                );
                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes))),
                );
                let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
                let nonce_bytes = codec::to_bytes_canonical(&0u64).expect("encode nonce");
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&nonce_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&nonce_bytes))),
                );

                let client_id = ClientId::from_str(client_id).unwrap();
                let client_state_path = ClientStatePath::new(client_id.clone());
                let client_state_pb = RawTmClientState {
                    chain_id: mock_cosmos_chain_id.to_string(),
                    trust_level: Some(ibc_client_tendermint::types::proto::v1::Fraction {
                        numerator: 1,
                        denominator: 3,
                    }),
                    trusting_period: Some(PbDuration {
                        seconds: 14 * 24 * 60 * 60,
                        nanos: 0,
                    }),
                    unbonding_period: Some(PbDuration {
                        seconds: 21 * 24 * 60 * 60,
                        nanos: 0,
                    }),
                    max_clock_drift: Some(PbDuration {
                        seconds: 3,
                        nanos: 0,
                    }),
                    latest_height: Some(ibc_proto::ibc::core::client::v1::Height {
                        revision_number: 0,
                        revision_height: 1,
                    }),
                    proof_specs: {
                        let specs: Vec<_> = ProofSpecs::cosmos().into();
                        specs.into_iter().map(Into::into).collect()
                    },
                    upgrade_path: vec!["upgrade".into(), "upgradedIBCState".into()],
                    frozen_height: Some(ibc_proto::ibc::core::client::v1::Height {
                        revision_number: 0,
                        revision_height: 0,
                    }),
                    ..Default::default()
                };
                let client_state_bytes = client_state_pb.encode_to_vec();
                genesis_state.insert(
                    client_state_path.to_string(),
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(client_state_bytes)
                    )),
                );
                let consensus_state_pb = RawTmConsensusState {
                    timestamp: Some(IbcTimestamp {
                        seconds: 1,
                        nanos: 0,
                    }),
                    root: Some(MerkleRoot { hash: vec![] }),
                    next_validators_hash: shared_vals_hash.clone(),
                };
                let consensus_state_bytes = consensus_state_pb.encode_to_vec();
                let consensus_state_path = ClientConsensusStatePath::new(client_id, 0, 1);
                genesis_state.insert(
                    consensus_state_path.to_string(),
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(consensus_state_bytes)
                    )),
                );
            }
        })
        .build()
        .await?;

    let node = &cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // 3. QUERY INITIAL STATE VIA HTTP GATEWAY
    let http_client = Client::new();
    let client_id_parsed = ClientId::from_str(client_id)?;
    let client_state_path = ClientStatePath::new(client_id_parsed.clone());
    let query_resp: serde_json::Value = http_client
        .post(format!("http://{}/v1/ibc/query", gateway_addr))
        .json(&json!({
            "path": client_state_path.to_string(),
            "latest": true
        }))
        .send()
        .await?
        .json()
        .await?;

    let value_pb_b64 = query_resp["value_pb"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing value_pb"))?;
    let value_bytes = BASE64_STANDARD.decode(value_pb_b64)?;
    let cs_from_gateway = RawTmClientState::decode(value_bytes.as_slice())?;
    assert_eq!(cs_from_gateway.chain_id, mock_cosmos_chain_id);
    println!("SUCCESS: Queried and verified initial client state via HTTP gateway.");

    // 4. SUBMIT A HEADER UPDATE VIA A DIRECT, SIGNED SERVICE CALL
    let header_bytes = {
        let light_block_h2: TmLightBlock = TmLightBlock::new_default(2);
        let mut hdr = pb_header_from_testgen(light_block_h2.header.clone().unwrap());
        hdr.chain_id = mock_cosmos_chain_id.to_string();
        hdr.validators_hash = shared_vals_hash.clone();
        hdr.next_validators_hash = shared_vals_hash.clone();

        let hdr_domain: tendermint::block::Header = hdr.clone().try_into()?;
        let header_hash = hdr_domain.hash().as_bytes().to_vec();

        let psh_hash = {
            let mut psh_bytes = Vec::new();
            psh_bytes.extend_from_slice(&(1u32).to_be_bytes());
            psh_bytes.extend_from_slice(&header_hash);
            depin_sdk_crypto::algorithms::hash::sha256(&psh_bytes)?.to_vec()
        };
        let part_set_header = block::parts::Header::new(
            1,
            Hash::from_bytes(hdr_domain.hash().algorithm(), &psh_hash)?,
        )?;

        let tm_chain_id = TmChainId::try_from(mock_cosmos_chain_id.to_string())?;
        let block_id = block::Id {
            hash: Hash::from_bytes(hdr_domain.hash().algorithm(), &header_hash)?,
            part_set_header,
        };
        let vote = Vote {
            vote_type: VoteType::Precommit,
            height: (hdr.height as u64).try_into()?,
            round: 0u16.into(),
            block_id: Some(block_id.clone()),
            timestamp: Some(TmTime::from_unix_timestamp(1, 0)?),
            validator_address: account::Id::try_from(shared_addr.clone())?,
            validator_index: ValidatorIndex::try_from(0u32)?,
            signature: Default::default(),
            extension: Default::default(),
            extension_signature: Default::default(),
        };
        let mut sign_bytes = Vec::new();
        vote.to_signable_bytes(tm_chain_id, &mut sign_bytes)?;
        let sig = dcrypt::sign::eddsa::Ed25519::sign(&sign_bytes, &shared_key)?;

        let mut commit = pb_minimal_commit_for_with_hash(&hdr, header_hash);
        commit.block_id = Some(TmProtoBlockId {
            hash: block_id.hash.as_bytes().to_vec(),
            part_set_header: Some(block_id.part_set_header.into()),
        });
        commit.signatures.push(TmProtoCommitSig {
            block_id_flag: 2,
            validator_address: shared_addr.clone(),
            timestamp: Some(PbTimestamp {
                seconds: 1,
                nanos: 0,
            }),
            signature: sig.to_bytes().to_vec(),
        });
        let tm_signed_header_proto = TmProtoSignedHeader {
            header: Some(hdr),
            commit: Some(commit),
        };
        let tm_signed_header_domain = TendermintSignedHeader::try_from(tm_signed_header_proto)?;
        let tm_signed_header_unversioned = tm_signed_header_domain.into();
        let ibc_header = ibc_client_tendermint::types::proto::v1::Header {
            signed_header: Some(tm_signed_header_unversioned),
            validator_set: Some(shared_proto_valset.clone()),
            trusted_height: Some(IbcHeight::new(0, 1)?.into()),
            trusted_validators: Some(shared_proto_valset.clone()),
        };
        ibc_header.encode_to_vec()
    };

    let msg_update_client = MsgUpdateClient {
        client_id: client_id_parsed.clone(),
        client_message: Any {
            type_url: "/ibc.lightclients.tendermint.v1.Header".to_string(),
            value: header_bytes,
        },
        signer: "some-cosmos-signer".to_string().into(),
    };
    let any_msg = Any {
        type_url: "/ibc.core.client.v1.MsgUpdateClient".to_string(),
        value: msg_update_client.encode_vec(),
    };
    let tx_body = TxBody {
        messages: vec![any_msg],
        memo: String::new(),
        timeout_height: 0,
        extension_options: vec![],
        non_critical_extension_options: vec![],
    };
    let call_params = tx_body.encode_to_vec();
    let validator_key = &cluster.validators[0].keypair;
    let validator_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::Ed25519,
            &validator_key.public().encode_protobuf(),
        )
        .unwrap(),
    );

    let next_nonce: u64 = {
        let nonce_key = [ACCOUNT_NONCE_PREFIX, validator_account_id.as_ref()].concat();
        match depin_sdk_forge::testing::rpc::query_state_key(rpc_addr, &nonce_key).await {
            Ok(Some(bytes)) => codec::from_bytes_canonical::<u64>(&bytes).unwrap_or(0),
            _ => 0,
        }
    };
    println!(
        "Using on-chain next_nonce={} for validator account",
        next_nonce
    );

    let call_tx = {
        let payload = SystemPayload::CallService {
            service_id: "ibc".to_string(),
            method: "msg_dispatch@v1".to_string(),
            params: call_params,
        };
        let mut tx_to_sign = depin_sdk_types::app::SystemTransaction {
            header: depin_sdk_types::app::SignHeader {
                account_id: validator_account_id,
                nonce: next_nonce,
                chain_id: 1.into(),
                tx_version: 1,
            },
            payload,
            signature_proof: Default::default(),
        };
        let sign_bytes = tx_to_sign.to_sign_bytes().unwrap();
        let signature = validator_key.sign(&sign_bytes).unwrap();
        tx_to_sign.signature_proof = depin_sdk_types::app::SignatureProof {
            suite: SignatureSuite::Ed25519,
            public_key: validator_key.public().encode_protobuf(),
            signature,
        };
        ChainTransaction::System(Box::new(tx_to_sign))
    };

    depin_sdk_forge::testing::submit_transaction(&node.rpc_addr, &call_tx).await?;
    println!("SUCCESS: Submitted MsgUpdateClient via signed CallService transaction.");

    // 5. VERIFY ON-CHAIN STATE
    wait_for_height(rpc_addr, 2, Duration::from_secs(20)).await?;
    let consensus_state_path_h2 = ClientConsensusStatePath::new(client_id_parsed, 0, 2);
    let cs_bytes = wait_for(
        "consensus state for height 2",
        Duration::from_millis(250),
        Duration::from_secs(30),
        || async {
            depin_sdk_forge::testing::rpc::query_state_key(
                rpc_addr,
                consensus_state_path_h2.to_string().as_bytes(),
            )
            .await
        },
    )
    .await?;
    let cs_pb = RawTmConsensusState::decode(cs_bytes.as_slice())?;
    let _cs_h2 = TmConsensusState::try_from(cs_pb)?;
    println!("SUCCESS: Tendermint consensus state for height 2 was written and decoded.");

    println!("--- Universal Interoperability (Tendermint) E2E Test Passed ---");
    Ok(())
}
