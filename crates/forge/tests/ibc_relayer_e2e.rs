// Path: crates/forge/tests/ibc_relayer_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash",
    feature = "ibc-deps"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dcrypt::{api::Signature as DcryptSignature, sign::eddsa::Ed25519SecretKey};
use ibc_client_tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc_client_tendermint::types::proto::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState,
    Fraction as TmTrustFraction,
};
use ibc_core_client_types::msgs::MsgUpdateClient;
use ibc_core_client_types::Height as IbcHeight;
use ibc_core_commitment_types::specs::ProofSpecs;
use ibc_core_host_types::{
    identifiers::{ChannelId, ClientId, PortId},
    path::{ChannelEndPath, ClientConsensusStatePath, ClientStatePath},
};
use ibc_primitives::ToProto;
use ibc_proto::ibc::lightclients::tendermint::v1::Header as RawTmHeader;
use ibc_proto::{
    cosmos::tx::v1beta1::TxBody, google::protobuf::Any, google::protobuf::Duration as PbDuration,
    ibc::core::commitment::v1::MerkleRoot,
};
use ioi_forge::testing::{
    build_test_artifacts,
    wait_for, wait_for_height,
    rpc::query_state_key,
    TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, Credential,
        SignatureSuite, SystemPayload, SystemTransaction, ValidatorSetBlob, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, ACCOUNT_NONCE_PREFIX, IDENTITY_CREDENTIALS_PREFIX,
        VALIDATOR_SET_KEY,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use prost::Message;
use reqwest::Client;
use serde_json::{json, Value};
use std::{str::FromStr, time::Duration};
use tendermint::{
    account,
    block::{
        parts::Header as PartsHeader, signed_header::SignedHeader as TendermintSignedHeader,
        Id as BlockId,
    },
    chain::Id as TmChainId,
    vote::{Type as VoteType, ValidatorIndex, Vote},
};
use tendermint_proto::google::protobuf::Timestamp as PbTimestamp;
use tendermint_proto::types::{
    BlockId as TmProtoBlockId, Commit as TmProtoCommit, CommitSig as TmProtoCommitSig,
    Header as TmProtoHeader, PartSetHeader as TmProtoPartSetHeader,
    ValidatorSet as TmProtoValidatorSetUnversioned,
};
use tendermint_proto::version::Consensus as TmProtoConsensus;
use tendermint_testgen::{light_block::LightBlock as TmLightBlock, Header as TmHeaderGen};

// ── Local compatibility wrapper for on‑wire ClientMessage ──────────────────────
#[derive(Clone, PartialEq, ::prost::Message)]
struct TmClientMessageCompat {
    #[prost(oneof = "tm_client_message_compat::Sum", tags = "1")]
    pub sum: ::core::option::Option<tm_client_message_compat::Sum>,
}
mod tm_client_message_compat {
    use super::RawTmHeader;
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Sum {
        #[prost(message, tag = "1")]
        Header(RawTmHeader),
    }
}

#[derive(Copy, Clone)]
enum WireFlavor {
    ClientMessage,
    HeaderOnly,
}

fn encode_header_with_flavor(hdr: RawTmHeader, flavor: WireFlavor) -> (String, Vec<u8>) {
    match flavor {
        WireFlavor::ClientMessage => {
            let client_msg = TmClientMessageCompat {
                sum: Some(tm_client_message_compat::Sum::Header(hdr)),
            };
            (
                "/ibc.lightclients.tendermint.v1.ClientMessage".to_string(),
                client_msg.encode_to_vec(),
            )
        }
        WireFlavor::HeaderOnly => (
            "/ibc.lightclients.tendermint.v1.Header".to_string(),
            hdr.encode_to_vec(),
        ),
    }
}

fn pb_header_from_testgen(h: TmHeaderGen) -> TmProtoHeader {
    const SHA256_EMPTY: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    TmProtoHeader {
        chain_id: h.chain_id.unwrap_or_else(|| "test-chain".to_string()),
        height: h.height.unwrap_or(1) as i64,
        time: Some(PbTimestamp::from(h.time.unwrap())),
        version: Some(TmProtoConsensus { block: 11, app: 0 }),
        proposer_address: vec![0; 20],
        validators_hash: SHA256_EMPTY.to_vec(),
        next_validators_hash: SHA256_EMPTY.to_vec(),
        app_hash: SHA256_EMPTY.to_vec(),
        ..Default::default()
    }
}

fn one_validator_set_and_key() -> (
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
    let tm_pk = tendermint::PublicKey::from_raw_ed25519(&pk_bytes).unwrap();
    let addr = account::Id::from(tm_pk.clone());

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

    (
        domain_set,
        validators_hash,
        proto_set,
        addr.as_bytes().to_vec(),
        sk,
    )
}

fn add_full_identity_to_genesis(
    genesis_state: &mut serde_json::Map<String, Value>,
    keypair: &Keypair,
) -> AccountId {
    let suite = SignatureSuite::Ed25519;
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(suite, &public_key_bytes).unwrap();
    let account_id = AccountId(account_id_hash);

    let initial_cred = Credential {
        suite,
        public_key_hash: account_id_hash,
        activation_height: 0,
        l2_location: None,
    };
    let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
    let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
    let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
    genesis_state.insert(
        format!("b64:{}", BASE64.encode(&creds_key)),
        json!(format!("b64:{}", BASE64.encode(&creds_bytes))),
    );

    let record = ActiveKeyRecord {
        suite,
        public_key_hash: account_id_hash,
        since_height: 0,
    };
    let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
    let record_bytes = codec::to_bytes_canonical(&record).unwrap();
    genesis_state.insert(
        format!("b64:{}", BASE64.encode(&record_key)),
        json!(format!("b64:{}", BASE64.encode(&record_bytes))),
    );

    let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
    genesis_state.insert(
        format!("b64:{}", BASE64.encode(&pubkey_map_key)),
        json!(format!("b64:{}", BASE64.encode(&public_key_bytes))),
    );

    account_id
}

#[tokio::test(flavor = "multi_thread")]
async fn ibc_relayer_e2e() -> Result<()> {
    build_test_artifacts();

    let client_id = "07-tendermint-0";
    let mock_cosmos_chain_id = "cosmos-hub-test";
    let gateway_addr = "127.0.0.1:9876";

    let (_set_domain, shared_vals_hash, shared_proto_valset, shared_addr, shared_key) =
        one_validator_set_and_key();

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
        .with_initial_service(InitialServiceConfig::Ibc(ioi_types::config::IbcConfig {
            // Allow the canonical ICS‑07 type; keep the alias if your host uses it elsewhere.
            enabled_clients: vec!["07-tendermint".to_string(), "tendermint-v0.34".to_string()],
        })) // <-- [+] FIX: The trailing comma was removed here
        .with_genesis_modifier({
            let shared_vals_hash = shared_vals_hash.clone();
            move |genesis, keys| {
                let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
                let keypair = &keys[0];

                // --- Seed clientType so ibc-rs can route updates to the Tendermint client ---
                // Use the canonical ICS-24 path directly: "clients/{client_id}/clientType"
                let client_type_key = format!("clients/{}/clientType", client_id);
                genesis_state.insert(
                    client_type_key,
                    serde_json::json!(format!("b64:{}", BASE64.encode("07-tendermint"))),
                );

                let validator_account_id = add_full_identity_to_genesis(genesis_state, keypair);
                let vs_blob = ValidatorSetBlob {
                    schema_version: 2,
                    payload: ValidatorSetsV1 {
                        current: ValidatorSetV1 {
                            effective_from_height: 1,
                            total_weight: 1,
                            validators: vec![ValidatorV1 {
                                account_id: validator_account_id,
                                weight: 1,
                                consensus_key: ActiveKeyRecord {
                                    suite: SignatureSuite::Ed25519,
                                    public_key_hash: validator_account_id.0,
                                    since_height: 0,
                                },
                            }],
                        },
                        next: None,
                    },
                };
                let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();
                genesis_state.insert(
                    std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                    json!(format!("b64:{}", BASE64.encode(vs_bytes))),
                );

                // [+] FIX: Add block timing parameters to genesis
                use ioi_types::app::{BlockTimingParams, BlockTimingRuntime};
                use ioi_types::keys::{BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY};

                let timing_params = BlockTimingParams {
                    base_interval_secs: 5,
                    min_interval_secs: 2,
                    max_interval_secs: 10,
                    target_gas_per_block: 1_000_000,
                    ema_alpha_milli: 200,
                    interval_step_bps: 500,
                    retarget_every_blocks: 0, // Disable adaptive for simplicity in test
                };
                genesis_state.insert(
                    std::str::from_utf8(BLOCK_TIMING_PARAMS_KEY)
                        .unwrap()
                        .to_string(),
                    json!(format!(
                        "b64:{}",
                        BASE64.encode(codec::to_bytes_canonical(&timing_params).unwrap())
                    )),
                );

                let timing_runtime = BlockTimingRuntime {
                    ema_gas_used: 0,
                    effective_interval_secs: timing_params.base_interval_secs,
                };
                genesis_state.insert(
                    std::str::from_utf8(BLOCK_TIMING_RUNTIME_KEY)
                        .unwrap()
                        .to_string(),
                    json!(format!(
                        "b64:{}",
                        BASE64.encode(codec::to_bytes_canonical(&timing_runtime).unwrap())
                    )),
                );

                // --- Store ClientState as google.protobuf.Any (expected by ibc-rs) ---
                let client_state_any = Any {
                    type_url: "/ibc.lightclients.tendermint.v1.ClientState".to_string(),
                    value: RawTmClientState {
                        chain_id: mock_cosmos_chain_id.to_string(),
                        trust_level: Some(TmTrustFraction {
                            numerator: 1,
                            denominator: 3,
                        }),
                        trusting_period: Some(PbDuration {
                            seconds: 60 * 60 * 24 * 365 * 100,
                            nanos: 0,
                        }), // 100 years
                        unbonding_period: Some(PbDuration {
                            seconds: 60 * 60 * 24 * 365 * 101,
                            nanos: 0,
                        }), // > trusting
                        max_clock_drift: Some(PbDuration {
                            seconds: 60 * 60 * 24,
                            nanos: 0,
                        }), // 1 day
                        latest_height: Some(IbcHeight::new(0, 1).unwrap().into()),
                        frozen_height: Some(ibc_proto::ibc::core::client::v1::Height {
                            revision_number: 0,
                            revision_height: 0,
                        }),
                        proof_specs: {
                            let specs: Vec<_> = ProofSpecs::cosmos().into();
                            specs.into_iter().map(Into::into).collect()
                        },
                        upgrade_path: vec!["upgrade".into(), "upgradedIBCState".into()],
                        ..Default::default()
                    }
                    .encode_to_vec(),
                };
                let cs_path = ClientStatePath::new(ClientId::from_str(client_id).unwrap());
                genesis_state.insert(
                    cs_path.to_string(),
                    json!(format!(
                        "b64:{}",
                        BASE64.encode(client_state_any.encode_to_vec())
                    )),
                );

                // --- Store ConsensusState (height 1) as Any as well ---
                let consensus_state_any = Any {
                    type_url: "/ibc.lightclients.tendermint.v1.ConsensusState".to_string(),
                    value: RawTmConsensusState {
                        timestamp: Some(ibc_proto::google::protobuf::Timestamp {
                            seconds: 1,
                            nanos: 0,
                        }),
                        root: Some(MerkleRoot { hash: vec![] }),
                        next_validators_hash: shared_vals_hash.clone(),
                    }
                    .encode_to_vec(),
                };
                let ccs_path =
                    ClientConsensusStatePath::new(ClientId::from_str(client_id).unwrap(), 0, 1);
                genesis_state.insert(
                    ccs_path.to_string(),
                    json!(format!(
                        "b64:{}",
                        BASE64.encode(consensus_state_any.encode_to_vec())
                    )),
                );
            }
        })
        .build()
        .await?;

    let node = &cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // 3. QUERY INITIAL STATE VIA HTTP GATEWAY (Sanity check)
    let http_client = Client::new();
    let client_id_parsed = ClientId::from_str(client_id)?;
    let client_state_path = ClientStatePath::new(client_id_parsed.clone());
    let query_resp: serde_json::Value = http_client
        .post(format!("http://{}/v1/ibc/query", gateway_addr))
        .json(&json!({ "path": client_state_path.to_string(), "latest": true }))
        .send()
        .await?
        .json()
        .await?;
    let value_pb_b64 = query_resp["value_pb"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing value_pb"))?;
    let value_bytes = BASE64.decode(value_pb_b64)?;
    // Stored value is Any(ClientState)
    let any_wrapped = Any::decode(value_bytes.as_slice())?;
    assert_eq!(
        any_wrapped.type_url,
        "/ibc.lightclients.tendermint.v1.ClientState"
    );
    let cs_from_gateway = RawTmClientState::decode(any_wrapped.value.as_slice())?;
    assert_eq!(cs_from_gateway.chain_id, mock_cosmos_chain_id);
    println!("SUCCESS: Queried and verified initial client state via HTTP gateway.");

    // 4. SUBMIT A HEADER UPDATE VIA A SIGNED SERVICE CALL
    let header_bytes = {
        let light_block_h2: TmLightBlock = TmLightBlock::new_default(2);
        let mut hdr = pb_header_from_testgen(light_block_h2.header.clone().unwrap());
        hdr.chain_id = mock_cosmos_chain_id.to_string();
        hdr.validators_hash = shared_vals_hash.clone();
        hdr.next_validators_hash = shared_vals_hash.clone();
        hdr.time = Some(PbTimestamp {
            seconds: 2,
            nanos: 0,
        });

        let hdr_domain: tendermint::block::Header = hdr.clone().try_into()?;
        let header_hash = hdr_domain.hash();

        let part_set_header = PartsHeader::new(1, header_hash.into()).unwrap();
        let block_id = BlockId {
            hash: header_hash,
            part_set_header,
        };

        let vote = Vote {
            vote_type: VoteType::Precommit,
            height: hdr_domain.height,
            round: 0u16.into(),
            block_id: Some(block_id),
            timestamp: Some(hdr_domain.time),
            validator_address: account::Id::try_from(shared_addr.clone())?,
            validator_index: ValidatorIndex::try_from(0u32)?,
            signature: Default::default(),
            extension: Default::default(),
            extension_signature: Default::default(),
        };

        let tm_chain_id = TmChainId::try_from(mock_cosmos_chain_id.to_string())?;
        let mut sign_bytes = Vec::new();
        vote.to_signable_bytes(tm_chain_id, &mut sign_bytes)?;
        let sig = dcrypt::sign::eddsa::Ed25519::sign(&sign_bytes, &shared_key)?;

        let commit_proto = TmProtoCommit {
            height: hdr.height,
            round: 0,
            block_id: Some(TmProtoBlockId {
                hash: header_hash.as_bytes().to_vec(),
                part_set_header: Some(TmProtoPartSetHeader::from(part_set_header)),
            }),
            signatures: vec![TmProtoCommitSig {
                block_id_flag: 2, // BlockIdFlagCommit
                validator_address: shared_addr.clone(),
                timestamp: Some(PbTimestamp::from(hdr_domain.time)),
                signature: sig.to_bytes().to_vec(),
            }],
        };
        let commit: tendermint::block::Commit = commit_proto.try_into()?;
        let tm_signed_header_domain = TendermintSignedHeader::new(hdr_domain, commit)?;

        let ibc_header = RawTmHeader {
            signed_header: Some(tm_signed_header_domain.into()),
            validator_set: Some(shared_proto_valset.clone()),
            trusted_height: Some(IbcHeight::new(0, 1)?.into()),
            trusted_validators: Some(shared_proto_valset.clone()),
        };
        ibc_header.encode_to_vec()
    };

    let validator_key = &cluster.validators[0].keypair;
    let validator_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::Ed25519,
        &validator_key.public().encode_protobuf(),
    )?);

    let nonce = {
        let nonce_key = [ACCOUNT_NONCE_PREFIX, validator_account_id.as_ref()].concat();
        query_state_key(rpc_addr, &nonce_key)
            .await?
            .map(|b| codec::from_bytes_canonical::<u64>(&b).unwrap())
            .unwrap_or(0)
    };

    let ibc_header_decoded = RawTmHeader::decode(header_bytes.as_slice())?;
    let (_cm_type_url, _cm_value) =
        encode_header_with_flavor(ibc_header_decoded.clone(), WireFlavor::ClientMessage);
    let (hdr_type_url, hdr_value) =
        encode_header_with_flavor(ibc_header_decoded, WireFlavor::HeaderOnly);

    async fn try_submit(
        client_id: &str,
        type_url: String,
        value: Vec<u8>,
        validator_key: &libp2p::identity::Keypair,
        validator_account_id: AccountId,
        node_rpc_addr: &str,
        nonce: u64,
    ) -> Result<(), anyhow::Error> {
        let msg_update_client = MsgUpdateClient {
            client_id: ClientId::from_str(client_id)?,
            client_message: Any { type_url, value },
            signer: "ioi-signer".to_string().into(),
        };
        let tx_body = TxBody {
            messages: vec![msg_update_client.to_any()],
            memo: "E2E Test UpdateClient".to_string(),
            ..Default::default()
        };
        let call_params = tx_body.encode_to_vec();
        use ioi_types::app::SignHeader;
        let mut sys = SystemTransaction {
            header: SignHeader {
                account_id: validator_account_id,
                nonce,
                chain_id: 1.into(),
                tx_version: 1,
            },
            payload: SystemPayload::CallService {
                service_id: "ibc".to_string(),
                method: "msg_dispatch@v1".to_string(),
                params: call_params,
            },
            signature_proof: ioi_types::app::SignatureProof::default(),
        };
        let sign_bytes = sys.to_sign_bytes().map_err(|e| anyhow!(e))?;
        let signature = validator_key.sign(&sign_bytes)?;
        sys.signature_proof = ioi_types::app::SignatureProof {
            suite: SignatureSuite::Ed25519,
            public_key: validator_key.public().encode_protobuf(),
            signature,
        };
        let call_tx = ChainTransaction::System(Box::new(sys));
        ioi_forge::testing::rpc::submit_transaction_and_wait_block(node_rpc_addr, &call_tx).await?;
        Ok(())
    }

    // Based on the log, we know the bare Header works. Submit that directly.
    try_submit(
        client_id,
        hdr_type_url,
        hdr_value,
        &cluster.validators[0].keypair,
        validator_account_id,
        &node.rpc_addr,
        nonce,
    )
    .await?;
    println!("SUCCESS: UpdateClient accepted using Header-only envelope.");

    // 5. VERIFY ON-CHAIN STATE
    let consensus_state_path_h2 =
        ClientConsensusStatePath::new(ClientId::from_str(client_id)?, 0, 2);
    let cs_bytes = wait_for(
        "consensus state for height 2",
        Duration::from_millis(250),
        Duration::from_secs(30),
        || async {
            query_state_key(rpc_addr, consensus_state_path_h2.to_string().as_bytes()).await
        },
    )
    .await?;
    // ibc-rs writes Any(ConsensusState); unwrap then decode
    let cs_any = Any::decode(cs_bytes.as_slice())?;
    assert_eq!(
        cs_any.type_url,
        "/ibc.lightclients.tendermint.v1.ConsensusState"
    );
    let cs_pb = RawTmConsensusState::decode(cs_any.value.as_slice())?;
    let _cs_h2 = TmConsensusState::try_from(cs_pb)?;
    println!("SUCCESS: Tendermint consensus state for height 2 was written and decoded.");

    println!("--- Universal Interoperability (Tendermint) E2E Test Passed ---");
    Ok(())
}
