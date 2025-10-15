// Path: forge/tests/interop_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dcrypt::api::Signature as DcryptSignature;
use dcrypt::sign::eddsa::{Ed25519, Ed25519SecretKey};
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::{wait_for, wait_for_height},
    rpc::query_state_key,
    submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    config::InitialServiceConfig,
    ibc::{Finality, Header, ICS23Proof, InclusionProof, Packet, TendermintHeader},
    keys::VALIDATOR_SET_KEY,
    service_configs::MigrationConfig,
};
// IBC-related imports
use ibc_client_tendermint::{
    client_state::ClientState as TmClientState,
    consensus_state::ConsensusState as TmConsensusState,
    types::{
        proto::v1::{
            ClientState as RawTmClientState, ConsensusState as RawTmConsensusState,
            Header as RawTmIbcHeader,
        },
        AllowUpdate, TrustThreshold,
    },
};
use ibc_core_client_types::Height as IbcHeight;
use ibc_core_commitment_types::proto::v1::MerkleRoot;
use ibc_core_commitment_types::specs::ProofSpecs;
use ibc_core_host_types::{
    identifiers::{ChainId as IbcChainId, ChannelId, ClientId, PortId, Sequence},
    path::{ClientConsensusStatePath, ClientStatePath, ReceiptPath},
};
use ibc_proto::google::protobuf::Timestamp as IbcTimestamp;
use libp2p::identity::Keypair;
use prost::Message;
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
use tendermint_testgen::light_block::LightBlock as TmLightBlock;

// Import the specific Tendermint proto types required by the ibc-rs version.
use tendermint_proto::{
    crypto::{public_key::Sum as TmProtoPubKeySum, PublicKey as TmProtoPubKey},
    google::protobuf::Timestamp as PbTimestamp,
    types::ValidatorSet as TmProtoValidatorSetUnversioned,
    v0_34::{
        types::{
            BlockId as TmProtoBlockId, Commit as TmProtoCommit, CommitSig as TmProtoCommitSig,
            Header as TmProtoHeader, PartSetHeader as TmProtoPartSetHeader,
            SignedHeader as TmProtoSignedHeader,
        },
        version::Consensus as TmProtoConsensus,
    },
};

// --- helpers: testgen -> canonical tendermint protobuf types ---
fn pb_header_from_testgen(h: tendermint_testgen::Header) -> TmProtoHeader {
    // SHA-256("") in hex:
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
        version: Some(TmProtoConsensus {
            block: 11, // Corresponds to v0.34
            app: 0,
        }),
        proposer_address: vec![0; 20],
        validators_hash: SHA256_EMPTY.to_vec(),
        next_validators_hash: SHA256_EMPTY.to_vec(),
        app_hash: SHA256_EMPTY.to_vec(),
        ..Default::default()
    }
}

fn pb_minimal_commit_for_with_hash(header: &TmProtoHeader, header_hash: Vec<u8>) -> TmProtoCommit {
    let zero32 = vec![0u8; 32];
    TmProtoCommit {
        height: header.height,
        round: 0,
        block_id: Some(TmProtoBlockId {
            hash: header_hash,
            part_set_header: Some(TmProtoPartSetHeader {
                total: 1,
                hash: zero32,
            }),
        }),
        signatures: vec![],
    }
}

fn with_one_dummy_sig_from(mut commit: TmProtoCommit, validator_address: Vec<u8>) -> TmProtoCommit {
    const BLOCK_ID_FLAG_COMMIT: i32 = 2;
    let dummy_sig = TmProtoCommitSig {
        block_id_flag: BLOCK_ID_FLAG_COMMIT,
        validator_address,
        timestamp: Some(PbTimestamp {
            seconds: 1,
            nanos: 0,
        }),
        signature: vec![1; 64],
    };
    commit.signatures.push(dummy_sig);
    commit
}

// Helper to build a 1-validator set and its hash for tendermint v0.36.0.
fn one_validator_set_and_hash() -> (
    tendermint::validator::Set,
    Vec<u8>,
    tendermint_proto::types::ValidatorSet,
    Vec<u8>,
    [u8; 32],
) {
    use tendermint::{
        account, crypto::ed25519::VerificationKey, public_key::PublicKey as TmPublicKey, validator,
    };

    let seed: [u8; 32] = [1u8; 32];
    let sk = Ed25519SecretKey::from_seed(&seed).expect("ed25519 sk from seed");
    let pk = sk.public_key().expect("derive ed25519 pk from sk");
    let pk_bytes: [u8; 32] = pk.to_bytes().try_into().expect("32 bytes");

    let tm_vk = VerificationKey::try_from(pk_bytes.as_ref()).expect("tm vk");
    let tm_pk = TmPublicKey::Ed25519(tm_vk);
    let addr = account::Id::from(tm_pk.clone());
    let addr_bytes = addr.as_bytes().to_vec();

    // Build a domain set once (handy to return for completeness).
    let info = validator::Info {
        address: addr.clone(),
        pub_key: tm_pk.clone(),
        power: 1_u32.into(),
        proposer_priority: 0.into(),
        name: None,
    };
    let domain_set = validator::Set::new(vec![info], None);

    // Build the *proto* set you will embed in the header.
    let proto_val = tendermint_proto::types::Validator {
        address: addr.as_bytes().to_vec(),
        pub_key: Some(TmProtoPubKey {
            sum: Some(TmProtoPubKeySum::Ed25519(pk_bytes.to_vec())),
        }),
        voting_power: 1,
        proposer_priority: 0,
    };
    let proto_set = TmProtoValidatorSetUnversioned {
        validators: vec![proto_val],
        proposer: None,
        total_voting_power: 1,
    };

    // ⬅️ FIXED: compute the hash exactly the way the light client will:
    // hash( domain(Set) reconstructed from the *proto* valset you embed )
    let set_for_hash: tendermint::validator::Set =
        proto_set.clone().try_into().expect("proto->domain set");
    let validators_hash = set_for_hash.hash().as_bytes().to_vec();

    (domain_set, validators_hash, proto_set, addr_bytes, seed)
}

// Helper to create a signed system transaction with a specific nonce
fn create_signed_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = depin_sdk_types::app::AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes()?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ibc_tendermint_header_and_packet_flow() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts();

    let client_id = "07-tendermint-0";
    let mock_cosmos_chain_id = "cosmos-hub-test";
    let port_id_str = "transfer";
    let channel_id_str = "channel-0";

    // Build the validator set ONCE and reuse its components.
    let (_set_domain, shared_vals_hash, shared_proto_valset, shared_addr, shared_seed) =
        one_validator_set_and_hash();

    // 2. LAUNCH CLUSTER WITH IBC CLIENT STATE IN GENESIS
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier({
            let shared_vals_hash = shared_vals_hash.clone();
            move |genesis, keys| {
                let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

                // --- Set up validator identity (needed for signing txs) ---
                let keypair = &keys[0];
                let suite = SignatureSuite::Ed25519;
                let public_key_bytes = keypair.public().encode_protobuf();
                let account_id_hash =
                    account_id_from_key_material(suite, &public_key_bytes).unwrap();
                let account_id = AccountId(account_id_hash);

                let vs_blob = depin_sdk_types::app::ValidatorSetBlob {
                    schema_version: 2,
                    payload: ValidatorSetsV1 {
                        current: ValidatorSetV1 {
                            effective_from_height: 1,
                            total_weight: 1,
                            validators: vec![ValidatorV1 {
                                account_id,
                                weight: 1,
                                consensus_key: ActiveKeyRecord {
                                    suite,
                                    public_key_hash: account_id_hash,
                                    since_height: 0,
                                },
                            }],
                        },
                        next: None,
                    },
                };
                let vs_bytes =
                    depin_sdk_types::app::write_validator_sets(&vs_blob.payload).unwrap();
                genesis_state.insert(
                    std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
                );

                // --- Set up initial IBC client state in genesis ---
                let inner_client_state = ibc_client_tendermint::types::ClientState {
                    chain_id: IbcChainId::from_str(mock_cosmos_chain_id).unwrap(),
                    trust_level: TrustThreshold::new(1, 3).unwrap(),
                    trusting_period: Duration::from_secs(60 * 60 * 24 * 14), // 2 weeks
                    unbonding_period: Duration::from_secs(60 * 60 * 24 * 21), // 3 weeks
                    max_clock_drift: Duration::from_millis(3000),
                    latest_height: IbcHeight::new(0, 1).unwrap(),
                    proof_specs: ProofSpecs::cosmos(),
                    upgrade_path: vec!["".to_string()],
                    allow_update: AllowUpdate {
                        after_expiry: true,
                        after_misbehaviour: true,
                    },
                    frozen_height: None,
                };
                let tm_client_state = TmClientState::from(inner_client_state);
                let client_id = ClientId::from_str(client_id).unwrap();

                // Store ClientState
                let client_state_path = ClientStatePath::new(client_id.clone()).to_string();
                let client_state_pb: RawTmClientState = tm_client_state.into();
                let client_state_bytes = client_state_pb.encode_to_vec();
                genesis_state.insert(
                    client_state_path,
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(client_state_bytes)
                    )),
                );

                // Store ConsensusState.
                let consensus_state_pb = RawTmConsensusState {
                    timestamp: Some(IbcTimestamp {
                        seconds: 1,
                        nanos: 0,
                    }),
                    root: Some(MerkleRoot { hash: vec![] }),
                    next_validators_hash: shared_vals_hash.clone(), // Use the shared hash
                };
                let consensus_state_bytes = consensus_state_pb.encode_to_vec();
                let consensus_state_path = ClientConsensusStatePath::new(
                    client_id, 0, // revision_number
                    1, // revision_height
                )
                .to_string();
                genesis_state.insert(
                    consensus_state_path,
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(consensus_state_bytes)
                    )),
                );
            }
        })
        .build()
        .await?;

    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let keypair = &node.keypair;
    let mut nonce = 0;
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // 3. SUBMIT A HEADER UPDATE
    let light_block_h2: TmLightBlock = TmLightBlock::new_default(2);
    let header_bytes = {
        let mut hdr = pb_header_from_testgen(light_block_h2.header.clone().expect("h2 header"));
        hdr.chain_id = mock_cosmos_chain_id.to_string();

        // Use the shared hash for both header fields.
        hdr.validators_hash = shared_vals_hash.clone();
        hdr.next_validators_hash = shared_vals_hash.clone();

        let hdr_domain: tendermint::block::Header = hdr
            .clone()
            .try_into()
            .expect("convert proto->domain header");
        let header_hash = hdr_domain.hash().as_bytes().to_vec();

        let unsigned_commit = pb_minimal_commit_for_with_hash(&hdr, header_hash.clone());

        let tm_chain_id = TmChainId::try_from(mock_cosmos_chain_id.to_string()).unwrap();
        let zero32_arr = [0u8; 32];
        let block_id = block::Id {
            hash: Hash::Sha256(header_hash.clone().try_into().unwrap()),
            part_set_header: block::parts::Header::new(1, Hash::Sha256(zero32_arr)).unwrap(),
        };

        let vote = Vote {
            vote_type: VoteType::Precommit,
            height: (hdr.height as u64).try_into().unwrap(),
            round: 0u16.into(),
            block_id: Some(block_id),
            timestamp: Some(TmTime::from_unix_timestamp(1, 0).unwrap()),
            validator_address: account::Id::try_from(shared_addr.clone()).unwrap(),
            validator_index: ValidatorIndex::try_from(0u32).unwrap(),
            signature: Default::default(),
            extension: Default::default(),
            extension_signature: Default::default(),
        };
        let mut sign_bytes = Vec::new();
        vote.to_signable_bytes(tm_chain_id, &mut sign_bytes)?;

        let sk = Ed25519SecretKey::from_seed(&shared_seed)?;
        let sig = Ed25519::sign(&sign_bytes, &sk)?;

        let mut commit = with_one_dummy_sig_from(unsigned_commit, shared_addr.clone());
        commit.signatures[0].signature = sig.to_bytes().to_vec();

        let tm_signed_header_proto = TmProtoSignedHeader {
            header: Some(hdr.clone()),
            commit: Some(commit),
        };

        let tm_signed_header_domain = TendermintSignedHeader::try_from(tm_signed_header_proto)?;
        let tm_signed_header_unversioned: tendermint_proto::types::SignedHeader =
            tm_signed_header_domain.into();

        let ibc_header = RawTmIbcHeader {
            signed_header: Some(tm_signed_header_unversioned),
            validator_set: Some(shared_proto_valset.clone()),
            trusted_height: Some(IbcHeight::new(0, 1)?.into()),
            trusted_validators: Some(shared_proto_valset.clone()),
        };

        ibc_header.encode_to_vec()
    };

    let header_payload = SystemPayload::VerifyHeader {
        chain_id: mock_cosmos_chain_id.to_string(),
        header: Header::Tendermint(TendermintHeader {
            trusted_height: 1,
            data: header_bytes,
        }),
        finality: Finality::TendermintCommit {
            commit_and_valset: vec![],
        },
    };
    let tx = create_signed_system_tx(keypair, header_payload, nonce, 1.into())?;
    submit_transaction(rpc_addr, &tx).await?;
    nonce += 1;
    wait_for_height(rpc_addr, 2, Duration::from_secs(20)).await?;

    // 4. ASSERT HEADER UPDATE
    let client_id_parsed = ClientId::from_str(client_id)?;
    let consensus_state_path_h2 = ClientConsensusStatePath::new(client_id_parsed, 0, 2).to_string();
    let cs_bytes = wait_for(
        "consensus state for height 2",
        Duration::from_millis(250),
        Duration::from_secs(30),
        || async { query_state_key(rpc_addr, consensus_state_path_h2.as_bytes()).await },
    )
    .await?;

    let cs_pb = RawTmConsensusState::decode(cs_bytes.as_slice())?;
    let _cs_h2 = TmConsensusState::try_from(cs_pb)?;
    println!("SUCCESS: Tendermint consensus state for height 2 was written and decoded.");

    // 5. SUBMIT A RECEIVE PACKET TRANSACTION
    let packet = Packet {
        sequence: 1,
        source_port: port_id_str.to_string(),
        source_channel: channel_id_str.to_string(),
        destination_port: port_id_str.to_string(),
        destination_channel: channel_id_str.to_string(),
        data: b"hello".to_vec(),
    };
    let recv_payload = SystemPayload::RecvPacket {
        packet: packet.clone(),
        proof: InclusionProof::Ics23(ICS23Proof {
            proof_bytes: b"mock_ics23_proof".to_vec(),
        }),
        proof_height: 2,
    };
    let tx2 = create_signed_system_tx(keypair, recv_payload, nonce, 1.into())?;
    submit_transaction(rpc_addr, &tx2).await?;
    wait_for_height(rpc_addr, 3, Duration::from_secs(20)).await?;

    // 6. ASSERT PACKET RECEIPT
    let port_id = PortId::from_str(port_id_str)?;
    let channel_id = ChannelId::from_str(channel_id_str)?;
    let sequence = Sequence::from(1);
    let receipt_path = ReceiptPath::new(&port_id, &channel_id, sequence).to_string();
    let receipt_val = wait_for(
        "packet receipt",
        Duration::from_millis(250),
        Duration::from_secs(10),
        || async { query_state_key(rpc_addr, receipt_path.as_bytes()).await },
    )
    .await?;
    assert_eq!(receipt_val, vec![1]);
    println!("SUCCESS: Packet receipt was successfully written to state.");

    println!("--- Universal Interoperability (Tendermint) E2E Test Passed ---");
    Ok(())
}