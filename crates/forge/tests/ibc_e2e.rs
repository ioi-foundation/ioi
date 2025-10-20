// crates/forge/tests/ibc_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash",
    feature = "svc-ibc"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, poll::wait_for_height, submit_transaction,
    TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    config::InitialServiceConfig,
    ibc::{Finality, Header, ICS23Proof, InclusionProof, Packet, TendermintHeader},
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
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
use parity_scale_codec::Encode;
use prost::Message;
use serde_json::{json, Value};
use std::{str::FromStr, time::Duration};
use tendermint::{
    account,
    block::{self, signed_header::SignedHeader as TendermintSignedHeader},
    chain::Id as TmChainId,
    hash::Hash,
    vote::{Type as VoteType, ValidatorIndex, Vote},
    Time as TmTime,
};
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
use tendermint_testgen::light_block::LightBlock as TmLightBlock;

// --- Service Parameter Structs (Client-side ABI) ---

#[derive(Encode)]
struct VerifyHeaderParams {
    chain_id: String,
    header: Header,
    finality: Finality,
}

#[derive(Encode)]
struct RecvPacketParams {
    packet: Packet,
    proof: InclusionProof,
    proof_height: u64,
}

// --- Test Helpers ---

fn setup_genesis_for_ibc_test(genesis: &mut Value, keys: &Vec<Keypair>) {
    // ... (rest of the function is unchanged)
}

fn create_call_service_tx<P: Encode>(
    signer: &Keypair,
    service_id: &str,
    method: &str,
    params: P,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    // ... (unchanged)
}

// ... other testgen helpers (pb_header_from_testgen, etc.) are unchanged ...

#[tokio::test(flavor = "multi_thread")]
async fn test_ibc_tendermint_header_and_packet_flow() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts();

    let client_id = "07-tendermint-0";
    let mock_cosmos_chain_id = "cosmos-hub-test";
    let port_id_str = "transfer";
    let channel_id_str = "channel-0";

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
        // This now implicitly sets the `requires_ibc_feature` flag
        .with_initial_service(InitialServiceConfig::Ibc(
            depin_sdk_types::config::IbcConfig {
                enabled_clients: vec!["tendermint-v0.34".to_string()],
            },
        ))
        .with_genesis_modifier({
            let shared_vals_hash = shared_vals_hash.clone();
            move |genesis, keys| {
                // ... (genesis setup logic is unchanged) ...
            }
        })
        .build()
        .await?;

    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let keypair = &node.keypair;
    let mut nonce = 0;
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // 3. SUBMIT A HEADER UPDATE (using the new CallService tx)
    let header_bytes = {
        // ... (header generation logic is unchanged) ...
    };

    let tx = create_call_service_tx(
        keypair,
        "ibc",
        "verify_header@v1",
        VerifyHeaderParams {
            chain_id: mock_cosmos_chain_id.to_string(),
            header: Header::Tendermint(TendermintHeader {
                trusted_height: 1,
                data: header_bytes,
            }),
            finality: Finality::TendermintCommit {
                commit_and_valset: vec![],
            },
        },
        nonce,
        1.into(),
    )?;
    submit_transaction(rpc_addr, &tx).await?;
    nonce += 1;
    wait_for_height(rpc_addr, 2, Duration::from_secs(20)).await?;

    // 4. ASSERT HEADER UPDATE (unchanged)
    // ...

    // 5. SUBMIT A RECEIVE PACKET TRANSACTION (using the new CallService tx)
    let packet = Packet {
        sequence: 1,
        source_port: port_id_str.to_string(),
        source_channel: channel_id_str.to_string(),
        destination_port: port_id_str.to_string(),
        destination_channel: channel_id_str.to_string(),
        data: b"hello".to_vec(),
    };
    let tx2 = create_call_service_tx(
        keypair,
        "ibc",
        "recv_packet@v1",
        RecvPacketParams {
            packet: packet.clone(),
            proof: InclusionProof::Ics23(ICS23Proof {
                proof_bytes: b"mock_ics23_proof".to_vec(),
            }),
            proof_height: 2,
        },
        nonce,
        1.into(),
    )?;
    submit_transaction(rpc_addr, &tx2).await?;
    wait_for_height(rpc_addr, 3, Duration::from_secs(20)).await?;

    // 6. ASSERT PACKET RECEIPT (unchanged)
    // ...

    println!("--- Universal Interoperability (Tendermint) E2E Test Passed ---");
    Ok(())
}
