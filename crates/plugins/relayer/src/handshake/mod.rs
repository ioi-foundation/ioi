// Path: crates/relayer/src/handshake/mod.rs

//! High-level IBC handshake orchestration logic.

pub mod builders;
pub mod proofs;

use crate::gateway::Gateway;
use anyhow::{anyhow, Result};
use prost::Message;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

// [FIX] Import BASE64
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

// Re-export specific builders for external use if needed
// [FIX] Re-export infer functions so they are visible to lib.rs via crate::handshake::...
pub use crate::handshake::proofs::{infer_allocated_channel_id, infer_allocated_connection_id};
pub use builders::{
    build_chan_open_ack_any, build_chan_open_confirm_any, build_chan_open_init_any,
    build_chan_open_try_any, build_conn_open_ack_any, build_conn_open_confirm_any,
    build_conn_open_init_any, build_conn_open_try_any, build_create_client_any,
    build_update_client_any,
};
pub use proofs::{
    existence_root_from_proof_bytes, proof_indicates_membership, query_proof_bytes_at,
};

// --- Imports for Deterministic Test Setup ---
use dcrypt::sign::eddsa::Ed25519SecretKey;
use ibc_proto::google::protobuf::Any as PbAny;
use ibc_proto::ibc::lightclients::tendermint::v1::{
    ClientState as RawTmClientState, ConsensusState as RawTmConsensusState,
    Fraction as TmTrustFraction, Header as RawTmHeader,
};
use tendermint::{
    account,
    block::{
        parts::Header as PartsHeader, signed_header::SignedHeader as TmSignedHeader, Id as BlockId,
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
use tendermint_testgen::{light_block::LightBlock as TmLightBlock, Header as TmHeaderGen};

use crate::{commitment_root_at_height_robust, commitment_root_latest_robust};

/// Canonical IBC key prefix used in Merkle proofs (ICS‑24).
pub const IBC_PREFIX: &[u8] = b"ibc";

// --- Deterministic one‑validator machinery ---

fn one_validator_set_and_key() -> (
    Vec<u8>,                        // validators_hash
    TmProtoValidatorSetUnversioned, // proto set
    Vec<u8>,                        // validator address
    Ed25519SecretKey,               // signing key
) {
    let seed: [u8; 32] = [1; 32];
    let sk = Ed25519SecretKey::from_seed(&seed).expect("ed25519 sk");
    let pk = sk.public_key().expect("pk");
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

    (validators_hash, proto_set, addr.as_bytes().to_vec(), sk)
}

fn pb_header_from_testgen(h: TmHeaderGen) -> TmProtoHeader {
    TmProtoHeader {
        chain_id: h.chain_id.unwrap_or_else(|| "test-chain".to_string()),
        height: h.height.unwrap_or(1) as i64,
        time: Some(PbTimestamp::from(h.time.unwrap())),
        version: Some(tendermint_proto::version::Consensus { block: 11, app: 0 }),
        proposer_address: vec![0; 20],
        ..Default::default()
    }
}

fn build_tm_header_for_root(
    remote_chain_id: &str,
    height: u64,
    trusted_height: u64,
    app_hash: &[u8; 32],
    vals_hash: &[u8],
    proto_valset: &TmProtoValidatorSetUnversioned,
    val_addr: &[u8],
    sk: &Ed25519SecretKey,
) -> Result<RawTmHeader> {
    use dcrypt::api::Signature;
    let light_block: TmLightBlock = TmLightBlock::new_default(height);
    let mut hdr = pb_header_from_testgen(light_block.header.clone().unwrap());
    hdr.chain_id = remote_chain_id.to_string();
    hdr.validators_hash = vals_hash.to_vec();
    hdr.next_validators_hash = vals_hash.to_vec();
    hdr.time = Some(PbTimestamp {
        seconds: height as i64,
        nanos: 0,
    });
    hdr.app_hash = app_hash.to_vec();

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
        validator_address: account::Id::try_from(val_addr.to_vec())?,
        validator_index: ValidatorIndex::try_from(0u32)?,
        signature: Default::default(),
        extension: Default::default(),
        extension_signature: Default::default(),
    };
    let tm_chain_id = TmChainId::try_from(remote_chain_id.to_string())?;
    let mut sign_bytes = Vec::new();
    vote.to_signable_bytes(tm_chain_id, &mut sign_bytes)?;
    let sig = dcrypt::sign::eddsa::Ed25519::sign(&sign_bytes, sk)?;

    let commit_proto = TmProtoCommit {
        height: hdr.height,
        round: 0,
        block_id: Some(TmProtoBlockId {
            hash: header_hash.as_bytes().to_vec(),
            part_set_header: Some(TmProtoPartSetHeader::from(part_set_header)),
        }),
        signatures: vec![TmProtoCommitSig {
            block_id_flag: 2,
            validator_address: val_addr.to_vec(),
            timestamp: Some(PbTimestamp::from(hdr_domain.time)),
            signature: sig.to_bytes().to_vec(),
        }],
    };
    let commit: tendermint::block::Commit = commit_proto.try_into()?;
    let tm_signed_header_domain = TmSignedHeader::new(hdr_domain, commit)?;
    Ok(RawTmHeader {
        signed_header: Some(tm_signed_header_domain.into()),
        validator_set: Some(proto_valset.clone()),
        trusted_height: Some(
            ibc_core_client_types::Height::new(0, trusted_height)
                .map_err(|e| anyhow!(e))?
                .into(),
        ),
        trusted_validators: Some(proto_valset.clone()),
    })
}

// ... [Helper: submit messages]
async fn submit_messages(gw: &Gateway, msgs: Vec<PbAny>) -> Result<()> {
    use ibc_proto::cosmos::tx::v1beta1::TxBody;
    let tx_body = TxBody {
        messages: msgs,
        ..Default::default()
    };
    // [FIX] Correctly encode tx_body length for base64 encoding
    let body_b64 = BASE64.encode(tx_body.encode_to_vec());
    gw.submit(&body_b64).await?;
    // Wait for the next block to be produced to ensure inclusion.
    sleep(Duration::from_secs(5)).await;
    Ok(())
}

fn tm_client_state_any(remote_chain_id: &str, latest_height: u64) -> PbAny {
    let cs = RawTmClientState {
        chain_id: remote_chain_id.to_string(),
        trust_level: Some(TmTrustFraction {
            numerator: 1,
            denominator: 3,
        }),
        trusting_period: Some(ibc_proto::google::protobuf::Duration {
            seconds: 60 * 60 * 24 * 365 * 100,
            nanos: 0,
        }),
        unbonding_period: Some(ibc_proto::google::protobuf::Duration {
            seconds: 60 * 60 * 24 * 365 * 101,
            nanos: 0,
        }),
        max_clock_drift: Some(ibc_proto::google::protobuf::Duration {
            seconds: 60 * 60 * 24,
            nanos: 0,
        }),
        latest_height: Some(
            ibc_core_client_types::Height::new(0, latest_height)
                .unwrap()
                .into(),
        ),
        frozen_height: Some(ibc_proto::ibc::core::client::v1::Height {
            revision_number: 0,
            revision_height: 0,
        }),
        // [FIX] Use default proof specs for simplicity, or construct properly if needed.
        // For testing against IOI which mimics Cosmos, default might suffice or be empty.
        proof_specs: vec![],
        upgrade_path: vec!["upgrade".into(), "upgradedIBCState".into()],
        ..Default::default()
    };
    PbAny {
        type_url: "/ibc.lightclients.tendermint.v1.ClientState".into(),
        value: cs.encode_to_vec(),
    }
}

fn tm_consensus_state_any(root: &[u8], next_validators_hash: &[u8], seconds: i64) -> PbAny {
    let ccs = RawTmConsensusState {
        timestamp: Some(ibc_proto::google::protobuf::Timestamp { seconds, nanos: 0 }),
        root: Some(ibc_proto::ibc::core::commitment::v1::MerkleRoot {
            hash: root.to_vec(),
        }),
        next_validators_hash: next_validators_hash.to_vec(),
    };
    PbAny {
        type_url: "/ibc.lightclients.tendermint.v1.ConsensusState".into(),
        value: ccs.encode_to_vec(),
    }
}

// ... [Update Handlers]

async fn update_b_about_a_to(
    gw_a: &Gateway,
    gw_b: &Gateway,
    client_a_on_b: &str,
    trusted_height: u64,
    new_height: u64,
    vals_hash: &[u8],
    proto_valset: &TmProtoValidatorSetUnversioned,
    val_addr: &[u8],
    sk: &Ed25519SecretKey,
    chain_id_a: &str,
) -> Result<u64> {
    // We need robust root fetching from proofs/gateway
    let (root, _) = commitment_root_at_height_robust(gw_a, new_height).await?;
    let app_hash: [u8; 32] = root
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("root must be 32 bytes"))?;
    let hdr = build_tm_header_for_root(
        chain_id_a,
        new_height,
        trusted_height,
        &app_hash,
        vals_hash,
        proto_valset,
        val_addr,
        sk,
    )?;
    let hdr_any = PbAny {
        type_url: "/ibc.lightclients.tendermint.v1.Header".into(),
        value: hdr.encode_to_vec(),
    };
    let msg = build_update_client_any(client_a_on_b, hdr_any, "ioi-relayer")?;
    submit_messages(gw_b, vec![msg]).await?;
    Ok(new_height)
}

async fn update_a_about_b_to(
    gw_b: &Gateway,
    gw_a: &Gateway,
    client_b_on_a: &str,
    trusted_height: u64,
    new_height: u64,
    vals_hash: &[u8],
    proto_valset: &TmProtoValidatorSetUnversioned,
    val_addr: &[u8],
    sk: &Ed25519SecretKey,
    chain_id_b: &str,
) -> Result<u64> {
    let (root, _) = commitment_root_at_height_robust(gw_b, new_height).await?;
    let app_hash: [u8; 32] = root
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("root must be 32 bytes"))?;
    let hdr = build_tm_header_for_root(
        chain_id_b,
        new_height,
        trusted_height,
        &app_hash,
        vals_hash,
        proto_valset,
        val_addr,
        sk,
    )?;
    let hdr_any = PbAny {
        type_url: "/ibc.lightclients.tendermint.v1.Header".into(),
        value: hdr.encode_to_vec(),
    };
    let msg = build_update_client_any(client_b_on_a, hdr_any, "ioi-relayer")?;
    submit_messages(gw_a, vec![msg]).await?;
    Ok(new_height)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_handshake(
    gw_a: &Gateway,
    gw_b: &Gateway,
    _client_a_on_a: &str, // kept for compatibility
    client_b_on_a: &str,
    client_a_on_b: &str,
    _client_b_on_b: &str, // kept for compatibility
    port_a: &str,
    port_b: &str,
    signer: &str,
) -> Result<()> {
    info!("🤝 Starting IBC Handshake with client bootstrap...");

    // Shared 1‑validator set for synthetic headers
    let (vals_hash, proto_valset, val_addr, sk) = one_validator_set_and_key();

    // Create clients on both sides with initial consensus states at height 1
    let (root_a, _) = commitment_root_latest_robust(gw_a).await?;
    let (root_b, _) = commitment_root_latest_robust(gw_b).await?;

    submit_messages(
        gw_a,
        vec![build_create_client_any(
            tm_client_state_any("chain-B", 1),
            tm_consensus_state_any(&root_b, &vals_hash, 1),
            signer,
        )?],
    )
    .await?;
    submit_messages(
        gw_b,
        vec![build_create_client_any(
            tm_client_state_any("chain-A", 1),
            tm_consensus_state_any(&root_a, &vals_hash, 1),
            signer,
        )?],
    )
    .await?;

    let mut h_a_on_b = 1u64;
    let mut h_b_on_a = 1u64;

    // 1) ConnOpenInit on A
    submit_messages(
        gw_a,
        vec![build_conn_open_init_any(
            client_b_on_a,
            client_a_on_b,
            signer,
        )?],
    )
    .await?;
    // [FIX] Explicit type for inferred connection id tuple
    let (conn_a_id, h_init_a): (String, u64) = infer_allocated_connection_id(gw_a).await?;
    h_a_on_b = update_b_about_a_to(
        gw_a,
        gw_b,
        client_a_on_b,
        h_a_on_b,
        h_init_a,
        &vals_hash,
        &proto_valset,
        &val_addr,
        &sk,
        "chain-A",
    )
    .await?;

    // 2) ConnOpenTry on B
    submit_messages(
        gw_b,
        vec![
            build_conn_open_try_any(
                gw_a,
                client_b_on_a,
                client_a_on_b,
                &conn_a_id,
                client_b_on_a,
                h_init_a,
                signer,
            )
            .await?,
        ],
    )
    .await?;
    let (conn_b_id, h_try_b): (String, u64) = infer_allocated_connection_id(gw_b).await?;
    h_b_on_a = update_a_about_b_to(
        gw_b,
        gw_a,
        client_b_on_a,
        h_b_on_a,
        h_try_b,
        &vals_hash,
        &proto_valset,
        &val_addr,
        &sk,
        "chain-B",
    )
    .await?;

    // 3) ConnOpenAck on A
    submit_messages(
        gw_a,
        vec![
            build_conn_open_ack_any(gw_b, &conn_a_id, &conn_b_id, client_a_on_b, h_try_b, signer)
                .await?,
        ],
    )
    .await?;
    let (_v, _p, h_ack_a) = gw_a
        .query_latest(
            &ibc_core_host_types::path::ConnectionPath::new(&conn_a_id.parse()?).to_string(),
        )
        .await?;
    h_a_on_b = update_b_about_a_to(
        gw_a,
        gw_b,
        client_a_on_b,
        h_a_on_b,
        h_ack_a,
        &vals_hash,
        &proto_valset,
        &val_addr,
        &sk,
        "chain-A",
    )
    .await?;

    // 4) ConnOpenConfirm on B
    submit_messages(
        gw_b,
        vec![build_conn_open_confirm_any(gw_a, &conn_b_id, &conn_a_id, h_ack_a, signer).await?],
    )
    .await?;

    // --- Channel handshake ---
    submit_messages(
        gw_a,
        vec![
            build_chan_open_init_any(port_a, &conn_a_id, port_b, "ics20-1", 1, signer)?, // 1 = Unordered
        ],
    )
    .await?;
    // [FIX] Explicit type for inferred channel id tuple
    let (chan_a_id, h_chan_init_a): (String, u64) = infer_allocated_channel_id(gw_a).await?;
    h_a_on_b = update_b_about_a_to(
        gw_a,
        gw_b,
        client_a_on_b,
        h_a_on_b,
        h_chan_init_a,
        &vals_hash,
        &proto_valset,
        &val_addr,
        &sk,
        "chain-A",
    )
    .await?;

    submit_messages(
        gw_b,
        vec![
            build_chan_open_try_any(
                gw_a,
                port_b,
                &conn_b_id,
                port_a,
                &chan_a_id,
                "ics20-1",
                1,
                h_chan_init_a,
                signer,
            )
            .await?,
        ],
    )
    .await?;
    let (chan_b_id, h_chan_try_b): (String, u64) = infer_allocated_channel_id(gw_b).await?;
    let _ = update_a_about_b_to(
        gw_b,
        gw_a,
        client_b_on_a,
        h_b_on_a,
        h_chan_try_b,
        &vals_hash,
        &proto_valset,
        &val_addr,
        &sk,
        "chain-B",
    )
    .await?;

    submit_messages(
        gw_a,
        vec![
            build_chan_open_ack_any(
                gw_b,
                port_a,
                &chan_a_id,
                port_b,
                &chan_b_id,
                "ics20-1",
                h_chan_try_b,
                signer,
            )
            .await?,
        ],
    )
    .await?;
    let (_v2, _p2, h_chan_ack_a) = gw_a
        .query_latest(
            &ibc_core_host_types::path::ChannelEndPath::new(&port_a.parse()?, &chan_a_id.parse()?)
                .to_string(),
        )
        .await?;
    let _ = update_b_about_a_to(
        gw_a,
        gw_b,
        client_a_on_b,
        h_a_on_b,
        h_chan_ack_a,
        &vals_hash,
        &proto_valset,
        &val_addr,
        &sk,
        "chain-A",
    )
    .await?;

    submit_messages(
        gw_b,
        vec![
            build_chan_open_confirm_any(
                gw_a,
                port_b,
                &chan_b_id,
                port_a,
                &chan_a_id,
                h_chan_ack_a,
                signer,
            )
            .await?,
        ],
    )
    .await?;

    info!("🤝 Handshake Successful!");
    Ok(())
}
