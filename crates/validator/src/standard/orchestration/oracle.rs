// Path: crates/validator/src/standard/orchestration/oracle.rs
//! Contains the reactive, off-chain logic for the Oracle service.
//! This module handles incoming gossip events (attestations) from other validators,
//! verifies them, aggregates them, and submits a finalization transaction
//! once a quorum is reached.

use super::context::MainLoopContext;
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use ioi_services::oracle::SubmitDataParams;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ChainTransaction, OracleAttestation,
        OracleConsensusProof, SignHeader, SignatureProof, SignatureSuite, SystemPayload,
        SystemTransaction,
    },
    codec,
};
use libp2p::{identity::PublicKey as Libp2pPublicKey, PeerId};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

// Time-to-live for attestations to prevent replay of old, potentially invalid data.
const ATTESTATION_TTL_SECS: u64 = 300; // 5 minutes

/// Handles a received oracle attestation from a peer validator.
pub async fn handle_oracle_attestation_received<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    from: PeerId,
    attestation: OracleAttestation,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    log::info!(
        "Oracle: Received attestation for request_id {} from peer {}",
        attestation.request_id,
        from
    );

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => {
            log::error!("Oracle: System time is before UNIX_EPOCH, cannot validate timestamp.");
            return;
        }
    };
    if now.saturating_sub(attestation.timestamp) > ATTESTATION_TTL_SECS {
        log::warn!(
            "Oracle: Received stale attestation from {}, disregarding.",
            from
        );
        return;
    }

    const ED25519_PUBKEY_LEN: usize = 32;
    if attestation.signature.len() <= ED25519_PUBKEY_LEN {
        log::warn!(
            "Oracle: Received attestation with malformed signature (too short) from {}",
            from
        );
        return;
    }
    let (pubkey_bytes, sig_bytes) = attestation.signature.split_at(ED25519_PUBKEY_LEN);

    let pubkey = match libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey_bytes) {
        Ok(pk) => Libp2pPublicKey::from(pk),
        Err(_) => {
            log::warn!(
                "Oracle: Failed to decode Ed25519 public key from attestation from {}",
                from
            );
            return;
        }
    };

    if pubkey.to_peer_id() != from {
        log::warn!(
            "Oracle: Attestation signer PeerId {} does not match gossip source PeerId {}. This could indicate a relay, but signature must be valid.",
            pubkey.to_peer_id(), from
        );
    }

    let workload_client = match context
        .view_resolver
        .as_any()
        .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
    {
        Some(resolver) => resolver.workload_client(),
        None => {
            log::error!("Oracle: Could not get WorkloadClient for verification.");
            return;
        }
    };

    let validator_stakes = match workload_client.get_staked_validators().await {
        Ok(vs) => vs,
        Err(e) => {
            log::error!(
                "Oracle: Could not get validator stakes for verification: {}",
                e
            );
            return;
        }
    };

    if validator_stakes.is_empty() {
        return;
    }

    let signer_account_id =
        match account_id_from_key_material(SignatureSuite::Ed25519, &pubkey.encode_protobuf()) {
            Ok(hash) => AccountId(hash),
            Err(_) => {
                log::error!("Oracle: Could not derive AccountId from public key.");
                return;
            }
        };

    if !validator_stakes.contains_key(&signer_account_id) {
        log::warn!(
            "Oracle: Received attestation from non-staker {}, disregarding.",
            from
        );
        return;
    }

    // Recreate the same domain to verify the signature
    let mut domain = b"ioi/oracle-attest/v1".to_vec();
    domain.extend_from_slice(&context.chain_id.0.to_le_bytes());
    domain.extend_from_slice(&context.genesis_hash);

    if let Ok(payload_to_verify) = attestation.to_signing_payload(&domain) {
        if !pubkey.verify(&payload_to_verify, sig_bytes) {
            log::warn!(
                "Oracle: Received attestation with invalid signature from {}",
                from
            );
            return;
        }
    } else {
        log::warn!(
            "Oracle: Failed to create payload for verifying attestation from {}",
            from
        );
        return;
    }

    let entry = context
        .pending_attestations
        .entry(attestation.request_id)
        .or_default();

    let signer_peer_id = pubkey.to_peer_id();
    if !entry.iter().any(|a| {
        if a.signature.len() > ED25519_PUBKEY_LEN {
            let (pk_bytes, _) = a.signature.split_at(ED25519_PUBKEY_LEN);
            if let Ok(pk) = libp2p::identity::ed25519::PublicKey::try_from_bytes(pk_bytes) {
                return Libp2pPublicKey::from(pk).to_peer_id() == signer_peer_id;
            }
        }
        false
    }) {
        entry.push(attestation.clone());
    }

    check_quorum_and_submit(context, attestation.request_id).await;
}

/// Checks if a quorum of attestations has been reached for a request and submits a finalization transaction if so.
pub async fn check_quorum_and_submit<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    request_id: u64,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let attestations = match context.pending_attestations.get(&request_id) {
        Some(a) => a,
        None => return,
    };

    let workload_client = match context
        .view_resolver
        .as_any()
        .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
    {
        Some(resolver) => resolver.workload_client(),
        None => {
            log::error!("Oracle: Could not get WorkloadClient for quorum check.");
            return;
        }
    };
    let validator_stakes = match workload_client.get_staked_validators().await {
        Ok(vs) => vs,
        Err(_) => return,
    };

    if validator_stakes.is_empty() {
        return;
    }

    let total_stake: u64 = validator_stakes.values().sum();
    let quorum_threshold = (total_stake * 2) / 3 + 1;

    let mut unique_signers = HashSet::new();
    let mut valid_attestations_for_quorum = Vec::new();

    const ED25519_PUBKEY_LEN: usize = 32;
    for att in attestations {
        if att.signature.len() <= ED25519_PUBKEY_LEN {
            continue;
        }
        let (pubkey_bytes, sig_bytes) = att.signature.split_at(ED25519_PUBKEY_LEN);

        let pubkey = match libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey_bytes) {
            Ok(pk) => Libp2pPublicKey::from(pk),
            Err(_) => continue,
        };

        let signer_account_id = match account_id_from_key_material(
            SignatureSuite::Ed25519,
            &pubkey.encode_protobuf(),
        ) {
            Ok(hash) => AccountId(hash),
            Err(_) => continue,
        };

        if validator_stakes.contains_key(&signer_account_id) {
            let mut domain = b"ioi/oracle-attest/v1".to_vec();
            domain.extend_from_slice(&context.chain_id.0.to_le_bytes());
            domain.extend_from_slice(&context.genesis_hash);
            if let Ok(payload_to_verify) = att.to_signing_payload(&domain) {
                if pubkey.verify(&payload_to_verify, sig_bytes)
                    && unique_signers.insert(signer_account_id)
                {
                    valid_attestations_for_quorum.push((att.clone(), signer_account_id));
                }
            }
        }
    }
    valid_attestations_for_quorum.sort_by(|(_, id_a), (_, id_b)| id_a.cmp(id_b));

    let attested_stake: u64 = valid_attestations_for_quorum
        .iter()
        .filter_map(|(_, account_id)| validator_stakes.get(account_id))
        .sum();

    if attested_stake >= quorum_threshold {
        log::info!(
            "Oracle: Quorum reached for request_id {} with {}/{} stake!",
            request_id,
            attested_stake,
            total_stake
        );

        let mut values: Vec<Vec<u8>> = valid_attestations_for_quorum
            .iter()
            .map(|(a, _)| a.value.clone())
            .collect();
        values.sort();
        let Some(final_value) = values.get(values.len() / 2).cloned() else {
            log::error!("Oracle: Quorum met, but could not determine median value.");
            return;
        };

        let consensus_proof = OracleConsensusProof {
            attestations: valid_attestations_for_quorum
                .into_iter()
                .map(|(a, _)| a)
                .collect(),
        };

        let params = SubmitDataParams {
            request_id,
            final_value,
            consensus_proof,
        };
        let payload = SystemPayload::CallService {
            service_id: "oracle".to_string(),
            method: "submit_data@v1".to_string(),
            params: codec::to_bytes_canonical(&params).unwrap_or_default(),
        };

        let our_pk = context.local_keypair.public();
        let our_pk_bytes = our_pk.encode_protobuf();
        let our_account_id =
            match account_id_from_key_material(SignatureSuite::Ed25519, &our_pk_bytes) {
                Ok(hash) => AccountId(hash),
                Err(_) => return,
            };

        let current_nonce = {
            let mut nonce_manager = context.nonce_manager.lock().await;
            let nonce = nonce_manager.entry(our_account_id).or_insert(0);
            let current = *nonce;
            *nonce += 1;
            current
        };

        let mut sys_tx = SystemTransaction {
            header: SignHeader {
                account_id: our_account_id,
                nonce: current_nonce,
                chain_id: context.chain_id,
                tx_version: 1,
            },
            payload,
            signature_proof: SignatureProof::default(),
        };

        let sign_bytes = match sys_tx.to_sign_bytes() {
            Ok(b) => b,
            Err(_) => return,
        };
        let signature = match context.local_keypair.sign(&sign_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };

        sys_tx.signature_proof = SignatureProof {
            suite: SignatureSuite::Ed25519,
            public_key: our_pk_bytes,
            signature,
        };

        let tx = ChainTransaction::System(Box::new(sys_tx));

        context.tx_pool_ref.lock().await.push_back(tx);
        log::info!(
            "Oracle: Submitted finalization transaction for request_id {} to local mempool.",
            request_id
        );

        context.pending_attestations.remove(&request_id);
    }
}
