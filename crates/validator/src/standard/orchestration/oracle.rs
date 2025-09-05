// Path: crates/validator/src/standard/orchestration/oracle.rs
use super::context::MainLoopContext;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateCommitment, StateManager},
};
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_services::external_data::ExternalDataService;
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ChainTransaction, OracleAttestation,
        OracleConsensusProof, SignHeader, SignatureProof, SignatureSuite, StateEntry,
        SystemPayload, SystemTransaction,
    },
    keys::ORACLE_PENDING_REQUEST_PREFIX,
};
use libp2p::{identity::PublicKey as Libp2pPublicKey, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

// Time-to-live for attestations to prevent replay of old, potentially invalid data.
const ATTESTATION_TTL_SECS: u64 = 300; // 5 minutes

/// Checks for pending oracle requests after a block is processed and initiates data fetching.
pub async fn handle_newly_processed_block<CS, ST, CE>(
    context: &MainLoopContext<CS, ST, CE>,
    _block_height: u64,
    external_data_service: &ExternalDataService,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    let pending_requests = match context
        .workload_client
        .prefix_scan(ORACLE_PENDING_REQUEST_PREFIX)
        .await
    {
        Ok(kvs) => kvs,
        Err(e) => {
            log::error!("Oracle: Failed to scan for pending requests: {}", e);
            return;
        }
    };

    let validator_stakes = match context.workload_client.get_staked_validators().await {
        Ok(vs) => vs,
        Err(e) => {
            log::error!("Oracle: Could not get validator stakes: {}", e);
            return;
        }
    };

    let validator_account_ids: HashSet<AccountId> = validator_stakes
        .keys()
        .filter_map(|hex_str| hex::decode(hex_str).ok())
        .filter_map(|bytes| bytes.try_into().ok().map(AccountId))
        .collect();

    let our_account_id_hash = account_id_from_key_material(
        SignatureSuite::Ed25519,
        &context.local_keypair.public().encode_protobuf(),
    )
    .expect("Local key should be valid");
    let our_account_id = AccountId(our_account_id_hash);

    if !validator_account_ids.contains(&our_account_id) {
        return; // This node is not a staked validator, so it shouldn't perform oracle tasks.
    }

    log::info!("Oracle: This node is in the validator set, checking for new tasks...");

    for (key, value_bytes) in pending_requests {
        if let Ok(entry) = serde_json::from_slice::<StateEntry>(&value_bytes) {
            let request_id_bytes: [u8; 8] = key[ORACLE_PENDING_REQUEST_PREFIX.len()..]
                .try_into()
                .unwrap_or_default();
            let request_id = u64::from_le_bytes(request_id_bytes);
            let url: String = serde_json::from_slice(&entry.value).unwrap_or_default();

            log::info!(
                "Oracle: Found new oracle task for request_id {} from URL: {}",
                request_id,
                url
            );

            match external_data_service.fetch(&url).await {
                Ok(value) => {
                    let Ok(ed25519_pk) = context.local_keypair.public().try_into_ed25519() else {
                        log::error!(
                            "Oracle: Local keypair is not Ed25519, cannot create attestation."
                        );
                        continue;
                    };
                    let pubkey_bytes = ed25519_pk.to_bytes();

                    let mut attestation = OracleAttestation {
                        request_id,
                        value,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        signature: vec![],
                    };

                    let payload_to_sign = attestation.to_signing_payload("test-chain");
                    let signature_bytes = context.local_keypair.sign(&payload_to_sign).unwrap();
                    attestation.signature = [pubkey_bytes.as_ref(), &signature_bytes].concat();

                    let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
                    context
                        .swarm_commander
                        .send(SwarmCommand::GossipOracleAttestation(attestation_bytes))
                        .await
                        .ok();
                    log::info!("Oracle: Gossiped attestation for request_id {}", request_id);
                }
                Err(e) => log::error!(
                    "Oracle: Failed to fetch external data for request {}: {}",
                    request_id,
                    e
                ),
            }
        }
    }
}

/// Handles a received oracle attestation from a peer validator.
pub async fn handle_oracle_attestation_received<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    from: PeerId,
    attestation: OracleAttestation,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    log::info!(
        "Oracle: Received attestation for request_id {} from peer {}",
        attestation.request_id,
        from
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
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

    let validator_stakes = match context.workload_client.get_staked_validators().await {
        Ok(vs) => vs,
        Err(e) => {
            log::error!(
                "Oracle: Could not get validator stakes for verification: {}",
                e
            );
            return;
        }
    };

    let signer_account_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &pubkey.encode_protobuf())
            .expect("libp2p public key should be valid");
    let signer_account_id_hex = hex::encode(signer_account_id_hash);

    if !validator_stakes.contains_key(&signer_account_id_hex) {
        log::warn!(
            "Oracle: Received attestation from non-staker {}, disregarding.",
            from
        );
        return;
    }

    let payload_to_verify = attestation.to_signing_payload("test-chain");

    if !pubkey.verify(&payload_to_verify, sig_bytes) {
        log::warn!(
            "Oracle: Received attestation with invalid signature from {}",
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
pub async fn check_quorum_and_submit<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    request_id: u64,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    let attestations = match context.pending_attestations.get(&request_id) {
        Some(a) => a,
        None => return,
    };

    let validator_stakes = match context.workload_client.get_staked_validators().await {
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

        let signer_account_id_hash =
            account_id_from_key_material(SignatureSuite::Ed25519, &pubkey.encode_protobuf())
                .expect("libp2p public key should be valid");
        let signer_account_id_hex = hex::encode(signer_account_id_hash);

        if validator_stakes.contains_key(&signer_account_id_hex) {
            let payload_to_verify = att.to_signing_payload("test-chain");
            if pubkey.verify(&payload_to_verify, sig_bytes)
                && unique_signers.insert(signer_account_id_hex.clone())
            {
                valid_attestations_for_quorum.push((att.clone(), signer_account_id_hex));
            }
        }
    }
    valid_attestations_for_quorum.sort_by(|(_, pk_a), (_, pk_b)| pk_a.cmp(pk_b));

    let attested_stake: u64 = valid_attestations_for_quorum
        .iter()
        .filter_map(|(_, account_id_hex)| validator_stakes.get(account_id_hex))
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
        let final_value = values[values.len() / 2].clone();

        let consensus_proof = OracleConsensusProof {
            attestations: valid_attestations_for_quorum
                .into_iter()
                .map(|(a, _)| a)
                .collect(),
        };

        let payload = SystemPayload::SubmitOracleData {
            request_id,
            final_value,
            consensus_proof,
        };

        let tx = ChainTransaction::System(Box::new(SystemTransaction {
            payload,
            header: SignHeader {
                account_id: AccountId([0; 32]),
                nonce: 0,
                chain_id: 0,
                tx_version: 1,
            },
            signature_proof: SignatureProof::default(),
        }));

        context.tx_pool_ref.lock().await.push_back(tx);
        log::info!(
            "Oracle: Submitted finalization transaction for request_id {} to local mempool.",
            request_id
        );

        context.pending_attestations.remove(&request_id);
    }
}
