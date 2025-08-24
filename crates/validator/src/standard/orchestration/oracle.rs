// Path: crates/validator/src/standard/orchestration/oracle.rs
use super::context::MainLoopContext;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    state::{StateCommitment, StateManager},
};
use depin_sdk_consensus::ConsensusEngine;
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_services::external_data::ExternalDataService;
use depin_sdk_types::{
    app::{
        ChainTransaction, OracleAttestation, OracleConsensusProof, StateEntry, SystemPayload,
        SystemTransaction,
    },
    keys::ORACLE_PENDING_REQUEST_PREFIX,
};
use libp2p::{identity::PublicKey as Libp2pPublicKey, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

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

    let validator_set = match context.workload_client.get_validator_set().await {
        Ok(vs) => vs,
        Err(e) => {
            log::error!("Oracle: Could not get validator set: {}", e);
            return;
        }
    };

    let our_id_bytes = context.local_peer_id.to_bytes();
    if !validator_set.iter().any(|v| *v == our_id_bytes) {
        return;
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
                    let mut attestation = OracleAttestation {
                        request_id,
                        value,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        signature: vec![],
                    };

                    let payload_to_sign = serde_json::to_vec(&(
                        &attestation.request_id,
                        &attestation.value,
                        &attestation.timestamp,
                    ))
                    .unwrap();
                    attestation.signature = context.local_keypair.sign(&payload_to_sign).unwrap();

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
    let validator_stakes = match context.workload_client.get_staked_validators().await {
        Ok(vs) => vs,
        Err(_) => return,
    };

    let payload_to_verify = serde_json::to_vec(&(
        &attestation.request_id,
        &attestation.value,
        &attestation.timestamp,
    ))
    .unwrap();
    let mut is_valid_signature = false;
    for (pk_b58, _) in &validator_stakes {
        if let Ok(pk_bytes) = bs58::decode(pk_b58).into_vec() {
            if let Ok(pubkey) = Libp2pPublicKey::try_decode_protobuf(&pk_bytes) {
                if pubkey.to_peer_id() == from
                    && pubkey.verify(&payload_to_verify, &attestation.signature)
                {
                    is_valid_signature = true;
                    break;
                }
            }
        }
    }

    if !is_valid_signature {
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
    if !entry.iter().any(|a| a.signature == attestation.signature) {
        entry.push(attestation.clone());
    }

    check_quorum_and_submit(context, attestation.request_id).await;
}

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

    for att in attestations {
        for (pk_b58, _) in &validator_stakes {
            if let Ok(pk_bytes) = bs58::decode(pk_b58).into_vec() {
                if let Ok(pubkey) = Libp2pPublicKey::try_decode_protobuf(&pk_bytes) {
                    let payload_to_verify =
                        serde_json::to_vec(&(&att.request_id, &att.value, &att.timestamp)).unwrap();
                    if pubkey.verify(&payload_to_verify, &att.signature)
                        && unique_signers.insert(pk_b58.clone())
                    {
                        valid_attestations_for_quorum.push((att.clone(), pk_b58));
                        break;
                    }
                }
            }
        }
    }
    valid_attestations_for_quorum.sort_by(|(_, pk_a), (_, pk_b)| pk_a.cmp(pk_b));

    let attested_stake: u64 = valid_attestations_for_quorum
        .iter()
        .filter_map(|(_, pk_b58)| validator_stakes.get(*pk_b58))
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

        let tx = ChainTransaction::System(SystemTransaction {
            payload,
            signature: vec![],
        });
        context.tx_pool_ref.lock().await.push_back(tx);
        log::info!(
            "Oracle: Submitted finalization transaction for request_id {} to local mempool.",
            request_id
        );

        context.pending_attestations.remove(&request_id);
    }
}
