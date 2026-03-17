// Path: crates/validator/src/standard/orchestration/finalize.rs

use anyhow::{anyhow, Result};
use ioi_api::{
    chain::StateRef,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
// REMOVED: use ioi_client::WorkloadClient;
use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_types::{
    app::{
        account_id_from_key_material, build_committed_surface_canonical_order_certificate,
        derive_asymptote_observer_plan_entries, derive_guardian_witness_assignment,
        derive_guardian_witness_assignments_for_strata, effective_set_for_height,
        guardian_registry_asymptote_policy_key, guardian_registry_committee_account_key,
        guardian_registry_committee_key, guardian_registry_witness_key,
        guardian_registry_witness_seed_key, guardian_registry_witness_set_key, read_validator_sets,
        to_root_hash, AccountId, AsymptotePolicy, Block, ChainTransaction, ConsensusVote,
        GuardianCommitteeManifest, GuardianWitnessCommitteeManifest, GuardianWitnessEpochSeed,
        GuardianWitnessFaultEvidence, GuardianWitnessFaultKind, GuardianWitnessSet,
        SignatureBundle, SignatureSuite,
    },
    codec,
    config::AftSafetyMode,
    keys::{CURRENT_EPOCH_KEY, VALIDATOR_SET_KEY},
};
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

use crate::common::GuardianSigner;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::ingestion::ChainTipInfo;
use crate::standard::orchestration::mempool::Mempool;

fn relay_fanout() -> usize {
    std::env::var("IOI_AFT_TX_RELAY_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn post_commit_leader_fanout() -> usize {
    std::env::var("IOI_AFT_POST_COMMIT_LEADER_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn post_commit_relay_limit() -> usize {
    std::env::var("IOI_AFT_POST_COMMIT_RELAY_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2048)
}

fn post_commit_direct_relay_limit() -> usize {
    std::env::var("IOI_AFT_POST_COMMIT_DIRECT_RELAY_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(256)
}

fn post_commit_rekick_delays_ms() -> Vec<u64> {
    std::env::var("IOI_AFT_POST_COMMIT_REKICK_DELAYS_MS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<u64>().ok())
                .filter(|delay| *delay > 0)
                .collect::<Vec<_>>()
        })
        .filter(|delays| !delays.is_empty())
        .unwrap_or_else(|| vec![100, 300, 750])
}

fn post_commit_vote_replay_delays_ms() -> Vec<u64> {
    std::env::var("IOI_AFT_POST_COMMIT_VOTE_REPLAY_DELAYS_MS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<u64>().ok())
                .filter(|delay| *delay > 0)
                .collect::<Vec<_>>()
        })
        .filter(|delays| !delays.is_empty())
        .unwrap_or_else(|| vec![150, 500, 1200])
}

async fn replay_committed_block_vote_once<CE>(
    consensus_engine_ref: &Arc<Mutex<CE>>,
    local_keypair: &libp2p::identity::Keypair,
    swarm_sender: &mpsc::Sender<SwarmCommand>,
    block: &Block<ChainTransaction>,
) where
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    if block.header.height == 0 {
        return;
    }

    let vote_hash_vec = match block.header.hash() {
        Ok(hash) => hash,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the block hash could not be derived."
            );
            return;
        }
    };
    let vote_hash = match to_root_hash(&vote_hash_vec) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the block hash root conversion failed."
            );
            return;
        }
    };

    let our_pk = local_keypair.public().encode_protobuf();
    let our_id_hash = match account_id_from_key_material(SignatureSuite::ED25519, &our_pk) {
        Ok(id) => id,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the local account id could not be derived."
            );
            return;
        }
    };
    let vote_payload = (block.header.height, block.header.view, vote_hash);
    let vote_bytes = match codec::to_bytes_canonical(&vote_payload) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the vote payload could not be encoded."
            );
            return;
        }
    };
    let signature = match local_keypair.sign(&vote_bytes) {
        Ok(signature) => signature,
        Err(error) => {
            tracing::debug!(
                target: "consensus",
                height = block.header.height,
                view = block.header.view,
                error = %error,
                "Skipping committed block vote replay because the vote could not be signed."
            );
            return;
        }
    };

    let vote = ConsensusVote {
        height: block.header.height,
        view: block.header.view,
        block_hash: vote_hash,
        voter: AccountId(our_id_hash),
        signature,
    };

    if let Ok(vote_blob) = codec::to_bytes_canonical(&vote) {
        let _ = swarm_sender
            .send(SwarmCommand::BroadcastVote(vote_blob))
            .await;
    }

    let mut engine = consensus_engine_ref.lock().await;
    if let Err(error) = engine.handle_vote(vote).await {
        tracing::debug!(
            target: "consensus",
            height = block.header.height,
            view = block.header.view,
            error = %error,
            "Committed block vote replay loopback was ignored."
        );
        return;
    }
    let pending_qcs = engine.take_pending_quorum_certificates();
    drop(engine);

    for qc in pending_qcs {
        if let Ok(qc_blob) = codec::to_bytes_canonical(&qc) {
            let _ = swarm_sender
                .send(SwarmCommand::BroadcastQuorumCertificate(qc_blob))
                .await;
        }
    }
}

pub(crate) fn schedule_committed_block_vote_replays<CE>(
    consensus_engine_ref: Arc<Mutex<CE>>,
    local_keypair: libp2p::identity::Keypair,
    swarm_sender: mpsc::Sender<SwarmCommand>,
    block: Block<ChainTransaction>,
) where
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    for delay_ms in post_commit_vote_replay_delays_ms() {
        let consensus_engine_ref = Arc::clone(&consensus_engine_ref);
        let local_keypair = local_keypair.clone();
        let swarm_sender = swarm_sender.clone();
        let block = block.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            replay_committed_block_vote_once(
                &consensus_engine_ref,
                &local_keypair,
                &swarm_sender,
                &block,
            )
            .await;
        });
    }
}

fn schedule_post_commit_rekicks(
    tx_pool: Arc<Mempool>,
    kick_tx: mpsc::UnboundedSender<()>,
    kick_scheduled: Arc<AtomicBool>,
) {
    if tx_pool.is_empty() {
        return;
    }

    for delay_ms in post_commit_rekick_delays_ms() {
        let tx_pool = Arc::clone(&tx_pool);
        let kick_tx = kick_tx.clone();
        let kick_scheduled = Arc::clone(&kick_scheduled);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            if !tx_pool.is_empty() {
                crate::standard::orchestration::schedule_consensus_kick(&kick_tx, &kick_scheduled);
            }
        });
    }
}

fn dispatch_swarm_command(sender: &tokio::sync::mpsc::Sender<SwarmCommand>, command: SwarmCommand) {
    match sender.try_send(command) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(command)) => {
            let sender = sender.clone();
            tokio::spawn(async move {
                let _ = sender.send(command).await;
            });
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
    }
}

fn leader_accounts_for_upcoming_heights(
    local_height: u64,
    validator_ids: &[Vec<u8>],
    fanout: usize,
) -> Vec<AccountId> {
    if validator_ids.is_empty() || fanout == 0 {
        return Vec::new();
    }

    let mut leaders = Vec::new();
    let mut seen = HashSet::new();
    let validator_len = validator_ids.len() as u64;
    let steps = fanout.min(validator_ids.len());
    for offset in 1..=steps {
        let target_height = local_height.saturating_add(offset as u64).max(1);
        let leader_index = ((target_height - 1) % validator_len) as usize;
        let Some(leader_bytes) = validator_ids.get(leader_index) else {
            continue;
        };
        let Ok(leader_bytes) = <[u8; 32]>::try_from(leader_bytes.as_slice()) else {
            continue;
        };
        let account = AccountId(leader_bytes);
        if seen.insert(account) {
            leaders.push(account);
        }
    }
    leaders
}

pub async fn finalize_and_broadcast_block<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    mut final_block: Block<ChainTransaction>,
    deferred_transactions: Vec<ChainTransaction>,
    signer: Arc<dyn GuardianSigner>,
    swarm_commander: &mpsc::Sender<SwarmCommand>,
    consensus_engine_ref: &Arc<Mutex<CE>>,
    tx_pool: &Arc<Mempool>,
    node_state_arc: &Arc<Mutex<NodeState>>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let block_height = final_block.header.height;
    let preimage = final_block.header.to_preimage_for_signing()?;
    let preimage_hash = ioi_crypto::algorithms::hash::sha256(&preimage)?;
    let bundle_started = Instant::now();
    let bundle =
        issue_consensus_bundle(context_arc, signer.as_ref(), &final_block, preimage_hash).await?;
    let bundle_elapsed = bundle_started.elapsed();
    if bundle_elapsed.as_millis() >= 250 {
        tracing::warn!(
            target: "consensus",
            height = block_height,
            tx_count = final_block.transactions.len(),
            elapsed_ms = bundle_elapsed.as_millis(),
            "issue_consensus_bundle() is slow"
        );
    }
    final_block.header.signature = bundle.signature;
    final_block.header.oracle_counter = bundle.counter;
    final_block.header.oracle_trace_hash = bundle.trace_hash;
    final_block.header.guardian_certificate = bundle.guardian_certificate;
    final_block.header.sealed_finality_proof = bundle.sealed_finality_proof;
    let aft_mode = {
        let ctx = context_arc.lock().await;
        ctx.config.aft_safety_mode
    };
    final_block.header.canonical_order_certificate = if matches!(aft_mode, AftSafetyMode::Asymptote)
    {
        Some(
            build_committed_surface_canonical_order_certificate(
                &final_block.header,
                &final_block.transactions,
            )
            .map_err(|e| anyhow!(e))?,
        )
    } else {
        None
    };

    {
        let ctx = context_arc.lock().await;
        let receipt_guard = ctx.receipt_map.lock().await;
        let mut status_guard = ctx.tx_status_cache.lock().await;

        for tx in &final_block.transactions {
            let tx_hash_res: Result<ioi_types::app::TxHash, _> = tx.hash();
            if let Ok(h) = tx_hash_res {
                let tx_hash_hex = receipt_guard
                    .peek(&h)
                    .cloned()
                    .unwrap_or_else(|| hex::encode(h));
                if let Some(entry) = status_guard.get_mut(&tx_hash_hex) {
                    entry.status = TxStatus::Committed;
                    entry.block_height = Some(block_height);
                } else {
                    status_guard.put(
                        tx_hash_hex,
                        crate::standard::orchestration::context::TxStatusEntry {
                            status: TxStatus::Committed,
                            error: None,
                            block_height: Some(block_height),
                        },
                    );
                }
            }
        }
    }

    {
        let mut ctx = context_arc.lock().await;
        ctx.last_committed_block = Some(final_block.clone());
        {
            let mut chain_guard = ctx.chain_ref.lock().await;
            let status = chain_guard.status_mut();
            if block_height > status.height {
                status.total_transactions = status
                    .total_transactions
                    .saturating_add(final_block.transactions.len() as u64);
            }
            status.height = block_height;
            status.latest_timestamp = final_block.header.timestamp;
        }
        let _ = ctx.tip_sender.send(ChainTipInfo {
            height: block_height,
            timestamp: final_block.header.timestamp,
            timestamp_ms: final_block.header.timestamp_ms_or_legacy(),
            gas_used: final_block.header.gas_used,
            state_root: final_block.header.state_root.0.clone(),
            genesis_root: ctx.genesis_hash.to_vec(),
            validator_set: final_block.header.validator_set.clone(),
        });
    }

    let data = codec::to_bytes_canonical(&final_block).map_err(|e| anyhow!(e))?;
    dispatch_swarm_command(swarm_commander, SwarmCommand::PublishBlock(data));

    if matches!(aft_mode, AftSafetyMode::Asymptote) {
        let sealing_context = Arc::clone(context_arc);
        let sealing_signer = Arc::clone(&signer);
        let sealing_swarm = swarm_commander.clone();
        let sealing_block = final_block.clone();
        tokio::spawn(async move {
            if let Err(error) = seal_and_publish_block(
                &sealing_context,
                sealing_block,
                sealing_signer,
                &sealing_swarm,
            )
            .await
            {
                tracing::warn!(
                    target: "consensus",
                    event = "asymptote_sealing_failed",
                    error = %error
                );
            }
        });
    }

    if let Err(e) = crate::standard::orchestration::gossip::prune_mempool(tx_pool, &final_block) {
        tracing::error!(target: "consensus", event = "mempool_prune_fail", error=%e);
    }

    {
        let mut engine = consensus_engine_ref.lock().await;
        engine.observe_committed_block(&final_block.header);
        engine.reset(block_height);
    }

    let mut ns = node_state_arc.lock().await;
    if *ns == NodeState::Syncing {
        *ns = NodeState::Synced;
    }

    if !final_block.transactions.is_empty() {
        tracing::info!(
            target: "consensus",
            "🧱 BLOCK #{} COMMITTED | Tx Count: {} | State Root: 0x{}",
            final_block.header.height,
            final_block.transactions.len(),
            hex::encode(&final_block.header.state_root.0[..4])
        );
    } else {
        tracing::debug!(target: "consensus", "Committed empty block #{}", final_block.header.height);
    }

    // [FIX] Self-Vote Logic for the Leader/Producer
    // The producer must vote for their own block to ensure Quorum is reached.
    if final_block.header.height > 0 {
        let (local_keypair, swarm_sender) = {
            let ctx = context_arc.lock().await;
            (ctx.local_keypair.clone(), ctx.swarm_commander.clone())
        };

        let vote_height = final_block.header.height;
        let vote_view = final_block.header.view;
        let vote_hash_vec = final_block.header.hash().unwrap_or(vec![0u8; 32]);
        let vote_hash = to_root_hash(&vote_hash_vec).unwrap_or([0u8; 32]);

        let our_pk = local_keypair.public().encode_protobuf();
        if let Ok(our_id_hash) = account_id_from_key_material(SignatureSuite::ED25519, &our_pk) {
            let our_id = AccountId(our_id_hash);

            let vote_payload = (vote_height, vote_view, vote_hash);
            if let Ok(vote_bytes) = codec::to_bytes_canonical(&vote_payload) {
                if let Ok(sig) = local_keypair.sign(&vote_bytes) {
                    let vote = ConsensusVote {
                        height: vote_height,
                        view: vote_view,
                        block_hash: vote_hash,
                        voter: our_id,
                        signature: sig,
                    };

                    if let Ok(vote_blob) = codec::to_bytes_canonical(&vote) {
                        // 1. Broadcast to network
                        dispatch_swarm_command(
                            &swarm_sender,
                            SwarmCommand::BroadcastVote(vote_blob),
                        );

                        // 2. Feed back to local engine (so we track our own contribution to the QC)
                        let mut engine = consensus_engine_ref.lock().await;
                        if let Err(e) = engine.handle_vote(vote).await {
                            tracing::warn!(target: "consensus", "Failed to handle own vote: {}", e);
                        } else {
                            let pending_qcs = engine.take_pending_quorum_certificates();
                            drop(engine);
                            for qc in pending_qcs {
                                if let Ok(qc_blob) = codec::to_bytes_canonical(&qc) {
                                    dispatch_swarm_command(
                                        &swarm_sender,
                                        SwarmCommand::BroadcastQuorumCertificate(qc_blob),
                                    );
                                }
                            }
                        }

                        tracing::info!(target: "consensus", "Self-Voted for block {} (H={} V={})", hex::encode(&vote_hash[..4]), vote_height, vote_view);
                    }
                }
            }
        }

        schedule_committed_block_vote_replays(
            Arc::clone(consensus_engine_ref),
            local_keypair,
            swarm_sender,
            final_block.clone(),
        );
    }

    {
        let relay_context = Arc::clone(context_arc);
        let relay_pool = Arc::clone(tx_pool);
        let relay_block = final_block.clone();
        let relay_deferred_transactions = deferred_transactions;
        tokio::spawn(async move {
            relay_remaining_mempool_to_upcoming_leaders(
                &relay_context,
                &relay_pool,
                &relay_block,
                relay_deferred_transactions,
            )
            .await;
        });
    }

    // A committed block usually implies the next height is immediately actionable.
    // Trigger the next consensus tick instead of waiting for the coarse timer loop.
    {
        let (kick_tx, kick_scheduled) = {
            let ctx = context_arc.lock().await;
            (
                ctx.consensus_kick_tx.clone(),
                ctx.consensus_kick_scheduled.clone(),
            )
        };
        let _ = kick_tx.send(());
        schedule_post_commit_rekicks(Arc::clone(tx_pool), kick_tx, kick_scheduled);
    }

    {
        let workload_client = {
            let ctx = context_arc.lock().await;
            ctx.view_resolver.workload_client().clone()
        };
        let header_update_block = final_block.clone();
        tokio::spawn(async move {
            let update_header_started = Instant::now();
            if let Err(error) = workload_client
                .update_block_header(header_update_block.clone())
                .await
            {
                tracing::warn!(
                    target: "consensus",
                    height = header_update_block.header.height,
                    tx_count = header_update_block.transactions.len(),
                    error = %error,
                    "Failed to persist finalized block header update"
                );
                return;
            }

            let update_header_elapsed = update_header_started.elapsed();
            if update_header_elapsed.as_millis() >= 250 {
                tracing::warn!(
                    target: "consensus",
                    height = header_update_block.header.height,
                    tx_count = header_update_block.transactions.len(),
                    elapsed_ms = update_header_elapsed.as_millis(),
                    "update_block_header() is slow"
                );
            }
        });
    }

    Ok(())
}

async fn relay_remaining_mempool_to_upcoming_leaders<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    tx_pool: &Arc<Mempool>,
    committed_block: &Block<ChainTransaction>,
    deferred_transactions: Vec<ChainTransaction>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let relay_limit = post_commit_relay_limit();
    if relay_limit == 0 {
        return;
    }
    let mut pending = if deferred_transactions.is_empty() {
        tx_pool.select_transactions(relay_limit)
    } else {
        deferred_transactions
    };
    if pending.len() > relay_limit {
        pending.truncate(relay_limit);
    }
    if pending.is_empty() {
        return;
    }

    let (local_account_id, leader_peer_targets, leader_peers, swarm_commander) = {
        let ctx = context_arc.lock().await;
        let local_account_id = AccountId(
            account_id_from_key_material(
                SignatureSuite::ED25519,
                &ctx.local_keypair.public().encode_protobuf(),
            )
            .unwrap_or_default(),
        );
        let leader_accounts = leader_accounts_for_upcoming_heights(
            committed_block.header.height,
            &committed_block.header.validator_set,
            post_commit_leader_fanout(),
        );
        let leader_peer_targets = leader_accounts
            .iter()
            .filter(|account_id| **account_id != local_account_id)
            .count();
        let leader_peers = {
            let peers = ctx.peer_accounts_ref.lock().await;
            leader_accounts
                .into_iter()
                .filter(|account_id| *account_id != local_account_id)
                .filter_map(|leader_account_id| {
                    peers.iter().find_map(|(peer_id, account_id)| {
                        (*account_id == leader_account_id).then_some(*peer_id)
                    })
                })
                .collect::<Vec<_>>()
        };
        (
            local_account_id,
            leader_peer_targets,
            leader_peers,
            ctx.swarm_commander.clone(),
        )
    };
    tracing::debug!(
        target: "consensus",
        height = committed_block.header.height,
        local = %hex::encode(&local_account_id.0[..4]),
        remaining = pending.len(),
        next_leaders = leader_peers.len(),
        "Relaying remaining mempool transactions to upcoming leaders after local commit."
    );

    let direct_relay_limit = post_commit_direct_relay_limit();
    for (idx, tx) in pending.into_iter().enumerate() {
        if let Ok(data) = codec::to_bytes_canonical(&tx) {
            dispatch_swarm_command(
                &swarm_commander,
                SwarmCommand::PublishTransaction(data.clone()),
            );
            if idx < direct_relay_limit {
                for peer in &leader_peers {
                    dispatch_swarm_command(
                        &swarm_commander,
                        SwarmCommand::RelayTransactionToPeer {
                            peer: *peer,
                            data: data.clone(),
                        },
                    );
                }
            }
        }
    }
}

async fn issue_consensus_bundle<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    signer: &dyn GuardianSigner,
    final_block: &Block<ChainTransaction>,
    preimage_hash: [u8; 32],
) -> Result<SignatureBundle>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let (mode, view_resolver, last_committed_block) = {
        let ctx = context_arc.lock().await;
        (
            ctx.config.aft_safety_mode,
            ctx.view_resolver.clone(),
            ctx.last_committed_block.clone(),
        )
    };

    if !matches!(
        mode,
        AftSafetyMode::ExperimentalNestedGuardian | AftSafetyMode::Asymptote
    ) {
        return signer
            .sign_consensus_payload(
                preimage_hash,
                final_block.header.height,
                final_block.header.view,
                None,
            )
            .await;
    }

    if matches!(mode, AftSafetyMode::Asymptote) {
        return signer
            .sign_consensus_payload(
                preimage_hash,
                final_block.header.height,
                final_block.header.view,
                None,
            )
            .await;
    }

    let parent_ref =
        resolve_parent_state_ref(&last_committed_block, view_resolver.as_ref()).await?;
    let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
    let current_epoch = match parent_view.get(CURRENT_EPOCH_KEY).await? {
        Some(bytes) => codec::from_bytes_canonical::<u64>(&bytes)
            .map_err(|e| anyhow!("failed to decode current epoch: {e}"))?,
        None => 1,
    };
    let witness_set: GuardianWitnessSet = codec::from_bytes_canonical(
        &parent_view
            .get(&guardian_registry_witness_set_key(current_epoch))
            .await?
            .ok_or_else(|| anyhow!("active witness set missing for epoch {}", current_epoch))?,
    )
    .map_err(|e| anyhow!("failed to decode witness set: {e}"))?;
    let witness_seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(
        &parent_view
            .get(&guardian_registry_witness_seed_key(current_epoch))
            .await?
            .ok_or_else(|| anyhow!("witness seed missing for epoch {}", current_epoch))?,
    )
    .map_err(|e| anyhow!("failed to decode witness seed: {e}"))?;

    let mut last_error: Option<anyhow::Error> = None;
    for reassignment_depth in 0..=witness_seed.max_reassignment_depth {
        let assignment = derive_guardian_witness_assignment(
            &witness_seed,
            &witness_set,
            final_block.header.producer_account_id,
            final_block.header.height,
            final_block.header.view,
            reassignment_depth,
        )
        .map_err(|e| anyhow!(e))?;
        match signer
            .sign_consensus_payload(
                preimage_hash,
                final_block.header.height,
                final_block.header.view,
                Some((assignment.manifest_hash, reassignment_depth)),
            )
            .await
        {
            Ok(bundle) => {
                if reassignment_depth > 0 {
                    tracing::warn!(
                        target: "consensus",
                        event = "witness_reassigned",
                        height = final_block.header.height,
                        view = final_block.header.view,
                        reassignment_depth,
                        epoch = current_epoch,
                        "Witness stratum assignment succeeded after reassignment"
                    );
                }
                return Ok(bundle);
            }
            Err(error) => {
                let evidence = build_witness_omission_evidence(
                    &assignment,
                    final_block.header.producer_account_id,
                    &error.to_string(),
                )?;
                if let Err(report_error) = signer.report_witness_fault(&evidence).await {
                    tracing::warn!(
                        target: "consensus",
                        event = "witness_fault_report_failed",
                        error = %report_error
                    );
                }
                tracing::warn!(
                    target: "consensus",
                    event = "witness_assignment_failed",
                    height = final_block.header.height,
                    view = final_block.header.view,
                    reassignment_depth,
                    manifest_hash = %hex::encode(assignment.manifest_hash),
                    error = %error
                );
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("witness stratum assignment failed")))
}

async fn seal_and_publish_block<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    mut sealed_block: Block<ChainTransaction>,
    signer: Arc<dyn GuardianSigner>,
    swarm_commander: &mpsc::Sender<SwarmCommand>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let view_resolver = { context_arc.lock().await.view_resolver.clone() };
    let parent_ref = StateRef {
        height: sealed_block.header.height.saturating_sub(1),
        state_root: sealed_block.header.parent_state_root.as_ref().to_vec(),
        block_hash: sealed_block.header.parent_hash,
    };
    let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
    let current_epoch = match parent_view.get(CURRENT_EPOCH_KEY).await? {
        Some(bytes) => codec::from_bytes_canonical::<u64>(&bytes)
            .map_err(|e| anyhow!("failed to decode current epoch: {e}"))?,
        None => 1,
    };
    let policy: AsymptotePolicy = codec::from_bytes_canonical(
        &parent_view
            .get(&guardian_registry_asymptote_policy_key(current_epoch))
            .await?
            .ok_or_else(|| anyhow!("asymptote policy missing for epoch {}", current_epoch))?,
    )
    .map_err(|e| anyhow!("failed to decode asymptote policy: {e}"))?;
    let witness_seed: GuardianWitnessEpochSeed = codec::from_bytes_canonical(
        &parent_view
            .get(&guardian_registry_witness_seed_key(current_epoch))
            .await?
            .ok_or_else(|| anyhow!("witness seed missing for epoch {}", current_epoch))?,
    )
    .map_err(|e| anyhow!("failed to decode witness seed: {e}"))?;
    let observer_mode = policy.observer_rounds > 0 && policy.observer_committee_size > 0;
    let observer_plan = if observer_mode {
        let validator_set_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await?
            .ok_or_else(|| anyhow!("active validator set missing for asymptote observer mode"))?;
        let validator_sets = read_validator_sets(&validator_set_bytes)
            .map_err(|e| anyhow!("failed to decode validator set: {e}"))?;
        let active_set = effective_set_for_height(&validator_sets, sealed_block.header.height);
        let mut observer_manifests = BTreeMap::new();
        for validator in &active_set.validators {
            if validator.account_id == sealed_block.header.producer_account_id {
                continue;
            }
            let manifest_hash_bytes = parent_view
                .get(&guardian_registry_committee_account_key(
                    &validator.account_id,
                ))
                .await?
                .ok_or_else(|| {
                    anyhow!(
                        "observer guardian manifest index missing for {}",
                        hex::encode(validator.account_id)
                    )
                })?;
            let manifest_hash: [u8; 32] = manifest_hash_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("observer manifest hash must be 32 bytes"))?;
            let manifest: GuardianCommitteeManifest = codec::from_bytes_canonical(
                &parent_view
                    .get(&guardian_registry_committee_key(&manifest_hash))
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "observer guardian manifest missing for hash {}",
                            hex::encode(manifest_hash)
                        )
                    })?,
            )
            .map_err(|e| anyhow!("failed to decode observer guardian manifest: {e}"))?;
            observer_manifests.insert(validator.account_id, manifest);
        }
        derive_asymptote_observer_plan_entries(
            &witness_seed,
            active_set,
            &observer_manifests,
            sealed_block.header.producer_account_id,
            sealed_block.header.height,
            sealed_block.header.view,
            policy.observer_rounds,
            policy.observer_committee_size,
            &policy.observer_correlation_budget,
        )
        .map_err(|e| anyhow!(e))?
    } else {
        Vec::new()
    };
    let witness_manifest_hashes = if observer_plan.is_empty() {
        let witness_set: GuardianWitnessSet = codec::from_bytes_canonical(
            &parent_view
                .get(&guardian_registry_witness_set_key(current_epoch))
                .await?
                .ok_or_else(|| anyhow!("active witness set missing for epoch {}", current_epoch))?,
        )
        .map_err(|e| anyhow!("failed to decode witness set: {e}"))?;
        let mut witness_manifests = Vec::with_capacity(witness_set.manifest_hashes.len());
        for manifest_hash in &witness_set.manifest_hashes {
            let manifest: GuardianWitnessCommitteeManifest = codec::from_bytes_canonical(
                &parent_view
                    .get(&guardian_registry_witness_key(manifest_hash))
                    .await?
                    .ok_or_else(|| {
                        anyhow!(
                            "active witness manifest missing for hash {}",
                            hex::encode(manifest_hash)
                        )
                    })?,
            )
            .map_err(|e| anyhow!("failed to decode witness manifest: {e}"))?;
            witness_manifests.push(manifest);
        }
        derive_guardian_witness_assignments_for_strata(
            &witness_seed,
            &witness_set,
            &witness_manifests,
            sealed_block.header.producer_account_id,
            sealed_block.header.height,
            sealed_block.header.view,
            0,
            &policy.required_witness_strata,
        )
        .map_err(|e| anyhow!(e))?
        .iter()
        .map(|assignment| assignment.manifest_hash)
        .collect()
    } else {
        Vec::new()
    };
    let preimage_hash =
        ioi_crypto::algorithms::hash::sha256(&sealed_block.header.to_preimage_for_signing()?)?;
    let sealed_finality_proof = signer
        .seal_consensus_payload(
            preimage_hash,
            sealed_block.header.height,
            sealed_block.header.view,
            witness_manifest_hashes,
            observer_plan,
        )
        .await?;

    sealed_block.header.sealed_finality_proof = Some(sealed_finality_proof);
    view_resolver
        .workload_client()
        .update_block_header(sealed_block.clone())
        .await?;
    let data = codec::to_bytes_canonical(&sealed_block).map_err(|e| anyhow!(e))?;
    let _ = swarm_commander.send(SwarmCommand::PublishBlock(data)).await;
    let rebroadcast_block = sealed_block.clone();
    let rebroadcast_sender = swarm_commander.clone();
    tokio::spawn(async move {
        for delay in [
            Duration::from_millis(300),
            Duration::from_millis(1200),
            Duration::from_secs(3),
            Duration::from_secs(6),
        ] {
            tokio::time::sleep(delay).await;
            let Ok(bytes) = codec::to_bytes_canonical(&rebroadcast_block) else {
                return;
            };
            let _ = rebroadcast_sender
                .send(SwarmCommand::PublishBlock(bytes))
                .await;
        }
    });
    tracing::info!(
        target: "consensus",
        event = "asymptote_sealed_block_published",
        height = sealed_block.header.height,
        view = sealed_block.header.view
    );
    Ok(())
}

fn build_witness_omission_evidence(
    assignment: &ioi_types::app::GuardianWitnessAssignment,
    producer_account_id: AccountId,
    details: &str,
) -> Result<GuardianWitnessFaultEvidence> {
    let evidence_body = codec::to_bytes_canonical(&(
        assignment.epoch,
        producer_account_id,
        assignment.height,
        assignment.view,
        assignment.manifest_hash,
        details,
    ))
    .map_err(|e| anyhow!(e.to_string()))?;
    let evidence_id = ioi_crypto::algorithms::hash::sha256(&evidence_body)?;
    Ok(GuardianWitnessFaultEvidence {
        evidence_id,
        kind: GuardianWitnessFaultKind::Omission,
        epoch: assignment.epoch,
        producer_account_id,
        height: assignment.height,
        view: assignment.view,
        expected_manifest_hash: assignment.manifest_hash,
        observed_manifest_hash: [0u8; 32],
        checkpoint_root: [0u8; 32],
        witness_certificate: None,
        details: details.to_string(),
    })
}

async fn resolve_parent_state_ref<V>(
    last_committed_block: &Option<Block<ChainTransaction>>,
    view_resolver: &dyn ioi_api::chain::ViewResolver<Verifier = V>,
) -> Result<StateRef>
where
    V: Verifier,
{
    if let Some(last) = last_committed_block.as_ref() {
        return Ok(StateRef {
            height: last.header.height,
            state_root: last.header.state_root.as_ref().to_vec(),
            block_hash: to_root_hash(last.header.hash()?)?,
        });
    }

    let genesis_root = view_resolver.genesis_root().await?;
    Ok(StateRef {
        height: 0,
        state_root: genesis_root.clone(),
        block_hash: to_root_hash(&genesis_root)?,
    })
}
