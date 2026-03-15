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
        account_id_from_key_material, derive_guardian_witness_assignment,
        guardian_registry_witness_seed_key, guardian_registry_witness_set_key, to_root_hash,
        AccountId, Block, ChainTransaction, ConsensusVote, GuardianWitnessEpochSeed,
        GuardianWitnessFaultEvidence, GuardianWitnessFaultKind, GuardianWitnessSet,
        SignatureBundle, SignatureSuite,
    },
    codec,
    config::ConvergentSafetyMode,
    keys::CURRENT_EPOCH_KEY,
};
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::common::GuardianSigner;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::ingestion::ChainTipInfo;
use crate::standard::orchestration::mempool::Mempool;

pub async fn finalize_and_broadcast_block<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    mut final_block: Block<ChainTransaction>,
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
    let bundle =
        issue_consensus_bundle(context_arc, signer.as_ref(), &final_block, preimage_hash).await?;
    final_block.header.signature = bundle.signature;
    final_block.header.oracle_counter = bundle.counter;
    final_block.header.oracle_trace_hash = bundle.trace_hash;
    final_block.header.guardian_certificate = bundle.guardian_certificate;

    {
        let view_resolver = context_arc.lock().await.view_resolver.clone();
        view_resolver
            .workload_client()
            .update_block_header(final_block.clone())
            .await?;
    }

    {
        let ctx = context_arc.lock().await;
        let receipt_guard = ctx.receipt_map.lock().await;
        let mut status_guard = ctx.tx_status_cache.lock().await;

        for tx in &final_block.transactions {
            let tx_hash_res: Result<ioi_types::app::TxHash, _> = tx.hash();
            if let Ok(h) = tx_hash_res {
                if let Some(receipt_hex) = receipt_guard.peek(&h) {
                    if let Some(entry) = status_guard.get_mut(receipt_hex) {
                        entry.status = TxStatus::Committed;
                        entry.block_height = Some(block_height);
                    }
                }
            }
        }
    }

    {
        let mut ctx = context_arc.lock().await;
        ctx.last_committed_block = Some(final_block.clone());
        let _ = ctx.tip_sender.send(ChainTipInfo {
            height: block_height,
            timestamp: final_block.header.timestamp,
            gas_used: final_block.header.gas_used,
            state_root: final_block.header.state_root.0.clone(),
            genesis_root: ctx.genesis_hash.to_vec(),
        });
    }

    let data = codec::to_bytes_canonical(&final_block).map_err(|e| anyhow!(e))?;
    let _ = swarm_commander.send(SwarmCommand::PublishBlock(data)).await;

    if let Err(e) = crate::standard::orchestration::gossip::prune_mempool(tx_pool, &final_block) {
        tracing::error!(target: "consensus", event = "mempool_prune_fail", error=%e);
    }

    consensus_engine_ref.lock().await.reset(block_height);

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
                        let _ = swarm_sender
                            .send(SwarmCommand::BroadcastVote(vote_blob))
                            .await;

                        // 2. Feed back to local engine (so we track our own contribution to the QC)
                        let mut engine = consensus_engine_ref.lock().await;
                        if let Err(e) = engine.handle_vote(vote).await {
                            tracing::warn!(target: "consensus", "Failed to handle own vote: {}", e);
                        }

                        tracing::info!(target: "consensus", "Self-Voted for block {} (H={} V={})", hex::encode(&vote_hash[..4]), vote_height, vote_view);
                    }
                }
            }
        }
    }

    Ok(())
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
            ctx.config.convergent_safety_mode,
            ctx.view_resolver.clone(),
            ctx.last_committed_block.clone(),
        )
    };

    if !matches!(mode, ConvergentSafetyMode::ExperimentalNestedGuardian) {
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
                        "Experimental witness assignment succeeded after reassignment"
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

    Err(last_error.unwrap_or_else(|| anyhow!("experimental witness assignment failed")))
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
