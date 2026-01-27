// Path: crates/validator/src/standard/orchestration/finalize.rs

use anyhow::{anyhow, Result};
use ioi_api::{
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
        account_id_from_key_material, to_root_hash, AccountId, Block, ChainTransaction,
        ConsensusVote, SignatureSuite,
    },
    codec,
};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use parity_scale_codec::{Decode, Encode};

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
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug + Encode + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let block_height = final_block.header.height;
    let preimage = final_block.header.to_preimage_for_signing()?;
    let preimage_hash = ioi_crypto::algorithms::hash::sha256(&preimage)?;

    let bundle = signer.sign_consensus_payload(preimage_hash).await?;
    final_block.header.signature = bundle.signature;
    final_block.header.oracle_counter = bundle.counter;
    final_block.header.oracle_trace_hash = bundle.trace_hash;

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