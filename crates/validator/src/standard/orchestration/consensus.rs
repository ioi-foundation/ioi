// Path: crates/validator/src/standard/orchestration/consensus.rs
use super::context::MainLoopContext;
use super::gossip::prune_mempool;
use super::oracle::handle_newly_processed_block;
use crate::standard::orchestration::remote_state_view::RemoteStateView;
use depin_sdk_api::{
    chain::ChainView,
    commitment::CommitmentScheme,
    consensus::{ConsensusDecision, ConsensusEngine},
    state::{StateCommitment, StateManager},
};
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_network::traits::NodeState;
use depin_sdk_types::app::{
    account_id_from_key_material, AccountId, Block, BlockHeader, ChainTransaction, SignatureSuite,
    StateRoot,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

/// Handles the consensus timer tick, deciding whether to produce a block.
pub async fn handle_consensus_tick<CS, ST, CE>(context: &mut MainLoopContext<CS, ST, CE>)
where
    CS: CommitmentScheme + Clone + Default + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + ChainView<CS, ST> + Send + Sync + 'static,
{
    let node_state = context.node_state.lock().await.clone();
    let cons_ty = {
        let engine = context.consensus_engine_ref.lock().await;
        (*engine).consensus_type()
    };
    log::info!("[Consensus] Engine = {:?}", cons_ty);

    // Allow the chain to "boot" at H=1 even if there are no user txs.
    let allow_bootstrap = matches!(
        cons_ty,
        depin_sdk_types::config::ConsensusType::ProofOfAuthority
            | depin_sdk_types::config::ConsensusType::ProofOfStake
    );

    if node_state != NodeState::Synced && !allow_bootstrap {
        return;
    }

    let our_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::Ed25519,
            &context.local_keypair.public().encode_protobuf(),
        )
        .unwrap(),
    );

    let decision = {
        let status = match context.workload_client.get_status().await {
            Ok(s) => s,
            Err(e) => {
                log::error!("[Orch] Could not get chain status for consensus: {}", e);
                return;
            }
        };

        // For height H+1, the parent view must be the *committed* state at the end of H.
        let parent_root = context
            .last_committed_block
            .as_ref()
            .map(|b| b.header.state_root.clone())
            .unwrap_or_else(|| context.genesis_root.clone());

        log::debug!(
            "[Consensus] Parent view root for deciding H={}: 0x{}",
            status.height + 1,
            hex::encode(parent_root.as_ref())
        );

        let consensus_type = context.consensus_engine_ref.lock().await.consensus_type();
        let parent_anchor = parent_root.to_anchor();
        let parent_view = RemoteStateView::new(
            parent_anchor,
            context.workload_client.clone(),
            consensus_type,
        );

        let target_height = status.height + 1;
        let current_view = 0;

        let mut engine = context.consensus_engine_ref.lock().await;
        let known_peers = context.known_peers_ref.lock().await;

        engine
            .decide(
                &our_account_id,
                target_height,
                current_view,
                &parent_view,
                &known_peers,
            )
            .await
    };

    if let ConsensusDecision::ProduceBlock(_) = decision {
        let status = context.workload_client.get_status().await.unwrap();
        let target_height = status.height + 1;

        let (candidate_txs, _mempool_len_before) = {
            let pool = context.tx_pool_ref.lock().await;
            (pool.iter().cloned().collect::<Vec<_>>(), pool.len())
        };

        if candidate_txs.is_empty() && !allow_bootstrap {
            log::info!("[Consensus] No transactions in mempool; skipping empty block production.");
            return;
        }

        let latest_anchor = context
            .last_committed_block
            .as_ref()
            .map(|b| b.header.state_root.to_anchor())
            .unwrap_or_else(|| context.genesis_root.to_anchor());

        let check_results = match context
            .workload_client
            .check_transactions_at(latest_anchor, candidate_txs.clone())
            .await
        {
            Ok(results) => results,
            Err(e) if e.to_string().contains("StaleAnchor") => {
                log::info!(
                    "[Consensus] State changed during block proposal; will retry on next tick."
                );
                return;
            }
            Err(e) => {
                log::error!(
                    "[Consensus] Failed to check transactions with workload: {}",
                    e
                );
                return;
            }
        };

        let mut valid_txs = Vec::new();
        let mut invalid_tx_hashes = HashSet::new();

        for (i, result) in check_results.into_iter().enumerate() {
            if let Err(e) = result {
                log::warn!("[Consensus] Discarding invalid tx from mempool: {}", e);
                let tx_hash = serde_jcs::to_vec(&candidate_txs[i]).unwrap();
                invalid_tx_hashes.insert(tx_hash);
            } else {
                valid_txs.push(candidate_txs[i].clone());
            }
        }

        if !invalid_tx_hashes.is_empty() {
            let mut pool = context.tx_pool_ref.lock().await;
            pool.retain(|tx| {
                let tx_hash = serde_jcs::to_vec(tx).unwrap();
                !invalid_tx_hashes.contains(&tx_hash)
            });
            log::info!(
                "[Consensus] Pruned {} invalid tx(s) from mempool.",
                invalid_tx_hashes.len()
            );
        }

        log::info!(
            "[Consensus] Producing block #{} with {} valid tx(s) (coinbase will be added by workload).",
            target_height,
            valid_txs.len()
        );

        let header_validator_set = match context.workload_client.get_validator_set().await {
            Ok(data) => data,
            Err(e) => {
                log::error!("[Orch] Could not get validator set for block header: {e}");
                return;
            }
        };

        let parent_hash: [u8; 32] = context
            .workload_client
            .get_last_block_hash()
            .await
            .unwrap_or(vec![0; 32])
            .try_into()
            .unwrap();
        let producer_pubkey = context.local_keypair.public().encode_protobuf();
        let producer_key_suite = SignatureSuite::Ed25519;
        let producer_pubkey_hash =
            account_id_from_key_material(producer_key_suite, &producer_pubkey).unwrap();

        let new_block_template = Block {
            header: BlockHeader {
                height: target_height,
                parent_hash,
                parent_state_root: StateRoot(vec![]),
                state_root: StateRoot(vec![]),
                transactions_root: vec![0; 32],
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                validator_set: header_validator_set,
                producer_account_id: our_account_id,
                producer_key_suite,
                producer_pubkey_hash,
                producer_pubkey,
                signature: vec![],
            },
            transactions: valid_txs,
        };

        match context
            .workload_client
            .process_block(new_block_template)
            .await
        {
            Ok((mut final_block, _)) => {
                let block_height = final_block.header.height;
                log::info!("Produced and processed new block #{}", block_height);
                let preimage = final_block.header.to_preimage_for_signing();
                final_block.header.signature = context.local_keypair.sign(&preimage).unwrap();

                context.last_committed_block = Some(final_block.clone());
                log::debug!(
                    "[Consensus] Advanced tip to #{} root=0x{}",
                    final_block.header.height,
                    hex::encode(final_block.header.state_root.as_ref())
                );

                let data = serde_json::to_vec(&final_block).unwrap();
                context
                    .swarm_commander
                    .send(SwarmCommand::PublishBlock(data))
                    .await
                    .ok();

                {
                    let mut pool = context.tx_pool_ref.lock().await;
                    prune_mempool(&mut pool, &final_block);
                }

                handle_newly_processed_block(context, block_height, &context.external_data_service)
                    .await;
                context
                    .consensus_engine_ref
                    .lock()
                    .await
                    .reset(block_height);
                if let Ok(outcomes) = context
                    .workload_client
                    .check_and_tally_proposals(block_height)
                    .await
                {
                    for outcome in outcomes {
                        log::info!("{}", outcome);
                    }
                }
            }
            Err(e) => {
                log::error!("Workload failed to process a pre-validated block proposal: {}. This should not happen.", e);
            }
        }
    }
}
