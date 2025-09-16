// Path: crates/validator/src/standard/orchestration/consensus.rs
use super::context::MainLoopContext;
use super::gossip::prune_mempool;
use super::oracle::handle_newly_processed_block;
use super::remote_state_view::RemoteStateView;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_network::traits::NodeState;
use depin_sdk_types::app::{
    account_id_from_key_material, AccountId, Block, BlockHeader, ChainTransaction, SignatureSuite,
    StateAnchor, StateRoot,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

/// Handles the consensus timer tick, deciding whether to produce a block.
pub async fn handle_consensus_tick<CS, ST, CE, V>(context: &mut MainLoopContext<CS, ST, CE, V>)
where
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
    let node_state = context.node_state.lock().await.clone();
    let cons_ty = context.config.consensus_type;

    let our_account_id_short =
        hex::encode(&context.local_keypair.public().to_peer_id().to_bytes()[..4]);
    log::info!(
        "[Orch Tick] state={:?}, parent_h={}, producing_h={}",
        node_state,
        context
            .last_committed_block
            .as_ref()
            .map(|b| b.header.height)
            .unwrap_or(0),
        context
            .last_committed_block
            .as_ref()
            .map(|b| b.header.height + 1)
            .unwrap_or(1),
    );

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

    let height_being_built = match context.last_committed_block.as_ref() {
        Some(b) => b.header.height + 1,
        None => 1,
    };

    let decision = {
        let status = match context.workload_client.get_status().await {
            Ok(s) => s,
            Err(e) => {
                log::error!("[Orch Tick][Node {}] Could not get chain status for consensus: {}. Aborting tick.", our_account_id_short, e);
                return;
            }
        };

        let parent_root: StateRoot = if let Some(last) = context.last_committed_block.as_ref() {
            last.header.state_root.clone()
        } else {
            match context.workload_client.get_state_root().await {
                Ok(r) => r,
                Err(e) => {
                    log::warn!(
                        "[Orch Tick][Node {}] Failed to fetch workload root, using context.genesis_root: {}",
                        our_account_id_short,
                        e
                    );
                    context.genesis_root.clone()
                }
            }
        };

        log::debug!(
            "[Orch Tick][Node {}] Parent view root for deciding H={}: 0x{}",
            our_account_id_short,
            status.height + 1,
            hex::encode(parent_root.as_ref())
        );

        let parent_anchor: StateAnchor = parent_root.to_anchor();

        let target_height = status.height + 1;
        let current_view = 0;

        let parent_view = RemoteStateView::new(
            parent_anchor,
            parent_root.clone(),
            context.workload_client.clone(),
            context.verifier.clone(),
            cons_ty,
            context.proof_cache_ref.clone(),
        );
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

    log::debug!(
        "[Orch Tick][Node {}] Consensus decision for H={}: {:?}",
        our_account_id_short,
        height_being_built,
        decision
    );

    if let depin_sdk_api::consensus::ConsensusDecision::ProduceBlock(_) = decision {
        let status = match context.workload_client.get_status().await {
            Ok(s) => s,
            Err(e) => {
                log::error!(
                    "[Orch Tick][Node {}] get_status() failed: {}. Will retry next tick.",
                    our_account_id_short,
                    e
                );
                return;
            }
        };
        let target_height = status.height + 1;

        let (candidate_txs, _mempool_len_before) = {
            let pool = context.tx_pool_ref.lock().await;
            (pool.iter().cloned().collect::<Vec<_>>(), pool.len())
        };

        if candidate_txs.is_empty() && !allow_bootstrap {
            log::info!(
                "[Orch Tick][Node {}] No transactions in mempool; skipping empty block production.",
                our_account_id_short
            );
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
                    "[Orch Tick][Node {}] StaleAnchor; refreshing root and retrying once.",
                    our_account_id_short
                );
                // Pull the freshest root from workload and retry once.
                let fresh_root = match context.workload_client.get_state_root().await {
                    Ok(r) => r,
                    Err(e2) => {
                        log::error!(
                            "[Orch Tick][Node {}] get_state_root() failed after StaleAnchor: {}",
                            our_account_id_short,
                            e2
                        );
                        return;
                    }
                };
                let fresh_anchor = fresh_root.to_anchor();
                match context
                    .workload_client
                    .check_transactions_at(fresh_anchor, candidate_txs.clone())
                    .await
                {
                    Ok(results2) => results2,
                    Err(e2) => {
                        log::error!(
                            "[Orch Tick][Node {}] Retry precheck failed: {}",
                            our_account_id_short,
                            e2
                        );
                        return;
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "[Orch Tick][Node {}] check_transactions_at failed: {}",
                    our_account_id_short,
                    e
                );
                return;
            }
        };

        log::info!(
            "[Orch Tick] precheck returned {} results for {} candidate tx(s)",
            check_results.len(),
            candidate_txs.len()
        );
        if check_results.len() != candidate_txs.len() {
            log::error!("[Orch Tick] BUG: check_transactions_at result length mismatch; refusing to produce this tick.");
            return;
        }

        let mut valid_txs = Vec::new();
        let mut invalid_tx_hashes = HashSet::new();

        for (i, result) in check_results.into_iter().enumerate() {
            if let Err(e) = result {
                log::warn!("[Orch Tick] Filtering tx {} as invalid: {}", i, e);
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
                "[Orch Tick][Node {}] Pruned {} invalid tx(s) from mempool.",
                our_account_id_short,
                invalid_tx_hashes.len()
            );
        }

        log::info!(
            "[Orch Tick][Node {}] Producing block #{} with {} valid tx(s) (coinbase will be added by workload).",
            our_account_id_short,
            target_height,
            valid_txs.len()
        );

        let header_validator_set = match context
            .workload_client
            .get_validator_set_for(height_being_built)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "[Orch Tick][Node {}] get_validator_set_for(H={}) failed ({}). Continuing with empty header.validator_set; verification uses on-chain state.",
                    our_account_id_short,
                    height_being_built, e
                );
                Vec::new()
            }
        };

        let parent_hash_vec = match context.workload_client.get_last_block_hash().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "[Orch Tick][Node {}] get_last_block_hash() failed: {}. Using zeros.",
                    our_account_id_short,
                    e
                );
                vec![0; 32]
            }
        };
        let mut parent_hash = [0u8; 32];
        if parent_hash_vec.len() == 32 {
            parent_hash.copy_from_slice(&parent_hash_vec);
        } else {
            log::warn!(
                "[Orch Tick][Node {}] last_block_hash length {} != 32. Using zeros.",
                our_account_id_short,
                parent_hash_vec.len()
            );
        }
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
                log::info!(
                    "[Orch Tick][Node {}] Produced and processed new block #{}",
                    our_account_id_short,
                    block_height
                );
                let preimage = final_block.header.to_preimage_for_signing();
                final_block.header.signature = context.local_keypair.sign(&preimage).unwrap();

                context.last_committed_block = Some(final_block.clone());
                log::debug!(
                    "[Orch Tick][Node {}] Advanced tip to #{} root=0x{}",
                    our_account_id_short,
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

                {
                    let mut ns = context.node_state.lock().await;
                    if *ns == depin_sdk_network::traits::NodeState::Syncing {
                        *ns = depin_sdk_network::traits::NodeState::Synced;
                        log::info!("[Orchestrator] State -> Synced.");
                    }
                }

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
                log::error!("[Orch Tick][Node {}] Workload failed to process a pre-validated block proposal: {}. This should not happen.", our_account_id_short, e);
            }
        }
    } else {
        log::debug!(
            "[Orch Tick][Node {}] Engine decision was not ProduceBlock; will retry next tick.",
            our_account_id_short
        );
    }
}
