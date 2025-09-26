// Path: crates/validator/src/standard/orchestration/consensus.rs
use super::context::MainLoopContext;
use super::gossip::prune_mempool;
use super::oracle::handle_newly_processed_block;
use super::remote_state_view::RemoteStateView;
use crate::metrics::consensus_metrics as metrics;
use anyhow::{anyhow, Result};
use depin_sdk_api::{
    chain::StateView,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, Verifier},
};
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_network::traits::NodeState;
use depin_sdk_types::{
    app::{
        account_id_from_key_material, read_validator_sets, AccountId, Block, BlockHeader,
        ChainTransaction, SignatureSuite, StateAnchor, StateRoot,
    },
    error::ChainError,
    keys::VALIDATOR_SET_KEY,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Drive one consensus tick without holding the MainLoopContext lock across awaits.
/// This avoids starving the ticker when other tasks briefly lock the context.
pub async fn drive_consensus_tick<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    cause: &str,
) -> Result<()>
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
    let _tick_timer = depin_sdk_telemetry::time::Timer::new(metrics());
    // ---- Snapshot immutable/Arc fields under a *short* lock, then release it. ----
    let (
        cons_ty,
        workload_client,
        consensus_engine_ref,
        known_peers_ref,
        tx_pool_ref,
        swarm_commander,
        verifier,
        proof_cache_ref,
        local_keypair,
        pqc_signer,
        genesis_root,
        last_committed_block_opt,
        node_state_arc,
    ) = {
        let ctx = context_arc.lock().await;
        (
            ctx.config.consensus_type,
            ctx.workload_client.clone(),
            ctx.consensus_engine_ref.clone(),
            ctx.known_peers_ref.clone(),
            ctx.tx_pool_ref.clone(),
            ctx.swarm_commander.clone(),
            ctx.verifier.clone(),
            ctx.proof_cache_ref.clone(),
            ctx.local_keypair.clone(),
            ctx.pqc_signer.clone(),
            ctx.genesis_root.clone(),
            ctx.last_committed_block.clone(),
            ctx.node_state.clone(),
        )
    };
    let node_state = node_state_arc.lock().await.clone();

    let parent_h = last_committed_block_opt
        .as_ref()
        .map(|b| b.header.height)
        .unwrap_or(0);
    let producing_h = parent_h + 1;

    tracing::info!(
        target: "consensus",
        event = "tick",
        %cause,
        ?node_state,
        parent_h,
        producing_h
    );

    let allow_bootstrap = matches!(
        cons_ty,
        depin_sdk_types::config::ConsensusType::ProofOfAuthority
            | depin_sdk_types::config::ConsensusType::ProofOfStake
    );

    if node_state != NodeState::Synced && !allow_bootstrap {
        return Ok(());
    }

    let our_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::Ed25519,
            &local_keypair.public().encode_protobuf(),
        )
        .map_err(|e| anyhow!("[Orch Tick] failed to derive local account id: {e}"))?,
    );

    let height_being_built = match last_committed_block_opt.as_ref() {
        Some(b) => b.header.height + 1,
        None => 1,
    };

    let decision = {
        let status = match workload_client.get_status().await {
            Ok(s) => s,
            Err(e) => {
                let msg = format!(
                    "[Orch Tick] Could not get chain status for consensus: {}. Aborting tick.",
                    e
                );
                tracing::error!(target: "consensus", "{}", msg);
                return Err(anyhow!(msg));
            }
        };

        let parent_root: StateRoot = if let Some(last) = last_committed_block_opt.as_ref() {
            last.header.state_root.clone()
        } else {
            match workload_client.get_state_root().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        target: "consensus",
                        event = "get_root_fail",
                        error = %e,
                        "Failed to fetch workload root, using context.genesis_root",
                    );
                    genesis_root.clone()
                }
            }
        };

        tracing::debug!(
            target: "consensus",
            event="parent_view_info",
            height = status.height + 1,
            root = hex::encode(parent_root.as_ref()),
            "Parent view root for deciding",
        );

        let parent_anchor: StateAnchor = parent_root.to_anchor()?;

        let target_height = status.height + 1;
        let current_view = 0;

        let parent_view = RemoteStateView::new(
            parent_anchor,
            parent_root.clone(),
            workload_client.clone(),
            verifier.clone(),
            cons_ty,
            proof_cache_ref.clone(),
        );
        let mut engine = consensus_engine_ref.lock().await;
        let known_peers = known_peers_ref.lock().await;
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

    tracing::info!(
        target: "consensus",
        event = "decision",
        decision = ?decision,
        height = height_being_built
    );

    if let depin_sdk_api::consensus::ConsensusDecision::ProduceBlock(_) = decision {
        metrics().inc_blocks_produced();
        let status = match workload_client.get_status().await {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("get_status() failed: {}. Will retry next tick.", e);
                tracing::error!(target: "consensus", "{}", msg);
                return Err(anyhow!(msg));
            }
        };
        let target_height = status.height + 1;

        let (candidate_txs, mempool_len_before) = {
            let pool = tx_pool_ref.lock().await;
            (pool.iter().cloned().collect::<Vec<_>>(), pool.len())
        };

        if candidate_txs.is_empty() && !allow_bootstrap {
            tracing::info!(
                target: "consensus",
                event = "skip_empty_block",
                "No transactions in mempool; skipping empty block production."
            );
            return Ok(());
        }

        tracing::info!(
            target: "consensus",
            event = "precheck_start",
            mempool_size = mempool_len_before,
        );

        let latest_anchor = last_committed_block_opt
            .as_ref()
            .map(|b| b.header.state_root.to_anchor())
            .unwrap_or_else(|| genesis_root.to_anchor())?;

        // FIX: The `check_transactions_at` RPC call expects canonical bytes, but the mempool
        // holds the deserialized `ChainTransaction` structs. We must re-serialize them
        // before sending them over the wire. The `WorkloadIpcServer` will then deserialize
        // them back into structs.
        let check_results = match workload_client
            .check_transactions_at(latest_anchor, candidate_txs.clone())
            .await
        {
            Ok(results) => results,
            Err(e) if e.to_string().contains("StaleAnchor") => {
                tracing::info!(
                    target: "consensus",
                    event = "stale_anchor_retry",
                    "StaleAnchor; refreshing root and retrying once."
                );
                let fresh_root = match workload_client.get_state_root().await {
                    Ok(r) => r,
                    Err(e2) => {
                        let msg = format!("get_state_root() failed after StaleAnchor: {}", e2);
                        tracing::error!(target: "consensus", "{}", msg);
                        return Err(anyhow!(msg));
                    }
                };
                let fresh_anchor = fresh_root.to_anchor()?;
                match workload_client
                    .check_transactions_at(fresh_anchor, candidate_txs.clone())
                    .await
                {
                    Ok(results2) => results2,
                    Err(e2) => {
                        let msg = format!("Retry precheck failed: {}", e2);
                        tracing::error!(target: "consensus", "{}", msg);
                        return Err(anyhow!(msg));
                    }
                }
            }
            Err(e) => {
                let msg = format!("check_transactions_at failed: {}", e);
                tracing::error!(target: "consensus", "{}", msg);
                return Err(anyhow!(msg));
            }
        };

        tracing::info!(
            target: "consensus",
            event = "precheck_complete",
            num_results = check_results.len(),
            num_candidates = candidate_txs.len(),
        );
        if check_results.len() != candidate_txs.len() {
            tracing::error!(target: "consensus", "BUG: check_transactions_at result length mismatch; refusing to produce this tick.");
            return Ok(());
        }

        let mut valid_txs = Vec::new();
        let mut invalid_tx_hashes = HashSet::new();

        for (i, result) in check_results.into_iter().enumerate() {
            if let Err(e) = result {
                tracing::warn!(target: "consensus", event = "tx_filtered", tx_index = i, error = %e);
                // Use a canonical hash of the transaction to identify it for removal from the mempool.
                // Using the transaction itself is fine if it implements Hash and Eq correctly,
                // but a byte-based hash is more robust against struct padding/representation issues.
                match serde_jcs::to_vec(&candidate_txs[i]) {
                    Ok(tx_hash) => {
                        invalid_tx_hashes.insert(tx_hash);
                    }
                    Err(e2) => {
                        tracing::error!(target: "consensus", event = "tx_hash_fail", tx_index = i, error = %e2);
                    }
                }
            } else {
                valid_txs.push(candidate_txs[i].clone());
            }
        }

        if !invalid_tx_hashes.is_empty() {
            let mut pool = tx_pool_ref.lock().await;
            pool.retain(|tx| {
                let tx_hash = serde_jcs::to_vec(tx).unwrap();
                !invalid_tx_hashes.contains(&tx_hash)
            });
            tracing::info!(
                target: "consensus",
                event = "mempool_prune",
                num_pruned = invalid_tx_hashes.len(),
            );
        }

        tracing::info!(
            target: "consensus",
            event = "producing_block",
            height = target_height,
            num_txs = valid_txs.len(),
            "Producing block (coinbase will be added by workload)."
        );

        let parent_root_for_keys = last_committed_block_opt
            .as_ref()
            .map(|b| b.header.state_root.clone())
            .unwrap_or_else(|| genesis_root.clone());
        let parent_anchor_for_keys = parent_root_for_keys.to_anchor()?;
        let parent_view_for_keys = RemoteStateView::new(
            parent_anchor_for_keys,
            parent_root_for_keys.clone(),
            workload_client.clone(),
            verifier.clone(),
            cons_ty,
            proof_cache_ref.clone(),
        );

        let vs_bytes = match parent_view_for_keys.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            _ => {
                let msg = "[Orch Tick] Could not load ValidatorSet at parent; aborting production.";
                tracing::error!(target: "consensus", "{}", msg);
                return Err(anyhow!(msg));
            }
        };

        let Ok(sets) = read_validator_sets(&vs_bytes) else {
            let msg = "[Orch Tick] Could not decode ValidatorSet; aborting production.";
            tracing::error!(target: "consensus", "{}", msg);
            return Err(anyhow!(msg));
        };

        let effective_vs = if let Some(next) = &sets.next {
            if target_height >= next.effective_from_height
                && !next.validators.is_empty()
                && next.total_weight > 0
            {
                next
            } else {
                &sets.current
            }
        } else {
            &sets.current
        };

        let Some(me) = effective_vs
            .validators
            .iter()
            .find(|v| v.account_id == our_account_id)
        else {
            tracing::info!(
                target: "consensus",
                event = "not_in_validator_set",
                height = target_height,
                "We are not in the effective validator set; will not produce."
            );
            return Ok(());
        };
        let required_suite = me.consensus_key.suite;
        tracing::info!(
            target: "consensus",
            event = "signing_info",
            height = target_height,
            ?required_suite
        );

        let (producer_key_suite, producer_pubkey, producer_pubkey_hash, signature_fn): (
            SignatureSuite,
            Vec<u8>,
            [u8; 32],
            Box<dyn Fn(&[u8]) -> Vec<u8> + Send>,
        ) = match required_suite {
            SignatureSuite::Ed25519 => {
                let pk = local_keypair.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::Ed25519, &pk)
                    .map_err(|e| anyhow!("[Orch Tick] failed to hash Ed25519 pubkey: {e}"))?;
                let signer = {
                    let kp = local_keypair.clone();
                    Box::new(move |msg: &[u8]| kp.sign(msg).expect("ed25519 sign failed"))
                        as Box<dyn Fn(&[u8]) -> Vec<u8> + Send>
                };
                (SignatureSuite::Ed25519, pk, hash, signer)
            }
            SignatureSuite::Dilithium2 => {
                let Some(pqc_signer) = pqc_signer.as_ref() else {
                    let msg = "[Orch Tick] Dilithium signing required but no PQC signer configured. Refusing to produce.";
                    tracing::error!(target: "consensus", "{}", msg);
                    return Err(anyhow!(msg));
                };
                let pqc_signer_clone = pqc_signer.clone();
                let pk = SigningKeyPair::public_key(&pqc_signer_clone).to_bytes();
                let hash = account_id_from_key_material(SignatureSuite::Dilithium2, &pk)
                    .map_err(|e| anyhow!("[Orch Tick] failed to hash Dilithium pubkey: {e}"))?;
                let signer = Box::new(move |msg: &[u8]| {
                    SigningKeyPair::sign(&pqc_signer_clone, msg).to_bytes()
                });
                (SignatureSuite::Dilithium2, pk, hash, signer)
            }
        };

        let header_validator_set = effective_vs
            .validators
            .iter()
            .map(|v| v.account_id.0.to_vec())
            .collect();

        let parent_hash_vec = match workload_client.get_last_block_hash().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "consensus",
                    event = "get_last_hash_fail",
                    error = %e,
                    "Using zeros."
                );
                vec![0; 32]
            }
        };
        let mut parent_hash = [0u8; 32];
        if parent_hash_vec.len() == 32 {
            parent_hash.copy_from_slice(&parent_hash_vec);
        }

        let new_block_template = Block {
            header: BlockHeader {
                height: target_height,
                parent_hash,
                parent_state_root: StateRoot(vec![]),
                state_root: StateRoot(vec![]),
                transactions_root: vec![0; 32],
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| ChainError::Transaction(format!("System time error: {}", e)))?
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

        match workload_client.process_block(new_block_template).await {
            Ok((mut final_block, _)) => {
                let block_height = final_block.header.height;
                tracing::info!(
                    target: "consensus",
                    event = "block_processed",
                    height = block_height,
                );
                let preimage = final_block.header.to_preimage_for_signing();
                final_block.header.signature = signature_fn(&preimage);

                // Write back: last_committed_block, node state, mempool prune, gossip, oracle, engine reset
                {
                    let mut ctx = context_arc.lock().await;
                    ctx.last_committed_block = Some(final_block.clone());
                    let mut chain_guard = ctx.chain_ref.lock().await;
                    let status = chain_guard.status_mut();
                    status.height = final_block.header.height;
                    status.latest_timestamp = final_block.header.timestamp;
                }
                tracing::debug!(
                    target: "consensus",
                    event = "tip_advanced",
                    height = final_block.header.height,
                    root = hex::encode(final_block.header.state_root.as_ref()),
                );

                {
                    let data = serde_json::to_vec(&final_block).map_err(|e| {
                        anyhow!("[Orch Tick] failed to serialize block for gossip: {e}")
                    })?;
                    // NOTE: mpsc::Sender is Clone and Send; no need to hold the context lock.
                    let _ = swarm_commander.send(SwarmCommand::PublishBlock(data)).await;
                }

                {
                    let mut pool = tx_pool_ref.lock().await;
                    prune_mempool(&mut pool, &final_block);
                }

                // FIX: Reset engine first to shorten engine lock window for subsequent ticks.
                {
                    consensus_engine_ref.lock().await.reset(block_height);
                }

                // Oracle / side-effects next, under brief context locks only.
                {
                    let service_clone = {
                        let ctx = context_arc.lock().await;
                        ctx.external_data_service.clone()
                    };
                    let mut ctx = context_arc.lock().await;
                    handle_newly_processed_block(&mut ctx, block_height, &service_clone).await;
                }

                {
                    let mut ns = node_state_arc.lock().await;
                    if *ns == depin_sdk_network::traits::NodeState::Syncing {
                        *ns = depin_sdk_network::traits::NodeState::Synced;
                        tracing::info!(target: "orchestration", "State -> Synced.");
                    }
                }
            }
            Err(e) => {
                let msg = format!("[Orch Tick] Workload failed to process a pre-validated block proposal: {}. This should not happen.", e);
                tracing::error!(target: "consensus", "{}", msg);
                return Err(anyhow!(msg));
            }
        }
    } else {
        tracing::debug!(
            target: "consensus",
            event = "tick_skip",
            "Engine decision was not ProduceBlock; will retry next tick."
        );
    }
    Ok(())
}