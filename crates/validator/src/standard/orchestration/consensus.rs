// Path: crates/validator/src/standard/orchestration/consensus.rs
use crate::metrics::consensus_metrics as metrics;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::gossip::prune_mempool;
use crate::standard::orchestration::oracle::handle_newly_processed_block;
use crate::standard::orchestration::view_resolver::DefaultViewResolver;
use anyhow::{anyhow, Result};
use depin_sdk_api::{
    chain::StateRef,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, Verifier},
};
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_network::traits::NodeState;
use depin_sdk_types::{
    app::{
        account_id_from_key_material, read_validator_sets, to_root_hash, AccountId, Block,
        BlockHeader, ChainTransaction, SignatureSuite,
    },
    codec, // Import the canonical codec
    keys::VALIDATOR_SET_KEY,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Helper function to canonically hash a transaction using the SDK's crypto abstractions.
fn hash_transaction(tx: &ChainTransaction) -> Result<Vec<u8>, anyhow::Error> {
    let serialized = codec::to_bytes_canonical(tx).map_err(|e| anyhow!(e))?;
    let digest = depin_sdk_crypto::algorithms::hash::sha256(&serialized)?;
    Ok(digest.to_vec())
}

// A type alias for the complex signature function to resolve the `type_complexity` lint.
type SignatureFn = Box<dyn Fn(&[u8]) -> Result<Vec<u8>> + Send>;

/// Drive one consensus tick without holding the MainLoopContext lock across awaits.
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
    let (
        cons_ty,
        view_resolver,
        consensus_engine_ref,
        known_peers_ref,
        tx_pool_ref,
        swarm_commander,
        local_keypair,
        pqc_signer,
        last_committed_block_opt,
        node_state_arc,
    ) = {
        let ctx = context_arc.lock().await;
        (
            ctx.config.consensus_type,
            ctx.view_resolver.clone(),
            ctx.consensus_engine_ref.clone(),
            ctx.known_peers_ref.clone(),
            ctx.tx_pool_ref.clone(),
            ctx.swarm_commander.clone(),
            ctx.local_keypair.clone(),
            ctx.pqc_signer.clone(),
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
    tracing::info!(target: "consensus", event = "tick", %cause, ?node_state, parent_h, producing_h);

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
        let parent_ref = if let Some(last) = last_committed_block_opt.as_ref() {
            let block_hash = to_root_hash(last.header.hash()?)?;
            StateRef {
                height: last.header.height,
                state_root: last.header.state_root.as_ref().to_vec(),
                block_hash,
            }
        } else {
            // For the very first block, resolve the *actual* genesis root
            // from the workload container.
            let genesis_root_bytes = view_resolver.genesis_root().await?;
            StateRef {
                height: 0,
                state_root: genesis_root_bytes,
                block_hash: [0; 32],
            }
        };

        let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
        let mut engine = consensus_engine_ref.lock().await;
        let known_peers = known_peers_ref.lock().await;
        engine
            .decide(
                &our_account_id,
                height_being_built,
                0,
                &*parent_view,
                &known_peers,
            )
            .await
    };

    tracing::info!(target: "consensus", event = "decision", decision = ?decision, height = height_being_built);

    if let depin_sdk_api::consensus::ConsensusDecision::ProduceBlock(_) = decision {
        metrics().inc_blocks_produced();
        let parent_ref = if let Some(last) = last_committed_block_opt.as_ref() {
            let block_hash = to_root_hash(last.header.hash()?)?;
            StateRef {
                height: last.header.height,
                state_root: last.header.state_root.as_ref().to_vec(),
                block_hash,
            }
        } else {
            let genesis_root_bytes = view_resolver.genesis_root().await?;
            StateRef {
                height: 0,
                state_root: genesis_root_bytes,
                block_hash: [0; 32],
            }
        };

        let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
        let (candidate_txs, mempool_len_before) = {
            let pool = tx_pool_ref.lock().await;
            (pool.iter().cloned().collect::<Vec<_>>(), pool.len())
        };

        // --- TWEAK: Only skip empty genesis block when we expect a multi-validator net. ---
        // In single-node setups (like state_iavl_e2e), we must produce height 1 even if empty.
        if height_being_built == 1
            && node_state == NodeState::Syncing
            && allow_bootstrap
            && known_peers_ref.lock().await.is_empty()
            && candidate_txs.is_empty()
        {
            // Try to load the validator set size from the genesis state using the parent view.
            let vs_size = match parent_view.get(VALIDATOR_SET_KEY).await {
                Ok(Some(vs_bytes)) => read_validator_sets(&vs_bytes)
                    .map(|sets| sets.current.validators.len())
                    .unwrap_or(1), // On decode error, assume 1 to be safe and not stall.
                _ => 1, // If key not found or other error, assume 1.
            };

            if vs_size > 1 {
                tracing::info!(
                    target: "consensus",
                    event = "skip_empty_block",
                    "Multi-validator genesis with no peers; skipping empty block."
                );
                return Ok(());
            }
            // Single-validator setup detected: allow empty block production to unblock tests.
        }

        tracing::info!(target: "consensus", event = "precheck_start", mempool_size = mempool_len_before);

        let check_results = {
            let workload_client = view_resolver
                .as_any()
                .downcast_ref::<DefaultViewResolver<V>>()
                .ok_or_else(|| anyhow!("Could not downcast ViewResolver to get WorkloadClient"))?
                .workload_client();
            let anchor =
                depin_sdk_types::app::StateRoot(parent_ref.state_root.clone()).to_anchor()?;
            workload_client
                .check_transactions_at(anchor, candidate_txs.clone())
                .await?
        };

        tracing::info!(target: "consensus", event = "precheck_complete", num_results = check_results.len(), num_candidates = candidate_txs.len());
        if check_results.len() != candidate_txs.len() {
            tracing::error!(target: "consensus", "BUG: check_transactions_at result length mismatch; refusing to produce this tick.");
            return Ok(());
        }
        let mut valid_txs = Vec::new();
        let mut invalid_tx_hashes = HashSet::new();
        for (i, result) in check_results.into_iter().enumerate() {
            if let Err(e) = result {
                tracing::warn!(target: "consensus", event = "tx_filtered", tx_index = i, error = %e);
                if let Some(tx) = candidate_txs.get(i) {
                    if let Ok(tx_hash) = hash_transaction(tx) {
                        invalid_tx_hashes.insert(tx_hash);
                    } else {
                        tracing::error!(target: "consensus", event = "tx_hash_fail", tx_index = i);
                    }
                }
            } else if let Some(tx) = candidate_txs.get(i) {
                valid_txs.push(tx.clone());
            }
        }
        if !invalid_tx_hashes.is_empty() {
            let mut pool = tx_pool_ref.lock().await;
            pool.retain(|tx| {
                hash_transaction(tx)
                    .map(|id| !invalid_tx_hashes.contains(&id))
                    .unwrap_or(true)
            }); // Keep tx if hashing fails
            tracing::info!(target: "consensus", event = "mempool_prune", num_pruned = invalid_tx_hashes.len());
        }

        tracing::info!(target: "consensus", event = "producing_block", height = height_being_built, num_txs = valid_txs.len());
        let vs_bytes = match parent_view.get(VALIDATOR_SET_KEY).await {
            Ok(Some(b)) => b,
            _ => {
                let msg = "[Orch Tick] Could not load ValidatorSet at parent; aborting production.";
                tracing::error!(target: "consensus", "{}", msg);
                return Err(anyhow!(msg));
            }
        };
        let sets = read_validator_sets(&vs_bytes)?;
        let effective_vs = if let Some(next) = &sets.next {
            if height_being_built >= next.effective_from_height
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
            tracing::info!(target: "consensus", event = "not_in_validator_set", height = height_being_built, "We are not in the effective validator set; will not produce.");
            return Ok(());
        };
        let required_suite = me.consensus_key.suite;
        tracing::info!(target: "consensus", event = "signing_info", height = height_being_built, ?required_suite);
        let (producer_key_suite, producer_pubkey, producer_pubkey_hash, signature_fn): (
            SignatureSuite,
            Vec<u8>,
            [u8; 32],
            SignatureFn,
        ) = match required_suite {
            SignatureSuite::Ed25519 => {
                let pk = local_keypair.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::Ed25519, &pk)?;
                let signer = {
                    let kp = local_keypair.clone();
                    Box::new(move |msg: &[u8]| kp.sign(msg).map_err(|e| anyhow!(e)))
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
                let hash = account_id_from_key_material(SignatureSuite::Dilithium2, &pk)?;
                let signer = Box::new(move |msg: &[u8]| {
                    SigningKeyPair::sign(&pqc_signer_clone, msg)
                        .map(|sig| sig.to_bytes())
                        .map_err(|e| anyhow!(e))
                });
                (SignatureSuite::Dilithium2, pk, hash, signer)
            }
        };
        let header_validator_set = effective_vs
            .validators
            .iter()
            .map(|v| v.account_id.0.to_vec())
            .collect();
        let new_block_template = Block {
            header: BlockHeader {
                height: height_being_built,
                parent_hash: parent_ref.block_hash,
                parent_state_root: depin_sdk_types::app::StateRoot(parent_ref.state_root.clone()),
                state_root: depin_sdk_types::app::StateRoot(vec![]),
                transactions_root: vec![0; 32],
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                validator_set: header_validator_set,
                producer_account_id: our_account_id,
                producer_key_suite,
                producer_pubkey_hash,
                producer_pubkey,
                signature: vec![],
            },
            transactions: valid_txs,
        };
        let workload_client = view_resolver
            .as_any()
            .downcast_ref::<DefaultViewResolver<V>>()
            .ok_or_else(|| anyhow!("Could not downcast ViewResolver to get WorkloadClient"))?
            .workload_client();
        match workload_client.process_block(new_block_template).await {
            Ok((mut final_block, _)) => {
                let block_height = final_block.header.height;
                tracing::info!(target: "consensus", event = "block_processed", height = block_height);
                let preimage = final_block.header.to_preimage_for_signing()?;
                final_block.header.signature = signature_fn(&preimage)?;
                {
                    let mut ctx = context_arc.lock().await;
                    ctx.last_committed_block = Some(final_block.clone());
                }
                tracing::debug!(target: "consensus", event = "tip_advanced", height = final_block.header.height, root = hex::encode(final_block.header.state_root.as_ref()));
                {
                    // FIX: Use the canonical SCALE codec for network serialization to prevent mismatches.
                    let data = codec::to_bytes_canonical(&final_block).map_err(|e| anyhow!(e))?;
                    let _ = swarm_commander.send(SwarmCommand::PublishBlock(data)).await;
                }
                {
                    let mut pool = tx_pool_ref.lock().await;
                    if let Err(e) = prune_mempool(&mut pool, &final_block) {
                        tracing::error!(target: "consensus", event = "mempool_prune_fail", error=%e);
                    }
                }
                {
                    consensus_engine_ref.lock().await.reset(block_height);
                }
                {
                    let service_clone = {
                        let ctx = context_arc.lock().await;
                        ctx.oracle_service.clone()
                    };
                    let ctx = context_arc.lock().await;
                    handle_newly_processed_block(&ctx, block_height, &service_clone).await;
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
        tracing::debug!(target: "consensus", event = "tick_skip", "Engine decision was not ProduceBlock; will retry next tick.");
    }
    Ok(())
}
