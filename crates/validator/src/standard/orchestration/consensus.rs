// Path: crates/validator/src/standard/orchestration/consensus.rs
use crate::metrics::consensus_metrics as metrics;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::mempool::Mempool;
use anyhow::{anyhow, Result};
use ioi_api::crypto::BatchVerifier;
use ioi_api::{
    chain::AnchoredStateView,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::SerializableKey,
    // [FIX] Added SigningKeyPair
    crypto::SigningKeyPair,
    state::{ProofProvider, StateManager, Verifier},
};
// [FIX] Added StateRef
use ioi_api::chain::StateRef;

// [FIX] Added MldsaKeyPair import
use ioi_crypto::sign::dilithium::MldsaKeyPair;

use ioi_networking::traits::NodeState;
use ioi_types::{
    app::{
        account_id_from_key_material, to_root_hash, AccountId, Block, BlockHeader,
        ChainTransaction, SignatureSuite, StateAnchor, StateRoot, TxHash,
    },
    keys::VALIDATOR_SET_KEY,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;
use parity_scale_codec::{Decode, Encode};

/// Drive one consensus tick without holding the MainLoopContext lock across awaits.
pub async fn drive_consensus_tick<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    cause: &str,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
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
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug + Encode + Decode, 
{
    eprintln!("[Consensus] Drive Tick: {}", cause); // [DEBUG]
    let _tick_timer = ioi_telemetry::time::Timer::new(metrics());

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
        signer,
        batch_verifier,
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
            ctx.signer.clone(),
            ctx.batch_verifier.clone(),
        )
    };

    // [FIX] Explicit type annotation for node_state
    let node_state: NodeState = node_state_arc.lock().await.clone();
    let parent_h = last_committed_block_opt
        .as_ref()
        .map_or(0, |b: &Block<ChainTransaction>| b.header.height); // [FIX] explicit type
    let producing_h = parent_h + 1;

    // [CHANGED] Elevated to INFO for visibility
    tracing::info!(target: "consensus", event = "tick_start", %cause, ?node_state, parent_h, producing_h);

    let consensus_allows_bootstrap = matches!(
        cons_ty,
        ioi_types::config::ConsensusType::Admft | ioi_types::config::ConsensusType::ProofOfStake
    );

    if node_state != NodeState::Synced && !(consensus_allows_bootstrap && producing_h == 1) {
        return Ok(());
    }

    let our_account_id = AccountId(
        account_id_from_key_material(
            // [FIX] Use SignatureSuite::ED25519
            SignatureSuite::ED25519,
            // [FIX] Explicit type inference helper if needed, but protobuf encoding is Vec<u8>
            &local_keypair.public().encode_protobuf(),
        )
        .map_err(|e| anyhow!("[Consensus Tick] failed to derive local account id: {e}"))?,
    );

    // [DEBUG] Add detailed logging for view resolution failures
    let (parent_ref, _parent_anchor) = match resolve_parent_ref_and_anchor(&last_committed_block_opt, view_resolver.as_ref()).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(target: "consensus", event = "view_resolve_fail", error = %e);
            return Err(e);
        }
    };

    let decision = {
        let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
        // [FIX] Type annotation for engine
        let mut engine: tokio::sync::MutexGuard<'_, CE> = consensus_engine_ref.lock().await;
        let known_peers = known_peers_ref.lock().await;
        engine
            .decide(&our_account_id, producing_h, 0, &*parent_view, &known_peers)
            .await
    };

    if let ioi_api::consensus::ConsensusDecision::ProduceBlock {
        expected_timestamp_secs,
        view,
        ..
    } = decision
    {
        metrics().inc_blocks_produced();

        // [FIX] Type annotation
        let candidate_txs: Vec<ChainTransaction> = tx_pool_ref.select_transactions(20_000);
        let valid_txs =
            verify_batch_and_filter(&candidate_txs, batch_verifier.as_ref(), &tx_pool_ref)?;

        // [FIX] Type annotation
        let parent_view: Arc<dyn AnchoredStateView> =
            view_resolver.resolve_anchored(&parent_ref).await?;
        let vs_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await?
            .ok_or_else(|| anyhow!("Validator set missing in parent state"))?;

        let sets = ioi_types::app::read_validator_sets(&vs_bytes)?;
        let effective_vs = ioi_types::app::effective_set_for_height(&sets, producing_h);
        let header_validator_set: Vec<Vec<u8>> = effective_vs
            .validators
            .iter()
            .map(|v| v.account_id.0.to_vec())
            .collect();

        let me = effective_vs
            .validators
            .iter()
            .find(|v| v.account_id == our_account_id)
            .ok_or_else(|| anyhow!("Local node not in validator set for height {}", producing_h))?;

        let (producer_key_suite, producer_pubkey) = match me.consensus_key.suite {
            // [FIX] Use SignatureSuite::ED25519
            SignatureSuite::ED25519 => (
                SignatureSuite::ED25519,
                local_keypair.public().encode_protobuf(),
            ),
            // [FIX] Use SignatureSuite::ML_DSA_44
            SignatureSuite::ML_DSA_44 => {
                // [FIX] Explicit type for kp
                let kp: &MldsaKeyPair = pqc_signer
                    .as_ref()
                    .ok_or_else(|| anyhow!("Dilithium required but no PQC signer configured"))?;
                (SignatureSuite::ML_DSA_44, kp.public_key().to_bytes())
            }
            // [FIX] Use SignatureSuite::HYBRID_ED25519_ML_DSA_44
            SignatureSuite::HYBRID_ED25519_ML_DSA_44 => {
                let kp = pqc_signer
                    .as_ref()
                    .ok_or_else(|| anyhow!("Hybrid required but no PQC signer configured"))?;
                let ed_raw = libp2p::identity::PublicKey::try_decode_protobuf(
                    &local_keypair.public().encode_protobuf(),
                )?
                .try_into_ed25519()?
                .to_bytes()
                .to_vec();
                let combined = [ed_raw, kp.public_key().to_bytes()].concat();
                (SignatureSuite::HYBRID_ED25519_ML_DSA_44, combined)
            }
            _ => return Err(anyhow!("Unsupported signature suite in validator set")),
        };

        let producer_pubkey_hash =
            account_id_from_key_material(producer_key_suite, &producer_pubkey)?;

        let new_block_template = Block {
            header: BlockHeader {
                height: producing_h,
                view,
                parent_hash: parent_ref.block_hash,
                parent_state_root: ioi_types::app::StateRoot(parent_ref.state_root.clone()),
                state_root: ioi_types::app::StateRoot(vec![]),
                transactions_root: vec![0; 32],
                timestamp: expected_timestamp_secs,
                gas_used: 0,
                validator_set: header_validator_set,
                producer_account_id: our_account_id,
                producer_key_suite,
                producer_pubkey_hash,
                producer_pubkey: producer_pubkey.to_vec(),
                signature: vec![],
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
            },
            transactions: valid_txs.clone(),
        };

        // [FIX] Log errors from process_block using match
        match view_resolver
            .workload_client()
            .process_block(new_block_template)
            .await
        {
            Ok((final_block, _)) => {
                if final_block.transactions.len() < valid_txs.len() {
                    let included_hashes: HashSet<TxHash> = final_block
                        .transactions
                        .iter()
                        // [FIX] Explicit type for filter_map
                        .filter_map(|tx: &ChainTransaction| tx.hash().ok())
                        .collect();
                    for tx in valid_txs {
                        if let Ok(h) = tx.hash() {
                            if !included_hashes.contains(&h) {
                                tx_pool_ref.remove_by_hash(&h);
                            }
                        }
                    }
                }
                // [FIX] Explicitly call finalize function from super::finalize
                crate::standard::orchestration::finalize::finalize_and_broadcast_block(
                    context_arc,
                    final_block,
                    signer,
                    &swarm_commander,
                    &consensus_engine_ref,
                    &tx_pool_ref,
                    &node_state_arc,
                )
                .await?;
            }
            Err(e) => {
                tracing::error!(target: "consensus", "Block processing failed: {}", e);
                return Err(anyhow!("Block processing failed: {}", e));
            }
        }
    }
    Ok(())
}

async fn resolve_parent_ref_and_anchor<V>(
    last_committed_block_opt: &Option<Block<ChainTransaction>>,
    view_resolver: &dyn ioi_api::chain::ViewResolver<Verifier = V>,
) -> Result<(StateRef, StateAnchor)>
where
    V: Verifier,
{
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
    let parent_anchor = StateRoot(parent_ref.state_root.clone()).to_anchor()?;
    Ok((parent_ref, parent_anchor))
}

fn verify_batch_and_filter(
    candidate_txs: &[ChainTransaction],
    batch_verifier: &dyn BatchVerifier,
    tx_pool: &Mempool,
) -> Result<Vec<ChainTransaction>> {
    let mut sig_indices = Vec::new();
    let mut sign_bytes_storage = Vec::new();

    for (i, tx) in candidate_txs.iter().enumerate() {
        if let Ok(Some((_, _, bytes))) = ioi_tx::system::validation::get_signature_components(tx) {
            sign_bytes_storage.push(bytes);
            sig_indices.push(i);
        }
    }

    let mut batch_items = Vec::with_capacity(sig_indices.len());
    for (i, &idx) in sig_indices.iter().enumerate() {
        if let Ok(Some((_, proof, _))) = ioi_tx::system::validation::get_signature_components(&candidate_txs[idx]) {
            batch_items.push((
                proof.public_key.as_slice(),
                sign_bytes_storage[i].as_slice(),
                proof.signature.as_slice(),
                proof.suite,
            ));
        }
    }

    let batch_results = if !batch_items.is_empty() {
        batch_verifier.verify_batch(&batch_items)?
    } else {
        vec![]
    };

    let mut valid_txs = Vec::with_capacity(candidate_txs.len());
    let mut results_iter = batch_results.into_iter();
    let mut sig_idx_iter = sig_indices.into_iter();
    let mut next_sig_idx = sig_idx_iter.next();

    for (i, tx) in candidate_txs.iter().enumerate() {
        if Some(i) == next_sig_idx {
            if results_iter.next().unwrap_or(false) {
                valid_txs.push(tx.clone());
            } else if let Ok(h) = tx.hash() {
                tx_pool.remove_by_hash(&h);
            }
            next_sig_idx = sig_idx_iter.next();
        } else {
            valid_txs.push(tx.clone());
        }
    }
    Ok(valid_txs)
}