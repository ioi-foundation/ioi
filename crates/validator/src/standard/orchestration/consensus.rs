// Path: crates/validator/src/standard/orchestration/consensus.rs
use crate::metrics::consensus_metrics as metrics;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::gossip::prune_mempool;
use anyhow::{anyhow, Result};
use ioi_api::{
    chain::{StateRef, ViewResolver},
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::{ProofProvider, StateManager, Verifier},
};
// [FIX] Removed unused ioi_ipc import
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_types::{
    app::{
        account_id_from_key_material, to_root_hash, AccountId, Block, BlockHeader,
        ChainTransaction, SignatureSuite, StateAnchor, StateRoot, SystemPayload, TxHash,
    },
    codec,
    keys::VALIDATOR_SET_KEY,
};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::common::GuardianSigner;

/// Drive one consensus tick without holding the MainLoopContext lock across awaits.
pub async fn drive_consensus_tick<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    cause: &str,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
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
        )
    };

    let node_state = {
        let guard = node_state_arc.lock().await;
        guard.clone()
    };

    let parent_h = last_committed_block_opt
        .as_ref()
        .map(|b| b.header.height)
        .unwrap_or(0);
    let producing_h = parent_h + 1;
    tracing::info!(target: "consensus", event = "tick", %cause, ?node_state, parent_h, producing_h);

    let consensus_allows_bootstrap = matches!(
        cons_ty,
        ioi_types::config::ConsensusType::ProofOfAuthority
            | ioi_types::config::ConsensusType::ProofOfStake
    );

    if node_state != NodeState::Synced && !(consensus_allows_bootstrap && producing_h == 1) {
        tracing::debug!(
            target: "consensus",
            event = "tick_skipped",
            reason = "not synced and not bootstrapping block 1"
        );
        return Ok(());
    }

    let our_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::Ed25519,
            &local_keypair.public().encode_protobuf(),
        )
        .map_err(|e| anyhow!("[Orch Tick] failed to derive local account id: {e}"))?,
    );

    // --- Step 1: Consensus Decision ---
    let (parent_ref, parent_anchor) =
        resolve_parent_ref_and_anchor(&last_committed_block_opt, view_resolver.as_ref()).await?;

    let decision = {
        let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
        let mut engine = consensus_engine_ref.lock().await;
        let known_peers = known_peers_ref.lock().await;
        engine
            .decide(&our_account_id, producing_h, 0, &*parent_view, &known_peers)
            .await
    };

    tracing::info!(target: "consensus", event = "decision", decision = ?decision, height = producing_h);

    if let ioi_api::consensus::ConsensusDecision::ProduceBlock {
        expected_timestamp_secs,
        view,
        ..
    } = decision
    {
        metrics().inc_blocks_produced();

        // --- Step 2: Gather Valid Transactions (Pre-check) ---
        let valid_txs = gather_valid_transactions(
            &view_resolver,
            &tx_pool_ref,
            parent_anchor,
            expected_timestamp_secs,
        )
        .await?;

        tracing::info!(target: "consensus", event = "producing_block", height = producing_h, num_txs = valid_txs.len());

        // --- Step 3: Determine Validator Set & Signer ---
        let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
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

        let Some(me) = effective_vs
            .validators
            .iter()
            .find(|v| v.account_id == our_account_id)
        else {
            tracing::info!(target:"consensus", event="not_in_validator_set", height = producing_h, "Will not produce.");
            return Ok(());
        };

        // Determine keys for the header
        let (producer_key_suite, producer_pubkey) = match me.consensus_key.suite {
            SignatureSuite::Ed25519 => (
                SignatureSuite::Ed25519,
                local_keypair.public().encode_protobuf(),
            ),
            SignatureSuite::Dilithium2 => {
                let kp = pqc_signer.as_ref().ok_or_else(|| {
                    anyhow!("Dilithium required by validator set, but no PQC signer configured")
                })?;
                (SignatureSuite::Dilithium2, kp.public_key().to_bytes())
            }
        };

        let producer_pubkey_hash =
            account_id_from_key_material(producer_key_suite, &producer_pubkey)?;

        // --- Step 4: Construct & Process Block Template ---
        let new_block_template = Block {
            header: BlockHeader {
                height: producing_h,
                view,
                parent_hash: parent_ref.block_hash,
                parent_state_root: ioi_types::app::StateRoot(parent_ref.state_root.clone()),
                state_root: ioi_types::app::StateRoot(vec![]),
                transactions_root: vec![0; 32], // Computed by Workload
                timestamp: expected_timestamp_secs,
                gas_used: 0, // Computed by Workload
                validator_set: header_validator_set,
                producer_account_id: our_account_id,
                producer_key_suite,
                producer_pubkey_hash,
                producer_pubkey: producer_pubkey.to_vec(),
                signature: vec![], // Computed in finalization
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
            },
            transactions: valid_txs,
        };

        let workload_client = view_resolver.workload_client();

        // The updated WorkloadClient internally handles switching to DataPlane
        // if the block size exceeds the threshold.
        let processed_result = workload_client.process_block(new_block_template).await;

        match processed_result {
            Ok((final_block, _)) => {
                // --- Step 5: Finalize, Broadcast, and Clean Up ---
                finalize_and_broadcast_block(
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

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

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

    let parent_anchor = StateRoot(parent_ref.state_root.clone())
        .to_anchor()
        .map_err(|e| anyhow!("Failed to create parent anchor: {}", e))?;

    Ok((parent_ref, parent_anchor))
}

async fn gather_valid_transactions<V>(
    view_resolver: &Arc<dyn ViewResolver<Verifier = V>>,
    tx_pool_ref: &Arc<Mutex<VecDeque<(ChainTransaction, TxHash)>>>,
    parent_anchor: StateAnchor,
    expected_timestamp_secs: u64,
) -> Result<Vec<ChainTransaction>>
where
    V: Verifier,
{
    let (candidate_txs, mempool_len_before) = {
        let pool = tx_pool_ref.lock().await;
        (
            pool.iter().map(|(tx, _)| tx.clone()).collect::<Vec<_>>(),
            pool.len(),
        )
    };

    if candidate_txs.is_empty() {
        return Ok(Vec::new());
    }

    tracing::info!(target: "consensus", event = "precheck_start", mempool_size = mempool_len_before);

    let mut valid_txs = Vec::new();
    let mut invalid_tx_hashes: HashSet<TxHash> = HashSet::new();
    let workload_client = view_resolver.workload_client();

    for (i, tx) in candidate_txs.iter().enumerate() {
        match workload_client
            .check_transactions_at(parent_anchor, expected_timestamp_secs, vec![tx.clone()])
            .await
        {
            Ok(res) if res.first().is_some_and(|r| r.is_ok()) => valid_txs.push(tx.clone()),
            Ok(res) => {
                let err = res
                    .first()
                    .and_then(|r| r.as_ref().err())
                    .cloned()
                    .unwrap_or_else(|| "Unknown pre-check failure".into());

                let (signer, nonce, payload_kind) = match tx {
                    ChainTransaction::System(s) => {
                        let SystemPayload::CallService {
                            service_id, method, ..
                        } = &s.payload;
                        (
                            s.header.account_id,
                            s.header.nonce,
                            format!("CallService({service_id}::{method})"),
                        )
                    }
                    ChainTransaction::Application(a) => match a {
                        ioi_types::app::ApplicationTransaction::DeployContract {
                            header, ..
                        } => (
                            header.account_id,
                            header.nonce,
                            "DeployContract".to_string(),
                        ),
                        ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                            (header.account_id, header.nonce, "CallContract".to_string())
                        }
                        _ => (AccountId::default(), 0, "UTXO".to_string()),
                    },
                    // [FIX] Handle Semantic transactions
                    ChainTransaction::Semantic { header, .. } => {
                        (header.account_id, header.nonce, "Semantic".to_string())
                    }
                };
                tracing::warn!(
                    target: "orchestration",
                    event = "tx_filtered",
                    tx_index = i,
                    signer = %hex::encode(signer.as_ref()),
                    nonce = nonce,
                    payload = %payload_kind,
                    error = %err,
                    "pre-check rejected tx"
                );

                if let Ok(tx_hash) = tx.hash() {
                    invalid_tx_hashes.insert(tx_hash);
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "orchestration",
                    event = "check_tx_ipc_error",
                    tx_index = i,
                    error=%e,
                    "treating as rejection"
                );
                if let Ok(tx_hash) = tx.hash() {
                    invalid_tx_hashes.insert(tx_hash);
                }
            }
        }
    }

    if !invalid_tx_hashes.is_empty() {
        let mut pool = tx_pool_ref.lock().await;
        pool.retain(|(_tx, hash)| !invalid_tx_hashes.contains(hash));
        tracing::info!(target: "consensus", event = "mempool_prune", num_pruned = invalid_tx_hashes.len());
    }

    Ok(valid_txs)
}

async fn finalize_and_broadcast_block<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    mut final_block: Block<ChainTransaction>,
    signer: Arc<dyn GuardianSigner>,
    swarm_commander: &mpsc::Sender<SwarmCommand>,
    consensus_engine_ref: &Arc<Mutex<CE>>,
    tx_pool_ref: &Arc<Mutex<VecDeque<(ChainTransaction, TxHash)>>>,
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let block_height = final_block.header.height;

    // 1. Sign the block
    let preimage = final_block.header.to_preimage_for_signing()?;
    // Hash the preimage first, as the signer expects a 32-byte hash
    let preimage_hash = ioi_crypto::algorithms::hash::sha256(&preimage)?;

    let bundle = signer.sign_consensus_payload(preimage_hash).await?;

    final_block.header.signature = bundle.signature;
    final_block.header.oracle_counter = bundle.counter;
    final_block.header.oracle_trace_hash = bundle.trace_hash;

    // Persist the fully signed block back to Workload storage.
    // This prevents the workload from serving an unsigned block on query.
    {
        let view_resolver = context_arc.lock().await.view_resolver.clone();
        let workload_client = view_resolver.workload_client();
        workload_client
            .update_block_header(final_block.clone())
            .await
            .map_err(|e| anyhow!("Failed to update block header in workload: {}", e))?;
    }

    // 2. Update Context (Last Committed Block)
    {
        let mut ctx = context_arc.lock().await;
        ctx.last_committed_block = Some(final_block.clone());
    }

    tracing::info!(
        target: "consensus",
        event = "block_finalized",
        height = block_height,
        tx_count = final_block.transactions.len(),
        root = hex::encode(final_block.header.state_root.as_ref())
    );

    // 3. Broadcast Block
    {
        let data = codec::to_bytes_canonical(&final_block).map_err(|e| anyhow!(e))?;
        let _ = swarm_commander.send(SwarmCommand::PublishBlock(data)).await;
    }

    // 4. Prune Mempool (Transactions included in the block)
    {
        let mut pool = tx_pool_ref.lock().await;
        if let Err(e) = prune_mempool(&mut pool, &final_block) {
            tracing::error!(target: "consensus", event = "mempool_prune_fail", error=%e);
        }
    }

    // 5. Reset Consensus Engine for next height
    {
        consensus_engine_ref.lock().await.reset(block_height);
    }

    // 6. Update Node State (if syncing)
    {
        let mut ns = node_state_arc.lock().await;
        if *ns == NodeState::Syncing {
            *ns = NodeState::Synced;
            tracing::info!(target: "orchestration", "State -> Synced.");
        }
    }

    Ok(())
}
