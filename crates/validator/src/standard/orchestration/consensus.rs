// Path: crates/validator/src/standard/orchestration/consensus.rs
use crate::metrics::consensus_metrics as metrics;
use crate::standard::orchestration::context::MainLoopContext;
use crate::standard::orchestration::gossip::prune_mempool;
use crate::standard::orchestration::view_resolver::DefaultViewResolver;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_api::{
    chain::StateRef,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, Verifier},
};
use ioi_types::{
    app::{
        account_id_from_key_material, compute_interval_from_parent_state, to_root_hash, AccountId,
        Block, BlockHeader, BlockTimingParams, BlockTimingRuntime, ChainTransaction,
        SignatureSuite, StateRoot, SystemPayload,
    },
    codec, // Import the canonical codec
    keys::{BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, VALIDATOR_SET_KEY},
};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Helper function to canonically hash a transaction using the SDK's crypto abstractions.
fn hash_transaction(tx: &ChainTransaction) -> Result<Vec<u8>, anyhow::Error> {
    let serialized = codec::to_bytes_canonical(tx).map_err(|e| anyhow!(e))?;
    let digest = ioi_crypto::algorithms::hash::sha256(&serialized)?;
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
        ioi_types::config::ConsensusType::ProofOfAuthority
            | ioi_types::config::ConsensusType::ProofOfStake
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

    if let ioi_api::consensus::ConsensusDecision::ProduceBlock(_) = decision {
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

        let (candidate_txs, mempool_len_before) = {
            let pool = tx_pool_ref.lock().await;
            tracing::debug!(
                target: "mempool",
                "consensus view mempool_size={}, ptr = {:p}",
                pool.len(),
                Arc::as_ptr(&tx_pool_ref)
            );
            (pool.iter().cloned().collect::<Vec<_>>(), pool.len())
        };
        // log every candidate kind so we see the IBC CallService
        for (i, tx) in candidate_txs.iter().enumerate() {
            let payload_kind = match tx {
                ChainTransaction::System(s) => match &s.payload {
                    SystemPayload::CallService {
                        service_id, method, ..
                    } => format!("CallService({service_id}::{method})"),
                    other => format!("{other:?}"),
                },
                ChainTransaction::Application(a) => format!("{a:?}"),
            };
            tracing::debug!(target="orchestration", event="precheck_candidate", idx=i, %payload_kind);
        }

        tracing::info!(target: "consensus", event = "precheck_start", mempool_size = mempool_len_before);

        // Canonical pre-check: call into Workload IPC (which now mirrors process_transaction)
        let mut valid_txs = Vec::new();
        let mut invalid_tx_hashes = HashSet::new();
        let workload_client = view_resolver
            .as_any()
            .downcast_ref::<DefaultViewResolver<V>>()
            .ok_or_else(|| anyhow!("Could not downcast ViewResolver to get WorkloadClient"))?
            .workload_client();

        // Anchor pre-checks at the parent view’s root (block N is built on state at N-1)
        let parent_anchor = StateRoot(parent_ref.state_root.clone())
            .to_anchor()
            .map_err(|e| anyhow!("Failed to create parent anchor: {}", e))?;

        for (i, tx) in candidate_txs.iter().enumerate() {
            match workload_client
                .check_transactions_at(parent_anchor, vec![tx.clone()])
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
                        ChainTransaction::System(s) => (
                            s.header.account_id,
                            s.header.nonce,
                            format!("{:?}", s.payload)
                                .split_whitespace()
                                .next()
                                .unwrap_or("Unknown")
                                .to_string(),
                        ),
                        ChainTransaction::Application(a) => match a {
                            ioi_types::app::ApplicationTransaction::DeployContract {
                                header,
                                ..
                            } => (
                                header.account_id,
                                header.nonce,
                                "DeployContract".to_string(),
                            ),
                            ioi_types::app::ApplicationTransaction::CallContract {
                                header, ..
                            } => (header.account_id, header.nonce, "CallContract".to_string()),
                            _ => (AccountId::default(), 0, "UTXO".to_string()),
                        },
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
                    if let Ok(tx_hash) = hash_transaction(tx) {
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
                    if let Ok(tx_hash) = hash_transaction(tx) {
                        invalid_tx_hashes.insert(tx_hash);
                    }
                }
            }
        }

        if !invalid_tx_hashes.is_empty() {
            let mut pool = tx_pool_ref.lock().await;
            pool.retain(|tx| {
                hash_transaction(tx)
                    .map(|id| !invalid_tx_hashes.contains(&id))
                    .unwrap_or(true)
            });
            tracing::info!(target: "consensus", event = "mempool_prune", num_pruned = invalid_tx_hashes.len());
        }

        for (i, tx) in valid_txs.iter().enumerate() {
            let payload_kind = match tx {
                ChainTransaction::System(s) => match &s.payload {
                    SystemPayload::CallService {
                        service_id, method, ..
                    } => format!("CallService({service_id}::{method})"),
                    other => format!("{other:?}"),
                },
                ChainTransaction::Application(a) => format!("{a:?}"),
            };
            tracing::debug!(target="orchestration", event="precheck_valid", idx=i, %payload_kind);
        }
        tracing::info!(target: "consensus", event = "producing_block", height = height_being_built, num_txs = valid_txs.len());

        let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
        let (timing_params_bytes, timing_runtime_bytes) = tokio::try_join!(
            parent_view.get(BLOCK_TIMING_PARAMS_KEY),
            parent_view.get(BLOCK_TIMING_RUNTIME_KEY),
        )?;

        let timing_params: BlockTimingParams = timing_params_bytes
            .and_then(|b| codec::from_bytes_canonical(&b).ok())
            .ok_or_else(|| anyhow!("BlockTimingParams not found in state"))?;

        let timing_runtime: BlockTimingRuntime = timing_runtime_bytes
            .and_then(|b| codec::from_bytes_canonical(&b).ok())
            .ok_or_else(|| anyhow!("BlockTimingRuntime not found in state"))?;

        // TODO: The gas_used of the parent block is needed. For now, we use a placeholder.
        // This should be retrieved from the parent block's metadata.
        let parent_gas_used_placeholder = 0;

        let vs_bytes = parent_view
            .get(VALIDATOR_SET_KEY)
            .await?
            .ok_or_else(|| anyhow!("Validator set missing in parent state"))?;

        let sets = ioi_types::app::read_validator_sets(&vs_bytes)?;
        let effective_vs = if let Some(next) = &sets.next {
            if height_being_built >= next.effective_from_height
                && !next.validators.is_empty()
                && next.total_weight > 0
            {
                &sets.next.as_ref().unwrap()
            } else {
                &sets.current
            }
        } else {
            &sets.current
        };

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
            tracing::info!(target:"consensus", event="not_in_validator_set", height = height_being_built, "Will not produce.");
            return Ok(());
        };
        let required_suite = me.consensus_key.suite;

        let (producer_key_suite, producer_pubkey, signature_fn): (
            SignatureSuite,
            Vec<u8>,
            SignatureFn,
        ) = match required_suite {
            SignatureSuite::Ed25519 => {
                let pk = local_keypair.public().encode_protobuf();
                (
                    SignatureSuite::Ed25519,
                    pk,
                    Box::new(move |msg: &[u8]| Ok(local_keypair.sign(msg)?)) as SignatureFn,
                )
            }
            SignatureSuite::Dilithium2 => {
                let kp = pqc_signer.clone().ok_or_else(|| {
                    anyhow!("Dilithium required by validator set, but no PQC signer configured")
                })?;
                let pk = kp.public_key().to_bytes();
                (
                    SignatureSuite::Dilithium2,
                    pk,
                    Box::new(move |msg: &[u8]| Ok(kp.sign(msg)?.to_bytes())) as SignatureFn,
                )
            }
        };

        let producer_pubkey_hash =
            account_id_from_key_material(producer_key_suite, &producer_pubkey)?;

        let new_block_template = Block {
            header: BlockHeader {
                height: height_being_built,
                parent_hash: parent_ref.block_hash,
                parent_state_root: ioi_types::app::StateRoot(parent_ref.state_root.clone()),
                state_root: ioi_types::app::StateRoot(vec![]),
                transactions_root: vec![0; 32],
                timestamp: {
                    let parent_ts = last_committed_block_opt
                        .as_ref()
                        .map(|b| b.header.timestamp)
                        .unwrap_or(0);
                    let interval = match last_committed_block_opt.as_ref() {
                        Some(pb) => compute_interval_from_parent_state(
                            &timing_params,
                            &timing_runtime,
                            pb.header.height,
                            parent_gas_used_placeholder,
                        ),
                        None => timing_params.base_interval_secs, // genesis
                    };
                    parent_ts
                        .checked_add(interval)
                        .ok_or_else(|| anyhow!("timestamp overflow"))?
                },
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
                tracing::info!(
                    target: "consensus",
                    event = "block_processed",
                    height = block_height
                );
                let preimage = final_block.header.to_preimage_for_signing()?;
                final_block.header.signature = signature_fn(&preimage)?;
                {
                    let mut ctx = context_arc.lock().await;
                    ctx.last_committed_block = Some(final_block.clone());
                }
                tracing::debug!(
                    target: "consensus",
                    event = "tip_advanced",
                    height = final_block.header.height,
                    root = hex::encode(final_block.header.state_root.as_ref())
                );
                {
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
                    let mut ns = node_state_arc.lock().await;
                    if *ns == ioi_networking::traits::NodeState::Syncing {
                        *ns = ioi_networking::traits::NodeState::Synced;
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
