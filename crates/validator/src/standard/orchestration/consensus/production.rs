use super::*;

pub(super) fn duplicate_production_backoff() -> Duration {
    Duration::from_millis(
        std::env::var("IOI_AFT_DUPLICATE_PROPOSAL_BACKOFF_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(500),
    )
}

pub(super) fn proposal_tx_select_max_bytes() -> Option<usize> {
    std::env::var("IOI_CONSENSUS_TX_SELECT_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .or(Some(4 * 1024 * 1024))
}

pub(crate) fn recovered_consensus_header_stitch_window_budget() -> u64 {
    std::env::var("IOI_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET))
        .unwrap_or(DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_WINDOW_BUDGET)
}

pub(crate) fn recovered_consensus_header_stitch_segment_budget() -> u64 {
    std::env::var("IOI_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET))
        .unwrap_or(DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_BUDGET)
}

pub(crate) fn recovered_consensus_header_stitch_segment_fold_budget() -> u64 {
    std::env::var("IOI_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(MAX_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET))
        .unwrap_or(DEFAULT_AFT_RECOVERED_CONSENSUS_HEADER_STITCH_SEGMENT_FOLD_BUDGET)
}

pub(super) fn trim_candidate_transactions_to_byte_budget(
    candidate_txs: Vec<ChainTransaction>,
    max_bytes: Option<usize>,
) -> Result<Vec<ChainTransaction>> {
    let Some(max_bytes) = max_bytes else {
        return Ok(candidate_txs);
    };

    let mut selected = Vec::with_capacity(candidate_txs.len());
    let mut used_bytes = 0usize;

    for tx in candidate_txs {
        let encoded_len = codec::to_bytes_canonical(&tx)
            .map_err(|e| anyhow!("failed to encode candidate transaction for sizing: {e}"))?
            .len();

        if !selected.is_empty() && used_bytes.saturating_add(encoded_len) > max_bytes {
            break;
        }

        used_bytes = used_bytes.saturating_add(encoded_len);
        selected.push(tx);
    }

    Ok(selected)
}

pub(super) fn dispatch_swarm_command(
    sender: &tokio::sync::mpsc::Sender<SwarmCommand>,
    command: SwarmCommand,
) {
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

pub(super) async fn emit_local_view_change<CE>(
    consensus_engine_ref: &Arc<Mutex<CE>>,
    swarm_commander: &tokio::sync::mpsc::Sender<SwarmCommand>,
    local_keypair: &libp2p::identity::Keypair,
    our_account_id: &AccountId,
    height: u64,
    view: u64,
    reason: &'static str,
) -> Result<()>
where
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    use ioi_types::app::ViewChangeVote;

    let sign_payload = (height, view);
    let sign_bytes = codec::to_bytes_canonical(&sign_payload)
        .map_err(|e| anyhow!("Failed to serialize vote payload: {}", e))?;
    let sig = local_keypair.sign(&sign_bytes)?;

    let signed_vote = ViewChangeVote {
        height,
        view,
        voter: our_account_id.clone(),
        signature: sig,
    };

    let vote_blob = codec::to_bytes_canonical(&signed_vote)
        .map_err(|e| anyhow!("Failed to serialize ViewChangeVote: {}", e))?;

    {
        let mut engine = consensus_engine_ref.lock().await;
        let local_peer_id = local_keypair.public().to_peer_id();
        if let Err(error) = engine.handle_view_change(local_peer_id, &vote_blob).await {
            tracing::warn!(
                target: "consensus",
                height,
                view,
                reason,
                error = %error,
                "Failed to loop back local view-change vote into the consensus engine."
            );
        }
    }

    dispatch_swarm_command(
        swarm_commander,
        SwarmCommand::BroadcastViewChange(vote_blob),
    );
    tracing::info!(
        target: "consensus",
        height,
        view,
        reason,
        "Broadcasted local view-change vote."
    );

    Ok(())
}

pub(super) async fn maybe_replay_tip_vote<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    consensus_engine_ref: &Arc<Mutex<CE>>,
    local_keypair: &libp2p::identity::Keypair,
    tip_block: &Block<ChainTransaction>,
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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    if tip_block.header.height == 0 {
        return Ok(());
    }

    let vote_hash = to_root_hash(&tip_block.header.hash()?)?;
    let replay_marker = (tip_block.header.height, tip_block.header.view, vote_hash);
    let replay_backoff = std::time::Duration::from_millis(750);

    let swarm_commander = {
        let mut ctx = context_arc.lock().await;
        if let Some((height, view, hash, replayed_at)) = ctx.last_tip_vote_replay.as_ref() {
            if (*height, *view, *hash) == replay_marker && replayed_at.elapsed() < replay_backoff {
                return Ok(());
            }
        }
        ctx.last_tip_vote_replay = Some((
            replay_marker.0,
            replay_marker.1,
            replay_marker.2,
            std::time::Instant::now(),
        ));
        ctx.swarm_commander.clone()
    };

    let our_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::ED25519,
            &local_keypair.public().encode_protobuf(),
        )
        .map_err(|e| anyhow!("failed to derive local account id for tip replay: {e}"))?,
    );
    let vote_payload = (tip_block.header.height, tip_block.header.view, vote_hash);
    let vote_bytes = codec::to_bytes_canonical(&vote_payload)
        .map_err(|e| anyhow!("failed to encode tip replay vote payload: {e}"))?;
    let signature = local_keypair.sign(&vote_bytes)?;
    let vote = ConsensusVote {
        height: tip_block.header.height,
        view: tip_block.header.view,
        block_hash: vote_hash,
        voter: our_account_id,
        signature,
    };
    let vote_blob = codec::to_bytes_canonical(&vote)
        .map_err(|e| anyhow!("failed to encode tip replay vote: {e}"))?;

    {
        let mut engine = consensus_engine_ref.lock().await;
        if let Err(error) = engine.handle_vote(vote.clone()).await {
            tracing::debug!(
                target: "consensus",
                height = tip_block.header.height,
                view = tip_block.header.view,
                error = %error,
                "Ignoring local tip-vote replay loopback failure."
            );
        } else {
            let pending_qcs = engine.take_pending_quorum_certificates();
            drop(engine);
            for qc in pending_qcs {
                if let Ok(qc_blob) = codec::to_bytes_canonical(&qc) {
                    let _ = swarm_commander
                        .send(SwarmCommand::BroadcastQuorumCertificate(qc_blob))
                        .await;
                }
            }
        }
    }

    let _ = swarm_commander
        .send(SwarmCommand::BroadcastVote(vote_blob))
        .await;
    tracing::info!(
        target: "consensus",
        height = tip_block.header.height,
        view = tip_block.header.view,
        block = %hex::encode(&vote_hash[..4]),
        "Broadcast replayed tip vote for the local tip."
    );

    Ok(())
}

pub(super) fn parent_ref_from_last_committed_or_recovered_tip(
    last_committed_block_opt: &Option<Block<ChainTransaction>>,
    recovered_tip_anchor: Option<&RecoveredConsensusTipAnchor>,
) -> Result<Option<StateRef>> {
    if let Some(last) = last_committed_block_opt.as_ref() {
        let block_hash = to_root_hash(last.header.hash()?)?;
        return Ok(Some(StateRef {
            height: last.header.height,
            state_root: last.header.state_root.as_ref().to_vec(),
            block_hash,
        }));
    }

    Ok(recovered_tip_anchor.map(|recovered_tip| StateRef {
        height: recovered_tip.height,
        state_root: recovered_tip.state_root.clone(),
        block_hash: recovered_tip.block_hash,
    }))
}

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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let _tick_timer = ioi_telemetry::time::Timer::new(metrics());
    let mut workload_status_height = None;

    let (
        cons_ty,
        view_resolver,
        consensus_engine_ref,
        known_peers_ref,
        tx_pool_ref,
        swarm_commander,
        local_keypair,
        pqc_signer,
        mut last_committed_block_opt,
        node_state_arc,
        configured_bootstrap_peers,
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
            ctx.configured_bootstrap_peers,
            ctx.signer.clone(),
            ctx.batch_verifier.clone(),
        )
    };

    let node_state: NodeState = node_state_arc.lock().await.clone();
    let known_peer_count = known_peers_ref.lock().await.len();
    let is_quarantined = {
        let ctx = context_arc.lock().await;
        ctx.is_quarantined.load(std::sync::atomic::Ordering::SeqCst)
    };

    if is_quarantined {
        tracing::info!(target: "consensus", "Consensus halted: local validator is quarantined.");
        return Ok(());
    }

    let initial_local_tip_height = last_committed_block_opt
        .as_ref()
        .map(|block| block.header.height)
        .unwrap_or(0);

    if let Ok(status) = view_resolver.workload_client().get_status().await {
        workload_status_height = Some(status.height);
        if status.height > initial_local_tip_height {
            if let Ok(Some(workload_tip)) = view_resolver
                .workload_client()
                .get_block_by_height(status.height)
                .await
            {
                if let Err(error) = require_persisted_aft_canonical_collapse_if_needed(
                    cons_ty,
                    view_resolver.workload_client().as_ref(),
                    &workload_tip,
                )
                .await
                {
                    tracing::warn!(
                        target: "consensus",
                        height = workload_tip.header.height,
                        error = %error,
                        "Skipping workload-tip hydration because the persisted canonical collapse object is missing or mismatched."
                    );
                } else {
                    {
                        let mut ctx = context_arc.lock().await;
                        let ctx_tip_height = ctx
                            .last_committed_block
                            .as_ref()
                            .map(|block| block.header.height)
                            .unwrap_or(0);
                        if workload_tip.header.height > ctx_tip_height {
                            tracing::info!(
                                target: "consensus",
                                reconciled_height = workload_tip.header.height,
                                previous_height = ctx_tip_height,
                                "Hydrating last_committed_block from workload status before consensus tick."
                            );
                            ctx.last_committed_block = Some(workload_tip.clone());
                        }
                    }
                    last_committed_block_opt = Some(workload_tip);
                }
            }
        }
    }

    let mut aft_recovered_state = AftRecoveredStateSurface::default();
    let mut recovered_tip_anchor = None;
    let stitch_window_budget = recovered_consensus_header_stitch_window_budget();
    let stitch_segment_budget = recovered_consensus_header_stitch_segment_budget();
    let stitch_segment_fold_budget = recovered_consensus_header_stitch_segment_fold_budget();
    if matches!(cons_ty, ioi_types::config::ConsensusType::Aft)
        && last_committed_block_opt.is_none()
    {
        if let Some(status_height) = workload_status_height.filter(|height| *height > 0) {
            match load_folded_recovered_consensus_headers(
                view_resolver.workload_client().as_ref(),
                status_height,
                AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                stitch_window_budget,
                stitch_segment_budget,
                stitch_segment_fold_budget,
            )
            .await
            {
                Ok(headers) => {
                    if !headers.is_empty() {
                        tracing::info!(
                            target: "consensus",
                            recovered_header_len = headers.len(),
                            stitch_window_budget,
                            stitch_segment_budget,
                            stitch_segment_fold_budget,
                            start_height = headers.first().map(|entry| entry.height).unwrap_or(status_height),
                            end_height = headers.last().map(|entry| entry.height).unwrap_or(status_height),
                            "Loaded bounded recovered canonical-header ancestry for validator restart continuity."
                        );
                    }
                    aft_recovered_state.consensus_headers = headers;
                }
                Err(error) => {
                    tracing::info!(
                        target: "consensus",
                        status_height,
                        error = %error,
                        "Recovered canonical-header ancestry unavailable for bounded validator restart window."
                    );
                }
            }
            match load_folded_recovered_certified_headers(
                view_resolver.workload_client().as_ref(),
                status_height,
                AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                stitch_window_budget,
                stitch_segment_budget,
                stitch_segment_fold_budget,
            )
            .await
            {
                Ok(headers) => {
                    if !headers.is_empty() {
                        tracing::info!(
                            target: "consensus",
                            recovered_certified_header_len = headers.len(),
                            stitch_window_budget,
                            stitch_segment_budget,
                            stitch_segment_fold_budget,
                            start_height = headers
                                .first()
                                .map(|entry| entry.header.height)
                                .unwrap_or(status_height),
                            end_height = headers
                                .last()
                                .map(|entry| entry.header.height)
                                .unwrap_or(status_height),
                            "Loaded bounded recovered certified-header ancestry for validator restart continuity."
                        );
                    }
                    aft_recovered_state.certified_headers = headers;
                }
                Err(error) => {
                    tracing::info!(
                        target: "consensus",
                        status_height,
                        error = %error,
                        "Recovered certified-header ancestry unavailable for bounded validator restart window."
                    );
                }
            }
            match load_folded_recovered_restart_block_headers(
                view_resolver.workload_client().as_ref(),
                status_height,
                AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                stitch_window_budget,
                stitch_segment_budget,
                stitch_segment_fold_budget,
            )
            .await
            {
                Ok(headers) => {
                    if !headers.is_empty() {
                        tracing::info!(
                            target: "consensus",
                            recovered_restart_header_len = headers.len(),
                            stitch_window_budget,
                            stitch_segment_budget,
                            stitch_segment_fold_budget,
                            start_height = headers
                                .first()
                                .map(|entry| entry.header.height)
                                .unwrap_or(status_height),
                            end_height = headers
                                .last()
                                .map(|entry| entry.header.height)
                                .unwrap_or(status_height),
                            "Loaded bounded recovered restart block-header ancestry for validator restart continuity."
                        );
                    }
                    aft_recovered_state.restart_headers = headers;
                }
                Err(error) => {
                    tracing::info!(
                        target: "consensus",
                        status_height,
                        error = %error,
                        "Recovered restart block-header ancestry unavailable for bounded validator restart window."
                    );
                }
            }
            match load_recovered_consensus_tip_anchor(
                view_resolver.workload_client().as_ref(),
                status_height,
                &aft_recovered_state.consensus_headers,
            )
            .await
            {
                Ok(anchor) => {
                    if let Some(anchor) = anchor.as_ref() {
                        tracing::info!(
                            target: "consensus",
                            height = anchor.height,
                            block = %hex::encode(&anchor.block_hash[..4]),
                            "Loaded recovered consensus tip anchor for validator restart continuity."
                        );
                    }
                    recovered_tip_anchor = anchor;
                }
                Err(error) => {
                    tracing::info!(
                        target: "consensus",
                        status_height,
                        error = %error,
                        "Recovered consensus tip anchor unavailable for validator restart continuity."
                    );
                }
            }
            match load_archived_recovered_history_anchor_from_canonical_collapse_tip(
                view_resolver.workload_client().as_ref(),
                status_height,
            )
            .await
            {
                Ok(historical_retrievability) => {
                    if let Some(surface) = historical_retrievability.as_ref() {
                        tracing::info!(
                            target: "consensus",
                            height = surface.checkpoint.covered_end_height,
                            "Loaded ordinary AFT historical retrievability from canonical collapse for restart continuity."
                        );
                    }
                    aft_recovered_state.historical_retrievability = historical_retrievability;
                }
                Err(error) => {
                    tracing::info!(
                        target: "consensus",
                        status_height,
                        error = %error,
                        "Ordinary AFT historical retrievability unavailable for validator restart continuity."
                    );
                }
            }
            if !aft_recovered_state.consensus_headers.is_empty()
                || !aft_recovered_state.certified_headers.is_empty()
                || !aft_recovered_state.restart_headers.is_empty()
            {
                let accepted_recovered_state = {
                    let mut engine = consensus_engine_ref.lock().await;
                    seed_aft_recovered_state_into_engine(&mut *engine, &aft_recovered_state)
                };
                if accepted_recovered_state.accepted_consensus_headers > 0 {
                    tracing::info!(
                        target: "consensus",
                        accepted_recovered_headers = accepted_recovered_state.accepted_consensus_headers,
                        recovered_header_len = aft_recovered_state.consensus_headers.len(),
                        "Seeded bounded recovered canonical-header restart hints into the consensus engine."
                    );
                }
                if accepted_recovered_state.accepted_certified_headers > 0 {
                    tracing::info!(
                        target: "consensus",
                        accepted_recovered_certified_headers = accepted_recovered_state.accepted_certified_headers,
                        recovered_certified_header_len = aft_recovered_state.certified_headers.len(),
                        "Seeded bounded recovered certified-header restart hints into the consensus engine."
                    );
                }
                if accepted_recovered_state.accepted_restart_headers > 0 {
                    tracing::info!(
                        target: "consensus",
                        accepted_recovered_restart_headers = accepted_recovered_state.accepted_restart_headers,
                        recovered_restart_header_len = aft_recovered_state.restart_headers.len(),
                        "Seeded bounded recovered restart block-header hints into the consensus engine."
                    );
                }
            }
            if recovered_tip_anchor.is_none() {
                tracing::warn!(
                    target: "consensus",
                    status_height,
                    "Skipping AFT consensus tick because neither an ordinary committed block nor a recovered validator restart anchor is locally available."
                );
                return Ok(());
            }
        }
    }

    let local_tip_height = last_committed_block_opt
        .as_ref()
        .map(|block| block.header.height)
        .or_else(|| recovered_tip_anchor.as_ref().map(|anchor| anchor.height))
        .unwrap_or(0);
    let validator_count_hint = last_committed_block_opt
        .as_ref()
        .map(|block| block.header.validator_set.len())
        .unwrap_or_else(|| configured_bootstrap_peers.saturating_add(1));

    let parent_h = last_committed_block_opt
        .as_ref()
        .map(|b: &Block<ChainTransaction>| b.header.height)
        .or_else(|| recovered_tip_anchor.as_ref().map(|anchor| anchor.height))
        .unwrap_or(0);
    let producing_h = parent_h + 1;

    if benchmark_trace_enabled() && producing_h <= 3 {
        if let Some(last) = last_committed_block_opt.as_ref() {
            let root = last.header.state_root.0.as_slice();
            let root_prefix_len = root.len().min(4);
            eprintln!(
                "[BENCH-AFT-ORCH] cause={} producing_h={} local_tip_height={} local_tip_root_len={} local_tip_root={} local_tip_ts_ms={}",
                cause,
                producing_h,
                last.header.height,
                root.len(),
                hex::encode(&root[..root_prefix_len]),
                last.header.timestamp_ms_or_legacy(),
            );
        } else if let Some(anchor) = recovered_tip_anchor.as_ref() {
            let root = anchor.state_root.as_slice();
            let root_prefix_len = root.len().min(4);
            eprintln!(
                "[BENCH-AFT-ORCH] cause={} producing_h={} recovered_tip_height={} recovered_tip_root_len={} recovered_tip_root={}",
                cause,
                producing_h,
                anchor.height,
                root.len(),
                hex::encode(&root[..root_prefix_len]),
            );
        } else {
            eprintln!(
                "[BENCH-AFT-ORCH] cause={} producing_h={} local_tip_height=0 local_tip_root_len=0 local_tip_root=",
                cause,
                producing_h,
            );
        }
    }

    let consensus_allows_bootstrap = matches!(
        cons_ty,
        ioi_types::config::ConsensusType::Aft
            | ioi_types::config::ConsensusType::ProofOfAuthority
            | ioi_types::config::ConsensusType::ProofOfStake
    );

    let isolated_bootstrap = consensus_allows_bootstrap
        && producing_h == 1
        && configured_bootstrap_peers == 0
        && known_peer_count == 0;

    if node_state != NodeState::Synced && !isolated_bootstrap {
        if producing_h <= 3 {
            tracing::info!(
                target: "consensus",
                cause,
                producing_h,
                local_tip_height,
                ?node_state,
                known_peer_count,
                "Skipping consensus tick because the node is not yet synced."
            );
        }
        return Ok(());
    }

    if producing_h > 1 && validator_count_hint > 1 && known_peer_count == 0 {
        tracing::warn!(
            target: "consensus",
            height = producing_h,
            validator_count = validator_count_hint,
            "Skipping block production because the node has no live peers in a multi-validator AFT cluster."
        );
        return Ok(());
    }

    if let Some(tip_block) = last_committed_block_opt.as_ref() {
        if let Err(error) = maybe_replay_tip_vote(
            context_arc,
            &consensus_engine_ref,
            &local_keypair,
            tip_block,
        )
        .await
        {
            tracing::warn!(
                target: "consensus",
                height = tip_block.header.height,
                view = tip_block.header.view,
                error = %error,
                "Failed to replay local tip vote before the consensus tick."
            );
        }
    }

    let our_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::ED25519,
            &local_keypair.public().encode_protobuf(),
        )
        .map_err(|e| anyhow!("[Consensus Tick] failed to derive local account id: {e}"))?,
    );

    let (parent_ref, _parent_anchor) = match resolve_parent_ref_and_anchor(
        &last_committed_block_opt,
        recovered_tip_anchor.as_ref(),
        view_resolver.as_ref(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(target: "consensus", event = "view_resolve_fail", error = %e);
            return Err(e);
        }
    };

    let decision = {
        let parent_view = view_resolver.resolve_anchored(&parent_ref).await?;
        let mut engine: tokio::sync::MutexGuard<'_, CE> = consensus_engine_ref.lock().await;
        let known_peers = known_peers_ref.lock().await;

        engine
            .decide(&our_account_id, producing_h, 0, &*parent_view, &known_peers)
            .await
    };

    if producing_h <= 3 {
        let decision_label = match &decision {
            ioi_api::consensus::ConsensusDecision::Panic(_) => "panic",
            ioi_api::consensus::ConsensusDecision::Timeout { .. } => "timeout",
            ioi_api::consensus::ConsensusDecision::Vote { .. } => "vote",
            ioi_api::consensus::ConsensusDecision::ProduceBlock { .. } => "produce_block",
            ioi_api::consensus::ConsensusDecision::WaitForBlock => "wait_for_block",
            ioi_api::consensus::ConsensusDecision::ProposeViewChange => "propose_view_change",
            ioi_api::consensus::ConsensusDecision::Stall => "stall",
        };
        tracing::info!(
            target: "consensus",
            cause,
            producing_h,
            local_tip_height,
            known_peer_count,
            decision = decision_label,
            "Consensus tick decided the next action."
        );
    }

    match decision {
        ioi_api::consensus::ConsensusDecision::Panic(proof) => {
            tracing::error!(
                target: "consensus",
                "CRITICAL: consensus engine detected divergence evidence."
            );

            let proof_bytes = codec::to_bytes_canonical(&proof)
                .map_err(|e| anyhow!("Failed to serialize proof: {}", e))?;
            let sig = local_keypair.sign(&proof_bytes)?;

            let panic_msg = ioi_types::app::PanicMessage {
                proof: proof.clone(),
                sender_sig: sig,
            };

            let panic_bytes = codec::to_bytes_canonical(&panic_msg)
                .map_err(|e| anyhow!("Failed to serialize PanicMessage: {}", e))?;

            let _ = swarm_commander
                .send(SwarmCommand::BroadcastPanic(panic_bytes))
                .await;

            crate::standard::orchestration::transition::execute_divergence_response(
                context_arc,
                proof,
            )
            .await?;
        }

        ioi_api::consensus::ConsensusDecision::Timeout { view, height } => {
            tracing::warn!(target: "consensus", "Consensus timeout at H={} View={}. Broadcasting ViewChange.", height, view);
            emit_local_view_change(
                &consensus_engine_ref,
                &swarm_commander,
                &local_keypair,
                &our_account_id,
                height,
                view,
                "timeout",
            )
            .await?;
        }

        ioi_api::consensus::ConsensusDecision::Vote {
            block_hash,
            height,
            view,
        } => {
            tracing::info!(target: "consensus", "Voting for block {} (H={} V={})", hex::encode(&block_hash[..4]), height, view);
            // Sign the vote
            let vote_payload = (height, view, block_hash);
            let vote_bytes = codec::to_bytes_canonical(&vote_payload)
                .map_err(|e| anyhow!("Failed to serialize vote payload: {}", e))?;

            let signature = local_keypair.sign(&vote_bytes)?;

            let vote = ConsensusVote {
                height,
                view,
                block_hash,
                voter: our_account_id,
                signature,
            };

            let vote_blob = codec::to_bytes_canonical(&vote)
                .map_err(|e| anyhow!("Failed to serialize ConsensusVote: {}", e))?;

            // Broadcast vote to peers
            dispatch_swarm_command(&swarm_commander, SwarmCommand::BroadcastVote(vote_blob));

            // Loopback to local engine to ensure we count our own vote
            {
                let mut engine = consensus_engine_ref.lock().await;
                if let Err(e) = engine.handle_vote(vote).await {
                    tracing::warn!(target: "consensus", "Failed to handle own vote: {}", e);
                } else {
                    let pending_qcs = engine.take_pending_quorum_certificates();
                    drop(engine);
                    for qc in pending_qcs {
                        if let Ok(qc_blob) = codec::to_bytes_canonical(&qc) {
                            dispatch_swarm_command(
                                &swarm_commander,
                                SwarmCommand::BroadcastQuorumCertificate(qc_blob),
                            );
                        }
                    }
                }
            }
        }

        ioi_api::consensus::ConsensusDecision::ProduceBlock {
            expected_timestamp_secs,
            expected_timestamp_ms,
            view,
            parent_qc,
            previous_canonical_collapse_commitment_hash,
            canonical_collapse_extension_certificate,
            timeout_certificate,
            ..
        } => {
            let mut parent_ref = resolve_parent_ref_and_anchor(
                &last_committed_block_opt,
                recovered_tip_anchor.as_ref(),
                view_resolver.as_ref(),
            )
            .await
            .map(|(parent_ref, _)| parent_ref)?;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0));
            let now_ms = now.as_millis().min(u128::from(u64::MAX)) as u64;
            if expected_timestamp_ms > now_ms {
                let due_at = Duration::from_millis(expected_timestamp_ms);
                let delay = due_at.saturating_sub(now);
                let (kick_tx, kick_scheduled, next_due_wakeup_at_ms) = {
                    let ctx = context_arc.lock().await;
                    (
                        ctx.consensus_kick_tx.clone(),
                        ctx.consensus_kick_scheduled.clone(),
                        ctx.next_due_wakeup_at_ms.clone(),
                    )
                };
                next_due_wakeup_at_ms
                    .store(expected_timestamp_ms, std::sync::atomic::Ordering::SeqCst);
                if !kick_scheduled.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = kick_tx.send(());
                        kick_scheduled.store(false, std::sync::atomic::Ordering::SeqCst);
                    });
                }
                tracing::debug!(
                    target: "consensus",
                    height = producing_h,
                    view,
                    expected_timestamp_ms,
                    expected_timestamp_secs,
                    now_ms,
                    delay_ms = delay.as_millis(),
                    "Deferring block production until the configured block timestamp is due."
                );
                return Ok(());
            }
            {
                let ctx = context_arc.lock().await;
                ctx.next_due_wakeup_at_ms
                    .store(0, std::sync::atomic::Ordering::SeqCst);
            }

            let production_marker = (producing_h, view, parent_qc.block_hash);
            let production_backoff = duplicate_production_backoff();
            {
                let ctx = context_arc.lock().await;
                if let Some((height, existing_view, existing_parent_hash, attempted_at)) =
                    ctx.last_production_attempt.as_ref()
                {
                    if (*height, *existing_view, *existing_parent_hash) == production_marker
                        && attempted_at.elapsed() < production_backoff
                    {
                        tracing::debug!(
                            target: "consensus",
                            height = producing_h,
                            view,
                            backoff_ms = production_backoff.as_millis(),
                            "Skipping duplicate local production attempt for the same height/view/parent QC."
                        );
                        return Ok(());
                    }
                }
            }

            if producing_h > 1
                && (parent_qc.height != parent_ref.height
                    || parent_qc.block_hash != parent_ref.block_hash)
            {
                let (
                    mut certified_parent_header,
                    mut certified_recovered_parent_header,
                    mut certified_recovered_parent_entry,
                    mut certified_recovered_restart_parent_entry,
                ) = {
                    let engine = consensus_engine_ref.lock().await;
                    (
                        engine.header_for_quorum_certificate(&parent_qc),
                        engine.aft_recovered_consensus_header_for_quorum_certificate(&parent_qc),
                        engine.aft_recovered_certified_header_for_quorum_certificate(&parent_qc),
                        engine.aft_recovered_restart_header_for_quorum_certificate(&parent_qc),
                    )
                };
                if last_committed_block_opt.is_none()
                    && certified_parent_header.is_none()
                    && certified_recovered_parent_header.is_none()
                    && certified_recovered_parent_entry.is_none()
                    && certified_recovered_restart_parent_entry.is_none()
                {
                    let current_recovered_start = loaded_recovered_ancestry_start_height(
                        &aft_recovered_state.consensus_headers,
                        &aft_recovered_state.certified_headers,
                        &aft_recovered_state.restart_headers,
                    )
                    .unwrap_or(u64::MAX);
                    if parent_qc.height < current_recovered_start {
                        match stream_recovered_ancestry_to_height(
                            view_resolver.workload_client().as_ref(),
                            &consensus_engine_ref,
                            parent_qc.height,
                            AFT_RECOVERED_CONSENSUS_HEADER_WINDOW,
                            AFT_RECOVERED_CONSENSUS_HEADER_STITCH_OVERLAP,
                            stitch_window_budget,
                            stitch_segment_budget,
                            stitch_segment_fold_budget,
                            &aft_recovered_state.consensus_headers,
                            &aft_recovered_state.certified_headers,
                            &aft_recovered_state.restart_headers,
                        )
                        .await
                        {
                            Ok(report) if !report.loaded_pages.is_empty() => {
                                let first_page = report
                                    .loaded_pages
                                    .first()
                                    .copied()
                                    .expect("non-empty paged ancestry load");
                                let last_page = report
                                    .loaded_pages
                                    .last()
                                    .copied()
                                    .expect("non-empty paged ancestry load");
                                tracing::info!(
                                    target: "consensus",
                                    parent_qc_height = parent_qc.height,
                                    loaded_page_count = report.loaded_pages.len(),
                                    paged_start_height = first_page.0,
                                    paged_end_height = last_page.1,
                                    covered_target = report.covered_target,
                                    exhausted = report.exhausted,
                                    "Paged older recovered restart ancestry into the live engine because the parent QC fell below the bounded cached prefix."
                                );
                                (
                                    certified_parent_header,
                                    certified_recovered_parent_header,
                                    certified_recovered_parent_entry,
                                    certified_recovered_restart_parent_entry,
                                ) = {
                                    let engine = consensus_engine_ref.lock().await;
                                    (
                                        engine.header_for_quorum_certificate(&parent_qc),
                                        engine
                                            .aft_recovered_consensus_header_for_quorum_certificate(
                                                &parent_qc,
                                            ),
                                        engine
                                            .aft_recovered_certified_header_for_quorum_certificate(
                                                &parent_qc,
                                            ),
                                        engine.aft_recovered_restart_header_for_quorum_certificate(
                                            &parent_qc,
                                        ),
                                    )
                                };
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::info!(
                                    target: "consensus",
                                    parent_qc_height = parent_qc.height,
                                    error = %error,
                                    "Failed to page older recovered restart ancestry for parent-QC reconciliation."
                                );
                            }
                        }
                    }
                }
                let mut reconciled = false;
                let certified_parent_header_found = certified_parent_header.is_some();
                let certified_recovered_parent_header_found =
                    certified_recovered_parent_header.is_some();
                let certified_recovered_parent_entry_found =
                    certified_recovered_parent_entry.is_some();
                let certified_recovered_restart_parent_entry_found =
                    certified_recovered_restart_parent_entry.is_some();
                let mut state_root_match = false;
                let mut parent_state_root_match = false;
                let mut transactions_root_match = false;
                let mut timestamp_match = false;
                let mut timestamp_ms_match = false;
                let mut gas_used_match = false;
                let mut timeout_certificate_match = false;
                let mut parent_qc_match = false;
                let mut validator_set_match = false;
                let mut certified_parent_hash_prefix = String::from("unknown");
                let mut recovered_parent_hash_prefix = String::from("unknown");
                let mut recovered_certified_parent_hash_prefix = String::from("unknown");
                let mut recovered_restart_parent_hash_prefix = String::from("unknown");

                if let (Some(local_tip), Some(certified_parent_header)) =
                    (last_committed_block_opt.as_ref(), certified_parent_header)
                {
                    let local_tip_hash_prefix = local_tip
                        .header
                        .hash()
                        .ok()
                        .map(|hash| hex::encode(&hash[..4.min(hash.len())]))
                        .unwrap_or_else(|| "unknown".to_string());
                    let hashes_diverged = local_tip
                        .header
                        .hash()
                        .ok()
                        .and_then(|hash| to_root_hash(&hash).ok())
                        .map(|hash| hash != parent_qc.block_hash)
                        .unwrap_or(true);
                    certified_parent_hash_prefix = certified_parent_header
                        .hash()
                        .ok()
                        .map(|hash| hex::encode(&hash[..4.min(hash.len())]))
                        .unwrap_or_else(|| "unknown".to_string());
                    state_root_match =
                        local_tip.header.state_root == certified_parent_header.state_root;
                    parent_state_root_match = local_tip.header.parent_state_root
                        == certified_parent_header.parent_state_root;
                    transactions_root_match = local_tip.header.transactions_root
                        == certified_parent_header.transactions_root;
                    timestamp_match =
                        local_tip.header.timestamp == certified_parent_header.timestamp;
                    timestamp_ms_match =
                        local_tip.header.timestamp_ms == certified_parent_header.timestamp_ms;
                    gas_used_match = local_tip.header.gas_used == certified_parent_header.gas_used;
                    timeout_certificate_match = local_tip.header.timeout_certificate
                        == certified_parent_header.timeout_certificate;
                    parent_qc_match =
                        local_tip.header.parent_qc == certified_parent_header.parent_qc;
                    validator_set_match =
                        local_tip.header.validator_set == certified_parent_header.validator_set;
                    let roots_match =
                        state_root_match && parent_state_root_match && transactions_root_match;

                    if local_tip.header.height == parent_qc.height && hashes_diverged && roots_match
                    {
                        let mut reconciled_block = local_tip.clone();
                        reconciled_block.header = certified_parent_header.clone();

                        view_resolver
                            .workload_client()
                            .update_block_header(reconciled_block.clone())
                            .await
                            .map_err(|e| {
                                anyhow!("failed to reconcile local tip to QC branch: {e}")
                            })?;
                        let reconciled_collapse = require_persisted_aft_canonical_collapse_if_needed(
                            cons_ty,
                            view_resolver.workload_client().as_ref(),
                            &reconciled_block,
                        )
                        .await
                        .map_err(|e| anyhow!(
                            "reconciled local tip does not have a matching persisted canonical collapse object: {e}"
                        ))?;

                        {
                            let mut ctx = context_arc.lock().await;
                            ctx.last_committed_block = Some(reconciled_block.clone());
                            {
                                let mut chain_guard = ctx.chain_ref.lock().await;
                                let status = chain_guard.status_mut();
                                if reconciled_block.header.height >= status.height {
                                    status.height = reconciled_block.header.height;
                                    status.latest_timestamp = reconciled_block.header.timestamp;
                                }
                            }
                            let _ = ctx.tip_sender.send(ChainTipInfo {
                                height: reconciled_block.header.height,
                                timestamp: reconciled_block.header.timestamp,
                                timestamp_ms: reconciled_block.header.timestamp_ms_or_legacy(),
                                gas_used: reconciled_block.header.gas_used,
                                state_root: reconciled_block.header.state_root.0.clone(),
                                genesis_root: ctx.genesis_root.clone(),
                                validator_set: reconciled_block.header.validator_set.clone(),
                            });
                        }

                        {
                            let mut engine = consensus_engine_ref.lock().await;
                            let accepted = engine.observe_committed_block(
                                &reconciled_block.header,
                                reconciled_collapse.as_ref(),
                            );
                            if !accepted {
                                tracing::warn!(
                                    target: "consensus",
                                    height = reconciled_block.header.height,
                                    "Consensus engine ignored the reconciled committed-block hint because it was not collapse-backed."
                                );
                            }
                        }

                        tracing::info!(
                            target: "consensus",
                            height = producing_h,
                            view,
                            parent_height = certified_parent_header.height,
                            parent_qc_hash = %hex::encode(&parent_qc.block_hash[..4]),
                            local_tip_hash = %local_tip_hash_prefix,
                            "Reconciled the local tip onto the QC-certified parent branch because the execution roots matched."
                        );
                        if benchmark_trace_enabled() {
                            eprintln!(
                                "[BENCH-AFT-ORCH] height={} view={} action=branch_mismatch_reconciled parent_height={} parent_qc_hash={}",
                                producing_h,
                                view,
                                certified_parent_header.height,
                                hex::encode(&parent_qc.block_hash[..4]),
                            );
                        }

                        last_committed_block_opt = Some(reconciled_block);
                        parent_ref = resolve_parent_ref_and_anchor(
                            &last_committed_block_opt,
                            recovered_tip_anchor.as_ref(),
                            view_resolver.as_ref(),
                        )
                        .await
                        .map(|(parent_ref, _)| parent_ref)?;
                        reconciled = true;
                    }
                }

                if !reconciled && last_committed_block_opt.is_none() {
                    if let Some(recovered_parent_header) = certified_recovered_parent_header {
                        recovered_parent_hash_prefix = hex::encode(
                            &recovered_parent_header.canonical_block_commitment_hash[..4],
                        );
                        if let Some(recovered_anchor) =
                            reconcile_recovered_tip_anchor_with_parent_qc(
                                &parent_ref,
                                &parent_qc,
                                &recovered_parent_header,
                            )
                        {
                            recovered_tip_anchor = Some(recovered_anchor);
                            parent_ref = resolve_parent_ref_and_anchor(
                                &last_committed_block_opt,
                                recovered_tip_anchor.as_ref(),
                                view_resolver.as_ref(),
                            )
                            .await
                            .map(|(parent_ref, _)| parent_ref)?;
                            tracing::info!(
                                target: "consensus",
                                height = producing_h,
                                view,
                                parent_height = recovered_parent_header.height,
                                parent_qc_hash = %hex::encode(&parent_qc.block_hash[..4]),
                                "Reconciled the recovered validator restart tip onto the QC-certified parent branch because the recovered state root matched."
                            );
                            reconciled = true;
                        }
                    }
                }

                if !reconciled && last_committed_block_opt.is_none() {
                    if let (Some(current_anchor), Some(recovered_parent_entry)) = (
                        recovered_tip_anchor.as_ref(),
                        certified_recovered_parent_entry.as_ref(),
                    ) {
                        recovered_certified_parent_hash_prefix = hex::encode(
                            &recovered_parent_entry
                                .header
                                .canonical_block_commitment_hash[..4],
                        );
                        if let Some(advanced_anchor) =
                            advance_recovered_tip_anchor_with_certified_parent_qc(
                                current_anchor,
                                &parent_qc,
                                recovered_parent_entry,
                            )
                        {
                            recovered_tip_anchor = Some(advanced_anchor);
                            parent_ref = resolve_parent_ref_and_anchor(
                                &last_committed_block_opt,
                                recovered_tip_anchor.as_ref(),
                                view_resolver.as_ref(),
                            )
                            .await
                            .map(|(parent_ref, _)| parent_ref)?;
                            tracing::info!(
                                target: "consensus",
                                height = producing_h,
                                view,
                                parent_height = recovered_parent_entry.header.height,
                                parent_qc_hash = %hex::encode(&parent_qc.block_hash[..4]),
                                "Advanced the recovered validator restart tip along a bounded QC-certified recovered branch."
                            );
                            reconciled = true;
                        }
                    }
                }

                if !reconciled && last_committed_block_opt.is_none() {
                    if let Some(recovered_restart_parent_entry) =
                        certified_recovered_restart_parent_entry.as_ref()
                    {
                        recovered_restart_parent_hash_prefix = hex::encode(
                            &recovered_restart_parent_entry
                                .certified_header
                                .header
                                .canonical_block_commitment_hash[..4],
                        );
                    }
                    if let Some(current_anchor) = recovered_tip_anchor.as_ref() {
                        if let Some(advanced_anchor) =
                            advance_recovered_tip_anchor_along_restart_headers(
                                current_anchor,
                                &parent_qc,
                                &aft_recovered_state.restart_headers,
                            )
                        {
                            recovered_tip_anchor = Some(advanced_anchor);
                            parent_ref = resolve_parent_ref_and_anchor(
                                &last_committed_block_opt,
                                recovered_tip_anchor.as_ref(),
                                view_resolver.as_ref(),
                            )
                            .await
                            .map(|(parent_ref, _)| parent_ref)?;
                            tracing::info!(
                                target: "consensus",
                                height = producing_h,
                                view,
                                parent_height = parent_qc.height,
                                parent_qc_hash = %hex::encode(&parent_qc.block_hash[..4]),
                                "Advanced the recovered validator restart tip along a bounded recovered header/QC cache branch."
                            );
                            reconciled = true;
                        }
                    }
                }

                if reconciled
                    && parent_qc.height == parent_ref.height
                    && parent_qc.block_hash == parent_ref.block_hash
                {
                    tracing::debug!(
                        target: "consensus",
                        height = producing_h,
                        view,
                        "Recovered from parent branch mismatch by reconciling the local tip to the QC-certified header."
                    );
                } else {
                    tracing::warn!(
                        target: "consensus",
                        height = producing_h,
                        view,
                        certified_parent_header_found,
                        certified_recovered_parent_header_found,
                        certified_recovered_parent_entry_found,
                        certified_recovered_restart_parent_entry_found,
                        parent_height = parent_ref.height,
                        parent_hash = %hex::encode(&parent_ref.block_hash[..4]),
                        parent_qc_height = parent_qc.height,
                        parent_qc_hash = %hex::encode(&parent_qc.block_hash[..4]),
                        certified_parent_hash = %certified_parent_hash_prefix,
                        recovered_parent_hash = %recovered_parent_hash_prefix,
                        recovered_certified_parent_hash = %recovered_certified_parent_hash_prefix,
                        recovered_restart_parent_hash = %recovered_restart_parent_hash_prefix,
                        state_root_match,
                        parent_state_root_match,
                        transactions_root_match,
                        timestamp_match,
                        timestamp_ms_match,
                        gas_used_match,
                        timeout_certificate_match,
                        parent_qc_match,
                        validator_set_match,
                        "Parent QC and local tip diverged. Emitting a view change instead of silently skipping production."
                    );
                    if benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-AFT-ORCH] height={} view={} action=branch_mismatch_recovery parent_height={} parent_qc_height={} parent_hash={} parent_qc_hash={} next_view={}",
                            producing_h,
                            view,
                            parent_ref.height,
                            parent_qc.height,
                            hex::encode(&parent_ref.block_hash[..4]),
                            hex::encode(&parent_qc.block_hash[..4]),
                            view + 1
                        );
                    }
                    emit_local_view_change(
                        &consensus_engine_ref,
                        &swarm_commander,
                        &local_keypair,
                        &our_account_id,
                        producing_h,
                        view + 1,
                        "branch_mismatch",
                    )
                    .await?;
                    return Ok(());
                }
            }

            {
                let mut ctx = context_arc.lock().await;
                ctx.last_production_attempt = Some((
                    production_marker.0,
                    production_marker.1,
                    production_marker.2,
                    std::time::Instant::now(),
                ));
            }

            let proposal_tx_limit = std::env::var("IOI_CONSENSUS_TX_SELECT_LIMIT")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(20_000);
            let proposal_tx_max_bytes = proposal_tx_select_max_bytes();
            let select_started = Instant::now();
            let candidate_txs: Vec<ChainTransaction> = trim_candidate_transactions_to_byte_budget(
                tx_pool_ref.select_transactions(proposal_tx_limit),
                proposal_tx_max_bytes,
            )?;
            let selection_elapsed = select_started.elapsed();
            let verify_started = Instant::now();
            let valid_txs =
                verify_batch_and_filter(&candidate_txs, batch_verifier.as_ref(), &tx_pool_ref)?;
            let verify_elapsed = verify_started.elapsed();

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

            if producing_h == 1 && validator_count_hint > 1 {
                let bootstrap_leader = effective_vs.validators.first().map(|v| v.account_id);
                eprintln!(
                    "[BOOTSTRAP-GATE] local={} leader={} configured_bootstrap_peers={} known_peer_count={} validator_count_hint={} validator_set_len={}",
                    hex::encode(&our_account_id.0[..4]),
                    bootstrap_leader
                        .map(|id| hex::encode(&id.0[..4]))
                        .unwrap_or_else(|| "none".to_string()),
                    configured_bootstrap_peers,
                    known_peer_count,
                    validator_count_hint,
                    effective_vs.validators.len(),
                );
                tracing::info!(
                    target: "consensus",
                    height = producing_h,
                    view,
                    local = %hex::encode(&our_account_id.0[..4]),
                    bootstrap_leader = ?bootstrap_leader.map(|id| hex::encode(&id.0[..4])),
                    configured_bootstrap_peers,
                    known_peer_count,
                    validator_count_hint,
                    validator_set_len = effective_vs.validators.len(),
                    "Evaluating deterministic bootstrap leader gate."
                );
                if bootstrap_leader != Some(our_account_id) {
                    tracing::info!(
                        target: "consensus",
                        height = producing_h,
                        view,
                        local = %hex::encode(&our_account_id.0[..4]),
                        bootstrap_leader = ?bootstrap_leader.map(|id| hex::encode(&id.0[..4])),
                        configured_bootstrap_peers,
                        known_peer_count,
                        validator_count_hint,
                        "Skipping height-1 production because only the deterministic bootstrap leader may mint the first child."
                    );
                    return Ok(());
                }
            }

            metrics().inc_blocks_produced();

            let me = effective_vs
                .validators
                .iter()
                .find(|v| v.account_id == our_account_id)
                .ok_or_else(|| {
                    anyhow!("Local node not in validator set for height {}", producing_h)
                })?;

            let (producer_key_suite, producer_pubkey) = match me.consensus_key.suite {
                SignatureSuite::ED25519 => (
                    SignatureSuite::ED25519,
                    local_keypair.public().encode_protobuf(),
                ),
                SignatureSuite::ML_DSA_44 => {
                    let kp: &MldsaKeyPair = pqc_signer.as_ref().ok_or_else(|| {
                        anyhow!("Dilithium required but no PQC signer configured")
                    })?;
                    (SignatureSuite::ML_DSA_44, kp.public_key().to_bytes())
                }
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

            let aft_mode = {
                let ctx = context_arc.lock().await;
                ctx.config.aft_safety_mode
            };
            let header = BlockHeader {
                height: producing_h,
                view,
                parent_hash: parent_ref.block_hash,
                parent_state_root: ioi_types::app::StateRoot(parent_ref.state_root.clone()),
                state_root: ioi_types::app::StateRoot(vec![]),
                transactions_root: vec![],
                timestamp: timestamp_millis_to_legacy_seconds(expected_timestamp_ms),
                timestamp_ms: expected_timestamp_ms,
                gas_used: 0,
                validator_set: header_validator_set,
                producer_account_id: our_account_id,
                producer_key_suite,
                producer_pubkey_hash,
                producer_pubkey: producer_pubkey.to_vec(),
                signature: vec![],
                oracle_counter: 0,
                oracle_trace_hash: [0u8; 32],
                parent_qc,
                previous_canonical_collapse_commitment_hash,
                canonical_collapse_extension_certificate,
                publication_frontier: None,
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate,
            };
            let ordered_txs = if matches!(aft_mode, AftSafetyMode::Asymptote) {
                canonicalize_transactions_for_header(&header, &valid_txs)
                    .map_err(|e| anyhow!("failed to canonicalize AFT transaction order: {e}"))?
            } else {
                valid_txs.clone()
            };
            let new_block_template = Block {
                header,
                transactions: ordered_txs,
            };

            if benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-CONSENSUS] proposal_select height={} view={} candidate_txs={} valid_txs={} select_ms={} verify_ms={}",
                    producing_h,
                    view,
                    candidate_txs.len(),
                    valid_txs.len(),
                    selection_elapsed.as_millis(),
                    verify_elapsed.as_millis(),
                );
                tracing::info!(
                    target: "consensus_bench",
                    height = producing_h,
                    view,
                    candidate_txs = candidate_txs.len(),
                    valid_txs = valid_txs.len(),
                    proposal_tx_max_bytes = proposal_tx_max_bytes,
                    select_ms = selection_elapsed.as_millis(),
                    verify_ms = verify_elapsed.as_millis(),
                    "proposal candidate selection timing"
                );
            }

            let process_started = Instant::now();
            match view_resolver
                .workload_client()
                .process_block(new_block_template)
                .await
            {
                Ok((final_block, _)) => {
                    let process_elapsed = process_started.elapsed();
                    if benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-CONSENSUS] proposal_process height={} view={} tx_count={} process_block_ms={}",
                            final_block.header.height,
                            view,
                            final_block.transactions.len(),
                            process_elapsed.as_millis(),
                        );
                        tracing::info!(
                            target: "consensus_bench",
                            height = final_block.header.height,
                            view,
                            tx_count = final_block.transactions.len(),
                            process_block_ms = process_elapsed.as_millis(),
                            "proposal process_block timing"
                        );
                    }
                    if process_elapsed.as_millis() >= 500 {
                        tracing::warn!(
                            target: "consensus",
                            height = final_block.header.height,
                            view,
                            tx_count = final_block.transactions.len(),
                            elapsed_ms = process_elapsed.as_millis(),
                            "workload_client.process_block() is slow"
                        );
                    }
                    if final_block.transactions.len() < valid_txs.len() {
                        tracing::info!(
                            target: "consensus",
                            height = final_block.header.height,
                            view,
                            proposed_valid_txs = valid_txs.len(),
                            included_txs = final_block.transactions.len(),
                            deferred_txs = valid_txs.len().saturating_sub(final_block.transactions.len()),
                            "Keeping valid-but-deferred transactions in the mempool for subsequent blocks."
                        );
                    }
                    let included_hashes = final_block
                        .transactions
                        .iter()
                        .filter_map(|tx| tx.hash().ok())
                        .collect::<std::collections::HashSet<_>>();
                    let deferred_transactions = valid_txs
                        .iter()
                        .filter_map(|tx| {
                            tx.hash()
                                .ok()
                                .filter(|hash| !included_hashes.contains(hash))
                                .map(|_| tx.clone())
                        })
                        .collect::<Vec<_>>();
                    let finalize_started = Instant::now();
                    crate::standard::orchestration::finalize::finalize_and_broadcast_block(
                        context_arc,
                        final_block,
                        deferred_transactions,
                        signer,
                        &swarm_commander,
                        &consensus_engine_ref,
                        &tx_pool_ref,
                        &node_state_arc,
                    )
                    .await?;
                    let finalize_elapsed = finalize_started.elapsed();
                    if benchmark_trace_enabled() {
                        eprintln!(
                            "[BENCH-CONSENSUS] proposal_finalize height={} view={} finalize_ms={}",
                            producing_h,
                            view,
                            finalize_elapsed.as_millis(),
                        );
                        tracing::info!(
                            target: "consensus_bench",
                            height = producing_h,
                            view,
                            finalize_ms = finalize_elapsed.as_millis(),
                            "proposal finalize_and_broadcast timing"
                        );
                    }
                    if finalize_elapsed.as_millis() >= 500 {
                        tracing::warn!(
                            target: "consensus",
                            height = producing_h,
                            view,
                            elapsed_ms = finalize_elapsed.as_millis(),
                            "finalize_and_broadcast_block() is slow"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(target: "consensus", "Block processing failed: {}", e);
                    return Err(anyhow!("Block processing failed: {}", e));
                }
            }
        }
        ioi_api::consensus::ConsensusDecision::WaitForBlock => {
            if benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-CONSENSUS] wait_for_block height={} cause={}",
                    producing_h, cause
                );
            }
        }
        ioi_api::consensus::ConsensusDecision::ProposeViewChange => {
            if benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-CONSENSUS] propose_view_change height={} cause={}",
                    producing_h, cause
                );
            }
        }
        ioi_api::consensus::ConsensusDecision::Stall => {
            if benchmark_trace_enabled() {
                eprintln!(
                    "[BENCH-CONSENSUS] stall height={} cause={}",
                    producing_h, cause
                );
            }
        }
    }
    Ok(())
}

pub(super) async fn resolve_parent_ref_and_anchor<V>(
    last_committed_block_opt: &Option<Block<ChainTransaction>>,
    recovered_tip_anchor: Option<&RecoveredConsensusTipAnchor>,
    view_resolver: &dyn ioi_api::chain::ViewResolver<Verifier = V>,
) -> Result<(StateRef, StateAnchor)>
where
    V: Verifier,
{
    let parent_ref = if let Some(parent_ref) = parent_ref_from_last_committed_or_recovered_tip(
        last_committed_block_opt,
        recovered_tip_anchor,
    )? {
        parent_ref
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

pub(super) fn verify_batch_and_filter(
    candidate_txs: &[ChainTransaction],
    batch_verifier: &dyn BatchVerifier,
    tx_pool: &Mempool,
) -> Result<Vec<ChainTransaction>> {
    struct BatchCandidate<'a> {
        index: usize,
        public_key: &'a [u8],
        sign_bytes: Vec<u8>,
        signature: &'a [u8],
        suite: SignatureSuite,
    }

    let mut batch_candidates = Vec::new();
    for (index, tx) in candidate_txs.iter().enumerate() {
        if let Ok(Some((_, proof, sign_bytes))) =
            ioi_tx::system::validation::get_signature_components(tx)
        {
            batch_candidates.push(BatchCandidate {
                index,
                public_key: proof.public_key.as_slice(),
                sign_bytes,
                signature: proof.signature.as_slice(),
                suite: proof.suite,
            });
        }
    }

    let batch_results = if batch_candidates.is_empty() {
        vec![]
    } else {
        let batch_items = batch_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.public_key,
                    candidate.sign_bytes.as_slice(),
                    candidate.signature,
                    candidate.suite,
                )
            })
            .collect::<Vec<_>>();
        batch_verifier.verify_batch(&batch_items)?
    };

    let mut valid_txs = Vec::with_capacity(candidate_txs.len());
    let mut verified_candidates = batch_candidates.into_iter().zip(batch_results.into_iter());
    let mut next_verified = verified_candidates.next();

    for (i, tx) in candidate_txs.iter().enumerate() {
        if next_verified
            .as_ref()
            .map(|(candidate, _)| candidate.index == i)
            .unwrap_or(false)
        {
            let (_, accepted) = next_verified.take().expect("verified candidate present");
            if accepted {
                valid_txs.push(tx.clone());
            } else if let Ok(h) = tx.hash() {
                tx_pool.remove_by_hash(&h);
            }
            next_verified = verified_candidates.next();
        } else {
            valid_txs.push(tx.clone());
        }
    }
    Ok(valid_txs)
}
