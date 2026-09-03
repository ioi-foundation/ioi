use super::consensus::aft_async_storage_paths;
use super::context::MainLoopContext;
use crate::metrics::consensus_metrics as metrics;
use anyhow::{anyhow, Result};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use ioi_consensus::aft::hash_async::{HashAsyncSession, HashAsyncSessionAction};
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::app::{
    aft_async_canonical_qc_reference, canonical_collapse_commitment_hash_from_object,
    canonical_collapse_extension_certificate, timestamp_millis_to_legacy_seconds,
    AftAsyncBatchProposalV1, AftAsyncCarrierBodyV1, AftAsyncCarrierV1, AftAsyncGeometryV1,
    AftAsyncInstanceV1, AftAsyncParentProofV1, Block, BlockHeader, ChainTransaction,
    FallbackStartCertificateV1, StateRoot,
};
use ioi_types::codec;
use ioi_types::error::ChainError;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::collections::{BTreeSet, VecDeque};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

fn carrier_class(body: &AftAsyncCarrierBodyV1) -> &'static str {
    match body {
        AftAsyncCarrierBodyV1::ProposalPayload { .. } => "proposal_payload",
        AftAsyncCarrierBodyV1::ProposalAvailabilityVote { .. } => "availability_vote",
        AftAsyncCarrierBodyV1::ProposalAvailabilityCertificate(_) => "availability_certificate",
        AftAsyncCarrierBodyV1::Message(_) => "protocol_message",
        AftAsyncCarrierBodyV1::DecisionVote(_) => "ordering_vote",
        AftAsyncCarrierBodyV1::OrderingCertificate(_) => "ordering_certificate",
        AftAsyncCarrierBodyV1::ExecutedBlockVote(_) => "executed_block_vote",
        AftAsyncCarrierBodyV1::ExecutedBlockCertificate(_) => "executed_block_certificate",
    }
}

/// Opens the durable per-height hash-only runtime only after the optimistic
/// engine accepted the complete fallback-start certificate.
pub(crate) fn activate<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    start: FallbackStartCertificateV1,
) -> Result<Vec<HashAsyncSessionAction>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let (set, registry) = context
        .aft_async_membership
        .as_ref()
        .ok_or_else(|| anyhow!("hash-only fallback has no rooted PQ membership"))?;
    let local_account = context
        .local_validator_account_id
        .ok_or_else(|| anyhow!("hash-only fallback has no rooted local account"))?;
    let signer = context
        .pqc_signer
        .as_ref()
        .ok_or_else(|| anyhow!("hash-only fallback has no local ML-DSA signer"))?;
    let custody_key = context
        .aft_async_custody_key
        .as_ref()
        .ok_or_else(|| anyhow!("hash-only fallback has no journal custody key"))?;
    let signing_fence = context
        .aft_cross_path_signing_fence
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("hash-only fallback has no shared durable signing fence"))?;
    let n = u16::try_from(set.validators.len())
        .map_err(|_| anyhow!("hash-only fallback membership exceeds u16"))?;
    let geometry = AftAsyncGeometryV1::exact(n).map_err(anyhow::Error::msg)?;
    let instance =
        AftAsyncInstanceV1::from_fallback_start(&start, geometry).map_err(anyhow::Error::msg)?;
    let instance_hash = instance.instance_hash().map_err(anyhow::Error::msg)?;
    if let Some((completed, _)) = context.aft_async_executed.get(&start.height) {
        let completed_instance_hash = completed
            .decision
            .instance
            .instance_hash()
            .map_err(anyhow::Error::msg)?;
        if completed_instance_hash != instance_hash {
            return Err(anyhow!(
                "completed hash-only fallback height names a conflicting instance"
            ));
        }
        // A completed height is a durable protocol tombstone for the lifetime
        // of this process. Relayed copies of its fallback-start witness must
        // not reopen the journal and replay the all-to-all protocol.
        return Ok(Vec::new());
    }
    if let Some(existing) = context.aft_async_sessions.get(&start.height) {
        if existing.instance_hash() != instance_hash {
            return Err(anyhow!(
                "hash-only fallback height already has a conflicting instance"
            ));
        }
        return Ok(Vec::new());
    }
    let paths = aft_async_storage_paths(
        context.config.aft_pq_outbox_dir.as_deref(),
        context.config.aft_external_anchor_dir.as_deref(),
        start.scope.configuration_hash,
        local_account,
        start.height,
    )?;
    let entropy = if paths.node_journal.exists() {
        None
    } else {
        let mut value = [0u8; 32];
        OsRng.fill_bytes(&mut value);
        Some(value)
    };
    let (session, replay) = HashAsyncSession::open(
        instance,
        local_account,
        signer.clone(),
        set.clone(),
        registry.clone(),
        signing_fence,
        &paths.node_journal,
        &paths.node_anchor,
        &paths.proposal_root,
        custody_key,
        entropy,
    )
    .map_err(|error| anyhow!(error.to_string()))?;
    context.aft_async_sessions.insert(start.height, session);
    metrics().set_aft_hash_async_active_sessions(context.aft_async_sessions.len() as u64);
    Ok(replay)
}

/// Routes a strict-PQ authenticated carrier to its exact active instance.
pub(crate) fn handle_carrier<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    authenticated_account: ioi_types::app::AccountId,
    carrier: AftAsyncCarrierV1,
) -> Result<Vec<HashAsyncSessionAction>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let started = Instant::now();
    carrier.validate_shape().map_err(anyhow::Error::msg)?;
    let carrier_bytes = codec::to_bytes_canonical(&carrier).map_err(anyhow::Error::msg)?;
    let class = carrier_class(&carrier.body);
    metrics().observe_aft_hash_async_message("inbound", class, carrier_bytes.len() as u64);
    let batch_verifier = context.batch_verifier.clone();
    let tx_pool = context.tx_pool_ref.clone();
    let session = context
        .aft_async_sessions
        .values_mut()
        .find(|session| session.instance_hash() == carrier.instance_hash)
        .ok_or_else(|| anyhow!("strict-PQ carrier names no active fallback instance"))?;
    let result = match carrier.body {
        AftAsyncCarrierBodyV1::ProposalPayload {
            descriptor,
            payload,
        } => {
            let proposal = codec::from_bytes_canonical::<AftAsyncBatchProposalV1>(&payload)
                .map_err(anyhow::Error::msg)?;
            proposal
                .validate_for(session.instance())
                .map_err(anyhow::Error::msg)?;
            let verified = super::consensus::verify_batch_and_filter(
                &proposal.transactions,
                batch_verifier.as_ref(),
                tx_pool.as_ref(),
            )?;
            if verified != proposal.transactions {
                return Err(anyhow!(
                    "asynchronous proposal contains an invalid transaction signature"
                ));
            }
            session
                .handle_validated_proposal_payload(authenticated_account, descriptor, payload)
                .map_err(|error| anyhow!(error.to_string()))
        }
        body => session
            .handle(
                authenticated_account,
                AftAsyncCarrierV1 {
                    protocol_version: carrier.protocol_version,
                    schema_version: carrier.schema_version,
                    instance_hash: carrier.instance_hash,
                    body,
                },
            )
            .map_err(|error| anyhow!(error.to_string())),
    };
    metrics().observe_aft_hash_async_stage_duration("ingress", started.elapsed().as_secs_f64());
    result
}

/// Builds one typed, signature-checked local transaction proposal for an
/// active fallback height and hands it to the durable availability pipeline.
pub(crate) fn propose_local<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    height: u64,
) -> Result<Vec<HashAsyncSessionAction>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    if context
        .aft_async_sessions
        .get(&height)
        .is_some_and(HashAsyncSession::has_local_proposal)
    {
        return Ok(Vec::new());
    }
    let candidates = context.tx_pool_ref.select_transactions(1_000);
    let bounded = super::consensus::trim_candidate_transactions_to_byte_budget(
        candidates,
        Some(4 * 1024 * 1024),
    )?;
    let verified = super::consensus::verify_batch_and_filter(
        &bounded,
        context.batch_verifier.as_ref(),
        context.tx_pool_ref.as_ref(),
    )?;
    let session = context
        .aft_async_sessions
        .get_mut(&height)
        .ok_or_else(|| anyhow!("no active hash-only fallback session at height {height}"))?;
    let proposal =
        AftAsyncBatchProposalV1::new(session.instance(), verified).map_err(anyhow::Error::msg)?;
    let payload = codec::to_bytes_canonical(&proposal).map_err(anyhow::Error::msg)?;
    session
        .propose(&payload)
        .map_err(|error| anyhow!(error.to_string()))
}

/// Maps runtime-neutral session effects to strict-PQ swarm commands and the
/// local verified-certificate queue. Every network action is durably addressed
/// to a rooted account; transient peer discovery may happen afterward.
pub(crate) async fn dispatch<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    actions: Vec<HashAsyncSessionAction>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let started = Instant::now();
    let mut pending = VecDeque::from(actions);
    while let Some(action) = pending.pop_front() {
        match action {
            HashAsyncSessionAction::Broadcast(carrier) => {
                let class = carrier_class(&carrier.body);
                let bytes = codec::to_bytes_canonical(&carrier).map_err(anyhow::Error::msg)?;
                let (sender, recipients) = {
                    let context = context_arc.lock().await;
                    let local = context.local_validator_account_id.ok_or_else(|| {
                        anyhow!("hash-only broadcast has no rooted local account")
                    })?;
                    let set = context
                        .aft_async_membership
                        .as_ref()
                        .ok_or_else(|| anyhow!("hash-only broadcast has no rooted membership"))?;
                    (
                        context.swarm_commander.clone(),
                        set.0
                            .validators
                            .iter()
                            .map(|member| member.account_id)
                            .filter(|account| *account != local)
                            .collect::<Vec<_>>(),
                    )
                };
                for recipient in recipients {
                    metrics().observe_aft_hash_async_message("outbound", class, bytes.len() as u64);
                    sender
                        .send(SwarmCommand::QueueAftAsyncOrdering {
                            recipient,
                            data: bytes.clone(),
                        })
                        .await
                        .map_err(|error| {
                            anyhow!("failed to queue hash-only broadcast recipient: {error}")
                        })?;
                }
            }
            HashAsyncSessionAction::Send { recipient, carrier } => {
                let class = carrier_class(&carrier.body);
                let sender = context_arc.lock().await.swarm_commander.clone();
                let bytes = codec::to_bytes_canonical(&carrier).map_err(anyhow::Error::msg)?;
                metrics().observe_aft_hash_async_message("outbound", class, bytes.len() as u64);
                sender
                    .send(SwarmCommand::QueueAftAsyncOrdering {
                        recipient,
                        data: bytes,
                    })
                    .await
                    .map_err(|error| {
                        anyhow!("failed to queue private hash-only message: {error}")
                    })?;
            }
            HashAsyncSessionAction::Finalized(certificate) => {
                let height = certificate.decision.instance.height;
                let decision_hash = certificate
                    .decision
                    .decision_hash()
                    .map_err(anyhow::Error::msg)?;
                let should_execute = {
                    let mut context = context_arc.lock().await;
                    let transactions = reconstruct_selected_batch(&context, &certificate)?;
                    match context.aft_async_finalized.get(&height) {
                        Some(previous)
                            if previous
                                .decision
                                .decision_hash()
                                .map_err(anyhow::Error::msg)?
                                != decision_hash =>
                        {
                            return Err(anyhow!(
                                "conflicting verified asynchronous decisions at one height"
                            ));
                        }
                        Some(_) => false,
                        None => {
                            context.aft_async_finalized.insert(height, certificate);
                            context
                                .aft_async_finalized_batches
                                .insert(height, transactions);
                            true
                        }
                    }
                };
                if should_execute {
                    pending.extend(execute_finalized_ordering(context_arc, height).await?);
                }
            }
            HashAsyncSessionAction::ExecutedBlockFinalized {
                certificate,
                witness,
            } => {
                let height = certificate.decision.instance.height;
                let instance_hash = certificate
                    .decision
                    .instance
                    .instance_hash()
                    .map_err(anyhow::Error::msg)?;
                let decision_hash = certificate
                    .decision
                    .decision_hash()
                    .map_err(anyhow::Error::msg)?;
                let mut context = context_arc.lock().await;
                let block = context
                    .view_resolver
                    .workload_client()
                    .get_block_by_height(height)
                    .await?
                    .ok_or_else(|| anyhow!("executed-block certificate has no workload block"))?;
                let block_hash = canonical_block_hash(&block)?;
                if block_hash != certificate.decision.block_hash {
                    return Err(anyhow!(
                        "executed-block certificate does not name the local workload block"
                    ));
                }
                match context.aft_async_executed.get(&height) {
                    Some((previous, _))
                        if previous
                            .decision
                            .decision_hash()
                            .map_err(anyhow::Error::msg)?
                            != decision_hash =>
                    {
                        return Err(anyhow!(
                            "conflicting verified executed-block decisions at one height"
                        ));
                    }
                    Some(_) => {}
                    None => {
                        let parent_proof = AftAsyncParentProofV1::new(
                            &block.header,
                            certificate.clone(),
                            witness.clone(),
                        )
                        .map_err(anyhow::Error::msg)?;
                        let admission_started = Instant::now();
                        super::runtime_finality::admit_hash_async_finalized(
                            &mut context,
                            certificate.clone(),
                            witness.clone(),
                        )
                        .await?;
                        metrics().observe_aft_hash_async_stage_duration(
                            "runtime_admission",
                            admission_started.elapsed().as_secs_f64(),
                        );
                        let parent_proof_started = Instant::now();
                        context
                            .consensus_engine_ref
                            .lock()
                            .await
                            .observe_aft_async_parent_proof(parent_proof)
                            .map_err(|error| anyhow!(error.to_string()))?;
                        metrics().observe_aft_hash_async_stage_duration(
                            "parent_proof_install",
                            parent_proof_started.elapsed().as_secs_f64(),
                        );
                        context
                            .aft_async_executed
                            .insert(height, (certificate, witness));
                        // The executed certificate and selected-batch witness
                        // are the completed-height tombstone. Retire the live
                        // session and its redundant ordering caches so delayed
                        // carriers cannot keep an all-to-all protocol alive
                        // while the optimistic path advances to H+1.
                        context.aft_async_sessions.remove(&height);
                        context.aft_async_finalized.remove(&height);
                        context.aft_async_finalized_batches.remove(&height);
                        context
                            .swarm_commander
                            .send(SwarmCommand::RetireAftAsyncOrdering { instance_hash })
                            .await
                            .map_err(|error| {
                                anyhow!("failed to retire terminal hash-async outbox: {error}")
                            })?;
                        metrics().set_aft_hash_async_active_sessions(
                            context.aft_async_sessions.len() as u64,
                        );
                        let _ = context.consensus_kick_tx.send(());
                    }
                }
            }
        }
    }
    metrics().observe_aft_hash_async_stage_duration("dispatch", started.elapsed().as_secs_f64());
    Ok(())
}

/// Deterministically materializes the ordered fallback batch, stages its
/// execution, and starts the exact-q block-hash round. The resulting block is
/// a virtual multi-producer envelope and never passes through optimistic
/// single-leader validation.
async fn execute_finalized_ordering<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    height: u64,
) -> Result<Vec<HashAsyncSessionAction>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let preparation_started = Instant::now();
    let (
        certificate,
        transactions,
        set,
        registry,
        workload,
        consensus_engine,
        live_tip,
        admitted_height,
    ) = {
        let context = context_arc.lock().await;
        let certificate = context
            .aft_async_finalized
            .get(&height)
            .cloned()
            .ok_or_else(|| anyhow!("missing finalized asynchronous ordering"))?;
        let transactions = context
            .aft_async_finalized_batches
            .get(&height)
            .cloned()
            .ok_or_else(|| anyhow!("missing finalized asynchronous batch"))?;
        let (set, registry) = context
            .aft_async_membership
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("missing rooted asynchronous membership"))?;
        (
            certificate,
            transactions,
            set,
            registry,
            context.view_resolver.workload_client().clone(),
            context.consensus_engine_ref.clone(),
            context.last_executed_block.clone(),
            super::runtime_finality::agentgres_admitted_height(&context).await?,
        )
    };
    let (previous_canonical_collapse_commitment_hash, canonical_collapse_extension_certificate) =
        if height <= 1 {
            ([0u8; 32], None)
        } else {
            let previous = consensus_engine
                .lock()
                .await
                .canonical_collapse_for_committed_height(height - 1)
                .ok_or_else(|| {
                    anyhow!(
                        "asynchronous execution lacks the admitted canonical collapse for parent height {}",
                        height - 1
                    )
                })?;
            let hash = canonical_collapse_commitment_hash_from_object(&previous)
                .map_err(anyhow::Error::msg)?;
            let certificate = canonical_collapse_extension_certificate(height, &previous)
                .map_err(anyhow::Error::msg)?;
            (hash, Some(certificate))
        };
    let instance = &certificate.decision.instance;
    // The workload commit precedes consensus broadcast/finalization. A crash,
    // timeout, or planted race can therefore leave its bounded speculative
    // projection ahead of orchestration's consensus-facing cache. Resolve the
    // fenced live bytes from the workload before falling back to that cache;
    // never advance the pacemaker merely because execution ran first.
    let child_height = height
        .checked_add(1)
        .ok_or_else(|| anyhow!("asynchronous fallback height overflow"))?;
    let live_tip = if let Some(child) = workload.get_block_by_height(child_height).await? {
        child
    } else if let Some(target) = workload.get_block_by_height(height).await? {
        target
    } else {
        live_tip.ok_or_else(|| anyhow!("asynchronous execution has no workload tip"))?
    };
    if height == 0
        || live_tip.header.height < height - 1
        || live_tip.header.height > height.saturating_add(1)
    {
        return Err(anyhow!(
            "asynchronous replacement requires the parent or bounded two-projection workload tip"
        ));
    }
    let parent = if live_tip.header.height == height - 1 {
        live_tip.clone()
    } else {
        workload
            .get_block_by_height(height - 1)
            .await?
            .ok_or_else(|| anyhow!("asynchronous replacement parent is unavailable"))?
    };
    let previous_hash = canonical_block_hash(&parent)?;
    if height > 1
        && (instance.fallback_start.highest_qc.height != height - 1
            || instance.fallback_start.highest_qc.block_hash != previous_hash)
    {
        return Err(anyhow!(
            "asynchronous fallback high QC is not the exact executed parent"
        ));
    }
    let virtual_member = set
        .validators
        .first()
        .ok_or_else(|| anyhow!("asynchronous membership is empty"))?;
    let virtual_key = registry
        .get(&virtual_member.consensus_key.public_key_hash)
        .ok_or_else(|| anyhow!("virtual asynchronous header lacks its rooted key"))?;
    let view = instance
        .fallback_start
        .trigger_certificate
        .consecutive_timeout_certificates
        .last()
        .map(|certificate| certificate.view.saturating_add(1))
        .ok_or_else(|| anyhow!("fallback trigger has no terminal view"))?;
    let existing_target = if live_tip.header.height >= height {
        Some(
            workload
                .get_block_by_height(height)
                .await?
                .ok_or_else(|| anyhow!("asynchronous replacement target is unavailable"))?,
        )
    } else {
        None
    };
    if let Some(executed) = existing_target.as_ref() {
        let is_recovered_virtual = transactions == executed.transactions
            && executed.header.view == view
            && executed.header.parent_qc
                == aft_async_canonical_qc_reference(&instance.fallback_start.highest_qc)
            && executed.header.producer_account_id == virtual_member.account_id
            && executed.header.producer_key_suite == virtual_member.consensus_key.suite
            && executed.header.producer_pubkey_hash == virtual_member.consensus_key.public_key_hash
            && executed.header.producer_pubkey == virtual_key.raw()
            && executed.header.signature.is_empty();
        if is_recovered_virtual {
            let block_hash = canonical_block_hash(executed)?;
            let mut context = context_arc.lock().await;
            let session = context
                .aft_async_sessions
                .get_mut(&height)
                .ok_or_else(|| anyhow!("recovered asynchronous session disappeared"))?;
            return session
                .begin_executed_block(block_hash)
                .map_err(|error| anyhow!(error.to_string()));
        }
        if admitted_height >= height {
            return Err(anyhow!(
                "cannot replace an optimistic workload block already admitted by Agentgres"
            ));
        }
    }
    let timestamp_ms = parent.header.timestamp_ms_or_legacy().saturating_add(1);
    let template = Block {
        header: BlockHeader {
            height,
            view,
            parent_hash: if height == 1 { [0; 32] } else { previous_hash },
            parent_state_root: StateRoot(parent.header.state_root.0.clone()),
            state_root: StateRoot(Vec::new()),
            transactions_root: Vec::new(),
            timestamp: timestamp_millis_to_legacy_seconds(timestamp_ms),
            timestamp_ms,
            gas_used: 0,
            validator_set: set
                .validators
                .iter()
                .map(|member| member.account_id.0.to_vec())
                .collect(),
            producer_account_id: virtual_member.account_id,
            producer_key_suite: virtual_member.consensus_key.suite,
            producer_pubkey_hash: virtual_member.consensus_key.public_key_hash,
            producer_pubkey: virtual_key.raw().to_vec(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0; 32],
            parent_qc: aft_async_canonical_qc_reference(&instance.fallback_start.highest_qc),
            previous_canonical_collapse_commitment_hash,
            canonical_collapse_extension_certificate,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
        },
        transactions,
    };
    metrics().observe_aft_hash_async_stage_duration(
        "execution_prepare",
        preparation_started.elapsed().as_secs_f64(),
    );
    let workload_started = Instant::now();
    let (block, _, receipts) = if let Some(expected_target) = existing_target {
        match workload
            .replace_unfinalized_tip(expected_target, live_tip, template, admitted_height)
            .await
        {
            Ok(processed) => processed,
            Err(ChainError::Transaction(error)) => {
                return Err(anyhow!(
                    "bounded optimistic/fallback replacement was safely refused: {error}"
                ));
            }
            Err(error) => {
                context_arc
                    .lock()
                    .await
                    .is_quarantined
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(anyhow!(
                    "bounded optimistic/fallback replacement has uncertain durability; node frozen: {error}"
                ));
            }
        }
    } else {
        workload.process_block(template).await?
    };
    metrics().observe_aft_hash_async_stage_duration(
        "workload_execution",
        workload_started.elapsed().as_secs_f64(),
    );
    let block_hash = canonical_block_hash(&block)?;
    let mut context = context_arc.lock().await;
    let runtime_stage_started = Instant::now();
    super::runtime_finality::stage_runtime_block(&context, block.clone(), receipts).await?;
    metrics().observe_aft_hash_async_stage_duration(
        "runtime_stage",
        runtime_stage_started.elapsed().as_secs_f64(),
    );
    context.last_executed_block = Some(block);
    let session = context
        .aft_async_sessions
        .get_mut(&height)
        .ok_or_else(|| anyhow!("executed asynchronous session disappeared"))?;
    session
        .begin_executed_block(block_hash)
        .map_err(|error| anyhow!(error.to_string()))
}

fn canonical_block_hash(block: &Block<ChainTransaction>) -> Result<[u8; 32]> {
    block
        .header
        .hash()
        .map_err(|error| anyhow!(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("block header hash is not 32 bytes"))
}

/// Materializes the exact canonical transaction batch authorized by an
/// ordering certificate. Selected proposal order is already canonical; a
/// transaction repeated by multiple available proposals is retained once at
/// its first canonical occurrence.
fn reconstruct_selected_batch<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
    certificate: &ioi_types::app::AftAsyncOrderingCertificateV1,
) -> Result<Vec<ChainTransaction>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let height = certificate.decision.instance.height;
    let session = context
        .aft_async_sessions
        .get(&height)
        .ok_or_else(|| anyhow!("verified asynchronous result has no active session"))?;
    let payloads = session
        .selected_payloads(certificate)
        .map_err(|error| anyhow!(error.to_string()))?;
    let mut seen = BTreeSet::new();
    let mut transactions = Vec::new();
    for payload in payloads {
        let proposal = codec::from_bytes_canonical::<AftAsyncBatchProposalV1>(&payload)
            .map_err(anyhow::Error::msg)?;
        proposal
            .validate_for(session.instance())
            .map_err(anyhow::Error::msg)?;
        for transaction in proposal.transactions {
            let hash = transaction
                .hash()
                .map_err(|error| anyhow!(error.to_string()))?;
            if seen.insert(hash) {
                transactions.push(transaction);
            }
        }
    }
    let verified = super::consensus::verify_batch_and_filter(
        &transactions,
        context.batch_verifier.as_ref(),
        context.tx_pool_ref.as_ref(),
    )?;
    if verified != transactions {
        return Err(anyhow!(
            "asynchronous ordering selected a transaction that failed final signature verification"
        ));
    }
    Ok(transactions)
}
