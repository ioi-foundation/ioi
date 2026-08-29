// Path: crates/validator/src/standard/orchestration/sync.rs

//! The part of the libp2p implementation handling the BlockSync trait.

use super::{
    aft_collapse::observe_live_committed_chain_through_block,
    context::{MainLoopContext, SyncProgress},
    gossip,
};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use ioi_networking::libp2p::{SwarmCommand, SyncResponse};
use ioi_networking::traits::NodeState;
use ioi_types::app::{Block, ChainTransaction};
use ioi_types::config::RuntimeFinalityProfile;
use ioi_types::error::ChainError;
use libp2p::{request_response::ResponseChannel, PeerId};
use serde::Serialize;
use std::fmt::Debug;

// [FIX] Imports for catchup voting
use ioi_types::app::{
    account_id_from_key_material, to_root_hash, AccountId, ConsensusVote, SignatureSuite,
};
use ioi_types::codec;
use std::time::Instant;

// --- BlockSync Trait Implementation ---

pub(crate) fn sync_batch_max_bytes() -> u32 {
    std::env::var("IOI_AFT_SYNC_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value >= 4 * 1024 * 1024)
        .unwrap_or(64 * 1024 * 1024)
}

pub(crate) fn sync_batch_max_blocks() -> u32 {
    std::env::var("IOI_AFT_SYNC_MAX_BLOCKS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(50)
}

// The workload can persist the block currently being finalized before orchestration has
// committed its final identity metadata. Sync may expose history only through orchestration's
// committed tip, and the boundary block must be that exact identity.
fn sync_response_entry_is_committed(
    candidate_height: u64,
    candidate_hash: Option<&[u8]>,
    committed_height: u64,
    committed_hash: Option<&[u8]>,
) -> bool {
    candidate_height < committed_height
        || (candidate_height == committed_height
            && candidate_hash.is_some()
            && candidate_hash == committed_hash)
}

/// Sync follows canonical truth, not the workload's speculative execution tip.
///
/// A native-AFT workload can be one or two projections ahead of Agentgres while
/// it waits for descendant-QC finality. Starting a catch-up request from that
/// unadmitted height omits the canonical competing block and makes the next
/// peer block impossible to execute against the local parent state.
async fn agentgres_sync_floor<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
) -> Option<u64>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    match super::runtime_finality::agentgres_admitted_height(context).await {
        Ok(height) => Some(height),
        Err(error) => {
            context
                .is_quarantined
                .store(true, std::sync::atomic::Ordering::SeqCst);
            tracing::error!(
                target: "sync",
                error = %error,
                "Cannot establish the Agentgres sync floor; node frozen"
            );
            None
        }
    }
}

fn within_aft_sync_replacement_window(live_height: u64, target_height: u64) -> bool {
    live_height >= target_height && live_height.saturating_sub(target_height) <= 1
}

fn sync_cursor_when_peer_is_ahead(
    executed_height: u64,
    admitted_height: u64,
    peer_height: u64,
) -> Option<u64> {
    (peer_height > executed_height).then_some(admitted_height)
}

pub async fn start_catchup_to_peer<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer: PeerId,
    peer_height: u64,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let executed_height = context
        .last_executed_block
        .as_ref()
        .map(|block| block.header.height)
        .unwrap_or(0);

    let Some(canonical_height) = agentgres_sync_floor(context).await else {
        return;
    };
    let Some(sync_cursor) =
        sync_cursor_when_peer_is_ahead(executed_height, canonical_height, peer_height)
    else {
        return;
    };

    if let Some(progress) = context.sync_progress.as_mut() {
        if peer_height > progress.tip {
            tracing::info!(
                target: "sync",
                %peer,
                executed_height,
                canonical_height,
                previous_tip = progress.tip,
                peer_height,
                current_target = ?progress.target,
                "Extending catch-up sync tip from a gossiped height gap."
            );
            progress.tip = peer_height;
        }

        if progress.target.is_none() {
            progress.target = Some(peer);
        }

        if !progress.inflight {
            request_next_batch(context).await;
        }
        return;
    }

    tracing::info!(
        target: "sync",
        %peer,
        executed_height,
        canonical_height,
        peer_height,
        "Starting catch-up sync from a gossiped height gap."
    );

    *context.node_state.lock().await = NodeState::Syncing;
    context.sync_progress = Some(SyncProgress {
        target: Some(peer),
        tip: peer_height,
        next: sync_cursor,
        inflight: false,
        req_id: 0,
        requested_at: Instant::now(),
    });
    request_next_batch(context).await;
}

/// Handles a request for our node's status.
pub async fn handle_status_request<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    _peer: PeerId,
    channel: ResponseChannel<SyncResponse>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let (height, head_hash, chain_id) = {
        let chain = context.chain_ref.lock().await;
        let status = (*chain).status();
        let head_hash = (*chain)
            .get_block(status.height)
            .and_then(|b| b.header.hash().ok())
            .and_then(|h| h.try_into().ok())
            .unwrap_or([0; 32]);
        (status.height, head_hash, context.chain_id)
    };
    let genesis_root = context
        .view_resolver
        .genesis_root()
        .await
        .unwrap_or_default();
    let validator_account_id = Some(AccountId(
        account_id_from_key_material(
            SignatureSuite::ED25519,
            &context.local_keypair.public().encode_protobuf(),
        )
        .unwrap_or_default(),
    ));
    tracing::info!(
        target: "sync",
        %_peer,
        height,
        head = %hex::encode(&head_hash[..4]),
        chain_id = chain_id.0,
        genesis_root = %hex::encode(&genesis_root[..4.min(genesis_root.len())]),
        "Responding to status request."
    );
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusResponse {
            channel,
            height,
            head_hash,
            chain_id,
            genesis_root,
            validator_account_id,
        })
        .await
        .ok();
}

/// Handles a request for blocks from a peer.
pub async fn handle_blocks_request<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    _peer: PeerId,
    since: u64,
    max_blocks: u32,
    max_bytes: u32,
    channel: ResponseChannel<SyncResponse>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let committed_tip = context.last_executed_block.as_ref();
    let committed_height = committed_tip.map(|block| block.header.height).unwrap_or(0);
    let committed_hash = committed_tip.and_then(|block| block.header.hash().ok());
    let mut blocks = context
        .view_resolver
        .workload_client()
        .get_blocks_range(since + 1, max_blocks, max_bytes)
        .await
        .unwrap_or_default();
    let fetched_blocks = blocks.len();
    blocks.retain(|block| {
        let candidate_hash = (block.header.height == committed_height)
            .then(|| block.header.hash().ok())
            .flatten();
        sync_response_entry_is_committed(
            block.header.height,
            candidate_hash.as_deref(),
            committed_height,
            committed_hash.as_deref(),
        )
    });
    if blocks.len() != fetched_blocks {
        tracing::debug!(
            target: "sync",
            requested_since = since,
            committed_height,
            fetched_blocks,
            returned_blocks = blocks.len(),
            "Withheld workload blocks that are not yet orchestration-committed."
        );
    }
    context
        .swarm_commander
        .send(SwarmCommand::SendBlocksResponse(channel, blocks))
        .await
        .ok();
}

/// Handles receiving a status response from a peer, potentially triggering a sync.
pub async fn handle_status_response<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer: PeerId,
    peer_height: u64,
    _peer_head_hash: [u8; 32],
    peer_chain_id: ioi_types::app::ChainId,
    peer_genesis_root: Vec<u8>,
    validator_account_id: Option<AccountId>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    if let Some(account_id) = validator_account_id {
        context
            .peer_accounts_ref
            .lock()
            .await
            .insert(peer, account_id);
    }

    let our_height = context
        .last_executed_block
        .as_ref()
        .map(|block| block.header.height)
        .unwrap_or(0);
    let Some(canonical_height) = agentgres_sync_floor(context).await else {
        return;
    };
    let sync_cursor = sync_cursor_when_peer_is_ahead(our_height, canonical_height, peer_height);

    tracing::info!(
        target: "sync",
        %peer,
        peer_height,
        our_height,
        peer_chain_id = peer_chain_id.0,
        our_chain_id = context.chain_id.0,
        peer_genesis_root = %hex::encode(&peer_genesis_root[..4.min(peer_genesis_root.len())]),
        "Received status response."
    );

    if let Some(sync_cursor) = sync_cursor {
        let our_chain_id = context.chain_id;
        let our_genesis_root = match context.view_resolver.genesis_root().await {
            Ok(root) => root,
            Err(_) => return,
        };
        if peer_chain_id != our_chain_id || peer_genesis_root != our_genesis_root {
            log::warn!(
                "Ignoring peer {} for sync due to chain identity mismatch. our_chain_id={} peer_chain_id={} our_genesis={} peer_genesis={}",
                peer,
                our_chain_id.0,
                peer_chain_id.0,
                hex::encode(&our_genesis_root[..4.min(our_genesis_root.len())]),
                hex::encode(&peer_genesis_root[..4.min(peer_genesis_root.len())]),
            );
            return;
        }

        if let Some(progress) = context.sync_progress.as_mut() {
            if peer_height > progress.tip {
                tracing::info!(
                    target: "orchestration",
                    %peer,
                    previous_tip = progress.tip,
                    peer_height,
                    current_target = ?progress.target,
                    "Extending existing sync tip from peer status."
                );
                progress.tip = peer_height;
            }
            if progress.target.is_none() {
                progress.target = Some(peer);
            }
            if !progress.inflight {
                request_next_batch(context).await;
            }
        } else {
            tracing::info!(
                target: "orchestration",
                %peer,
                our_height,
                canonical_height,
                "Initiating sync from the Agentgres-admitted cursor."
            );
            *context.node_state.lock().await = NodeState::Syncing;
            context.sync_progress = Some(SyncProgress {
                target: Some(peer),
                tip: peer_height,
                next: sync_cursor,
                inflight: false,
                req_id: 0,
                requested_at: Instant::now(),
            });
            request_next_batch(context).await;
        }
    } else {
        let bootstrap_no_catchup = our_height == 0 && peer_height == 0;
        let node_state_is_syncing = *context.node_state.lock().await == NodeState::Syncing;
        if node_state_is_syncing && (context.sync_progress.is_none() || bootstrap_no_catchup) {
            if bootstrap_no_catchup {
                context.sync_progress = None;
            }
            *context.node_state.lock().await = NodeState::Synced;
            let _ = context.consensus_kick_tx.send(());
            tracing::info!(
                target: "orchestration",
                %peer,
                peer_height,
                our_height,
                bootstrap_no_catchup,
                "State -> Synced (status confirmed no catch-up needed)."
            );
        }
    }
}

/// Handles receiving a block response from a peer during sync.
pub async fn handle_blocks_response<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer: PeerId,
    blocks: Vec<Block<ChainTransaction>>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let mut blocks = blocks;
    let workload_client = context.view_resolver.workload_client().clone();
    if context.sync_progress.is_none() {
        let Some(local_height) = agentgres_sync_floor(context).await else {
            return;
        };
        let first_new_index = blocks
            .iter()
            .position(|block| block.header.height > local_height);
        let sequential_blocks = first_new_index
            .map(|index| blocks.split_off(index))
            .unwrap_or_default();
        let bootstrap_tip = sequential_blocks
            .last()
            .map(|block| block.header.height)
            .unwrap_or(0);
        let first_height = sequential_blocks
            .first()
            .map(|block| block.header.height)
            .unwrap_or(0);

        if !sequential_blocks.is_empty() && first_height == local_height + 1 {
            tracing::info!(
                target: "sync",
                %peer,
                received_blocks = sequential_blocks.len(),
                local_height,
                bootstrap_tip,
                "Adopting opportunistic sequential blocks response."
            );
            context.sync_progress = Some(SyncProgress {
                target: Some(peer),
                tip: bootstrap_tip,
                next: local_height,
                inflight: false,
                req_id: 0,
                requested_at: Instant::now(),
            });
            blocks = sequential_blocks;
        } else {
            for block in &blocks {
                if let Err(error) =
                    gossip::maybe_apply_block_enrichment(context, block, false).await
                {
                    tracing::warn!(
                        target: "sync",
                        %peer,
                        height = block.header.height,
                        view = block.header.view,
                        error = %error,
                        "Rejected opportunistic block enrichment from sync response."
                    );
                }
            }
            return;
        }
    }

    let Some(canonical_height) = agentgres_sync_floor(context).await else {
        return;
    };
    {
        let Some(progress) = context.sync_progress.as_mut() else {
            return;
        };
        if progress.target != Some(peer) {
            return;
        }
        progress.inflight = false;
        if canonical_height > progress.next {
            tracing::debug!(
                target: "sync",
                %peer,
                canonical_height,
                previous_next = progress.next,
                tip = progress.tip,
                "Advancing sync cursor to the Agentgres-admitted height before applying batch."
            );
            progress.next = canonical_height;
        }
    }

    let (next, tip) = match context.sync_progress.as_ref() {
        Some(progress) => (progress.next, progress.tip),
        None => return,
    };

    tracing::info!(
        target: "sync",
        %peer,
        received_blocks = blocks.len(),
        next,
        tip,
        "Received blocks response."
    );

    let mut blocks = blocks;
    let already_applied_prefix = blocks
        .iter()
        .take_while(|block| block.header.height <= next)
        .count();
    if already_applied_prefix > 0 {
        for block in &blocks[..already_applied_prefix] {
            if let Err(error) = gossip::maybe_apply_block_enrichment(context, block, false).await {
                tracing::warn!(
                    target: "sync",
                    %peer,
                    height = block.header.height,
                    view = block.header.view,
                    error = %error,
                    "Rejected block enrichment from an already-applied sync prefix."
                );
            }
        }
        tracing::debug!(
            target: "sync",
            %peer,
            already_applied_prefix,
            next,
            tip,
            "Skipping already-applied prefix from sync batch."
        );
        blocks.drain(0..already_applied_prefix);
    }

    if blocks.is_empty() {
        if next >= tip {
            finish_sync(context).await;
        } else {
            tracing::warn!(
                target: "sync",
                %peer,
                next,
                tip,
                "Peer returned only already-applied or empty blocks while we are still behind; retrying sync."
            );
            retry_sync_from_peer_set(context, Some(peer)).await;
        }
        return;
    }

    let Some(first_block) = blocks.get(0) else {
        return;
    };
    let first_block_height = first_block.header.height;
    if first_block_height != next + 1 {
        tracing::warn!(
            target: "sync",
            %peer,
            expected_next = next + 1,
            received_first = first_block_height,
            tip,
            received_blocks = blocks.len(),
            "Dropping sync progress because the peer returned a non-consecutive block batch."
        );
        retry_sync_from_peer_set(context, Some(peer)).await;
        return;
    }

    for block in blocks {
        let applying_height = block.header.height;
        let workload_height = workload_client
            .get_status()
            .await
            .map(|status| status.height)
            .unwrap_or_else(|_| {
                context
                    .last_executed_block
                    .as_ref()
                    .map(|candidate| candidate.header.height)
                    .unwrap_or(0)
            });

        let processed_block = if workload_height >= applying_height {
            match super::runtime_finality::stage_execution_equivalent_candidate(
                context,
                block.clone(),
            )
            .await
            {
                Ok(true) => {
                    if let Err(error) = workload_client.update_block_header(block.clone()).await {
                        tracing::warn!(
                            target: "sync",
                            %peer,
                            applying_height,
                            workload_height,
                            error = %error,
                            "Execution-equivalent synced block could not reconcile its exact header."
                        );
                        retry_sync_from_peer_set(context, Some(peer)).await;
                        return;
                    }
                    tracing::info!(
                        target: "sync",
                        %peer,
                        applying_height,
                        workload_height,
                        "Reconciled an execution-equivalent synced block against the speculative workload projection."
                    );
                    block.clone()
                }
                Ok(false) => {
                    let active_profile = match context
                        .runtime_finality
                        .lock()
                        .await
                        .active_profile()
                    {
                        Ok(profile) => profile,
                        Err(error) => {
                            context
                                .is_quarantined
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                            tracing::error!(
                                target: "sync",
                                applying_height,
                                error = %error,
                                "Cannot establish the active profile for sync reconciliation; node frozen"
                            );
                            return;
                        }
                    };
                    if active_profile != RuntimeFinalityProfile::BftConsensusAftV1 {
                        context
                            .is_quarantined
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        tracing::error!(
                            target: "sync",
                            applying_height,
                            workload_height,
                            "Single-authority workload disagrees with committed sync history; node frozen"
                        );
                        return;
                    }
                    let Some(admitted_height) = agentgres_sync_floor(context).await else {
                        return;
                    };
                    if applying_height <= admitted_height
                        || !within_aft_sync_replacement_window(workload_height, applying_height)
                    {
                        context
                            .is_quarantined
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        tracing::error!(
                            target: "sync",
                            applying_height,
                            workload_height,
                            admitted_height,
                            "Committed sync history disagrees outside the bounded unadmitted AFT projection window; node frozen"
                        );
                        return;
                    }
                    let expected_target = match workload_client
                        .get_block_by_height(applying_height)
                        .await
                    {
                        Ok(Some(target)) => target,
                        Ok(None) => {
                            tracing::warn!(
                                target: "sync",
                                %peer,
                                applying_height,
                                "Cannot reconcile synced AFT history without the exact local target block."
                            );
                            retry_sync_from_peer_set(context, Some(peer)).await;
                            return;
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "sync",
                                %peer,
                                applying_height,
                                error = %error,
                                "Cannot read the exact local AFT replacement target."
                            );
                            retry_sync_from_peer_set(context, Some(peer)).await;
                            return;
                        }
                    };
                    let expected_live_tip = match workload_client
                        .get_block_by_height(workload_height)
                        .await
                    {
                        Ok(Some(target)) => target,
                        Ok(None) => {
                            tracing::warn!(
                                target: "sync",
                                %peer,
                                applying_height,
                                workload_height,
                                "Cannot reconcile synced AFT history without the exact local live tip."
                            );
                            retry_sync_from_peer_set(context, Some(peer)).await;
                            return;
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "sync",
                                %peer,
                                applying_height,
                                workload_height,
                                error = %error,
                                "Cannot read the exact local AFT live tip for replacement."
                            );
                            retry_sync_from_peer_set(context, Some(peer)).await;
                            return;
                        }
                    };
                    let (processed_block, execution_receipts) = match workload_client
                        .replace_unfinalized_tip(
                            expected_target,
                            expected_live_tip,
                            block.clone(),
                            admitted_height,
                        )
                        .await
                    {
                        Ok((processed, _, receipts)) => (processed, receipts),
                        Err(ChainError::Transaction(error)) => {
                            tracing::warn!(
                                target: "sync",
                                %peer,
                                applying_height,
                                workload_height,
                                admitted_height,
                                error = %error,
                                "Peer AFT branch was refused before mutation or the original projection was restored."
                            );
                            retry_sync_from_peer_set(context, Some(peer)).await;
                            return;
                        }
                        Err(error) => {
                            context
                                .is_quarantined
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                            tracing::error!(
                                target: "sync",
                                applying_height,
                                workload_height,
                                admitted_height,
                                error = %error,
                                "Atomic AFT sync replacement failed with uncertain durability; node frozen"
                            );
                            return;
                        }
                    };
                    if let Err(error) = super::runtime_finality::stage_runtime_block(
                        context,
                        processed_block.clone(),
                        execution_receipts,
                    )
                    .await
                    {
                        context
                            .is_quarantined
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        tracing::error!(
                            target: "sync",
                            applying_height,
                            error = %error,
                            "Terminal runtime finality staging refusal after AFT sync replacement; node frozen"
                        );
                        return;
                    }
                    tracing::info!(
                        target: "sync",
                        %peer,
                        applying_height,
                        workload_height,
                        admitted_height,
                        "Atomically replaced an unadmitted AFT workload projection from committed sync history."
                    );
                    processed_block
                }
                Err(error) => {
                    context
                        .is_quarantined
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    tracing::error!(
                        target: "sync",
                        applying_height,
                        workload_height,
                        error = %error,
                        "Could not prove or replace the existing synced projection; node frozen"
                    );
                    return;
                }
            }
        } else {
            let (processed_block, execution_receipts) =
                match workload_client.process_block(block.clone()).await {
                    Ok((processed_block, _, execution_receipts)) => {
                        (processed_block, execution_receipts)
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: "sync",
                            %peer,
                            expected_next = context
                                .sync_progress
                                .as_ref()
                                .map(|progress| progress.next + 1)
                                .unwrap_or(applying_height),
                            applying_height,
                            tip,
                            error = %error,
                            "Dropping sync progress because applying a synced block failed."
                        );
                        retry_sync_from_peer_set(context, Some(peer)).await;
                        return;
                    }
                };
            if let Err(error) = super::runtime_finality::stage_runtime_block(
                context,
                processed_block.clone(),
                execution_receipts,
            )
            .await
            {
                context
                    .is_quarantined
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                tracing::error!(
                    target: "consensus",
                    height = processed_block.header.height,
                    error = %error,
                    "Terminal runtime finality staging refusal during sync; node frozen"
                );
                return;
            }
            processed_block
        };
        if let Some(progress) = context.sync_progress.as_mut() {
            progress.next = processed_block.header.height;
        }
        context.last_executed_block = match workload_client.get_status().await {
            Ok(status) => workload_client
                .get_block_by_height(status.height)
                .await
                .ok()
                .flatten()
                .or_else(|| Some(processed_block.clone())),
            Err(_) => Some(processed_block.clone()),
        };
        match observe_live_committed_chain_through_block(
            &context.consensus_engine_ref,
            context.config.consensus_type,
            workload_client.as_ref(),
            &processed_block,
        )
        .await
        {
            Ok(true) => context
                .consensus_engine_ref
                .lock()
                .await
                .reset(processed_block.header.height),
            Ok(false) => tracing::warn!(
                target: "sync",
                height = processed_block.header.height,
                "Consensus engine ignored the synced execution hint because it was not collapse-backed"
            ),
            Err(error) => {
                tracing::warn!(
                    target: "sync",
                    height = processed_block.header.height,
                    error = %error,
                    "Could not reconcile synced execution with the live consensus engine"
                );
                retry_sync_from_peer_set(context, Some(peer)).await;
                return;
            }
        }
        if let Err(error) =
            super::runtime_finality::admit_available(context, Some(&processed_block)).await
        {
            context
                .is_quarantined
                .store(true, std::sync::atomic::Ordering::SeqCst);
            tracing::error!(
                target: "consensus",
                height = processed_block.header.height,
                error = %error,
                "Terminal runtime finality admission refusal during sync; node frozen"
            );
            return;
        }
    }

    if context
        .sync_progress
        .as_ref()
        .map(|progress| progress.next < progress.tip)
        .unwrap_or(false)
    {
        request_next_batch(context).await;
    } else {
        finish_sync(context).await;
    }
}

async fn retry_sync_from_peer_set<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    failed_peer: Option<PeerId>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let Some(progress) = context.sync_progress.as_mut() else {
        return;
    };

    let preferred_target = progress.target.filter(|peer| Some(*peer) != failed_peer);
    progress.inflight = false;
    progress.requested_at = Instant::now();

    let fallback_target = {
        let known_peers = context.known_peers_ref.lock().await;
        known_peers
            .iter()
            .copied()
            .find(|peer| Some(*peer) != failed_peer)
    };

    progress.target = preferred_target.or(fallback_target);

    if progress.target.is_some() {
        request_next_batch(context).await;
    } else {
        tracing::warn!(
            target: "sync",
            failed_peer = ?failed_peer,
            next = progress.next,
            tip = progress.tip,
            "No sync target available after retry request."
        );
    }
}

async fn finish_sync<CS, ST, CE, V>(context: &mut MainLoopContext<CS, ST, CE, V>)
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    *context.node_state.lock().await = NodeState::Synced;
    context.sync_progress = None;
    log::info!("Block sync complete!");

    if let Some(tip_block) = context.last_executed_block.clone() {
        // [FIX] Reset the consensus engine to the new tip so it doesn't think it's behind.
        context
            .consensus_engine_ref
            .lock()
            .await
            .reset(tip_block.header.height);

        // [FIX] Trigger a "Catchup Vote" for the tip block.
        // This ensures that even if we synced the block (instead of producing/voting in real-time),
        // we still contribute to the Quorum Certificate for this height.
        // This is critical for liveness in small clusters where >1/3 of nodes might sync initially.
        trigger_catchup_vote(context, &tip_block).await;
    }
}

pub(crate) async fn request_next_batch<CS, ST, CE, V>(context: &mut MainLoopContext<CS, ST, CE, V>)
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    if let Some(progress) = context.sync_progress.as_mut() {
        if progress.inflight {
            return;
        }
        let Some(target_peer) = progress.target else {
            return;
        };
        tracing::info!(
            target: "sync",
            %target_peer,
            since = progress.next,
            tip = progress.tip,
            "Requesting next sync batch."
        );
        progress.inflight = true;
        progress.req_id += 1;
        progress.requested_at = Instant::now();
        context
            .swarm_commander
            .send(SwarmCommand::SendBlocksRequest {
                peer: target_peer,
                since: progress.next,
                max_blocks: sync_batch_max_blocks(),
                max_bytes: sync_batch_max_bytes(),
            })
            .await
            .ok();
    }
}

pub async fn handle_outbound_failure<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    failed_peer: PeerId,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    // Request/response outbound failures are not a strong enough signal to evict a peer
    // from the cluster view. Under heavy relay load they can fire transiently even while
    // the underlying libp2p connection is still healthy or about to recover. Keep the
    // peer/account mappings intact here and let confirmed transport loss be handled by the
    // connection-closed path instead.

    let Some(progress) = context.sync_progress.as_mut() else {
        return;
    };

    if progress.target == Some(failed_peer) {
        progress.inflight = false;
        progress.target = None;

        let new_target = {
            let known_peers = context.known_peers_ref.lock().await;
            known_peers.iter().find(|p| **p != failed_peer).cloned()
        };

        if let Some(new_peer) = new_target {
            tracing::info!(
                target: "orchestration",
                "Sync target {} failed. Switching to new target {}",
                failed_peer,
                new_peer
            );
            progress.target = Some(new_peer);
            request_next_batch(context).await;
        } else {
            tracing::warn!(
                target: "orchestration",
                "Sync target {} failed. No other peers available.",
                failed_peer
            );
        }
    }
}

/// Helper to cast a vote for a block we just synced, ensuring liveness.
async fn trigger_catchup_vote<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    block: &Block<ChainTransaction>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    // Don't vote for Genesis (Height 0)
    if block.header.height == 0 {
        return;
    }

    let vote_height = block.header.height;
    let vote_view = block.header.view;
    let vote_hash_vec = block.header.hash().unwrap_or(vec![0u8; 32]);
    let vote_hash = to_root_hash(&vote_hash_vec).unwrap_or([0u8; 32]);

    let our_pk = context.local_keypair.public().encode_protobuf();
    let our_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &our_pk).unwrap_or([0u8; 32]),
    );

    // Sign Vote
    let vote_payload = (vote_height, vote_view, vote_hash);
    if let Ok(vote_bytes) = codec::to_bytes_canonical(&vote_payload) {
        if let Ok(sig) = context.local_keypair.sign(&vote_bytes) {
            let vote = ConsensusVote {
                height: vote_height,
                view: vote_view,
                block_hash: vote_hash,
                voter: our_id,
                signature: sig,
            };

            if let Ok(vote_blob) = codec::to_bytes_canonical(&vote) {
                // 1. Broadcast to network
                let _ = context
                    .swarm_commander
                    .send(SwarmCommand::BroadcastVote(vote_blob))
                    .await;

                tracing::info!(
                    target: "consensus",
                    "Broadcast catchup vote for block {} (H={} V={})",
                    hex::encode(&vote_hash[..4]),
                    vote_height,
                    vote_view
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        sync_cursor_when_peer_is_ahead, sync_response_entry_is_committed,
        within_aft_sync_replacement_window,
    };

    #[test]
    fn sync_response_never_exposes_a_workload_height_above_the_committed_tip() {
        let committed_hash = [7_u8; 32];

        assert!(!sync_response_entry_is_committed(
            8,
            None,
            7,
            Some(&committed_hash),
        ));
    }

    #[test]
    fn sync_response_tip_requires_the_committed_identity() {
        let committed_hash = [7_u8; 32];
        let other_hash = [8_u8; 32];

        assert!(sync_response_entry_is_committed(
            7,
            Some(&committed_hash),
            7,
            Some(&committed_hash),
        ));
        assert!(!sync_response_entry_is_committed(
            7,
            Some(&other_hash),
            7,
            Some(&committed_hash),
        ));
        assert!(!sync_response_entry_is_committed(1, None, 0, None));
    }

    #[test]
    fn sync_response_keeps_committed_history_below_the_tip() {
        assert!(sync_response_entry_is_committed(6, None, 7, None));
    }

    #[test]
    fn aft_sync_replacement_is_bounded_to_target_and_one_descendant() {
        assert!(within_aft_sync_replacement_window(10, 10));
        assert!(within_aft_sync_replacement_window(11, 10));
        assert!(!within_aft_sync_replacement_window(9, 10));
        assert!(!within_aft_sync_replacement_window(12, 10));
    }

    #[test]
    fn peer_comparison_uses_executed_height_but_fetch_starts_at_admitted_height() {
        assert_eq!(sync_cursor_when_peer_is_ahead(12, 10, 13), Some(10));
        assert_eq!(sync_cursor_when_peer_is_ahead(12, 10, 12), None);
        assert_eq!(sync_cursor_when_peer_is_ahead(12, 10, 11), None);
    }
}
