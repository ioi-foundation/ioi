use crate::metrics::rpc_metrics as metrics;
use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::mempool::{AddResult, Mempool};
use ioi_api::chain::WorkloadClientApi;
use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::app::{AccountId, ChainTransaction, StateRoot};
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Mutex};

use crate::standard::orchestration::ingestion::types::{ChainTipInfo, ProcessedTx};
use ioi_client::WorkloadClient;

const MAX_LIVE_TIP_VALIDATION_ATTEMPTS: usize = 8;

/// Total budget for waiting on the committed tip to move, across the WHOLE
/// anchored-validation loop rather than per attempt.
///
/// A per-attempt budget would multiply by `MAX_LIVE_TIP_VALIDATION_ATTEMPTS`
/// and let one admission hold the ingestion path for an unbounded-looking
/// stretch. One shared deadline keeps the worst case flat no matter how many
/// times the anchored check is retried.
///
/// Sized to cross a single block boundary at the 1s test cadence with margin.
/// It is deliberately NOT tied to a configured cadence: this is a bound on how
/// long admission may wait before failing closed, not a prediction of when the
/// next block arrives.
const LIVE_TIP_ADVANCE_BUDGET: Duration = Duration::from_millis(2_000);

fn tip_changed_without_regressing(previous: &ChainTipInfo, observed: &ChainTipInfo) -> bool {
    observed.height >= previous.height
        && (observed.height != previous.height || observed.state_root != previous.state_root)
}

/// Why a bounded wait for a newer committed tip ended without one.
///
/// Carried into the rejection message so an operator can tell "the producer
/// never moved" from "the watch is gone" from "we ran out of attempts". All
/// four are fail-closed; none admits a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TipAdvanceFailure {
    /// The shared deadline expired with the tip still where it was.
    Timeout,
    /// Every sender was dropped, so no further tip will ever be published.
    WatchClosed,
    /// The watch fired but republished a tip that is not genuinely newer.
    Unchanged,
    /// The watch fired with a LOWER height than the anchor that just failed.
    Regressed,
    /// `MAX_LIVE_TIP_VALIDATION_ATTEMPTS` is spent; no further retry is allowed
    /// however the tip moves.
    AttemptsExhausted,
}

impl TipAdvanceFailure {
    fn reason(self) -> &'static str {
        match self {
            Self::Timeout => "committed tip did not advance within the wait budget",
            Self::WatchClosed => "committed-tip watch closed",
            Self::Unchanged => "committed tip republished unchanged",
            Self::Regressed => "committed tip regressed",
            Self::AttemptsExhausted => "retry attempts exhausted",
        }
    }
}

/// The outcome of waiting for the committed tip to move past a failed anchor.
#[derive(Debug)]
enum TipAdvance {
    /// A genuinely newer, non-regressing tip is available; retry against it.
    Advanced(ChainTipInfo),
    /// Nothing usable. The caller fails closed.
    Unavailable(TipAdvanceFailure),
}

/// Waits, up to `deadline`, for the committed tip to become genuinely newer
/// than `previous`.
///
/// WHY THIS AWAITS RATHER THAN PEEKS. The anchored check can fail because the
/// historical anchor it needs is momentarily unresolvable while the next height
/// is still in flight -- `grpc_blockchain.rs` holds the state read lock and
/// takes `machine.try_lock()`, dropping fallback roots under contention. At the
/// instant of that failure the committed tip has NOT yet moved, so a
/// synchronous `borrow()` sees no change and the caller fails closed
/// immediately, milliseconds before the very block that would have made the
/// retry succeed. Observed exactly once as: warm AFT fixture durably committed
/// height 28 (root 264f24a9…, anchor e088825d…), admission at
/// 2026-08-28T09:35:22.509Z rejected while height 29 was in flight, height 29
/// finalized shortly after.
///
/// The wait is on the EXISTING watch receiver, so it costs no polling and no
/// root scan -- in particular it never walks the version history looking for a
/// resolvable anchor, which would be O(version count) per admission.
///
/// FAIL CLOSED IN EVERY DIRECTION. A timeout, a closed channel, an unchanged
/// republish, and a regressing tip all return `Unavailable`. Only a strictly
/// non-regressing, genuinely changed tip authorises a retry, and that retry
/// still goes through the authoritative `check_transactions_at`.
async fn await_non_regressing_tip_change(
    tip_rx: &mut watch::Receiver<ChainTipInfo>,
    previous: &ChainTipInfo,
    deadline: tokio::time::Instant,
) -> TipAdvance {
    // Already observable: the tip moved while the failed check was in flight,
    // so there is nothing to wait for. `borrow_and_update` also marks the
    // current value seen, so the `changed()` below cannot return instantly for
    // a value this call has already rejected.
    {
        let observed = tip_rx.borrow_and_update().clone();
        if tip_changed_without_regressing(previous, &observed) {
            return TipAdvance::Advanced(observed);
        }
    }

    match tokio::time::timeout_at(deadline, tip_rx.changed()).await {
        Err(_elapsed) => TipAdvance::Unavailable(TipAdvanceFailure::Timeout),
        Ok(Err(_closed)) => TipAdvance::Unavailable(TipAdvanceFailure::WatchClosed),
        Ok(Ok(())) => {
            let observed = tip_rx.borrow_and_update().clone();
            if tip_changed_without_regressing(previous, &observed) {
                TipAdvance::Advanced(observed)
            } else if observed.height < previous.height {
                TipAdvance::Unavailable(TipAdvanceFailure::Regressed)
            } else {
                TipAdvance::Unavailable(TipAdvanceFailure::Unchanged)
            }
        }
    }
}

fn tip_anchor(tip: &ChainTipInfo) -> ioi_types::app::StateAnchor {
    StateRoot(if tip.height > 0 {
        tip.state_root.clone()
    } else {
        tip.genesis_root.clone()
    })
    .to_anchor()
    .unwrap_or_default()
}

fn relay_fanout() -> usize {
    std::env::var("IOI_AFT_TX_RELAY_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(2)
}

fn leader_accounts_for_upcoming_heights(
    local_height: u64,
    validator_ids: &[Vec<u8>],
    fanout: usize,
) -> Vec<AccountId> {
    if validator_ids.is_empty() || fanout == 0 {
        return Vec::new();
    }

    let mut leaders = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let validator_len = validator_ids.len() as u64;
    let steps = fanout.min(validator_ids.len());
    for offset in 1..=steps {
        let target_height = local_height.saturating_add(offset as u64).max(1);
        let leader_index = ((target_height - 1) % validator_len) as usize;
        let Some(leader_bytes) = validator_ids.get(leader_index) else {
            continue;
        };
        let Ok(leader_bytes) = <[u8; 32]>::try_from(leader_bytes.as_slice()) else {
            continue;
        };
        let account = AccountId(leader_bytes);
        if seen.insert(account) {
            leaders.push(account);
        }
    }
    leaders
}

fn dispatch_swarm_command(sender: &mpsc::Sender<SwarmCommand>, command: SwarmCommand) {
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

fn is_desktop_agent_step(tx: &ChainTransaction) -> bool {
    let ChainTransaction::System(system) = tx else {
        return false;
    };
    let ioi_types::app::SystemPayload::CallService {
        service_id, method, ..
    } = &system.payload;
    service_id == "desktop_agent" && method == "step@v1"
}

pub(crate) async fn finalize_valid_transactions(
    workload_client: &Arc<WorkloadClient>,
    tx_pool: &Arc<Mempool>,
    swarm_sender: &mpsc::Sender<SwarmCommand>,
    peer_accounts_ref: &Arc<Mutex<HashMap<PeerId, AccountId>>>,
    local_account_id: AccountId,
    status_cache: &Arc<tokio::sync::Mutex<lru::LruCache<String, TxStatusEntry>>>,
    receipt_map: &Arc<tokio::sync::Mutex<lru::LruCache<ioi_types::app::TxHash, String>>>,
    nonce_cache: &mut lru::LruCache<ioi_types::app::AccountId, u64>,
    semantically_valid_indices: &[usize],
    processed_batch: &[ProcessedTx],
    tip_watcher: &watch::Receiver<ChainTipInfo>,
    expected_ts: u64,
) -> bool {
    let mut ordered_check_indices = semantically_valid_indices.to_vec();
    ordered_check_indices.sort_by(|left_idx, right_idx| {
        let left = &processed_batch[*left_idx];
        let right = &processed_batch[*right_idx];

        match (left.account_id, right.account_id) {
            (Some(left_account), Some(right_account)) => left_account
                .cmp(&right_account)
                .then_with(|| left.nonce.unwrap_or(0).cmp(&right.nonce.unwrap_or(0)))
                .then_with(|| left_idx.cmp(right_idx)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left_idx.cmp(right_idx),
        }
    });

    let txs_to_check: Vec<ChainTransaction> = ordered_check_indices
        .iter()
        .map(|&i| processed_batch[i].tx.clone())
        .collect();

    // Semantic screening above can take long enough for a fast AFT producer to
    // advance past the state root captured when this batch was collected. Use
    // the live committed tip for the authoritative anchored check and retry
    // only when the watched tip demonstrably advanced. Every successful
    // admission still comes from check_transactions_at; an unavailable,
    // unchanged, or regressing anchor fails closed.
    //
    // The retry previously PEEKED the watch and gave up if it had not already
    // moved. That lost the common race outright: the anchored check fails
    // precisely because the next height is mid-flight, so at that instant the
    // committed tip is still the old one and the peek always sees no change.
    // Waiting on the watch, under one shared deadline, converts that
    // milliseconds-early rejection into a retry against the block that lands
    // moments later -- without loosening what counts as a valid anchor.
    let mut tip_rx = tip_watcher.clone();
    // Marks the current value seen, so a later `changed()` reports a genuinely
    // new publication rather than whatever the caller's receiver had not yet
    // observed.
    let mut validation_tip = tip_rx.borrow_and_update().clone();
    // ONE deadline for the whole loop, taken before the first attempt.
    let advance_deadline = tokio::time::Instant::now() + LIVE_TIP_ADVANCE_BUDGET;
    let mut validation_attempts = 0usize;
    let check_results = loop {
        validation_attempts += 1;
        match workload_client
            .check_transactions_at(
                tip_anchor(&validation_tip),
                expected_ts,
                txs_to_check.clone(),
            )
            .await
        {
            Ok(results) => break results,
            Err(error) => {
                let advance = if validation_attempts < MAX_LIVE_TIP_VALIDATION_ATTEMPTS {
                    await_non_regressing_tip_change(&mut tip_rx, &validation_tip, advance_deadline)
                        .await
                } else {
                    TipAdvance::Unavailable(TipAdvanceFailure::AttemptsExhausted)
                };

                let failure = match advance {
                    TipAdvance::Advanced(observed_tip) => {
                        validation_tip = observed_tip;
                        // Preserved from the original retry path: hand the
                        // producer a scheduling point before re-checking.
                        tokio::task::yield_now().await;
                        continue;
                    }
                    TipAdvance::Unavailable(failure) => failure,
                };

                tracing::error!(
                    target: "ingestion",
                    attempts = validation_attempts,
                    attempted_height = validation_tip.height,
                    failure = failure.reason(),
                    "Validation IPC failed closed: {}",
                    error
                );
                let mut status_guard = status_cache.lock().await;
                for index in semantically_valid_indices {
                    let processed = &processed_batch[*index];
                    status_guard.put(
                        processed.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: TxStatus::Rejected,
                            error: Some(format!(
                                "Anchored validation unavailable after {validation_attempts} attempt(s) ({}): {error}",
                                failure.reason()
                            )),
                            block_height: None,
                        },
                    );
                }
                return false;
            }
        }
    };

    let mut status_guard = status_cache.lock().await;
    let mut receipt_guard = receipt_map.lock().await;
    let mut accepted_count = 0;
    let (leader_peer_targets, leader_peers) =
        if validation_tip.height == 0 || validation_tip.validator_set.is_empty() {
            // Before the first committed tip exists, keep admission cheap and rely on generic publish
            // rather than fetching validator set state to derive targeted relays.
            (0, Vec::new())
        } else {
            let leader_accounts = leader_accounts_for_upcoming_heights(
                validation_tip.height,
                &validation_tip.validator_set,
                relay_fanout(),
            );
            let leader_peer_targets = leader_accounts
                .iter()
                .filter(|account_id| **account_id != local_account_id)
                .count();
            let peers = peer_accounts_ref.lock().await;
            let leader_peers = leader_accounts
                .into_iter()
                .filter(|account_id| *account_id != local_account_id)
                .filter_map(|leader_account_id| {
                    peers.iter().find_map(|(peer_id, account_id)| {
                        (*account_id == leader_account_id).then_some(*peer_id)
                    })
                })
                .collect::<Vec<_>>();
            (leader_peer_targets, leader_peers)
        };

    for (res_idx, result) in check_results.into_iter().enumerate() {
        let original_idx = ordered_check_indices[res_idx];
        let p_tx = &processed_batch[original_idx];

        let is_approval_error = if let Err(e) = &result {
            e.contains("Approval required for request")
        } else {
            false
        };

        let validation_ok = result.is_ok() || is_approval_error;

        if validation_ok {
            let receipt_already_present = receipt_guard.peek(&p_tx.canonical_hash).is_some();
            let readmit_after_operator_pause =
                receipt_already_present && is_desktop_agent_step(&p_tx.tx) && !is_approval_error;
            if readmit_after_operator_pause {
                receipt_guard.pop(&p_tx.canonical_hash);
                tx_pool.remove_by_hash(&p_tx.canonical_hash);
                if let (Some(account_id), Some(nonce)) = (p_tx.account_id, p_tx.nonce) {
                    tx_pool.remove_by_account_nonce(&account_id, nonce);
                }
            } else if receipt_already_present {
                accepted_count += 1;
                status_guard.put(
                    p_tx.receipt_hash_hex.clone(),
                    TxStatusEntry {
                        status: TxStatus::InMempool,
                        error: None,
                        block_height: None,
                    },
                );
                continue;
            }

            let tx_info = p_tx.account_id.map(|acc| (acc, p_tx.nonce.unwrap()));
            let committed_nonce = p_tx
                .account_id
                .and_then(|acc| nonce_cache.get(&acc).copied())
                .unwrap_or(0);
            let committed_nonce = if readmit_after_operator_pause {
                p_tx.nonce
                    .map(|nonce| committed_nonce.max(nonce))
                    .unwrap_or(committed_nonce)
            } else {
                committed_nonce
            };

            // Rejected-occupant healing: an execution-rejected transaction
            // never advances the account nonce, so finalize-time pruning can
            // never evict it and its slot poisons every later same-account
            // admission (reported Known, never tracked, submitter polls
            // forever). Heal only when the occupant differs from this
            // transaction AND is already recorded as Rejected.
            if let Some((account_id, nonce)) = tx_info {
                if let Some(occupant) = tx_pool.peek_account_nonce(&account_id, nonce) {
                    if occupant != p_tx.canonical_hash {
                        let occupant_rejected = receipt_guard
                            .peek(&occupant)
                            .map(|occupant_hex| {
                                matches!(
                                    status_guard.peek(occupant_hex),
                                    Some(entry) if matches!(entry.status, TxStatus::Rejected)
                                )
                            })
                            .unwrap_or(false);
                        if occupant_rejected {
                            tx_pool.remove_by_account_nonce(&account_id, nonce);
                            tracing::warn!(
                                target: "mempool",
                                nonce,
                                "Healed a nonce slot held by an execution-rejected transaction."
                            );
                        }
                    }
                }
            }
            let add_result = tx_pool.add(
                p_tx.tx.clone(),
                p_tx.canonical_hash,
                tx_info,
                committed_nonce,
            );

            match add_result {
                AddResult::Ready | AddResult::Future | AddResult::Known => {
                    accepted_count += 1;
                    if !matches!(add_result, AddResult::Known) {
                        metrics().inc_mempool_transactions_added();
                        if let Ok(tx_bytes) = ioi_types::codec::to_bytes_canonical(&p_tx.tx) {
                            dispatch_swarm_command(
                                swarm_sender,
                                SwarmCommand::PublishTransaction(tx_bytes.clone()),
                            );
                            for peer in &leader_peers {
                                dispatch_swarm_command(
                                    swarm_sender,
                                    SwarmCommand::RelayTransactionToPeer {
                                        peer: *peer,
                                        data: tx_bytes.clone(),
                                    },
                                );
                            }
                            if leader_peers.len() < leader_peer_targets {
                                tracing::debug!(
                                    target: "ingestion",
                                    expected_leader_peers = leader_peer_targets,
                                    resolved_leader_peers = leader_peers.len(),
                                    "Leader-aware relay fell back to generic publish for unresolved peers."
                                );
                            }
                        }
                    }
                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: TxStatus::InMempool,
                            error: None,
                            block_height: None,
                        },
                    );
                    receipt_guard.put(p_tx.canonical_hash, p_tx.receipt_hash_hex.clone());

                    tracing::debug!(
                        target: "ingestion",
                        "Added transaction to mempool: {}",
                        p_tx.receipt_hash_hex
                    );
                }
                AddResult::Rejected(r) => {
                    tracing::warn!(
                        target: "ingestion",
                        "Mempool rejected transaction {}: {}",
                        p_tx.receipt_hash_hex,
                        r
                    );
                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: TxStatus::Rejected,
                            error: Some(format!("Mempool: {}", r)),
                            block_height: None,
                        },
                    );
                }
            }
        } else {
            let e = result.unwrap_err();
            tx_pool.remove_by_hash(&p_tx.canonical_hash);
            let _ = receipt_guard.pop(&p_tx.canonical_hash);
            tracing::warn!(
                target: "ingestion",
                "Validation failed for transaction {}: {}",
                p_tx.receipt_hash_hex,
                e
            );
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: TxStatus::Rejected,
                    error: Some(format!("Validation: {}", e)),
                    block_height: None,
                },
            );
        }
    }

    metrics().set_mempool_size(tx_pool.len() as f64);
    accepted_count > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{
        ChainId, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
    };

    fn system_call(service_id: &str, method: &str) -> ChainTransaction {
        ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: AccountId([3u8; 32]),
                nonce: 1,
                chain_id: ChainId(1),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: service_id.to_string(),
                method: method.to_string(),
                params: Vec::new(),
            },
            signature_proof: SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: Vec::new(),
                signature: Vec::new(),
            },
        }))
    }

    fn tip(height: u64, root_byte: u8) -> ChainTipInfo {
        ChainTipInfo {
            height,
            timestamp: height,
            timestamp_ms: height.saturating_mul(1_000),
            gas_used: 0,
            state_root: vec![root_byte; 32],
            genesis_root: vec![0; 32],
            validator_set: Vec::new(),
        }
    }

    #[test]
    fn anchored_validation_retry_requires_a_non_regressing_tip_change() {
        let original = tip(9, 9);
        assert!(tip_changed_without_regressing(&original, &tip(10, 10)));
        assert!(tip_changed_without_regressing(&original, &tip(9, 10)));
        assert!(!tip_changed_without_regressing(&original, &tip(9, 9)));
        assert!(!tip_changed_without_regressing(&original, &tip(8, 8)));
    }

    #[test]
    fn ingestion_readmission_identifies_only_desktop_agent_step() {
        assert!(is_desktop_agent_step(&system_call(
            "desktop_agent",
            "step@v1"
        )));
        assert!(!is_desktop_agent_step(&system_call(
            "desktop_agent",
            "start@v1"
        )));
        assert!(!is_desktop_agent_step(&system_call("agentic", "step@v1")));
    }

    // -----------------------------------------------------------------------
    // Bounded wait for a newer committed tip
    // -----------------------------------------------------------------------
    //
    // DETERMINISM. `tokio`'s `test-util` feature is not enabled for this crate,
    // so `start_paused` virtual time is unavailable and enabling it would mean
    // editing Cargo.toml. Instead the deadline is a parameter:
    //
    //   * fail-closed cases pass an ALREADY-ELAPSED deadline, so `timeout_at`
    //     resolves on the first poll and nothing ever sleeps;
    //   * success cases pass a deadline far in the future and are woken by an
    //     actual `send`, so they finish as soon as the watch fires and never
    //     wait on the clock.
    //
    // No test outcome depends on how long anything takes.

    /// Far enough out that a success path can never reach it on any machine,
    /// while still being a real bound.
    fn generous_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(3_600)
    }

    /// Already spent, so the timeout branch is taken without sleeping.
    fn elapsed_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() - Duration::from_secs(1)
    }

    fn advanced_tip(advance: TipAdvance) -> ChainTipInfo {
        match advance {
            TipAdvance::Advanced(tip) => tip,
            TipAdvance::Unavailable(failure) => {
                panic!("expected an advance, got {failure:?}")
            }
        }
    }

    fn failure_of(advance: TipAdvance) -> TipAdvanceFailure {
        match advance {
            TipAdvance::Unavailable(failure) => failure,
            TipAdvance::Advanced(tip) => {
                panic!(
                    "expected fail-closed, got an advance to height {}",
                    tip.height
                )
            }
        }
    }

    #[tokio::test]
    async fn an_already_visible_advance_is_taken_without_waiting() {
        // The tip moved while the failed anchored check was in flight. There is
        // nothing to wait for, and waiting would add latency for no reason.
        let (tx, rx) = watch::channel(tip(28, 28));
        let mut rx = rx.clone();
        let previous = rx.borrow_and_update().clone();
        tx.send(tip(29, 29)).expect("receiver alive");

        // An already-elapsed deadline proves this path never reaches the wait:
        // if it did, it would time out instead of advancing.
        let observed = advanced_tip(
            await_non_regressing_tip_change(&mut rx, &previous, elapsed_deadline()).await,
        );
        assert_eq!(observed.height, 29);
    }

    #[tokio::test]
    async fn a_tip_that_arrives_after_the_failure_is_awaited_and_retried() {
        // THE REGRESSION THIS REPAIR EXISTS FOR. At the moment the anchored
        // check fails, height 29 is still in flight and the committed tip is
        // still 28 -- a synchronous peek sees no change and fails closed
        // milliseconds before the block that would have worked.
        let (tx, rx) = watch::channel(tip(28, 28));
        let mut rx = rx.clone();
        let previous = rx.borrow_and_update().clone();

        // Publish only AFTER the waiter is already parked.
        let sender = tokio::spawn(async move {
            tokio::task::yield_now().await;
            tx.send(tip(29, 29)).expect("receiver alive");
            // Hold the sender so the channel does not close and turn this into
            // the WatchClosed case by accident.
            tokio::time::sleep(Duration::from_secs(3_600)).await;
            drop(tx);
        });

        let observed = advanced_tip(
            await_non_regressing_tip_change(&mut rx, &previous, generous_deadline()).await,
        );
        assert_eq!(observed.height, 29);
        assert_eq!(observed.state_root, vec![29u8; 32]);
        sender.abort();
    }

    #[tokio::test]
    async fn a_tip_that_never_moves_fails_closed_on_the_budget() {
        // Fail closed, not admit: the anchor never became resolvable.
        let (_tx, rx) = watch::channel(tip(28, 28));
        let mut rx = rx.clone();
        let previous = rx.borrow_and_update().clone();

        assert_eq!(
            failure_of(
                await_non_regressing_tip_change(&mut rx, &previous, elapsed_deadline()).await
            ),
            TipAdvanceFailure::Timeout,
        );
    }

    #[tokio::test]
    async fn a_closed_watch_fails_closed_rather_than_retrying() {
        // Every sender is gone, so no tip will ever arrive. Retrying against
        // the stale anchor forever would be the alternative.
        let (tx, rx) = watch::channel(tip(28, 28));
        let mut rx = rx.clone();
        let previous = rx.borrow_and_update().clone();
        drop(tx);

        assert_eq!(
            failure_of(
                await_non_regressing_tip_change(&mut rx, &previous, generous_deadline()).await
            ),
            TipAdvanceFailure::WatchClosed,
        );
    }

    #[tokio::test]
    async fn a_regressing_tip_fails_closed_and_is_never_retried_against() {
        // A lower height is not a newer anchor. Accepting it would validate
        // against state the chain has moved past.
        let (tx, rx) = watch::channel(tip(28, 28));
        let mut rx = rx.clone();
        let previous = rx.borrow_and_update().clone();

        let sender = tokio::spawn(async move {
            tokio::task::yield_now().await;
            tx.send(tip(27, 27)).expect("receiver alive");
            tokio::time::sleep(Duration::from_secs(3_600)).await;
            drop(tx);
        });

        assert_eq!(
            failure_of(
                await_non_regressing_tip_change(&mut rx, &previous, generous_deadline()).await
            ),
            TipAdvanceFailure::Regressed,
        );
        sender.abort();
    }

    #[tokio::test]
    async fn an_unchanged_republish_fails_closed_rather_than_counting_as_progress() {
        // `watch` notifies on every send, even when the value is identical. A
        // republished height 28 is not the height 29 the retry needs, so
        // treating the notification alone as progress would retry against the
        // same unresolvable anchor.
        let (tx, rx) = watch::channel(tip(28, 28));
        let mut rx = rx.clone();
        let previous = rx.borrow_and_update().clone();

        let sender = tokio::spawn(async move {
            tokio::task::yield_now().await;
            tx.send(tip(28, 28)).expect("receiver alive");
            tokio::time::sleep(Duration::from_secs(3_600)).await;
            drop(tx);
        });

        assert_eq!(
            failure_of(
                await_non_regressing_tip_change(&mut rx, &previous, generous_deadline()).await
            ),
            TipAdvanceFailure::Unchanged,
        );
        sender.abort();
    }

    #[tokio::test]
    async fn a_same_height_root_change_counts_as_a_genuine_advance() {
        // Guards the Unchanged case above from over-refusing: the existing
        // non-regression rule admits a same-height tip whose root differs, and
        // the wait must not narrow that.
        let (tx, rx) = watch::channel(tip(28, 28));
        let mut rx = rx.clone();
        let previous = rx.borrow_and_update().clone();

        let sender = tokio::spawn(async move {
            tokio::task::yield_now().await;
            tx.send(tip(28, 99)).expect("receiver alive");
            tokio::time::sleep(Duration::from_secs(3_600)).await;
            drop(tx);
        });

        let observed = advanced_tip(
            await_non_regressing_tip_change(&mut rx, &previous, generous_deadline()).await,
        );
        assert_eq!(observed.height, 28);
        assert_eq!(observed.state_root, vec![99u8; 32]);
        sender.abort();
    }

    #[test]
    fn every_fail_closed_reason_is_distinct_and_reportable() {
        // The reason reaches the submitter's rejection message, so an operator
        // can tell a stalled producer from a dropped watch. Identical strings
        // would collapse that distinction silently.
        let reasons = [
            TipAdvanceFailure::Timeout,
            TipAdvanceFailure::WatchClosed,
            TipAdvanceFailure::Unchanged,
            TipAdvanceFailure::Regressed,
            TipAdvanceFailure::AttemptsExhausted,
        ]
        .map(TipAdvanceFailure::reason);
        let unique = reasons.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(
            unique.len(),
            reasons.len(),
            "reasons must be distinguishable"
        );
        assert!(reasons.iter().all(|reason| !reason.is_empty()));
    }
}
