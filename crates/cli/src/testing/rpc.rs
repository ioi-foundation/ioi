// Path: crates/cli/src/testing/rpc.rs

use anyhow::{anyhow, Result};
use ioi_ipc::blockchain::{GetStatusRequest, GetStatusResponse, QueryRawStateRequest}; // [FIX] Added GetStatusResponse
use ioi_ipc::public::public_api_client::PublicApiClient;
// [FIX] Removed unused imports
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, GetBlockByHeightRequest, GetTransactionStatusRequest,
    SubmitTransactionRequest, SubscribeEventsRequest, TxStatus,
};
use ioi_types::{
    app::{Block, ChainTransaction, Proposal, StateEntry, StateRoot},
    codec,
    keys::{EVIDENCE_REGISTRY_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, QUARANTINED_VALIDATORS_KEY},
};
use std::collections::BTreeSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tonic::transport::Channel;

// How many retries for transient RPC decode/transport glitches
const RPC_RETRY_MAX: usize = 5;
const RPC_RETRY_BASE_MS: u64 = 80;

/// The default interval between committed-status polls.
///
/// Every commit-wait measurement taken on this path is quantized to this
/// interval, so a profile that reports the wait must also report the quantum
/// rather than presenting the sampled figure as an exact latency.
const DEFAULT_COMMIT_POLL_INTERVAL_MS: u64 = 500;

/// Lower bound on the poll interval. Polling faster than this turns the status
/// RPC into a busy loop competing with the commit path being measured, so the
/// sampler would perturb the number it reports.
const MIN_COMMIT_POLL_INTERVAL_MS: u64 = 1;

/// Upper bound on the poll interval. A coarser quantum would dominate every
/// phase in the profile and silently turn a commit-latency measurement into a
/// measurement of the sampler.
const MAX_COMMIT_POLL_INTERVAL_MS: u64 = 5_000;

/// The interval between committed-status polls.
///
/// Independently controllable so an ordering/finality comparison can separate
/// the observation quantum from the profile under test: at the 500ms default a
/// sub-100ms Solo commit and a sub-100ms AFT commit are indistinguishable,
/// because both are rounded up to the same first poll. Changing this changes
/// only how often the client asks -- no admission, ordering, execution,
/// commitment, durability or receipt behaviour on the node depends on it.
///
/// Unparseable or out-of-range values fall back to the default rather than
/// silently configuring a degenerate sampler.
fn commit_poll_interval_ms() -> u64 {
    let Ok(raw) = std::env::var("IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS") else {
        return DEFAULT_COMMIT_POLL_INTERVAL_MS;
    };
    let trimmed = raw.trim().to_string();
    let Ok(parsed) = trimmed.parse::<u64>() else {
        eprintln!(
            "[ioi-testing-rpc] ignoring unparseable \
             IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS={trimmed:?}; using default \
             {DEFAULT_COMMIT_POLL_INTERVAL_MS}ms"
        );
        return DEFAULT_COMMIT_POLL_INTERVAL_MS;
    };
    if !(MIN_COMMIT_POLL_INTERVAL_MS..=MAX_COMMIT_POLL_INTERVAL_MS).contains(&parsed) {
        eprintln!(
            "[ioi-testing-rpc] ignoring out-of-range \
             IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS={parsed} (valid \
             {MIN_COMMIT_POLL_INTERVAL_MS}..={MAX_COMMIT_POLL_INTERVAL_MS}); using default \
             {DEFAULT_COMMIT_POLL_INTERVAL_MS}ms"
        );
        return DEFAULT_COMMIT_POLL_INTERVAL_MS;
    }
    parsed
}

/// Whether this run must resolve completion from the EXACT per-transaction
/// event rather than from polling alone.
///
/// Gated on the estate's existing benchmark-trace arming, which is what a
/// profiling run sets and an ordinary soak does not. Two consequences follow
/// deliberately:
///
///   * an ordinary run is byte-identical to its previous behaviour -- it opens
///     no event stream and its measurements are unchanged; and
///   * a PROFILED run has no weaker fallback. If the exact event does not
///     arrive, the submission fails rather than reporting a polled figure
///     under a name that promises an event-driven one.
fn exact_completion_event_required() -> bool {
    std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
}

/// Client wall-clock milliseconds since the UNIX epoch.
fn client_wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// One EXACT per-transaction completion event, as this client observed it.
#[derive(Debug, Clone)]
pub struct CompletionEventObservation {
    /// The exact committing height the SERVER reported on the event. Carried
    /// separately from the polled height so the two can be compared rather
    /// than one silently standing in for the other.
    pub height: u64,
    /// Server wall-clock ms at which the finalized header became durable.
    pub durable_commit_ms: u64,
    /// Server wall-clock ms at which the server published the notification.
    pub published_at_ms: u64,
    /// CLIENT wall-clock ms at which this client received it.
    ///
    /// A different clock domain from the two above. Their difference is a
    /// transport lag only to the extent the two clocks agree, which is a
    /// property of the deployment and not of this measurement.
    pub observed_at_wall_ms: u64,
    /// Client wait from the submission anchor until the event was received.
    /// Single-clock and monotonic, unlike `observed_at_wall_ms`.
    pub event_wait_ms: u128,
}

/// A wall-clock observation of one submission through [`submit_transaction`].
///
/// These are measurements of the very path `submit_transaction` already walks.
/// Producing them changes no admission, commitment, or status truth, and no
/// field here is ever substituted for a value the chain did not report.
#[derive(Debug, Clone)]
pub struct SubmissionProfile {
    /// The hash the RPC admitted the transaction under.
    pub tx_hash: String,
    /// Wall time of the `submit_transaction` RPC call itself.
    pub admission_ms: u128,
    /// Wall time from the end of admission until the status read COMMITTED.
    pub commit_wait_ms: u128,
    /// How many `get_transaction_status` polls that wait issued.
    pub commit_poll_count: u64,
    /// The interval those polls quantize `commit_wait_ms` to.
    pub commit_poll_interval_ms: u64,
    /// The EXACT block height the validator recorded for this transaction.
    ///
    /// `None` when the status cache published no height. A caller must report
    /// that absence; the chain tip is a different fact and is never a
    /// substitute for it.
    pub committed_height: Option<u64>,
    /// The exact per-transaction completion event, when this run required one.
    ///
    /// `None` means the run did not subscribe at all, never that an event was
    /// expected and missing: a profiled run that cannot match its exact event
    /// returns `Err` instead of a profile carrying `None` here.
    pub completion_event: Option<CompletionEventObservation>,
}

/// A live subscription to the public chain-event stream, opened BEFORE a
/// submission so a fast completion cannot land in the gap.
///
/// The reader task timestamps each event as it arrives, so the observation
/// keeps its true arrival time even though the caller drains the channel later
/// (after its own status poll has finished). Draining and timestamping in the
/// same place would have measured when the caller got round to looking.
struct TransactionCommittedWatch {
    events: mpsc::UnboundedReceiver<ObservedCommittedEvent>,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for TransactionCommittedWatch {
    fn drop(&mut self) {
        // One stream per submission, closed deterministically.
        //
        // Without this, the reader parks on `message()` and only notices the
        // dropped receiver when the NEXT event happens to arrive -- so a run
        // of N submissions would hold N gRPC streams and N server-side
        // broadcast receivers open for an unbounded time. Instrumentation that
        // accumulates load across a measured run is measuring itself.
        self.reader.abort();
    }
}

/// One event exactly as it left the server, plus when this client received it.
///
/// `received_at` is a monotonic reading and `received_at_wall_ms` a wall-clock
/// one, both taken in the reader task at arrival. They answer different
/// questions -- one is compared against this client's own submission anchor,
/// the other against the server's publication timestamp -- and neither is
/// derivable from the other.
struct ObservedCommittedEvent {
    tx_hash: String,
    height: u64,
    durable_commit_ms: u64,
    published_at_ms: u64,
    received_at: Instant,
    received_at_wall_ms: u64,
}

/// Opens the stream and starts consuming it immediately.
///
/// Returns once the server has accepted the subscription, which -- because the
/// server establishes its broadcast receivers before responding -- means every
/// event published after this call is deliverable to this stream.
async fn watch_transaction_committed_events(rpc_addr: &str) -> Result<TransactionCommittedWatch> {
    let mut client = connect(rpc_addr).await?;
    let mut stream = client
        .subscribe_events(tonic::Request::new(SubscribeEventsRequest {}))
        .await
        .map_err(|e| anyhow!("failed to subscribe to chain events: {}", e))?
        .into_inner();

    let (sender, events) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        // Unbounded on purpose: the caller does not drain until its status
        // poll returns, and a bounded channel would either block the reader
        // (delaying the very timestamps it exists to take) or drop events.
        // The queue is bounded in practice by one submission's lifetime.
        while let Ok(Some(event)) = stream.message().await {
            let Some(ChainEventEnum::TransactionCommitted(committed)) = event.event else {
                continue;
            };
            let observation = ObservedCommittedEvent {
                tx_hash: committed.tx_hash,
                height: committed.height,
                durable_commit_ms: committed.durable_commit_ms,
                published_at_ms: committed.published_at_ms,
                received_at: Instant::now(),
                received_at_wall_ms: client_wall_clock_ms(),
            };
            if sender.send(observation).is_err() {
                break;
            }
        }
        // Falling out of the loop drops `sender`, which the waiter reads as
        // "the stream ended". That is a refusal, not a completion.
    });

    Ok(TransactionCommittedWatch { events, reader })
}

impl TransactionCommittedWatch {
    /// Waits for the event naming EXACTLY `tx_hash`.
    ///
    /// Fails closed in every direction that is not an exact match:
    ///
    ///   * an event for a DIFFERENT transaction is skipped, never accepted as
    ///     this transaction's completion -- other transactions commit on the
    ///     same chain and their events share the stream;
    ///   * the stream ending is an error, not an absent completion;
    ///   * the deadline expiring is an error;
    ///   * a matching event carrying height 0, a height that disagrees with
    ///     the polled status, or a publication instant earlier than the
    ///     durability it asserts, is an error.
    ///
    /// No branch substitutes a block height, a chain tip, or the polled result
    /// for the event.
    async fn wait_for_exact_transaction(
        &mut self,
        tx_hash: &str,
        polled_height: Option<u64>,
        anchor: Instant,
        deadline: Instant,
    ) -> Result<CompletionEventObservation> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!(
                    "timed out waiting for the exact completion event for tx {}; \
                     refusing to report a polled figure as an event-driven one",
                    tx_hash
                ));
            }
            let received = tokio::time::timeout(remaining, self.events.recv())
                .await
                .map_err(|_| {
                    anyhow!(
                        "timed out waiting for the exact completion event for tx {}; \
                         refusing to report a polled figure as an event-driven one",
                        tx_hash
                    )
                })?;
            let Some(observed) = received else {
                return Err(anyhow!(
                    "the chain-event stream ended before the exact completion event for tx {} \
                     arrived",
                    tx_hash
                ));
            };
            let ObservedCommittedEvent {
                tx_hash: event_tx_hash,
                height,
                durable_commit_ms,
                published_at_ms,
                received_at,
                received_at_wall_ms,
            } = observed;
            if event_tx_hash != tx_hash {
                // Another transaction's completion. Skipped, not substituted.
                continue;
            }
            if height == 0 {
                return Err(anyhow!(
                    "completion event for tx {} carried height 0, which names no committed block",
                    tx_hash
                ));
            }
            if let Some(polled) = polled_height {
                if polled != height {
                    return Err(anyhow!(
                        "completion event for tx {} reports height {} while the committed status \
                         reported height {}; two disagreeing observations of one commit are not \
                         reconciled by preferring either",
                        tx_hash,
                        height,
                        polled
                    ));
                }
            }
            if published_at_ms < durable_commit_ms {
                return Err(anyhow!(
                    "completion event for tx {} claims it was published at {}ms, before the {}ms \
                     durability it asserts",
                    tx_hash,
                    published_at_ms,
                    durable_commit_ms
                ));
            }
            return Ok(CompletionEventObservation {
                height,
                durable_commit_ms,
                published_at_ms,
                observed_at_wall_ms: received_at_wall_ms,
                event_wait_ms: received_at.saturating_duration_since(anchor).as_millis(),
            });
        }
    }
}

/// Connects to the public gRPC API.
async fn connect(rpc_addr: &str) -> Result<PublicApiClient<Channel>> {
    let url = if rpc_addr.starts_with("http") {
        rpc_addr.to_string()
    } else {
        format!("http://{}", rpc_addr)
    };

    PublicApiClient::connect(url)
        .await
        .map_err(|e| anyhow!("Failed to connect to public gRPC: {}", e))
}

/// Robust get_block_by_height:
/// - Retries transient -32000 decode/network errors
/// - Treats future/hemi-available heights as Ok(None)
pub async fn get_block_by_height_resilient(
    rpc_addr: &str,
    height: u64,
) -> Result<Option<Block<ChainTransaction>>> {
    let mut attempt = 0usize;
    loop {
        match get_block_by_height(rpc_addr, height).await {
            Ok(opt) => return Ok(opt), // Found (Some) or cleanly NotFound (None)
            Err(e) => {
                let msg = e.to_string();
                // Check for Tonic/gRPC transport errors
                if msg.contains("transport error")
                    || msg.contains("unavailable")
                    || msg.contains("h2")
                {
                    attempt += 1;
                    if attempt >= RPC_RETRY_MAX {
                        return Ok(None);
                    }
                    sleep(Duration::from_millis(RPC_RETRY_BASE_MS * attempt as u64)).await;
                    continue;
                }
                return Err(anyhow!(e));
            }
        }
    }
}

/// Return latest known chain tip by probing upwards.
pub async fn tip_height_resilient(rpc_addr: &str) -> Result<u64> {
    let mut h = 0u64;
    loop {
        let next = h + 1;
        match get_block_by_height_resilient(rpc_addr, next).await? {
            Some(_) => h = next,
            None => return Ok(h),
        }
    }
}

/// Submits a transaction and waits for the next block to be produced.
pub async fn submit_transaction_and_get_block(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<Block<ChainTransaction>> {
    let initial_height = get_chain_height(rpc_addr).await?;
    let target_height = initial_height + 1;

    submit_transaction_no_wait(rpc_addr, tx).await?;

    super::assert::wait_for_height(rpc_addr, target_height, Duration::from_secs(60)).await?;

    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(b)) = get_block_by_height_resilient(rpc_addr, target_height).await {
            return Ok(b);
        }
        if start.elapsed() > Duration::from_secs(10) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(anyhow!(
        "Block {} committed but not found in store after polling",
        target_height
    ))
}

/// Submits a transaction via gRPC without waiting for inclusion.
pub async fn submit_transaction_no_wait(rpc_addr: &str, tx: &ChainTransaction) -> Result<String> {
    let mut client = connect(rpc_addr).await?;

    let tx_bytes =
        codec::to_bytes_canonical(tx).map_err(|e| anyhow!("Serialization failed: {}", e))?;

    let request = tonic::Request::new(SubmitTransactionRequest {
        transaction_bytes: tx_bytes,
    });

    let response = client.submit_transaction(request).await?;
    let tx_hash = response.into_inner().tx_hash;

    log::info!("submit_transaction: accepted -> hash: {}", tx_hash);
    Ok(tx_hash)
}

/// Submits a transaction and waits for it to be COMMITTED.
/// Returns error if the transaction is Rejected or times out.
pub async fn submit_transaction(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<()> {
    submit_transaction_profiled(rpc_addr, tx).await.map(|_| ())
}

/// The single implementation behind [`submit_transaction`], additionally
/// returning what it observed about its own timing.
///
/// [`submit_transaction`] delegates here so there is exactly ONE submission
/// path: a profiled copy that could drift from the path the soak actually
/// walks would measure a different journey than the one under test.
pub async fn submit_transaction_profiled(
    rpc_addr: &str,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<SubmissionProfile> {
    // SUBSCRIBE BEFORE SUBMITTING. A completion event can only be observed by
    // a stream that already exists, and a Solo commit can land within a few
    // milliseconds of admission, so opening the stream after the submit RPC
    // would lose exactly the fast completions this measurement is about.
    let mut event_watch = if exact_completion_event_required() {
        Some(watch_transaction_committed_events(rpc_addr).await?)
    } else {
        None
    };

    let admission_started = Instant::now();
    let tx_hash = submit_transaction_no_wait(rpc_addr, tx).await?;
    let admission_ms = admission_started.elapsed().as_millis();
    let mut commit_poll_count = 0u64;
    // Resolved once per submission so every poll in this wait, and the
    // interval reported alongside it, are the same figure.
    let poll_interval_ms = commit_poll_interval_ms();

    // Poll for status. Long held journeys against the debug wallet fixture
    // legitimately commit slowly as the chain deepens; callers opt into a
    // longer wait without changing the default for everyone else.
    let start = Instant::now();
    let timeout = Duration::from_secs(
        std::env::var("IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(60)
            .clamp(10, 900),
    );

    let mut client = connect(rpc_addr).await?;

    // The loop yields its result rather than assigning into an outer
    // `Option` that a later line would have to unwrap: there is exactly one
    // way out with a value, so no state where "committed" and "no wait
    // recorded" can coexist is representable.
    let (commit_wait_ms, committed_height) = loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for tx {} to commit", tx_hash));
        }

        let req = tonic::Request::new(GetTransactionStatusRequest {
            tx_hash: tx_hash.clone(),
        });

        commit_poll_count += 1;
        match client.get_transaction_status(req).await {
            Ok(resp) => {
                let r = resp.into_inner();
                match TxStatus::try_from(r.status).unwrap_or(TxStatus::Unknown) {
                    TxStatus::Committed => {
                        // The status cache publishes the exact including height
                        // on commit. A zero means it published none; that
                        // absence is carried forward as absence.
                        let height = (r.block_height > 0).then_some(r.block_height);
                        break (start.elapsed().as_millis(), height);
                    }
                    TxStatus::Rejected => {
                        return Err(anyhow!("Transaction rejected: {}", r.error_message));
                    }
                    _ => { /* Pending/InMempool, continue waiting */ }
                }
            }
            Err(_) => {
                // Ignore transient gRPC errors during polling
            }
        }

        sleep(Duration::from_millis(poll_interval_ms)).await;
    };

    // The polled wait and the event wait share ONE anchor (`start`) so they
    // measure the same interval by two mechanisms and can be compared. The
    // event is awaited after the poll returns, but its arrival was timestamped
    // by the reader task when it actually arrived -- so an event that landed
    // before this poll finished still reports the earlier time.
    let completion_event = match event_watch.as_mut() {
        Some(watch) => Some(
            watch
                .wait_for_exact_transaction(&tx_hash, committed_height, start, start + timeout)
                .await?,
        ),
        None => None,
    };

    Ok(SubmissionProfile {
        tx_hash,
        admission_ms,
        commit_wait_ms,
        commit_poll_count,
        commit_poll_interval_ms: poll_interval_ms,
        committed_height,
        completion_event,
    })
}

/// Queries a raw key from the workload state via Public gRPC.
pub async fn query_state_key(rpc_addr: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut client = connect(rpc_addr).await?;
    let req = QueryRawStateRequest { key: key.to_vec() };
    let response = client.query_raw_state(req).await?.into_inner();

    if response.found {
        Ok(Some(response.value))
    } else {
        Ok(None)
    }
}

/// Gets the current chain height from the state.
pub async fn get_chain_height(rpc_addr: &str) -> Result<u64> {
    let mut client = connect(rpc_addr).await?;
    let req = GetStatusRequest {};
    let status = client.get_status(req).await?.into_inner();
    Ok(status.height)
}

// [NEW] Get full status
pub async fn get_status(rpc_addr: &str) -> Result<GetStatusResponse> {
    let mut client = connect(rpc_addr).await?;
    let req = GetStatusRequest {};
    let status = client.get_status(req).await?.into_inner();
    Ok(status)
}

/// Gets the latest on-chain UNIX timestamp (seconds).
pub async fn get_chain_timestamp(rpc_addr: &str) -> Result<u64> {
    let mut client = connect(rpc_addr).await?;
    let req = GetStatusRequest {};
    let status = client.get_status(req).await?.into_inner();
    Ok(status.latest_timestamp)
}

/// Gets the current set of quarantined validators for PoA.
pub async fn get_quarantined_set(rpc_addr: &str) -> Result<BTreeSet<ioi_types::app::AccountId>> {
    let bytes_opt = query_state_key(rpc_addr, QUARANTINED_VALIDATORS_KEY).await?;
    if let Some(bytes) = bytes_opt {
        codec::from_bytes_canonical(&bytes)
            .map_err(|e| anyhow!("Failed to decode quarantined set: {}", e))
    } else {
        Ok(BTreeSet::new())
    }
}

/// Gets a governance proposal by its ID.
pub async fn get_proposal(rpc_addr: &str, id: u64) -> Result<Option<Proposal>> {
    let key = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &id.to_le_bytes()].concat();
    let bytes_opt = query_state_key(rpc_addr, &key).await?;
    if let Some(bytes) = bytes_opt {
        codec::from_bytes_canonical(&bytes).map_err(|e| anyhow!("Failed to decode proposal: {}", e))
    } else {
        Ok(None)
    }
}

/// Checks if a contract's code exists at a given address.
pub async fn get_contract_code(rpc_addr: &str, address: &[u8]) -> Result<Option<Vec<u8>>> {
    let key = [b"contract_code::", address].concat();
    let state_entry_bytes_opt = query_state_key(rpc_addr, &key).await?;
    if let Some(state_entry_bytes) = state_entry_bytes_opt {
        let entry: StateEntry = codec::from_bytes_canonical(&state_entry_bytes)
            .map_err(|e| anyhow!("StateEntry decode failed: {}", e))?;
        Ok(Some(entry.value))
    } else {
        Ok(None)
    }
}

/// Gets the current set of processed evidence IDs.
pub async fn get_evidence_set(rpc_addr: &str) -> Result<BTreeSet<[u8; 32]>> {
    let bytes_opt = query_state_key(rpc_addr, EVIDENCE_REGISTRY_KEY).await?;
    if let Some(bytes) = bytes_opt {
        codec::from_bytes_canonical(&bytes)
            .map_err(|e| anyhow!("Failed to decode evidence set: {}", e))
    } else {
        Ok(BTreeSet::new())
    }
}

/// Queries the block header for a specific, committed block height using gRPC.
pub async fn get_block_by_height(
    rpc_addr: &str,
    height: u64,
) -> Result<Option<Block<ChainTransaction>>> {
    let mut client = connect(rpc_addr).await?;
    let req = GetBlockByHeightRequest { height };
    // The server returns empty bytes if not found.
    let response = client.get_block_by_height(req).await?.into_inner();

    if response.block_bytes.is_empty() {
        Ok(None)
    } else {
        let block = codec::from_bytes_canonical(&response.block_bytes)
            .map_err(|e| anyhow!("Failed to decode block: {}", e))?;
        Ok(Some(block))
    }
}

/// Queries a raw key from the workload state against a specific historical root via RPC.
pub async fn query_state_key_at_root(
    rpc_addr: &str,
    root: &StateRoot,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    let mut client = connect(rpc_addr).await?;

    let req = ioi_ipc::blockchain::QueryStateAtRequest {
        root: root.0.clone(),
        key: key.to_vec(),
    };

    let response = client.query_state(req).await?.into_inner();

    // [FIX] Manually map the String error from codec to anyhow::Error
    let qs_resp: ioi_api::chain::QueryStateResponse =
        codec::from_bytes_canonical(&response.response_bytes)
            .map_err(|e| anyhow!("Failed to decode QueryStateResponse: {}", e))?;

    Ok(qs_resp.membership.into_option())
}

#[cfg(test)]
mod exact_completion_tests {
    use super::*;

    fn observed(
        tx_hash: &str,
        height: u64,
        durable_ms: u64,
        published_ms: u64,
    ) -> ObservedCommittedEvent {
        ObservedCommittedEvent {
            tx_hash: tx_hash.to_string(),
            height,
            durable_commit_ms: durable_ms,
            published_at_ms: published_ms,
            received_at: Instant::now(),
            received_at_wall_ms: published_ms.saturating_add(1),
        }
    }

    fn watch_with(events_to_send: Vec<ObservedCommittedEvent>) -> TransactionCommittedWatch {
        let (sender, events) = mpsc::unbounded_channel();
        for event in events_to_send {
            sender.send(event).expect("test receiver remains live");
        }
        drop(sender);
        TransactionCommittedWatch {
            events,
            reader: tokio::spawn(async {}),
        }
    }

    #[tokio::test]
    async fn wrong_transaction_is_never_substituted_for_the_exact_event() {
        let anchor = Instant::now();
        let mut watch = watch_with(vec![
            observed("wrong", 41, 100, 101),
            observed("expected", 42, 102, 103),
        ]);
        let result = watch
            .wait_for_exact_transaction(
                "expected",
                Some(42),
                anchor,
                anchor + Duration::from_secs(1),
            )
            .await
            .expect("the later exact event is the only admissible match");
        assert_eq!(result.height, 42);
        assert_eq!(result.durable_commit_ms, 102);
    }

    #[tokio::test]
    async fn missing_exact_event_fails_when_the_stream_ends() {
        let anchor = Instant::now();
        let mut watch = watch_with(vec![observed("other", 41, 100, 101)]);
        let error = watch
            .wait_for_exact_transaction(
                "expected",
                Some(42),
                anchor,
                anchor + Duration::from_secs(1),
            )
            .await
            .expect_err("a different event followed by stream end is not completion");
        assert!(error.to_string().contains("stream ended"));
    }

    #[tokio::test]
    async fn duplicate_exact_events_retain_one_identity_and_never_change_height() {
        let anchor = Instant::now();
        let mut watch = watch_with(vec![
            observed("expected", 42, 100, 101),
            observed("expected", 42, 100, 101),
        ]);
        for _ in 0..2 {
            let result = watch
                .wait_for_exact_transaction(
                    "expected",
                    Some(42),
                    anchor,
                    anchor + Duration::from_secs(1),
                )
                .await
                .expect("an identical duplicate cannot invent a second identity");
            assert_eq!(result.height, 42);
            assert_eq!(result.durable_commit_ms, 100);
            assert_eq!(result.published_at_ms, 101);
        }
    }

    #[tokio::test]
    async fn event_height_disagreement_and_pre_durability_publication_refuse() {
        let anchor = Instant::now();
        let mut wrong_height = watch_with(vec![observed("expected", 43, 100, 101)]);
        let height_error = wrong_height
            .wait_for_exact_transaction(
                "expected",
                Some(42),
                anchor,
                anchor + Duration::from_secs(1),
            )
            .await
            .expect_err("two heights for one commit must not be reconciled");
        assert!(height_error
            .to_string()
            .contains("disagreeing observations"));

        let mut premature = watch_with(vec![observed("expected", 42, 102, 101)]);
        let publication_error = premature
            .wait_for_exact_transaction(
                "expected",
                Some(42),
                anchor,
                anchor + Duration::from_secs(1),
            )
            .await
            .expect_err("publication before durability must refuse");
        assert!(publication_error
            .to_string()
            .contains("before the 102ms durability"));
    }
}
