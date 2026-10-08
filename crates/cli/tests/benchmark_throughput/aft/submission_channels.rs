fn preferred_submission_channel_span(
    prefer_target_height_leader_submission: bool,
    connections_per_addr: usize,
    total_submission_channels: usize,
) -> usize {
    if prefer_target_height_leader_submission {
        connections_per_addr.min(total_submission_channels).max(1)
    } else {
        total_submission_channels.max(1)
    }
}

async fn submit_account_sequence(
    channels: Arc<Vec<Channel>>,
    preferred_channel_index: usize,
    status_channel_index: usize,
    txs: Vec<Vec<u8>>,
) -> Result<Vec<SubmittedTx>> {
    let mut submitted = Vec::with_capacity(txs.len());
    for tx_bytes in txs {
        submitted.push(
            submit_transaction_bytes(
                channels.as_ref(),
                preferred_channel_index,
                status_channel_index,
                tx_bytes,
            )
            .await?,
        );
    }

    Ok(submitted)
}

async fn submit_transaction_bytes(
    channels: &[Channel],
    preferred_channel_index: usize,
    status_channel_index: usize,
    tx_bytes: Vec<u8>,
) -> Result<SubmittedTx> {
    let submit_timeout = Duration::from_millis(benchmark_override_u64(
        "IOI_AFT_BENCH_SUBMIT_TIMEOUT_MS",
        DEFAULT_SUBMIT_TIMEOUT_MS,
    ));

    let chain_hash = codec::from_bytes_canonical::<ChainTransaction>(&tx_bytes)
        .ok()
        .and_then(|tx| tx.hash().ok())
        .map(hex::encode)
        .unwrap_or_default();
    let mut retries = 0u64;
    let mut timeout_retries = 0u64;
    loop {
        let channel_index = if channels.is_empty() {
            0
        } else {
            preferred_channel_index.saturating_add(retries as usize) % channels.len()
        };
        let mut client = PublicApiClient::new(
            channels
                .get(channel_index)
                .ok_or_else(|| anyhow!("no submission channels available"))?
                .clone(),
        );
        let request = tonic::Request::new(SubmitTransactionRequest {
            transaction_bytes: tx_bytes.clone(),
        });
        let submit_started = Instant::now();

        match timeout(submit_timeout, client.submit_transaction(request)).await {
            Err(_) => {
                retries += 1;
                timeout_retries += 1;
                if retries > MAX_RETRIES as u64 {
                    return Err(anyhow!(
                        "submit retries exceeded after timeout waiting {} ms",
                        submit_timeout.as_millis()
                    ));
                }
                sleep(Duration::from_millis(BACKOFF_MS)).await;
                continue;
            }
            Ok(Err(status)) => {
                let message = status.message().to_string();
                let retryable = matches!(
                    status.code(),
                    Code::ResourceExhausted | Code::Unavailable | Code::Internal
                ) || (status.code() == Code::InvalidArgument
                    && (message.contains("Nonce mismatch")
                        || message.contains("Nonce record not found")));

                if retryable {
                    retries += 1;
                    if retries > MAX_RETRIES as u64 {
                        return Err(anyhow!(
                            "submit retries exceeded: code={}, message={}",
                            status.code(),
                            message
                        ));
                    }
                    sleep(Duration::from_millis(BACKOFF_MS)).await;
                    continue;
                }

                if status.code() == Code::InvalidArgument
                    && (message.contains("already exists")
                        || message.contains("nonce too low")
                        || message.contains("Mempool"))
                {
                    let admitted_at = Instant::now();
                    return Ok(SubmittedTx {
                        tx_hash: String::new(),
                        chain_hash: String::new(),
                        submitted_at: submit_started,
                        admitted_at,
                        status_channel_index,
                        submit_retries: retries,
                        submit_timeout_retries: timeout_retries,
                        duplicate_response: true,
                    });
                }

                return Err(anyhow!(
                    "submit failed: code={}, message={}",
                    status.code(),
                    message
                ));
            }
            Ok(Ok(response)) => {
                let tx_hash = response.into_inner().tx_hash;
                let admitted_at = Instant::now();
                return Ok(SubmittedTx {
                    tx_hash,
                    chain_hash: chain_hash.clone(),
                    submitted_at: submit_started,
                    admitted_at,
                    status_channel_index,
                    submit_retries: retries,
                    submit_timeout_retries: timeout_retries,
                    duplicate_response: false,
                });
            }
        }
    }
}

async fn poll_committed_transaction(
    channels: &[Channel],
    submitted: SubmittedTx,
    timeout: Duration,
) -> Result<CommittedTx> {
    let deadline = submitted
        .submitted_at
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timeout waiting for tx {} to commit",
                submitted.tx_hash
            ));
        }

        if let Some((status, error_message, block_height)) =
            query_transaction_status_any(channels, &submitted.tx_hash).await?
        {
            match status {
                TxStatus::Committed => {
                    return Ok(CommittedTx {
                        submitted_at: submitted.submitted_at,
                        committed_at: Instant::now(),
                        block_height,
                    });
                }
                TxStatus::Rejected => {
                    return Err(anyhow!(
                        "transaction {} rejected: {}",
                        submitted.tx_hash,
                        error_message
                    ));
                }
                _ => {}
            }
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn query_state_key_any_rpc(rpc_addrs: &[String], key: &[u8]) -> Result<Option<Vec<u8>>> {
    for rpc_addr in rpc_addrs {
        if let Some(value) = rpc::query_state_key(rpc_addr, key).await? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

async fn wait_for_canonical_ordering_terminal_block(
    rpc_addrs: &[String],
    height: u64,
    timeout: Duration,
) -> Result<AftTerminalBlock> {
    let start = Instant::now();
    let close_key = aft_order_certificate_key(height);
    let abort_key = aft_canonical_order_abort_key(height);
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "timeout waiting for canonical ordering terminal surface at height {}",
                height
            ));
        }

        if query_state_key_any_rpc(rpc_addrs, &abort_key)
            .await?
            .is_some()
        {
            return Ok(AftTerminalBlock {
                height,
                terminal_at: Instant::now(),
                outcome: AftTerminalOutcome::Abort,
            });
        }
        if query_state_key_any_rpc(rpc_addrs, &close_key)
            .await?
            .is_some()
        {
            return Ok(AftTerminalBlock {
                height,
                terminal_at: Instant::now(),
                outcome: AftTerminalOutcome::Close,
            });
        }
        if let Some(block) = get_block_by_height_any_rpc(rpc_addrs, height).await? {
            if block.header.canonical_order_certificate.is_some() {
                return Ok(AftTerminalBlock {
                    height,
                    terminal_at: Instant::now(),
                    outcome: AftTerminalOutcome::Close,
                });
            }
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_durable_collapse_terminal_block(
    rpc_addrs: &[String],
    height: u64,
    timeout: Duration,
) -> Result<AftTerminalBlock> {
    let start = Instant::now();
    let collapse_key = aft_canonical_collapse_object_key(height);
    let abort_key = aft_canonical_order_abort_key(height);
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "timeout waiting for durable collapse surface at height {}",
                height
            ));
        }

        if query_state_key_any_rpc(rpc_addrs, &collapse_key)
            .await?
            .is_some()
        {
            let outcome = if query_state_key_any_rpc(rpc_addrs, &abort_key)
                .await?
                .is_some()
            {
                AftTerminalOutcome::Abort
            } else {
                AftTerminalOutcome::Close
            };
            return Ok(AftTerminalBlock {
                height,
                terminal_at: Instant::now(),
                outcome,
            });
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_sealed_terminal_block(
    rpc_addrs: &[String],
    height: u64,
    timeout: Duration,
) -> Result<AftTerminalBlock> {
    let start = Instant::now();
    let abort_key = aft_canonical_order_abort_key(height);
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "timeout waiting for sealed AFT terminal surface at height {}",
                height
            ));
        }

        if query_state_key_any_rpc(rpc_addrs, &abort_key)
            .await?
            .is_some()
        {
            return Ok(AftTerminalBlock {
                height,
                terminal_at: Instant::now(),
                outcome: AftTerminalOutcome::Abort,
            });
        }

        if let Some(block) = get_block_by_height_any_rpc(rpc_addrs, height).await? {
            if block.header.sealed_finality_proof.is_some() {
                return Ok(AftTerminalBlock {
                    height,
                    terminal_at: Instant::now(),
                    outcome: AftTerminalOutcome::Close,
                });
            }
        }

        sleep(Duration::from_millis(200)).await;
    }
}

async fn query_transaction_status_any(
    channels: &[Channel],
    tx_hash: &str,
) -> Result<Option<(TxStatus, String, u64)>> {
    let status_timeout = Duration::from_millis(benchmark_override_u64(
        "IOI_AFT_BENCH_STATUS_TIMEOUT_MS",
        DEFAULT_STATUS_TIMEOUT_MS,
    ));
    let responses = stream::iter(channels.iter().cloned())
        .map(|channel| {
            let tx_hash = tx_hash.to_string();
            let status_timeout = status_timeout;
            async move {
                let mut client = PublicApiClient::new(channel);
                timeout(
                    status_timeout,
                    client.get_transaction_status(tonic::Request::new(
                        GetTransactionStatusRequest { tx_hash },
                    )),
                )
                .await
                .ok()
                .and_then(|result| result.ok())
                .map(|response| response.into_inner())
            }
        })
        .buffer_unordered(channels.len().max(1))
        .collect::<Vec<_>>()
        .await;

    let mut first_rejection = None;
    let mut first_pending = None;
    let mut first_unknown = None;

    for response in responses.into_iter().flatten() {
        let decoded = TxStatus::try_from(response.status).unwrap_or(TxStatus::Unknown);
        match decoded {
            TxStatus::Committed => {
                return Ok(Some((
                    TxStatus::Committed,
                    response.error_message,
                    response.block_height,
                )))
            }
            TxStatus::Rejected => {
                if first_rejection.is_none() {
                    first_rejection = Some((
                        TxStatus::Rejected,
                        response.error_message,
                        response.block_height,
                    ));
                }
            }
            TxStatus::InMempool | TxStatus::Pending => {
                if first_pending.is_none() {
                    first_pending = Some((decoded, response.error_message, response.block_height));
                }
            }
            TxStatus::Unknown => {
                if first_unknown.is_none() {
                    first_unknown = Some((
                        TxStatus::Unknown,
                        response.error_message,
                        response.block_height,
                    ));
                }
            }
        }
    }

    Ok(first_pending.or(first_unknown).or(first_rejection))
}

async fn get_block_by_height_any_rpc(
    rpc_addrs: &[String],
    height: u64,
) -> Result<Option<ioi_types::app::Block<ioi_types::app::ChainTransaction>>> {
    for rpc_addr in rpc_addrs {
        if let Some(block) = rpc::get_block_by_height_resilient(rpc_addr, height).await? {
            return Ok(Some(block));
        }
    }
    Ok(None)
}

/// fork_check `per_node_root_agreement.v1` (P7, build Ruling 12; NET's
/// `records/proposals/FORK-CHECK-per_node_root_agreement.v1/`, mirroring
/// `internal-docs/architecture/protocols/aft/bench/akash/fork_check_reference.py`).
///
/// The commit-latency scan above merges nodes by height (`get_block_by_height_any_rpc`), so a
/// forked run once read as one chain (OBS-10: `recent=[11:6880,12:256]`). This check never merges
/// nodes: every node must report the SAME (header hash, state_root) at every height up to the
/// common tip. An unreachable node or a hole below the common tip is `degraded`, never skipped;
/// a lagging node is not a fork.
const FORK_CHECK_SCHEMA: &str = "ioi.aft.fork-check.v1";

#[derive(Debug, Clone, serde::Serialize)]
struct ForkCheckNode {
    rpc: String,
    reachable: bool,
    tip: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ForkCheckDivergence {
    height: u64,
    /// `[rpc, header_hash_hex | null, state_root_hex | null]` per node.
    per_node: Vec<(String, Option<String>, Option<String>)>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ForkCheck {
    schema: &'static str,
    scenario: String,
    lane: String,
    /// `agree`, `forked` or `degraded`.
    verdict: &'static str,
    common_tip: u64,
    nodes: Vec<ForkCheckNode>,
    first_divergence: Option<ForkCheckDivergence>,
}

/// One node as the fork check observed it: whether it answered, its tip, and its block identity
/// (header hash, state root) at each height read.
#[derive(Debug, Clone, Default)]
struct ForkCheckObservation {
    rpc: String,
    reachable: bool,
    tip: Option<u64>,
    blocks: BTreeMap<u64, (Option<String>, Option<String>)>,
}

/// The verdict over the observations (the pure part of the check, unit-tested below).
fn root_agreement_verdict(nodes: &[ForkCheckObservation], scenario: &str, lane: &str) -> ForkCheck {
    let summary: Vec<ForkCheckNode> = nodes
        .iter()
        .map(|node| ForkCheckNode {
            rpc: node.rpc.clone(),
            reachable: node.reachable,
            tip: node.tip,
        })
        .collect();
    let verdict = |verdict, common_tip, first_divergence| ForkCheck {
        schema: FORK_CHECK_SCHEMA,
        scenario: scenario.to_string(),
        lane: lane.to_string(),
        verdict,
        common_tip,
        nodes: summary.clone(),
        first_divergence,
    };
    if nodes.is_empty()
        || nodes
            .iter()
            .any(|node| !node.reachable || node.tip.is_none())
    {
        // An unreachable node is never silently skipped.
        return verdict("degraded", 0, None);
    }
    let common_tip = nodes.iter().filter_map(|node| node.tip).min().unwrap_or(0);
    for height in 1..=common_tip {
        let mut per_node = Vec::with_capacity(nodes.len());
        for node in nodes {
            let Some((hash, root)) = node.blocks.get(&height) else {
                // A hole below the common tip.
                return verdict("degraded", common_tip, None);
            };
            per_node.push((node.rpc.clone(), hash.clone(), root.clone()));
        }
        let first = (&per_node[0].1, &per_node[0].2);
        if per_node[0].1.is_none() || per_node.iter().any(|(_, hash, root)| (hash, root) != first) {
            return verdict(
                "forked",
                common_tip,
                Some(ForkCheckDivergence { height, per_node }),
            );
        }
    }
    verdict("agree", common_tip, None)
}

/// Observes every node separately (tip, then each height up to the common tip) and returns the
/// verdict. It reads at most `common_tip × nodes` blocks.
async fn check_per_node_root_agreement(
    rpc_addrs: &[String],
    scenario: &str,
    lane: &str,
) -> ForkCheck {
    let mut nodes = Vec::with_capacity(rpc_addrs.len());
    for rpc_addr in rpc_addrs {
        let tip = rpc::tip_height_resilient(rpc_addr).await.ok();
        nodes.push(ForkCheckObservation {
            rpc: rpc_addr.clone(),
            reachable: tip.is_some(),
            tip,
            blocks: BTreeMap::new(),
        });
    }
    if nodes.iter().all(|node| node.reachable) {
        let common_tip = nodes.iter().filter_map(|node| node.tip).min().unwrap_or(0);
        for node in &mut nodes {
            for height in 1..=common_tip {
                let block = rpc::get_block_by_height_resilient(&node.rpc, height)
                    .await
                    .ok()
                    .flatten();
                let Some(block) = block else {
                    break;
                };
                let hash = block.header.hash().ok().map(hex::encode);
                let root = Some(hex::encode(&block.header.state_root.0));
                node.blocks.insert(height, (hash, root));
            }
        }
    }
    root_agreement_verdict(&nodes, scenario, lane)
}

#[cfg(test)]
mod fork_check_tests {
    //! The reference cases of `fork_check_reference.py` (NET, 7/7), on the Rust verdict.
    use super::*;

    fn node(
        rpc: &str,
        tip: Option<u64>,
        blocks: &[(u64, &str, &str)],
        reachable: bool,
    ) -> ForkCheckObservation {
        ForkCheckObservation {
            rpc: rpc.to_string(),
            reachable,
            tip,
            blocks: blocks
                .iter()
                .map(|(height, hash, root)| {
                    (*height, (Some(hash.to_string()), Some(root.to_string())))
                })
                .collect(),
        }
    }

    fn chain_a(to: u64) -> Vec<(u64, String, String)> {
        (1..=to)
            .map(|h| (h, format!("h{h}"), format!("r{h}")))
            .collect()
    }

    fn refs(chain: &[(u64, String, String)]) -> Vec<(u64, &str, &str)> {
        chain
            .iter()
            .map(|(h, a, b)| (*h, a.as_str(), b.as_str()))
            .collect()
    }

    #[test]
    fn all_nodes_agree() {
        let a = chain_a(12);
        let nodes: Vec<_> = (0..4)
            .map(|i| node(&format!("n{i}"), Some(12), &refs(&a), true))
            .collect();
        let verdict = root_agreement_verdict(&nodes, "s", "l");
        assert_eq!((verdict.verdict, verdict.common_tip), ("agree", 12));
        assert_eq!(verdict.schema, FORK_CHECK_SCHEMA);
    }

    #[test]
    fn a_lagging_node_is_not_a_fork() {
        let a = chain_a(12);
        let lag = chain_a(10);
        let mut nodes: Vec<_> = (0..3)
            .map(|i| node(&format!("n{i}"), Some(12), &refs(&a), true))
            .collect();
        nodes.push(node("n3", Some(10), &refs(&lag), true));
        let verdict = root_agreement_verdict(&nodes, "s", "l");
        assert_eq!((verdict.verdict, verdict.common_tip), ("agree", 10));
    }

    #[test]
    fn the_obs10_shape_is_forked_at_height_11() {
        let majority = chain_a(11);
        let mut b = chain_a(12);
        b[10] = (11, "hB11".into(), "rB11".into());
        b[11] = (12, "hB12".into(), "rB12".into());
        let mut nodes: Vec<_> = (0..3)
            .map(|i| node(&format!("n{i}"), Some(11), &refs(&majority), true))
            .collect();
        nodes.push(node("n3", Some(12), &refs(&b), true));
        let verdict = root_agreement_verdict(&nodes, "s", "l");
        assert_eq!(verdict.verdict, "forked");
        assert_eq!(verdict.first_divergence.map(|d| d.height), Some(11));
    }

    #[test]
    fn the_same_hash_with_another_root_is_forked() {
        let a = chain_a(12);
        let mut c = chain_a(12);
        c[4] = (5, "h5".into(), "rX".into());
        let nodes = vec![
            node("n0", Some(12), &refs(&a), true),
            node("n1", Some(12), &refs(&c), true),
        ];
        let verdict = root_agreement_verdict(&nodes, "s", "l");
        assert_eq!(verdict.verdict, "forked");
        assert_eq!(verdict.first_divergence.map(|d| d.height), Some(5));
    }

    #[test]
    fn an_unreachable_node_is_degraded_never_skipped() {
        let a = chain_a(12);
        let nodes = vec![
            node("n0", Some(12), &refs(&a), true),
            node("n1", None, &[], false),
        ];
        assert_eq!(root_agreement_verdict(&nodes, "s", "l").verdict, "degraded");
    }

    #[test]
    fn a_missing_block_below_the_common_tip_is_degraded() {
        let a = chain_a(12);
        let mut hole = chain_a(12);
        hole.remove(6);
        let nodes = vec![
            node("n0", Some(12), &refs(&a), true),
            node("n1", Some(12), &refs(&hole), true),
        ];
        assert_eq!(root_agreement_verdict(&nodes, "s", "l").verdict, "degraded");
    }

    #[test]
    fn a_cluster_of_only_unreachable_nodes_is_degraded_never_agree() {
        let nodes = vec![node("n0", None, &[], false), node("n1", None, &[], false)];
        assert_eq!(root_agreement_verdict(&nodes, "s", "l").verdict, "degraded");
        // A reachable node that reports no tip is also never skipped.
        let nodes = vec![node("n0", None, &[], true), node("n1", None, &[], true)];
        assert_eq!(root_agreement_verdict(&nodes, "s", "l").verdict, "degraded");
    }

    #[test]
    fn an_empty_node_list_is_degraded() {
        assert_eq!(root_agreement_verdict(&[], "s", "l").verdict, "degraded");
    }

    #[test]
    fn an_unhashable_block_is_forked_not_agreed() {
        let mut nodes = vec![
            node("n0", Some(1), &[], true),
            node("n1", Some(1), &[], true),
        ];
        for node in &mut nodes {
            node.blocks.insert(1, (None, Some("r1".into())));
        }
        assert_eq!(root_agreement_verdict(&nodes, "s", "l").verdict, "forked");
    }
}

#[derive(Debug, Clone)]
struct ChainCommitScan {
    committed: u64,
    scanned_tip_height: u64,
    committed_heights: BTreeSet<u64>,
    per_block_tx_counts: Vec<(u64, usize)>,
}

async fn scan_committed_hashes_from_chain(
    rpc_addrs: &[String],
    initial_height: u64,
    expected_hashes: &HashSet<String>,
    timeout: Duration,
) -> Result<ChainCommitScan> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut seen_hashes = HashSet::<String>::with_capacity(expected_hashes.len());
    let mut committed_heights = BTreeSet::new();
    let mut per_block_tx_counts = Vec::new();
    let mut next_height = initial_height.saturating_add(1);
    let mut last_progress_log = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    let mut last_scanned_tip = initial_height;

    loop {
        while let Some(block) = get_block_by_height_any_rpc(rpc_addrs, next_height).await? {
            let mut matched_in_block = 0usize;
            for tx in &block.transactions {
                if let Ok(hash) = tx.hash() {
                    let hash_hex = hex::encode(hash);
                    if expected_hashes.contains(&hash_hex) && seen_hashes.insert(hash_hex) {
                        matched_in_block += 1;
                    }
                }
            }
            per_block_tx_counts.push((next_height, matched_in_block));
            if matched_in_block > 0 {
                committed_heights.insert(next_height);
            }
            last_scanned_tip = next_height;
            next_height = next_height.saturating_add(1);
        }

        if last_progress_log.elapsed() >= Duration::from_secs(5) {
            println!(
                "chain scan progress: scanned_tip={} committed={}/{} scanned_blocks={}",
                last_scanned_tip,
                seen_hashes.len(),
                expected_hashes.len(),
                per_block_tx_counts.len()
            );
            last_progress_log = Instant::now();
        }

        if seen_hashes.len() >= expected_hashes.len() {
            return Ok(ChainCommitScan {
                committed: seen_hashes.len() as u64,
                scanned_tip_height: last_scanned_tip,
                committed_heights,
                per_block_tx_counts,
            });
        }

        if Instant::now() >= deadline {
            return Ok(ChainCommitScan {
                committed: seen_hashes.len() as u64,
                scanned_tip_height: last_scanned_tip,
                committed_heights,
                per_block_tx_counts,
            });
        }

        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_committed_hashes_on_chain(
    rpc_addrs: &[String],
    initial_height: u64,
    expected_hashes: &HashSet<String>,
    timeout: Duration,
) -> Result<(Instant, ChainCommitScan)> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut seen_hashes = HashSet::<String>::with_capacity(expected_hashes.len());
    let mut committed_heights = BTreeSet::new();
    let mut per_block_tx_counts = Vec::new();
    let mut next_height = initial_height.saturating_add(1);
    let mut last_progress_log = Instant::now()
        .checked_sub(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    let mut last_scanned_tip = initial_height;

    loop {
        while let Some(block) = get_block_by_height_any_rpc(rpc_addrs, next_height).await? {
            let mut matched_in_block = 0usize;
            for tx in &block.transactions {
                if let Ok(hash) = tx.hash() {
                    let hash_hex = hex::encode(hash);
                    if expected_hashes.contains(&hash_hex) && seen_hashes.insert(hash_hex) {
                        matched_in_block += 1;
                    }
                }
            }
            per_block_tx_counts.push((next_height, matched_in_block));
            if matched_in_block > 0 {
                committed_heights.insert(next_height);
            }
            last_scanned_tip = next_height;
            next_height = next_height.saturating_add(1);
        }

        if last_progress_log.elapsed() >= Duration::from_secs(5) {
            println!(
                "chain commit progress: scanned_tip={} committed={}/{} scanned_blocks={}",
                last_scanned_tip,
                seen_hashes.len(),
                expected_hashes.len(),
                per_block_tx_counts.len()
            );
            last_progress_log = Instant::now();
        }

        if seen_hashes.len() >= expected_hashes.len() {
            return Ok((
                Instant::now(),
                ChainCommitScan {
                    committed: seen_hashes.len() as u64,
                    scanned_tip_height: last_scanned_tip,
                    committed_heights,
                    per_block_tx_counts,
                },
            ));
        }

        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timeout waiting for {} committed transaction hashes; observed {} before deadline (scanned_tip={})",
                expected_hashes.len(),
                seen_hashes.len(),
                last_scanned_tip,
            ));
        }

        sleep(Duration::from_millis(250)).await;
    }
}

async fn capture_cluster_commit_view(rpc_addrs: &[String]) -> String {
    let mut rows = Vec::with_capacity(rpc_addrs.len());
    for rpc_addr in rpc_addrs {
        match rpc::get_status(rpc_addr).await {
            Ok(status) => rows.push(format!(
                "{} => height={} total_transactions={}",
                rpc_addr, status.height, status.total_transactions
            )),
            Err(error) => rows.push(format!("{} => status_error={}", rpc_addr, error)),
        }
    }
    rows.join(" | ")
}

async fn fetch_metric(metrics_addr: &str, name: &str) -> String {
    let url = format!("http://{metrics_addr}/metrics");
    match reqwest::get(&url).await {
        Ok(resp) => match resp.text().await {
            Ok(text) => text
                .lines()
                .find_map(|line| {
                    line.starts_with(name)
                        .then(|| line.split_whitespace().last().unwrap_or("?").to_string())
                })
                .unwrap_or_else(|| "missing".to_string()),
            Err(_) => "Err".to_string(),
        },
        Err(_) => "Down".to_string(),
    }
}

async fn capture_cluster_metrics_view(cluster: &TestCluster) -> String {
    let mut rows = Vec::with_capacity(cluster.validators.len());
    for validator in &cluster.validators {
        let rpc_addr = &validator.validator().rpc_addr;
        let metrics_addr = &validator.validator().orchestration_telemetry_addr;
        let snapshot = MetricsSnapshot {
            connected_peers: fetch_metric(metrics_addr, "ioi_networking_connected_peers").await,
            mempool_size: fetch_metric(metrics_addr, "ioi_mempool_size").await,
            blocks_produced_total: fetch_metric(
                metrics_addr,
                "ioi_consensus_blocks_produced_total",
            )
            .await,
        };
        rows.push(format!(
            "{} => peers={} mempool={} blocks_produced={}",
            rpc_addr,
            snapshot.connected_peers,
            snapshot.mempool_size,
            snapshot.blocks_produced_total,
        ));
    }
    rows.join(" | ")
}

