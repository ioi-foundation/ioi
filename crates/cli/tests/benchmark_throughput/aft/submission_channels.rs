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

