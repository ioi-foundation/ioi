fn benchmark_primary_only() -> bool {
    std::env::var("IOI_AFT_BENCH_PRIMARY_ONLY")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn benchmark_lane_filter() -> Option<AftBenchmarkLane> {
    std::env::var("IOI_AFT_BENCH_LANE")
        .ok()
        .as_deref()
        .and_then(AftBenchmarkLane::parse)
}

fn benchmark_route_to_leaders_override() -> Option<bool> {
    std::env::var("IOI_AFT_BENCH_ROUTE_TO_LEADERS")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
}

fn benchmark_round_robin_by_tx_index_override() -> Option<bool> {
    std::env::var("IOI_AFT_BENCH_ROUND_ROBIN_BY_TX_INDEX")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
}

fn benchmark_prefer_target_height_leader() -> bool {
    std::env::var("IOI_AFT_BENCH_PREFER_TARGET_HEIGHT_LEADER")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn default_route_to_leaders(fast_probe: bool, benchmark_tx_total: usize) -> bool {
    fast_probe && benchmark_tx_total > 256
}

fn default_round_robin_by_tx_index(fast_probe: bool, txs_per_account: u64) -> bool {
    fast_probe && txs_per_account > 1
}

fn default_warm_first_committed_height(
    auto_future_genesis: bool,
    fast_probe: bool,
    benchmark_tx_total: usize,
) -> bool {
    auto_future_genesis && fast_probe && benchmark_tx_total > 256
}

fn default_ingress_leader_fanout(
    validators: usize,
    benchmark_tx_total: usize,
    benchmark_tx_select_max_bytes: u64,
    fast_probe: bool,
) -> usize {
    let approx_tx_capacity_per_leader =
        usize::max((benchmark_tx_select_max_bytes / 1_024) as usize, 1);
    let byte_based_fanout = usize::max(
        1,
        benchmark_tx_total.div_ceil(approx_tx_capacity_per_leader),
    );
    let burst_based_fanout = if fast_probe && benchmark_tx_total > 256 {
        usize::max(1, benchmark_tx_total.div_ceil(256))
    } else {
        1
    };

    usize::min(
        validators.max(1),
        usize::max(byte_based_fanout, burst_based_fanout),
    )
}

fn default_submit_lead_ms(
    target_block_time_ms: u64,
    fast_probe: bool,
    trace_mode: bool,
    benchmark_tx_total: usize,
) -> u64 {
    if fast_probe {
        if benchmark_tx_total > 256 {
            target_block_time_ms.saturating_div(4).clamp(100, 250)
        } else {
            target_block_time_ms.saturating_div(8).clamp(0, 50)
        }
    } else if trace_mode {
        target_block_time_ms.saturating_div(6).clamp(0, 75)
    } else {
        target_block_time_ms.saturating_div(4).clamp(10, 250)
    }
}

fn benchmark_block_time_ms(default_ms: u64) -> u64 {
    std::env::var("IOI_AFT_BENCH_BLOCK_TIME_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .or_else(|| {
            std::env::var("IOI_AFT_BENCH_BLOCK_TIME_SECS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .map(|secs| secs.saturating_mul(1_000))
        })
        .unwrap_or(default_ms)
}

fn benchmark_live_logs_enabled() -> bool {
    std::env::var("IOI_AFT_BENCH_LIVE_LOGS")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn default_submit_concurrency(
    total_expected_submissions: usize,
    submission_channel_count: usize,
    fast_probe: bool,
) -> usize {
    let baseline = usize::max(
        submission_channel_count
            .saturating_mul(if fast_probe { 4 } else { 8 })
            .max(1),
        128,
    );
    let capped = if fast_probe {
        baseline.min(256)
    } else {
        baseline
    };
    usize::min(total_expected_submissions.max(1), capped)
}

fn default_submit_wave_size(
    total_expected_submissions: usize,
    ingress_rpc_count: usize,
    fast_probe: bool,
) -> usize {
    if fast_probe && total_expected_submissions > 256 {
        usize::min(
            total_expected_submissions.max(1),
            usize::max(ingress_rpc_count.max(1).saturating_mul(64), 128).min(256),
        )
    } else {
        total_expected_submissions.max(1)
    }
}

fn default_submit_wave_pause_ms(
    target_block_time_ms: u64,
    ingress_rpc_count: usize,
    fast_probe: bool,
    total_expected_submissions: usize,
) -> u64 {
    if fast_probe && total_expected_submissions > 256 {
        target_block_time_ms
            .div_ceil((ingress_rpc_count.max(1) as u64).saturating_mul(16))
            .clamp(10, 100)
    } else {
        0
    }
}

fn default_alignment_safety_pad_ms(
    target_block_time_ms: u64,
    fast_probe: bool,
    total_expected_submissions: usize,
) -> u64 {
    if fast_probe && total_expected_submissions > 256 {
        target_block_time_ms.saturating_div(10).clamp(50, 100)
    } else {
        0
    }
}

fn alignment_pacing_budget_ms(
    total_expected_submissions: usize,
    submit_wave_size: usize,
    submit_wave_pause_ms: u64,
) -> u64 {
    let total_submission_waves = total_expected_submissions.div_ceil(submit_wave_size.max(1));
    submit_wave_pause_ms.saturating_mul(total_submission_waves.saturating_sub(1) as u64)
}

fn remaining_wave_pause_ms(
    elapsed_since_schedule_start: Duration,
    completed_wave_index: usize,
    submit_wave_pause_ms: u64,
) -> u64 {
    let target_elapsed_ms =
        submit_wave_pause_ms.saturating_mul(completed_wave_index.saturating_add(1) as u64);
    target_elapsed_ms.saturating_sub(
        elapsed_since_schedule_start
            .as_millis()
            .min(u128::from(u64::MAX)) as u64,
    )
}

fn alignment_ready_budget_ms(
    submit_lead_ms: u64,
    total_expected_submissions: usize,
    submit_wave_size: usize,
    submit_wave_pause_ms: u64,
    estimated_submission_service_budget_ms: u64,
    alignment_safety_pad_ms: u64,
) -> u64 {
    let pacing_budget_ms = alignment_pacing_budget_ms(
        total_expected_submissions,
        submit_wave_size,
        submit_wave_pause_ms,
    );

    submit_lead_ms
        .saturating_add(pacing_budget_ms)
        .saturating_add(estimated_submission_service_budget_ms)
        .saturating_add(alignment_safety_pad_ms)
}

fn alignment_start_lead_ms(
    submit_lead_ms: u64,
    total_expected_submissions: usize,
    submit_wave_size: usize,
    submit_wave_pause_ms: u64,
    estimated_submission_service_budget_ms: u64,
) -> u64 {
    submit_lead_ms
        .saturating_add(alignment_pacing_budget_ms(
            total_expected_submissions,
            submit_wave_size,
            submit_wave_pause_ms,
        ))
        .saturating_add(estimated_submission_service_budget_ms)
}

fn select_aligned_due_ms(
    base_due_ms: u64,
    now_ms: u64,
    target_block_time_ms: u64,
    ready_budget_ms: u64,
) -> u64 {
    let earliest_due_ms = now_ms.saturating_add(ready_budget_ms);
    if base_due_ms >= earliest_due_ms {
        base_due_ms
    } else {
        let skipped_due_slots = earliest_due_ms
            .saturating_sub(base_due_ms)
            .div_ceil(target_block_time_ms);
        base_due_ms.saturating_add(skipped_due_slots.saturating_mul(target_block_time_ms))
    }
}

fn aligned_target_height_for_due_ms(
    alignment_height: u64,
    base_due_ms: u64,
    next_due_ms: u64,
    target_block_time_ms: u64,
) -> u64 {
    let skipped_due_slots = next_due_ms
        .saturating_sub(base_due_ms)
        .checked_div(target_block_time_ms.max(1))
        .unwrap_or_default();
    alignment_height
        .saturating_add(skipped_due_slots)
        .saturating_add(1)
}

fn summarize_alignment_block_packing(
    per_block_tx_counts: &[(u64, usize)],
    target_height: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    let Some(target_height) = target_height else {
        return (None, None);
    };

    let mut committed_before_target_height_txs = 0u64;
    let mut committed_at_target_height_txs = 0u64;
    for (height, matched_count) in per_block_tx_counts {
        if *height < target_height {
            committed_before_target_height_txs =
                committed_before_target_height_txs.saturating_add(*matched_count as u64);
        } else if *height == target_height {
            committed_at_target_height_txs =
                committed_at_target_height_txs.saturating_add(*matched_count as u64);
        }
    }

    (
        Some(committed_before_target_height_txs),
        Some(committed_at_target_height_txs),
    )
}

fn sampled_commit_visibility_lag_ms(
    authoritative_final_commit_instant: Instant,
    sampled_final_commit_instant: Option<Instant>,
) -> Option<i64> {
    sampled_final_commit_instant.map(|sampled_final_commit_instant| {
        if sampled_final_commit_instant >= authoritative_final_commit_instant {
            let lag_ms = sampled_final_commit_instant
                .duration_since(authoritative_final_commit_instant)
                .as_millis();
            lag_ms.min(i64::MAX as u128) as i64
        } else {
            let lag_ms = authoritative_final_commit_instant
                .duration_since(sampled_final_commit_instant)
                .as_millis();
            -(lag_ms.min(i64::MAX as u128) as i64)
        }
    })
}

fn sustained_commit_endpoint(
    fast_probe: bool,
    authoritative_final_commit_instant: Instant,
    sampled_final_commit_instant: Option<Instant>,
) -> Instant {
    if fast_probe {
        authoritative_final_commit_instant
    } else {
        sampled_final_commit_instant.unwrap_or(authoritative_final_commit_instant)
    }
}

async fn sample_status_latencies(rpc_addrs: &[String]) -> Result<LatencySummary> {
    let latency_samples = stream::iter(rpc_addrs.iter().cloned())
        .then(|rpc_addr| async move {
            let sample_started = Instant::now();
            rpc::get_status(&rpc_addr).await?;
            Ok::<Duration, anyhow::Error>(sample_started.elapsed())
        })
        .try_collect::<Vec<_>>()
        .await?;
    Ok(summarize_latencies(&latency_samples))
}

fn estimated_submission_service_budget_ms(
    total_expected_submissions: usize,
    submit_concurrency: usize,
    ingress_status_latency: LatencySummary,
) -> u64 {
    let submission_rounds = total_expected_submissions.div_ceil(submit_concurrency.max(1)) as u64;
    let round_trip_budget_ms = ingress_status_latency
        .p95_ms
        .ceil()
        .clamp(1.0, u64::MAX as f64) as u64;
    submission_rounds.saturating_mul(round_trip_budget_ms)
}

fn flatten_submissions(
    signed_account_txs: Vec<Vec<Vec<u8>>>,
    round_robin_by_tx_index: bool,
) -> Vec<(usize, usize, Vec<u8>)> {
    let total_expected_submissions = signed_account_txs.iter().map(Vec::len).sum();
    if !round_robin_by_tx_index {
        return signed_account_txs
            .into_iter()
            .enumerate()
            .flat_map(|(account_index, txs)| {
                txs.into_iter()
                    .enumerate()
                    .map(move |(tx_index, tx_bytes)| (account_index, tx_index, tx_bytes))
            })
            .collect::<Vec<_>>();
    }

    let mut flattened = Vec::with_capacity(total_expected_submissions);
    let mut per_account_iters = signed_account_txs
        .into_iter()
        .map(|txs| txs.into_iter())
        .collect::<Vec<_>>();
    let mut tx_index = 0usize;

    loop {
        let mut advanced = false;
        for (account_index, txs) in per_account_iters.iter_mut().enumerate() {
            if let Some(tx_bytes) = txs.next() {
                flattened.push((account_index, tx_index, tx_bytes));
                advanced = true;
            }
        }
        if !advanced {
            break;
        }
        tx_index = tx_index.saturating_add(1);
    }

    flattened
}

fn spawn_benchmark_live_log_drains(cluster: &TestCluster) {
    if !benchmark_live_logs_enabled() {
        return;
    }

    for (validator_index, guard) in cluster.validators.iter().enumerate() {
        let (mut orch_logs, mut workload_logs, guardian_logs) = guard.validator().subscribe_logs();
        tokio::spawn(async move {
            loop {
                match orch_logs.recv().await {
                    Ok(line) => {
                        println!("[BENCH-LIVE][v{validator_index}][orch] {line}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        println!(
                            "[BENCH-LIVE][v{validator_index}][orch] <lagged {skipped} log lines>"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        if benchmark_trace_enabled() {
            tokio::spawn(async move {
                loop {
                    match workload_logs.recv().await {
                        Ok(line) => {
                            println!("[BENCH-LIVE][v{validator_index}][workload] {line}");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            println!(
                                "[BENCH-LIVE][v{validator_index}][workload] <lagged {skipped} log lines>"
                            );
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });

            if let Some(mut guardian_logs) = guardian_logs {
                tokio::spawn(async move {
                    loop {
                        match guardian_logs.recv().await {
                            Ok(line) => {
                                println!("[BENCH-LIVE][v{validator_index}][guardian] {line}");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                println!(
                                    "[BENCH-LIVE][v{validator_index}][guardian] <lagged {skipped} log lines>"
                                );
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct PrepareBlockMetrics {
    height: u64,
    replay_mode: String,
    replay_debt: u64,
    validation_aborts: u64,
    execution_errors: u64,
}

#[derive(Debug, Default)]
struct BenchmarkChurnTracker {
    fallback_heights: BTreeSet<u64>,
    max_replay_debt: u64,
    max_validation_aborts: u64,
    max_execution_errors: u64,
}

impl BenchmarkChurnTracker {
    fn observe(&mut self, metrics: &PrepareBlockMetrics) {
        if metrics.replay_mode == "fallback_sequential" {
            self.fallback_heights.insert(metrics.height);
        }
        self.max_replay_debt = self.max_replay_debt.max(metrics.replay_debt);
        self.max_validation_aborts = self.max_validation_aborts.max(metrics.validation_aborts);
        self.max_execution_errors = self.max_execution_errors.max(metrics.execution_errors);
    }

    fn snapshot(&self) -> BenchmarkChurnSummary {
        BenchmarkChurnSummary {
            fallback_blocks: self.fallback_heights.len(),
            max_replay_debt: self.max_replay_debt,
            max_validation_aborts: self.max_validation_aborts,
            max_execution_errors: self.max_execution_errors,
        }
    }
}

