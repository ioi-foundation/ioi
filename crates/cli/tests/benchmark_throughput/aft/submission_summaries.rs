fn summarize_block_tx_counts(per_block_tx_counts: &[(u64, usize)]) -> String {
    if per_block_tx_counts.is_empty() {
        return "no scanned blocks".to_string();
    }

    let non_zero = per_block_tx_counts
        .iter()
        .filter(|(_, count)| *count > 0)
        .cloned()
        .collect::<Vec<_>>();
    let recent = per_block_tx_counts
        .iter()
        .rev()
        .take(12)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|(height, count)| format!("{height}:{count}"))
        .collect::<Vec<_>>()
        .join(",");

    let max_block = per_block_tx_counts
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(0);
    let non_zero_avg = if non_zero.is_empty() {
        0.0
    } else {
        non_zero.iter().map(|(_, count)| *count as f64).sum::<f64>() / non_zero.len() as f64
    };

    format!(
        "scanned_blocks={} non_zero_blocks={} max_block_match={} avg_non_zero_block_match={:.2} recent=[{}]",
        per_block_tx_counts.len(),
        non_zero.len(),
        max_block,
        non_zero_avg,
        recent
    )
}

fn canonicalize_submitted_records(submitted_records: &[SubmittedTx]) -> Vec<SubmittedTx> {
    let mut unique = BTreeMap::<String, SubmittedTx>::new();
    for submitted in submitted_records {
        if submitted.tx_hash.is_empty() {
            continue;
        }
        unique
            .entry(submitted.tx_hash.clone())
            .and_modify(|existing| {
                if submitted.submitted_at < existing.submitted_at {
                    *existing = submitted.clone();
                }
            })
            .or_insert_with(|| submitted.clone());
    }
    unique.into_values().collect()
}

fn sample_submitted_records_for_latency(
    submitted_records: &[SubmittedTx],
    limit: usize,
) -> Vec<SubmittedTx> {
    let mut buckets = BTreeMap::<usize, Vec<SubmittedTx>>::new();
    for submitted in submitted_records.iter().cloned() {
        buckets
            .entry(submitted.status_channel_index)
            .or_default()
            .push(submitted);
    }

    let mut sampled = Vec::with_capacity(limit.min(submitted_records.len()));
    loop {
        let mut progressed = false;
        for bucket in buckets.values_mut() {
            if sampled.len() >= limit {
                return sampled;
            }
            if !bucket.is_empty() {
                sampled.push(bucket.remove(0));
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    sampled
}

fn summarize_submissions(submitted_records: &[SubmittedTx]) -> BenchmarkSubmissionSummary {
    let submit_latencies = submitted_records
        .iter()
        .map(|submitted| {
            submitted
                .admitted_at
                .saturating_duration_since(submitted.submitted_at)
        })
        .collect::<Vec<_>>();

    BenchmarkSubmissionSummary {
        submit_retries: submitted_records
            .iter()
            .map(|submitted| submitted.submit_retries)
            .sum(),
        submit_timeout_retries: submitted_records
            .iter()
            .map(|submitted| submitted.submit_timeout_retries)
            .sum(),
        submit_duplicates: submitted_records
            .iter()
            .filter(|submitted| submitted.duplicate_response)
            .count() as u64,
        submit_latency: summarize_latencies(&submit_latencies),
    }
}

async fn collect_final_transaction_statuses(
    channels: &[Channel],
    submitted_records: &[SubmittedTx],
) -> Result<(u64, BTreeSet<u64>, BTreeMap<String, u64>)> {
    let results = stream::iter(
        submitted_records
            .iter()
            .filter(|submitted| !submitted.tx_hash.is_empty())
            .cloned(),
    )
    .map(|submitted| {
        let channels = channels.to_vec();
        async move { query_transaction_status_any(&channels, &submitted.tx_hash).await }
    })
    .buffer_unordered(usize::max(
        channels.len(),
        usize::min(submitted_records.len(), 256),
    ))
    .collect::<Vec<_>>()
    .await;

    let mut committed = 0u64;
    let mut committed_heights = BTreeSet::new();
    let mut status_buckets = BTreeMap::new();
    for result in results {
        if let Some((decoded, _error_message, block_height)) = result? {
            let bucket_name = match decoded {
                TxStatus::Pending => "pending",
                TxStatus::InMempool => "in_mempool",
                TxStatus::Committed => "committed",
                TxStatus::Rejected => "rejected",
                TxStatus::Unknown => "unknown",
            };
            *status_buckets.entry(bucket_name.to_string()).or_insert(0) += 1;
            if decoded == TxStatus::Committed {
                committed += 1;
                committed_heights.insert(block_height);
            }
        }
    }

    Ok((committed, committed_heights, status_buckets))
}

async fn run_scenario(
    scenario: AftBenchmarkScenario,
    lane: AftBenchmarkLane,
) -> Result<PaperBenchmarkResult> {
    if !lane.supports(scenario.safety_mode) {
        return Err(anyhow!(
            "benchmark lane {} is not supported for {:?}",
            lane.as_str(),
            scenario.safety_mode
        ));
    }

    let accounts = benchmark_override_usize("IOI_AFT_BENCH_ACCOUNTS", scenario.accounts);
    let txs_per_account =
        benchmark_override_u64("IOI_AFT_BENCH_TXS_PER_ACCOUNT", scenario.txs_per_account);
    let target_block_time_ms = benchmark_block_time_ms(scenario.target_block_time_ms);
    let target_block_time_secs_legacy = interval_millis_to_legacy_seconds(target_block_time_ms);
    let benchmark_tx_total = accounts.saturating_mul(txs_per_account as usize);
    let fast_probe = benchmark_fast_probe();
    let state_tree = std::env::var("IOI_AFT_BENCH_STATE_TREE").unwrap_or_else(|_| {
        if cfg!(feature = "state-iavl") {
            "IAVL".to_string()
        } else if cfg!(feature = "state-jellyfish") {
            "Jellyfish".to_string()
        } else {
            "IAVL".to_string()
        }
    });
    ensure_benchmark_node_built(&state_tree)?;
    let measurement_timeout_secs = benchmark_override_u64(
        "IOI_AFT_BENCH_TIMEOUT_SECS",
        scenario.measurement_timeout_secs,
    );
    let target_gas_per_block = benchmark_override_u64(
        "IOI_AFT_BENCH_TARGET_GAS_PER_BLOCK",
        scenario.target_gas_per_block,
    );
    let benchmark_tx_select_max_bytes = benchmark_override_u64(
        "IOI_AFT_BENCH_TX_SELECT_MAX_BYTES",
        (benchmark_tx_total as u64)
            .saturating_mul(1_024)
            .clamp(8 * 1024 * 1024, 64 * 1024 * 1024),
    );

    println!(
        "--- Running AFT paper benchmark scenario: {} [{}] ({:?}, {} validators, {} accounts x {} tx/account, gas/block {}, block_time_ms {}, state {}) ---",
        scenario.name,
        lane.as_str(),
        scenario.safety_mode,
        scenario.validators,
        accounts,
        txs_per_account,
        target_gas_per_block,
        target_block_time_ms,
        state_tree
    );

    let chain_id = 10_000 + scenario.validators as u32;
    let accounts = generate_accounts(accounts)?;
    let accounts_for_genesis = accounts.clone();
    let mut signed_account_txs = Vec::with_capacity(accounts.len());
    for (key, account_id) in &accounts {
        let mut txs = Vec::with_capacity(txs_per_account as usize);
        for nonce in 0..txs_per_account {
            let tx = create_transfer_tx(key, *account_id, *account_id, 1, nonce, chain_id);
            txs.push(ioi_types::codec::to_bytes_canonical(&tx).map_err(|e| anyhow!(e))?);
        }
        signed_account_txs.push(txs);
    }

    let target_batch = benchmark_tx_total.clamp(1_024, 32_768);
    let default_kick_debounce_ms = if benchmark_tx_total >= 8_192 {
        150
    } else if benchmark_tx_total >= 4_096 {
        100
    } else {
        25
    };
    let adaptive_view_timeout_ms = benchmark_override_u64(
        "IOI_AFT_BENCH_VIEW_TIMEOUT_MS",
        target_block_time_ms.saturating_mul(4).clamp(100, 2_000),
    );
    let trace_mode = benchmark_trace_enabled();
    let startup_buffer_secs = benchmark_override_u64(
        "IOI_AFT_BENCH_STARTUP_BUFFER_SECS",
        if trace_mode || fast_probe {
            // Benchmark nodes take materially longer than a few seconds to boot, especially when
            // we wait for multiple validator/workload pairs. Keep genesis far enough in the future
            // that submission setup still happens close to height 0.
            std::cmp::max(45, scenario.validators as u64 * 8)
        } else {
            std::cmp::max(60, scenario.validators as u64 * 10)
        },
    );
    let bootstrap_grace_secs = benchmark_override_u64(
        "IOI_AFT_BOOTSTRAP_GRACE_SECS",
        if trace_mode || fast_probe {
            startup_buffer_secs
                .saturating_add(target_block_time_secs_legacy.saturating_mul(2).max(5))
        } else {
            startup_buffer_secs
                .saturating_add(target_block_time_secs_legacy.saturating_mul(4).max(10))
        },
    );
    let mut benchmark_env = ScopedEnv::new();
    if benchmark_trace_enabled() {
        let trace_dir = std::env::var_os("IOI_AFT_BENCH_TRACE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "ioi-aft-bench-trace-{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_millis())
                        .unwrap_or_default()
                ))
            });
        std::fs::create_dir_all(&trace_dir)?;
        println!("--- Benchmark trace dir: {} ---", trace_dir.display());
        benchmark_env.set(
            "IOI_AFT_BENCH_TRACE_DIR",
            trace_dir.to_string_lossy().to_string(),
        );
    }
    benchmark_env.set(
        "IOI_INGESTION_BATCH_SIZE",
        env_or_default("IOI_INGESTION_BATCH_SIZE", target_batch.to_string()),
    );
    benchmark_env.set(
        "IOI_INGESTION_BATCH_TIMEOUT_MS",
        env_or_default("IOI_INGESTION_BATCH_TIMEOUT_MS", "5"),
    );
    benchmark_env.set(
        "IOI_INGESTION_CONSENSUS_KICK_DEBOUNCE_MS",
        env_or_default(
            "IOI_INGESTION_CONSENSUS_KICK_DEBOUNCE_MS",
            default_kick_debounce_ms.to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_RPC_FAST_ADMIT_MAX_MEMPOOL",
        env_or_default("IOI_RPC_FAST_ADMIT_MAX_MEMPOOL", "0"),
    );
    benchmark_env.set(
        "IOI_AFT_TX_RELAY_FANOUT",
        env_or_default(
            "IOI_AFT_TX_RELAY_FANOUT",
            scenario.validators.saturating_sub(1).max(1).to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_AFT_POST_COMMIT_RELAY_LIMIT",
        env_or_default("IOI_AFT_POST_COMMIT_RELAY_LIMIT", target_batch.to_string()),
    );
    benchmark_env.set(
        "IOI_AFT_POST_COMMIT_LEADER_FANOUT",
        env_or_default(
            "IOI_AFT_POST_COMMIT_LEADER_FANOUT",
            scenario.validators.saturating_sub(1).max(1).to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_CONSENSUS_TX_SELECT_LIMIT",
        env_or_default(
            "IOI_CONSENSUS_TX_SELECT_LIMIT",
            benchmark_tx_total.max(target_batch).to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_CONSENSUS_TX_SELECT_MAX_BYTES",
        env_or_default(
            "IOI_CONSENSUS_TX_SELECT_MAX_BYTES",
            benchmark_tx_select_max_bytes.to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_TEST_FULL_MESH_BOOTNODES",
        env_or_default(
            "IOI_TEST_FULL_MESH_BOOTNODES",
            // The AFT throughput matrix depends on successive leaders staying directly connected.
            // A star bootnode topology can strand later leaders behind a single peer and turn
            // dense multi-block runs into liveness artifacts instead of throughput measurements.
            "1",
        ),
    );
    benchmark_env.set(
        "ORCH_BLOCK_INTERVAL_MS",
        env_or_default("ORCH_BLOCK_INTERVAL_MS", "50"),
    );
    benchmark_env.set(
        "ORCH_CONSENSUS_MIN_TICK_MS",
        env_or_default("ORCH_CONSENSUS_MIN_TICK_MS", "10"),
    );
    benchmark_env.set(
        "IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS",
        env_or_default(
            "IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS",
            interval_millis_to_legacy_seconds(adaptive_view_timeout_ms).to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_MS",
        env_or_default(
            "IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_MS",
            adaptive_view_timeout_ms.to_string(),
        ),
    );
    benchmark_env.set(
        "IOI_AFT_BOOTSTRAP_GRACE_SECS",
        bootstrap_grace_secs.to_string(),
    );
    if let Some(interval_ms) = std::env::var("IOI_AFT_BENCH_TICK_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
    {
        benchmark_env.set("ORCH_BLOCK_INTERVAL_MS", interval_ms.to_string());
    }
    let auto_future_genesis = std::env::var("IOI_GENESIS_TIMESTAMP_SECS").is_err()
        && std::env::var("IOI_GENESIS_TIMESTAMP_MS").is_err();
    let warm_first_committed_height =
        default_warm_first_committed_height(auto_future_genesis, fast_probe, benchmark_tx_total);
    let benchmark_genesis_anchor_ms = if let Ok(ms) = std::env::var("IOI_GENESIS_TIMESTAMP_MS") {
        ms.parse::<u64>()
            .map_err(|error| anyhow!("invalid IOI_GENESIS_TIMESTAMP_MS override: {error}"))?
    } else if let Ok(secs) = std::env::var("IOI_GENESIS_TIMESTAMP_SECS") {
        secs.parse::<u64>()
            .map_err(|error| anyhow!("invalid IOI_GENESIS_TIMESTAMP_SECS override: {error}"))?
            .saturating_mul(1_000)
    } else {
        let block_time_floor = target_block_time_secs_legacy.max(1);
        let required_future_offset_secs = startup_buffer_secs
            .saturating_add(block_time_floor.saturating_mul(2))
            .saturating_add((scenario.validators as u64).div_ceil(2))
            .max(
                bootstrap_grace_secs
                    .saturating_add(block_time_floor)
                    .saturating_add(1),
            );
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                duration.as_millis().min(u128::from(u64::MAX)) as u64
                    + required_future_offset_secs.saturating_mul(1_000)
            })
            .unwrap_or_else(|_| required_future_offset_secs.saturating_mul(1_000))
    };
    let benchmark_genesis_timestamp_secs = (benchmark_genesis_anchor_ms / 1_000).to_string();
    benchmark_env.set(
        "IOI_GENESIS_TIMESTAMP_SECS",
        benchmark_genesis_timestamp_secs.clone(),
    );
    let benchmark_genesis_timestamp_ms = benchmark_genesis_anchor_ms.to_string();
    benchmark_env.set(
        "IOI_GENESIS_TIMESTAMP_MS",
        benchmark_genesis_timestamp_ms.clone(),
    );
    if let Ok(allow_zero_height_ready) = std::env::var("IOI_TEST_ALLOW_ZERO_HEIGHT_READY") {
        benchmark_env.set("IOI_TEST_ALLOW_ZERO_HEIGHT_READY", allow_zero_height_ready);
    } else if auto_future_genesis {
        benchmark_env.set("IOI_TEST_ALLOW_ZERO_HEIGHT_READY", "1");
    }

    println!(
        "--- Benchmark startup barrier: genesis_ts={} genesis_ts_ms={} startup_buffer_secs={} bootstrap_grace_secs={} ---",
        benchmark_genesis_timestamp_secs,
        benchmark_genesis_timestamp_ms,
        startup_buffer_secs,
        bootstrap_grace_secs
    );

    let keep_recent_heights = benchmark_override_u64(
        "IOI_AFT_BENCH_KEEP_RECENT_HEIGHTS",
        if fast_probe {
            24
        } else if trace_mode {
            32
        } else {
            64
        },
    );
    let min_finality_depth = benchmark_override_u64_allow_zero(
        "IOI_AFT_BENCH_MIN_FINALITY_DEPTH",
        if fast_probe {
            12
        } else if trace_mode {
            16
        } else {
            32
        },
    );
    let gc_interval_secs = benchmark_override_u64(
        "IOI_AFT_BENCH_GC_INTERVAL_SECS",
        if fast_probe || trace_mode { 1 } else { 2 },
    );

    let cluster = TestCluster::builder()
        .with_validators(scenario.validators)
        .with_consensus_type("Aft")
        .with_state_tree(&state_tree)
        .with_chain_id(chain_id)
        .with_aft_safety_mode(scenario.safety_mode)
        .with_epoch_size(100_000)
        .with_keep_recent_heights(keep_recent_heights)
        .with_min_finality_depth(min_finality_depth)
        .with_gc_interval(gc_interval_secs)
        .with_genesis_modifier(move |builder, keys| {
            let mut validators = Vec::new();
            for key in keys {
                let account_id = builder.add_identity(key);
                let pk = key.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::ED25519, &pk).unwrap();
                validators.push(ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: hash,
                        since_height: 0,
                    },
                });
            }
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            for (account_key, _) in &accounts_for_genesis {
                let account_id = builder.add_identity(account_key);
                builder.insert_typed([ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat(), &0u64);
                builder.insert_typed(
                    [b"balance::".as_ref(), account_id.as_ref()].concat(),
                    &(1_000_000u128),
                );
            }

            builder.set_validators(&ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: validators.len() as u128,
                    validators,
                },
                next: None,
            });

            let timing = BlockTimingParams {
                base_interval_secs: target_block_time_secs_legacy,
                min_interval_secs: target_block_time_secs_legacy,
                max_interval_secs: target_block_time_secs_legacy.saturating_mul(4),
                target_gas_per_block,
                retarget_every_blocks: 0,
                base_interval_ms: target_block_time_ms,
                min_interval_ms: target_block_time_ms,
                max_interval_ms: target_block_time_ms.saturating_mul(4),
                ..Default::default()
            };
            builder.set_block_timing(
                &timing,
                &BlockTimingRuntime {
                    effective_interval_secs: timing.base_interval_secs,
                    effective_interval_ms: target_block_time_ms,
                    ..Default::default()
                },
            );
        })
        .with_role(0, ValidatorRole::Consensus)
        .build()
        .await?;

    spawn_benchmark_live_log_drains(&cluster);
    let benchmark_churn = spawn_benchmark_churn_collectors(&cluster);

    let run_result = async {
        let rpc_addrs = cluster
            .validators
            .iter()
            .map(|guard| guard.validator().rpc_addr.clone())
            .collect::<Vec<_>>();
        let primary_rpc_addr = rpc_addrs[0].clone();
        let primary_only = benchmark_primary_only();
        let route_to_leaders_override = benchmark_route_to_leaders_override();
        let route_to_leaders =
            route_to_leaders_override.unwrap_or_else(|| default_route_to_leaders(fast_probe, benchmark_tx_total));
        let prefer_target_height_leader = benchmark_prefer_target_height_leader();
        if route_to_leaders_override.is_none() && route_to_leaders {
            println!(
                "--- Auto-enabling leader-targeted ingress for fast probe above the clean 256 frontier (tx_total={}) ---",
                benchmark_tx_total
            );
        }
        let default_ingress_leader_fanout = default_ingress_leader_fanout(
            scenario.validators,
            benchmark_tx_total,
            benchmark_tx_select_max_bytes,
            fast_probe,
        );
        let ingress_leader_fanout = benchmark_override_usize(
            "IOI_AFT_BENCH_INGRESS_LEADER_FANOUT",
            default_ingress_leader_fanout,
        );
        let connections_per_addr = benchmark_override_usize(
            "IOI_AFT_BENCH_RPC_CONNECTIONS_PER_ADDR",
            scenario.rpc_connections_per_validator.max(1),
        );
        let align_to_next_block = std::env::var("IOI_AFT_BENCH_ALIGN_TO_NEXT_BLOCK")
            .ok()
            .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "False"))
            .unwrap_or(true);
        let default_submit_lead_ms =
            default_submit_lead_ms(target_block_time_ms, fast_probe, trace_mode, benchmark_tx_total);
        if fast_probe && benchmark_tx_total > 256 {
            println!(
                "--- Auto-scaling submit lead for large fast probe: tx_total={} submit_lead_ms={} ---",
                benchmark_tx_total,
                default_submit_lead_ms
            );
        }
        let submit_lead_ms = benchmark_override_u64_allow_zero(
            "IOI_AFT_BENCH_SUBMIT_LEAD_MS",
            if align_to_next_block {
                default_submit_lead_ms.min(target_block_time_ms.saturating_sub(1))
            } else {
                default_submit_lead_ms
            },
        );
        let alignment_expected_submissions = benchmark_tx_total;
        let alignment_ingress_rpc_count = if primary_only {
            1
        } else if route_to_leaders {
            ingress_leader_fanout.max(1)
        } else {
            rpc_addrs.len().max(1)
        };
        let alignment_submit_wave_size = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_WAVE_SIZE",
            default_submit_wave_size(
                alignment_expected_submissions,
                alignment_ingress_rpc_count,
                fast_probe,
            ),
        )
        .clamp(1, alignment_expected_submissions.max(1));
        let alignment_submit_wave_pause_ms = benchmark_override_u64_allow_zero(
            "IOI_AFT_BENCH_SUBMIT_WAVE_PAUSE_MS",
            default_submit_wave_pause_ms(
                target_block_time_ms,
                alignment_ingress_rpc_count,
                fast_probe,
                alignment_expected_submissions,
            ),
        );
        let alignment_safety_pad_ms = benchmark_override_u64_allow_zero(
            "IOI_AFT_BENCH_ALIGNMENT_SAFETY_PAD_MS",
            default_alignment_safety_pad_ms(
                target_block_time_ms,
                fast_probe,
                alignment_expected_submissions,
            ),
        );
        let alignment_submission_channel_count =
            alignment_ingress_rpc_count.saturating_mul(connections_per_addr).max(1);
        let alignment_submit_concurrency = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_CONCURRENCY",
            default_submit_concurrency(
                alignment_expected_submissions,
                alignment_submission_channel_count,
                fast_probe,
            ),
        );
        let alignment_ingress_status_latency = sample_status_latencies(&rpc_addrs).await?;
        let alignment_estimated_submission_service_budget_ms =
            estimated_submission_service_budget_ms(
                alignment_expected_submissions,
                alignment_submit_concurrency,
                alignment_ingress_status_latency,
            );
        println!(
            "--- Alignment ingress preflight: ingress_status_p50_ms={:.2} ingress_status_p95_ms={:.2} estimated_submission_service_budget_ms={} ---",
            alignment_ingress_status_latency.p50_ms,
            alignment_ingress_status_latency.p95_ms,
            alignment_estimated_submission_service_budget_ms
        );
        let alignment_required_ready_ms = alignment_ready_budget_ms(
            submit_lead_ms,
            alignment_expected_submissions,
            alignment_submit_wave_size,
            alignment_submit_wave_pause_ms,
            alignment_estimated_submission_service_budget_ms,
            alignment_safety_pad_ms,
        );
        let mut alignment_due_ms = None;
        let mut alignment_target_height = None;
        let mut alignment_actual_start_lead_ms = submit_lead_ms;
        if align_to_next_block {
            let current_status = rpc::get_status(&primary_rpc_addr).await?;
            let authoritative_tip_block = if current_status.height > 0 {
                authoritative_tip_block_with_hint(&primary_rpc_addr, current_status.height).await?
            } else {
                None
            };
            let (alignment_height, latest_timestamp_ms) =
                if let Some(tip_block) = authoritative_tip_block.as_ref() {
                    (
                        tip_block.header.height,
                        tip_block.header.timestamp_ms_or_legacy(),
                    )
                } else if auto_future_genesis
                    && current_status.height == 0
                    && !warm_first_committed_height
                {
                    (current_status.height, benchmark_genesis_anchor_ms)
                } else if current_status.height == 0 {
                    if warm_first_committed_height {
                        println!(
                            "--- Warming benchmark past the first committed height before aligned submission (tx_total={}) ---",
                            benchmark_tx_total
                        );
                    }
                    wait_for_first_committed_tip(
                        &primary_rpc_addr,
                        current_status.height,
                        bootstrap_grace_secs,
                        target_block_time_secs_legacy,
                    )
                    .await?
                } else {
                    (
                        current_status.height,
                        current_status.latest_timestamp.saturating_mul(1_000),
                    )
                };
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let base_due_ms = latest_timestamp_ms.saturating_add(target_block_time_ms);
                let now_ms = now.as_millis().min(u128::from(u64::MAX)) as u64;
                let next_due_ms = select_aligned_due_ms(
                    base_due_ms,
                    now_ms,
                    target_block_time_ms,
                    alignment_required_ready_ms,
                );
                let due_at = Duration::from_millis(next_due_ms);
                let actual_start_lead_ms = alignment_start_lead_ms(
                    submit_lead_ms,
                    alignment_expected_submissions,
                    alignment_submit_wave_size,
                    alignment_submit_wave_pause_ms,
                    alignment_estimated_submission_service_budget_ms,
                );
                alignment_due_ms = Some(next_due_ms);
                alignment_target_height = Some(aligned_target_height_for_due_ms(
                    alignment_height,
                    base_due_ms,
                    next_due_ms,
                    target_block_time_ms,
                ));
                alignment_actual_start_lead_ms = actual_start_lead_ms;
                let target_start =
                    due_at.saturating_sub(Duration::from_millis(actual_start_lead_ms));
                let wait_for = target_start.saturating_sub(now);
                if !wait_for.is_zero() {
                    println!(
                        "--- Aligning submission burst to {} ms before next due block (height={}, base_due_ms={}, next_due_ms={}, actual_start_lead_ms={}, ready_budget_ms={}, wave_size={}, wave_pause_ms={}, safety_pad_ms={}) ---",
                        submit_lead_ms,
                        alignment_height,
                        base_due_ms,
                        next_due_ms,
                        actual_start_lead_ms,
                        alignment_required_ready_ms,
                        alignment_submit_wave_size,
                        alignment_submit_wave_pause_ms,
                        alignment_safety_pad_ms
                    );
                    sleep(wait_for).await;
                }
            }
        }
        let (channel_addrs, prefer_target_height_leader_submission) = if primary_only {
            (vec![primary_rpc_addr.clone()], false)
        } else if route_to_leaders {
            let current_status = rpc::get_status(&primary_rpc_addr).await?;
            let authoritative_tip_block =
                authoritative_tip_block_with_hint(&primary_rpc_addr, current_status.height).await?;
            let authoritative_tip_height = authoritative_tip_block
                .as_ref()
                .map(|tip_block| tip_block.header.height)
                .unwrap_or(current_status.height);
            if fast_probe && benchmark_tx_total > 256 && default_ingress_leader_fanout > 1 {
                println!(
                    "--- Auto-scaling leader-targeted ingress fanout for large fast probe: tx_total={} ingress_leader_fanout={} ---",
                    benchmark_tx_total,
                    default_ingress_leader_fanout
                );
            }
            let ingress_start_height = alignment_target_height
                .unwrap_or_else(|| authoritative_tip_height.saturating_add(1).max(1));
            let preferred_target_leader_rpc = if prefer_target_height_leader {
                authoritative_tip_block.as_ref().and_then(|tip_block| {
                    alignment_target_height.and_then(|target_height| {
                        leader_account_for_height(target_height, &tip_block.header.validator_set)
                            .and_then(|account_id| {
                                validator_rpc_addr_for_account_id(&cluster, account_id)
                            })
                    })
                })
            } else {
                None
            };
            let ingress_leader_rpcs = authoritative_tip_block
                .as_ref()
                .map(|tip_block| {
                    leader_accounts_from_height(
                        ingress_start_height,
                        &tip_block.header.validator_set,
                        ingress_leader_fanout,
                    )
                })
                .map(|leader_accounts| {
                    leader_accounts
                        .into_iter()
                        .filter_map(|leader_account_id| {
                            validator_rpc_addr_for_account_id(&cluster, leader_account_id)
                        })
                        .collect::<Vec<_>>()
                })
                .filter(|rpc_addrs| !rpc_addrs.is_empty())
                .unwrap_or_else(|| {
                    rpc_addrs
                        .iter()
                        .take(ingress_leader_fanout.max(1))
                        .cloned()
                        .collect::<Vec<_>>()
                });
            let ingress_leader_rpcs =
                prioritize_rpc_addr(ingress_leader_rpcs, preferred_target_leader_rpc.as_deref());

            println!(
                "--- Leader-targeted ingress RPCs (fanout={}): {} ---",
                ingress_leader_fanout,
                ingress_leader_rpcs.join(", ")
            );
            if let (Some(target_height), Some(preferred_target_leader_rpc)) =
                (alignment_target_height, preferred_target_leader_rpc.as_deref())
            {
                println!(
                    "--- Prioritizing target-height leader RPC for aligned submission: target_height={} rpc={} ---",
                    target_height,
                    preferred_target_leader_rpc
                );
            }
            (ingress_leader_rpcs, preferred_target_leader_rpc.is_some())
        } else {
            (rpc_addrs.clone(), false)
        };
        let status_channels = build_channels(&rpc_addrs, 1).await?;
        let submission_channels = build_channels(&channel_addrs, connections_per_addr).await?;
        let pre_submission_status = rpc::get_status(&primary_rpc_addr).await?;
        let pre_submission_tip_height =
            authoritative_tip_block_with_hint(&primary_rpc_addr, pre_submission_status.height)
                .await?
                .map(|tip_block| tip_block.header.height)
                .unwrap_or(pre_submission_status.height);
        let max_pre_submission_height = benchmark_override_u64(
            "IOI_AFT_BENCH_MAX_PRESUBMISSION_HEIGHT",
            if auto_future_genesis { 2 } else { u64::MAX },
        );
        if pre_submission_status.height > max_pre_submission_height {
            return Err(anyhow!(
                "benchmark startup drifted to height {} before submission (allowed <= {}). Adjust genesis/grace alignment before trusting this run.",
                pre_submission_status.height,
                max_pre_submission_height
            ));
        }
        let injection_started = Instant::now();
        let submitted_records = Arc::new(Mutex::new(Vec::new()));
        let total_expected_submissions = benchmark_tx_total;
        let submit_concurrency = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_CONCURRENCY",
            default_submit_concurrency(
                total_expected_submissions,
                submission_channels.len(),
                fast_probe,
            ),
        );
        println!(
            "--- Submission fanout: ingress_rpcs={} connections_per_addr={} submission_channels={} status_channels={} submit_concurrency={} route_to_leaders={} primary_only={} ---",
            channel_addrs.len(),
            connections_per_addr,
            submission_channels.len(),
            status_channels.len(),
            submit_concurrency,
            route_to_leaders,
            primary_only
        );
        let preferred_submission_channel_span = preferred_submission_channel_span(
            prefer_target_height_leader_submission,
            connections_per_addr,
            submission_channels.len(),
        );
        println!(
            "--- Submission target leader preference: enabled={} preferred_channel_span={} ---",
            prefer_target_height_leader_submission,
            preferred_submission_channel_span
        );
        let submit_wave_size = benchmark_override_usize(
            "IOI_AFT_BENCH_SUBMIT_WAVE_SIZE",
            default_submit_wave_size(total_expected_submissions, channel_addrs.len(), fast_probe),
        )
        .clamp(1, total_expected_submissions.max(1));
        let submit_wave_pause_ms = benchmark_override_u64_allow_zero(
            "IOI_AFT_BENCH_SUBMIT_WAVE_PAUSE_MS",
            default_submit_wave_pause_ms(
                target_block_time_ms,
                channel_addrs.len(),
                fast_probe,
                total_expected_submissions,
            ),
        );
        println!(
            "--- Submission pacing: wave_size={} wave_pause_ms={} ---",
            submit_wave_size,
            submit_wave_pause_ms
        );
        let round_robin_by_tx_index = benchmark_round_robin_by_tx_index_override()
            .unwrap_or_else(|| default_round_robin_by_tx_index(fast_probe, txs_per_account));
        println!(
            "--- Submission order: round_robin_by_tx_index={} ---",
            round_robin_by_tx_index
        );
        let flattened_submissions =
            flatten_submissions(signed_account_txs, round_robin_by_tx_index);
        let total_submission_waves = flattened_submissions
            .len()
            .div_ceil(submit_wave_size.max(1));
        let submission_channels = Arc::new(submission_channels);
        let submission_schedule_started = Instant::now();

        for (wave_index, wave) in flattened_submissions
            .chunks(submit_wave_size.max(1))
            .enumerate()
        {
            let mut submission_stream = stream::iter(wave.iter().cloned())
                .map(|(account_index, tx_index, tx_bytes)| {
                    let channels = Arc::clone(&submission_channels);
                    let preferred_channel_index = account_index.saturating_add(tx_index)
                        % preferred_submission_channel_span.max(1);
                    let status_channel_index = account_index % status_channels.len().max(1);
                    async move {
                        submit_transaction_bytes(
                            channels.as_ref(),
                            preferred_channel_index,
                            status_channel_index,
                            tx_bytes,
                        )
                        .await
                    }
                })
                .buffer_unordered(submit_concurrency.min(wave.len()).max(1));

            while let Some(submitted) = submission_stream.next().await {
                let submitted = submitted?;
                let accepted_so_far = {
                    let mut submitted_records = submitted_records.lock().await;
                    submitted_records.push(submitted);
                    submitted_records.len()
                };
                if accepted_so_far % 512 == 0 || accepted_so_far >= total_expected_submissions {
                    println!(
                        "submission progress: accepted_txs={}/{} accepted_so_far={}",
                        accepted_so_far,
                        total_expected_submissions,
                        accepted_so_far
                    );
                }
            }

            if submit_wave_pause_ms > 0 && wave_index + 1 < total_submission_waves {
                let elapsed_since_schedule_start = submission_schedule_started.elapsed();
                let remaining_pause_ms = remaining_wave_pause_ms(
                    elapsed_since_schedule_start,
                    wave_index,
                    submit_wave_pause_ms,
                );
                if remaining_pause_ms > 0 {
                    println!(
                        "--- Submission wave {}/{} complete; pausing {} ms to hold paced schedule ---",
                        wave_index + 1,
                        total_submission_waves,
                        remaining_pause_ms
                    );
                    sleep(Duration::from_millis(remaining_pause_ms)).await;
                } else {
                    println!(
                        "--- Submission wave {}/{} complete; no extra pause because wave execution already consumed the paced schedule budget ---",
                        wave_index + 1,
                        total_submission_waves
                    );
                }
            }
        }
        let submitted_records = submitted_records.lock().await.clone();
        let submission = summarize_submissions(&submitted_records);
        let unique_submitted_records = canonicalize_submitted_records(&submitted_records);

        let injection_duration = injection_started.elapsed();
        let accepted = unique_submitted_records.len() as u64;
        let injection_tps = accepted as f64 / injection_duration.as_secs_f64().max(f64::EPSILON);
        println!(
            "--- Submission summary: retries={} timeout_retries={} duplicates={} submit_p50_ms={:.2} submit_p95_ms={:.2} ---",
            submission.submit_retries,
            submission.submit_timeout_retries,
            submission.submit_duplicates,
            submission.submit_latency.p50_ms,
            submission.submit_latency.p95_ms,
        );
        let submission_completed_wallclock_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok());
        let alignment_submit_complete_vs_due_ms = alignment_due_ms
            .zip(submission_completed_wallclock_ms)
            .map(|(due_ms, completed_ms)| {
                let delta_ms = i128::from(due_ms) - i128::from(completed_ms);
                delta_ms.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
            });
        println!(
            "--- Alignment outcome: requested_submit_lead_ms={} actual_start_lead_ms={} ready_budget_ms={} submit_complete_vs_due_ms={} ---",
            submit_lead_ms,
            alignment_actual_start_lead_ms,
            alignment_required_ready_ms,
            alignment_submit_complete_vs_due_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        );
        let expected_hashes = unique_submitted_records
            .iter()
            .filter(|submitted| !submitted.chain_hash.is_empty())
            .map(|submitted| submitted.chain_hash.clone())
            .collect::<HashSet<_>>();

        let commit_timeout = Duration::from_secs(measurement_timeout_secs);
        let rpc_addrs_for_commit = rpc_addrs.clone();
        let expected_hashes_for_commit = expected_hashes.clone();
        let initial_height_for_commit = pre_submission_tip_height;
        let authoritative_commit_handle = tokio::spawn(async move {
            wait_for_committed_hashes_on_chain(
                &rpc_addrs_for_commit,
                initial_height_for_commit,
                &expected_hashes_for_commit,
                commit_timeout,
            )
            .await
        });
        let latency_sample_limit = if fast_probe {
            usize::min(LATENCY_SAMPLE_LIMIT, 32)
        } else {
            LATENCY_SAMPLE_LIMIT
        };
        let sampled_submitted_records =
            sample_submitted_records_for_latency(&unique_submitted_records, latency_sample_limit);
        let commit_poll_concurrency = usize::max(
            status_channels.len(),
            usize::min(sampled_submitted_records.len(), LATENCY_SAMPLE_LIMIT),
        );
        let commit_results = stream::iter(sampled_submitted_records.into_iter())
            .map(|submitted| {
                let channels = status_channels.clone();
                async move { poll_committed_transaction(&channels, submitted, commit_timeout).await }
            })
            .buffer_unordered(commit_poll_concurrency)
            .collect::<Vec<_>>()
            .await;

        let mut committed_records = Vec::new();
        let mut commit_failures = Vec::new();
        for result in commit_results {
            match result {
                Ok(record) => committed_records.push(record),
                Err(error) => commit_failures.push(error.to_string()),
            }
        }

        let no_sampled_commits_error = if committed_records.is_empty() {
            Some(
                commit_failures
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown commit failure".to_string()),
            )
        } else {
            None
        };

        if !commit_failures.is_empty() {
            println!(
                "scenario {} observed {} sampled commit timeout/rejection(s) out of {} latency-sampled submissions",
                scenario.name,
                commit_failures.len(),
                usize::min(accepted as usize, latency_sample_limit)
            );
        }

        let (final_commit_instant, authoritative_chain_scan) =
            match authoritative_commit_handle.await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                let cluster_view = capture_cluster_commit_view(&rpc_addrs).await;
                let chain_scan = scan_committed_hashes_from_chain(
                    &rpc_addrs,
                    pre_submission_tip_height,
                    &expected_hashes,
                    Duration::from_secs(5),
                )
                .await
                .unwrap_or(ChainCommitScan {
                    committed: 0,
                    scanned_tip_height: 0,
                    committed_heights: BTreeSet::new(),
                    per_block_tx_counts: Vec::new(),
                });
                let block_tx_summary =
                    summarize_block_tx_counts(&chain_scan.per_block_tx_counts);
                let metrics_view = capture_cluster_metrics_view(&cluster).await;
                let (final_committed, final_heights, status_buckets) =
                    collect_final_transaction_statuses(
                        &status_channels,
                        &unique_submitted_records,
                    )
                        .await
                        .unwrap_or((0, BTreeSet::new(), BTreeMap::new()));
                return Err(anyhow!(
                    "{error}; cluster_view: {cluster_view}; metrics_view: {metrics_view}; final_status_scan: committed={final_committed} heights={:?} status_buckets={:?}; chain_scan: committed={} tip={} heights={:?}; block_tx_summary: {}",
                    final_heights,
                    status_buckets,
                    chain_scan.committed,
                    chain_scan.scanned_tip_height,
                    chain_scan.committed_heights,
                    block_tx_summary,
                ));
            }
            Err(join_error) => {
                return Err(anyhow!("authoritative chain-commit task join failure: {}", join_error));
            }
        };

        let (committed, committed_heights, final_status_buckets) = if fast_probe {
            (
                authoritative_chain_scan.committed.max(accepted),
                if authoritative_chain_scan.committed_heights.is_empty() {
                    let current_height = rpc::get_status(&primary_rpc_addr).await?.height;
                    std::iter::once(current_height).collect()
                } else {
                    authoritative_chain_scan.committed_heights.clone()
                },
                BTreeMap::new(),
            )
        } else {
            let (status_committed, status_committed_heights, status_buckets) =
                collect_final_transaction_statuses(&status_channels, &unique_submitted_records)
                    .await?;
            (
                authoritative_chain_scan.committed.max(status_committed),
                if authoritative_chain_scan.committed_heights.is_empty() {
                    status_committed_heights
                } else {
                    authoritative_chain_scan.committed_heights.clone()
                },
                status_buckets,
            )
        };

        if let Some(sample_failure) = no_sampled_commits_error {
            if committed == 0 {
                let cluster_view = capture_cluster_commit_view(&rpc_addrs).await;
                let metrics_view = capture_cluster_metrics_view(&cluster).await;
                let chain_scan = scan_committed_hashes_from_chain(
                    &rpc_addrs,
                    pre_submission_tip_height,
                    &expected_hashes,
                    Duration::from_secs(5),
                )
                .await
                .unwrap_or(ChainCommitScan {
                    committed: 0,
                    scanned_tip_height: 0,
                    committed_heights: BTreeSet::new(),
                    per_block_tx_counts: Vec::new(),
                });
                let block_tx_summary =
                    summarize_block_tx_counts(&chain_scan.per_block_tx_counts);
                return Err(anyhow!(
                    "no committed records observed; sample failure: {sample_failure}; cluster_view: {cluster_view}; metrics_view: {metrics_view}; final_status_scan: committed={committed} heights={:?} status_buckets={:?}; chain_scan: committed={} tip={} heights={:?}; block_tx_summary: {}",
                    committed_heights,
                    final_status_buckets,
                    chain_scan.committed,
                    chain_scan.scanned_tip_height,
                    chain_scan.committed_heights,
                    block_tx_summary,
                ));
            }
        };

        let sampled_final_commit_instant = committed_heights
            .iter()
            .next_back()
            .and_then(|highest_committed_height| {
                committed_records
                    .iter()
                    .filter(|record| record.block_height == *highest_committed_height)
                    .map(|record| record.committed_at)
                    .max()
            });
        let sampled_commit_visibility_lag_ms = sampled_commit_visibility_lag_ms(
            final_commit_instant,
            sampled_final_commit_instant,
        );
        let measured_final_commit_instant = sustained_commit_endpoint(
            fast_probe,
            final_commit_instant,
            sampled_final_commit_instant,
        );

        let sustained_tps = committed as f64
            / measured_final_commit_instant
                .duration_since(injection_started)
                .as_secs_f64()
                .max(f64::EPSILON);
        let commit_latencies = committed_records
            .iter()
            .map(|record| record.committed_at.duration_since(record.submitted_at))
            .collect::<Vec<_>>();
        let commit_latency = summarize_latencies(&commit_latencies);
        let alignment_first_committed_height = committed_heights.iter().next().copied();
        let alignment_first_committed_height_delta = alignment_target_height
            .zip(alignment_first_committed_height)
            .map(|(target_height, first_committed_height)| {
                let delta_blocks = i128::from(first_committed_height) - i128::from(target_height);
                delta_blocks.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
            });
        let alignment_committed_on_target_height =
            alignment_first_committed_height_delta.map(|delta_blocks| delta_blocks == 0);
        let (
            alignment_committed_before_target_height_txs,
            alignment_committed_at_target_height_txs,
        ) = summarize_alignment_block_packing(
            &authoritative_chain_scan.per_block_tx_counts,
            alignment_target_height,
        );
        println!(
            "--- Alignment commit outcome: target_height={} committed_on_target_height={} first_commit_height_delta={} committed_before_target_height_txs={} committed_at_target_height_txs={} ---",
            alignment_target_height
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            alignment_committed_on_target_height
                .map(|value| {
                    if value {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    }
                })
                .unwrap_or_else(|| "n/a".to_string()),
            alignment_first_committed_height_delta
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            alignment_committed_before_target_height_txs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            alignment_committed_at_target_height_txs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        );
        println!(
            "--- Commit observation lag: sampled_commit_visibility_lag_ms={} sustained_endpoint={} ---",
            sampled_commit_visibility_lag_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            if fast_probe {
                "authoritative_chain_scan"
            } else {
                "sampled_status_or_authoritative_fallback"
            }
        );

        let terminal_result = if committed_heights.is_empty() || matches!(lane, AftBenchmarkLane::BaseFinal) {
            None
        } else {
            let mut earliest_commit_by_height = BTreeMap::new();
            for record in &committed_records {
                earliest_commit_by_height
                    .entry(record.block_height)
                    .and_modify(|current: &mut Instant| {
                        if record.committed_at < *current {
                            *current = record.committed_at;
                        }
                    })
                    .or_insert(record.committed_at);
            }

            let terminal_blocks = stream::iter(committed_heights.iter().copied())
                .map(|height| {
                    let rpc_addrs = rpc_addrs.clone();
                    let lane = lane;
                    async move {
                        match lane {
                            AftBenchmarkLane::BaseFinal => unreachable!("base-final lane should not wait for terminal blocks"),
                            AftBenchmarkLane::SealedFinal => {
                                wait_for_sealed_terminal_block(&rpc_addrs, height, commit_timeout)
                                    .await
                            }
                            AftBenchmarkLane::CanonicalOrdering => {
                                wait_for_canonical_ordering_terminal_block(
                                    &rpc_addrs,
                                    height,
                                    commit_timeout,
                                )
                                .await
                            }
                            AftBenchmarkLane::DurableCollapse => {
                                wait_for_durable_collapse_terminal_block(
                                    &rpc_addrs,
                                    height,
                                    commit_timeout,
                                )
                                .await
                            }
                        }
                    }
                })
                .buffer_unordered(usize::min(committed_heights.len(), 8))
                .try_collect::<Vec<_>>()
                .await?;

            let collapse_latencies = terminal_blocks
                .iter()
                .filter_map(|terminal| {
                    earliest_commit_by_height
                        .get(&terminal.height)
                        .map(|committed_at| terminal.terminal_at.duration_since(*committed_at))
                })
                .collect::<Vec<_>>();
            Some((
                summarize_latencies(&collapse_latencies),
                terminal_blocks
                    .iter()
                    .filter(|terminal| matches!(terminal.outcome, AftTerminalOutcome::Close))
                    .count(),
                terminal_blocks
                    .iter()
                    .filter(|terminal| matches!(terminal.outcome, AftTerminalOutcome::Abort))
                    .count(),
            ))
        };

        let (terminal_latency, terminal_close_blocks, terminal_abort_blocks) = terminal_result
            .map(|(latency, close_blocks, abort_blocks)| {
                (Some(latency), close_blocks, abort_blocks)
            })
            .unwrap_or((None, 0, 0));
        let churn = benchmark_churn
            .lock()
            .expect("benchmark churn tracker poisoned")
            .snapshot();
        let alignment = BenchmarkAlignmentSummary {
            requested_submit_lead_ms: submit_lead_ms,
            actual_start_lead_ms: alignment_actual_start_lead_ms,
            ready_budget_ms: alignment_required_ready_ms,
            submit_complete_vs_due_ms: alignment_submit_complete_vs_due_ms,
            target_height: alignment_target_height,
            committed_on_target_height: alignment_committed_on_target_height,
            first_committed_height_delta: alignment_first_committed_height_delta,
            committed_before_target_height_txs: alignment_committed_before_target_height_txs,
            committed_at_target_height_txs: alignment_committed_at_target_height_txs,
        };

        Ok(PaperBenchmarkResult {
            scenario: scenario.name.to_string(),
            validators: scenario.validators,
            safety_mode: format!("{:?}", scenario.safety_mode),
            lane: lane.as_str().to_string(),
            attempted: accounts.len() * txs_per_account as usize,
            accepted,
            committed,
            committed_blocks: committed_heights.len(),
            injection_tps,
            sustained_tps,
            commit_latency,
            sampled_commit_visibility_lag_ms,
            terminal_latency,
            terminal_close_blocks,
            terminal_abort_blocks,
            churn,
            submission,
            alignment,
        })
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    match (run_result, shutdown_result) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(run_error), Err(shutdown_error)) => Err(anyhow!(
            "benchmark failed: {}; cluster shutdown also failed: {}",
            run_error,
            shutdown_error
        )),
    }
}

