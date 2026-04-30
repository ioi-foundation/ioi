fn benchmark_lanes_for_scenario(
    scenario: AftBenchmarkScenario,
    lane_filter: Option<AftBenchmarkLane>,
) -> Vec<AftBenchmarkLane> {
    let supported = [
        AftBenchmarkLane::BaseFinal,
        AftBenchmarkLane::CanonicalOrdering,
        AftBenchmarkLane::DurableCollapse,
        AftBenchmarkLane::SealedFinal,
    ]
    .into_iter()
    .filter(|lane| lane.supports(scenario.safety_mode))
    .collect::<Vec<_>>();

    match lane_filter {
        Some(lane) if lane.supports(scenario.safety_mode) => vec![lane],
        Some(_) => Vec::new(),
        None => supported,
    }
}

async fn run_benchmark_matrix(lane_filter: Option<AftBenchmarkLane>) -> Result<()> {
    if std::env::var_os("IOI_TEST_BUILD_PROFILE").is_none() {
        std::env::set_var("IOI_TEST_BUILD_PROFILE", "release");
    }

    if !benchmark_skip_artifact_build() {
        build_test_artifacts();
    }

    let scenario_filter = std::env::var("IOI_AFT_BENCH_SCENARIO").ok();
    let scenarios = [
        AftBenchmarkScenario::paper_guardian_majority_4v(),
        AftBenchmarkScenario::paper_guardian_majority_7v(),
        AftBenchmarkScenario::paper_asymptote_4v(),
        AftBenchmarkScenario::paper_asymptote_7v(),
    ]
    .into_iter()
    .filter(|scenario| {
        scenario_filter
            .as_deref()
            .map(|selected| selected == scenario.name)
            .unwrap_or(true)
    })
    .collect::<Vec<_>>();

    let mut results = Vec::new();
    for scenario in scenarios {
        for lane in benchmark_lanes_for_scenario(scenario, lane_filter) {
            results.push(run_scenario(scenario, lane).await?);
        }
    }

    println!("\n--- AFT Paper Benchmark Matrix ---");
    println!("{}", render_markdown_table(&results));

    Ok(())
}

#[test]
fn parse_prepare_block_metrics_extracts_churn_fields() {
    let line = "[BENCH-EXEC] prepare_block height=10 tx_count=212 replay_mode=fallback_sequential replay_gate=parallel_execution_error_fallback nonce_chain_edges=0 replay_debt=5128 validation_aborts=4972 validation_errors=0 validation_rewinds=156 execution_errors=2926 snapshot_ms=29 parallel_exec_ms=114 fallback_exec_ms=5 overlay_ms=0 collect_results_ms=0 roots_ms=0 total_ms=149";
    let metrics = parse_prepare_block_metrics(line).expect("parse benchmark metrics");

    assert_eq!(metrics.height, 10);
    assert_eq!(metrics.replay_mode, "fallback_sequential");
    assert_eq!(metrics.replay_debt, 5128);
    assert_eq!(metrics.validation_aborts, 4972);
    assert_eq!(metrics.execution_errors, 2926);
}

#[test]
fn benchmark_churn_tracker_counts_unique_fallback_heights() {
    let mut tracker = BenchmarkChurnTracker::default();
    tracker.observe(&PrepareBlockMetrics {
        height: 10,
        replay_mode: "fallback_sequential".to_string(),
        replay_debt: 9,
        validation_aborts: 8,
        execution_errors: 7,
    });
    tracker.observe(&PrepareBlockMetrics {
        height: 10,
        replay_mode: "fallback_sequential".to_string(),
        replay_debt: 4,
        validation_aborts: 3,
        execution_errors: 2,
    });
    tracker.observe(&PrepareBlockMetrics {
        height: 11,
        replay_mode: "parallel".to_string(),
        replay_debt: 12,
        validation_aborts: 1,
        execution_errors: 5,
    });

    let summary = tracker.snapshot();
    assert_eq!(summary.fallback_blocks, 1);
    assert_eq!(summary.max_replay_debt, 12);
    assert_eq!(summary.max_validation_aborts, 8);
    assert_eq!(summary.max_execution_errors, 7);
}

#[test]
fn default_submit_concurrency_caps_fast_probe_depth_per_channel() {
    assert_eq!(default_submit_concurrency(16, 64, true), 16);
    assert_eq!(default_submit_concurrency(256, 64, true), 256);
    assert_eq!(default_submit_concurrency(512, 64, true), 256);
    assert_eq!(default_submit_concurrency(512, 96, true), 256);
    assert_eq!(default_submit_concurrency(512, 64, false), 512);
}

#[test]
fn default_submit_wave_size_only_splits_large_fast_probes() {
    assert_eq!(default_submit_wave_size(128, 1, true), 128);
    assert_eq!(default_submit_wave_size(256, 2, true), 256);
    assert_eq!(default_submit_wave_size(512, 1, true), 128);
    assert_eq!(default_submit_wave_size(512, 2, true), 128);
    assert_eq!(default_submit_wave_size(1_024, 4, true), 256);
    assert_eq!(default_submit_wave_size(512, 2, false), 512);
}

#[test]
fn default_submit_wave_pause_ms_only_applies_to_large_fast_probes() {
    assert_eq!(default_submit_wave_pause_ms(1_000, 1, true, 128), 0);
    assert_eq!(default_submit_wave_pause_ms(1_000, 1, true, 512), 63);
    assert_eq!(default_submit_wave_pause_ms(1_000, 2, true, 512), 32);
    assert_eq!(default_submit_wave_pause_ms(1_000, 4, true, 1_024), 16);
    assert_eq!(default_submit_wave_pause_ms(1_000, 2, false, 512), 0);
}

#[test]
fn default_alignment_safety_pad_ms_only_applies_to_large_fast_probes() {
    assert_eq!(default_alignment_safety_pad_ms(1_000, true, 128), 0);
    assert_eq!(default_alignment_safety_pad_ms(1_000, true, 512), 100);
    assert_eq!(default_alignment_safety_pad_ms(400, true, 512), 50);
    assert_eq!(default_alignment_safety_pad_ms(1_000, false, 512), 0);
}

#[test]
fn alignment_ready_budget_ms_includes_wave_pause_and_safety_pad() {
    assert_eq!(alignment_ready_budget_ms(250, 1_024, 256, 8, 80, 100), 454);
    assert_eq!(alignment_ready_budget_ms(50, 128, 128, 0, 0, 0), 50);
}

#[test]
fn remaining_wave_pause_ms_only_sleeps_until_the_scheduled_wave_deadline() {
    assert_eq!(remaining_wave_pause_ms(Duration::from_millis(0), 0, 8), 8);
    assert_eq!(remaining_wave_pause_ms(Duration::from_millis(8), 0, 8), 0);
    assert_eq!(remaining_wave_pause_ms(Duration::from_millis(20), 0, 8), 0);
    assert_eq!(remaining_wave_pause_ms(Duration::from_millis(10), 1, 8), 6);
}

#[test]
fn alignment_start_lead_ms_accounts_for_wave_pause_without_safety_pad() {
    assert_eq!(alignment_start_lead_ms(250, 1_024, 256, 8, 80), 354);
    assert_eq!(alignment_start_lead_ms(250, 128, 128, 0, 0), 250);
}

#[test]
fn select_aligned_due_ms_skips_tight_due_slots() {
    assert_eq!(select_aligned_due_ms(1_000, 500, 1_000, 374), 1_000);
    assert_eq!(select_aligned_due_ms(1_000, 700, 1_000, 374), 2_000);
}

#[test]
fn aligned_target_height_for_due_ms_tracks_skipped_slots() {
    assert_eq!(aligned_target_height_for_due_ms(0, 1_000, 1_000, 1_000), 1);
    assert_eq!(aligned_target_height_for_due_ms(1, 2_000, 4_000, 1_000), 4);
}

#[test]
fn leader_account_for_height_tracks_validator_rotation() {
    let validator_ids = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
    assert_eq!(
        leader_account_for_height(1, &validator_ids),
        Some(AccountId([1u8; 32]))
    );
    assert_eq!(
        leader_account_for_height(2, &validator_ids),
        Some(AccountId([2u8; 32]))
    );
    assert_eq!(
        leader_account_for_height(4, &validator_ids),
        Some(AccountId([1u8; 32]))
    );
}

#[test]
fn prioritize_rpc_addr_moves_the_target_to_the_front() {
    let rpc_addrs = vec![
        "127.0.0.1:20101".to_string(),
        "127.0.0.1:20201".to_string(),
        "127.0.0.1:20301".to_string(),
    ];
    assert_eq!(
        prioritize_rpc_addr(rpc_addrs.clone(), Some("127.0.0.1:20201")),
        vec![
            "127.0.0.1:20201".to_string(),
            "127.0.0.1:20101".to_string(),
            "127.0.0.1:20301".to_string(),
        ]
    );
    assert_eq!(
        prioritize_rpc_addr(rpc_addrs.clone(), Some("127.0.0.1:20101")),
        rpc_addrs
    );
}

#[test]
fn preferred_submission_channel_span_limits_first_attempts_to_the_target_leader_bucket() {
    assert_eq!(preferred_submission_channel_span(true, 48, 96), 48);
    assert_eq!(preferred_submission_channel_span(true, 48, 24), 24);
    assert_eq!(preferred_submission_channel_span(false, 48, 96), 96);
}

#[test]
fn estimated_submission_service_budget_scales_with_rounds_and_observed_rtt() {
    assert_eq!(
        estimated_submission_service_budget_ms(
            1_024,
            256,
            LatencySummary {
                p95_ms: 5.2,
                ..LatencySummary::default()
            }
        ),
        24
    );
    assert_eq!(
        estimated_submission_service_budget_ms(
            128,
            256,
            LatencySummary {
                p95_ms: 0.4,
                ..LatencySummary::default()
            }
        ),
        1
    );
}

#[test]
fn summarize_alignment_block_packing_counts_target_and_preceding_matches() {
    assert_eq!(
        summarize_alignment_block_packing(&[(2, 64), (3, 192), (4, 32)], Some(3)),
        (Some(64), Some(192))
    );
    assert_eq!(
        summarize_alignment_block_packing(&[(3, 192), (4, 32)], Some(2)),
        (Some(0), Some(0))
    );
    assert_eq!(
        summarize_alignment_block_packing(&[(2, 64), (3, 192)], None),
        (None, None)
    );
}

#[test]
fn sampled_commit_visibility_lag_ms_tracks_signed_visibility_drift() {
    let start = Instant::now();
    assert_eq!(
        sampled_commit_visibility_lag_ms(start, Some(start + Duration::from_millis(37))),
        Some(37)
    );
    assert_eq!(
        sampled_commit_visibility_lag_ms(start, Some(start - Duration::from_millis(12))),
        Some(-12)
    );
    assert_eq!(sampled_commit_visibility_lag_ms(start, None), None);
}

#[test]
fn sustained_commit_endpoint_prefers_authoritative_scan_for_fast_probes() {
    let authoritative = Instant::now();
    let sampled = authoritative + Duration::from_millis(125);
    assert_eq!(
        sustained_commit_endpoint(true, authoritative, Some(sampled)),
        authoritative
    );
    assert_eq!(
        sustained_commit_endpoint(false, authoritative, Some(sampled)),
        sampled
    );
    assert_eq!(
        sustained_commit_endpoint(false, authoritative, None),
        authoritative
    );
}

#[test]
fn summarize_submissions_counts_retries_timeouts_and_duplicates() {
    let now = Instant::now();
    let summary = summarize_submissions(&[
        SubmittedTx {
            tx_hash: "tx-a".to_string(),
            chain_hash: "chain-a".to_string(),
            submitted_at: now,
            admitted_at: now + Duration::from_millis(12),
            status_channel_index: 0,
            submit_retries: 3,
            submit_timeout_retries: 2,
            duplicate_response: false,
        },
        SubmittedTx {
            tx_hash: String::new(),
            chain_hash: String::new(),
            submitted_at: now,
            admitted_at: now + Duration::from_millis(48),
            status_channel_index: 1,
            submit_retries: 1,
            submit_timeout_retries: 0,
            duplicate_response: true,
        },
    ]);

    assert_eq!(summary.submit_retries, 4);
    assert_eq!(summary.submit_timeout_retries, 2);
    assert_eq!(summary.submit_duplicates, 1);
    assert_eq!(summary.submit_latency.p50_ms, 48.0);
    assert_eq!(summary.submit_latency.p95_ms, 48.0);
}

#[test]
fn default_route_to_leaders_auto_enables_only_for_large_fast_probes() {
    assert!(!default_route_to_leaders(false, 512));
    assert!(!default_route_to_leaders(true, 256));
    assert!(default_route_to_leaders(true, 257));
}

#[test]
fn default_round_robin_by_tx_index_only_enables_for_multi_tx_fast_probes() {
    assert!(!default_round_robin_by_tx_index(false, 2));
    assert!(!default_round_robin_by_tx_index(true, 1));
    assert!(default_round_robin_by_tx_index(true, 2));
}

#[test]
fn flatten_submissions_round_robins_by_tx_index_when_enabled() {
    let flattened = flatten_submissions(
        vec![
            vec![vec![10], vec![11]],
            vec![vec![20], vec![21]],
            vec![vec![30]],
        ],
        true,
    );

    assert_eq!(
        flattened,
        vec![
            (0, 0, vec![10]),
            (1, 0, vec![20]),
            (2, 0, vec![30]),
            (0, 1, vec![11]),
            (1, 1, vec![21]),
        ]
    );
}

#[test]
fn flatten_submissions_preserves_account_major_order_when_disabled() {
    let flattened = flatten_submissions(
        vec![vec![vec![10], vec![11]], vec![vec![20], vec![21]]],
        false,
    );

    assert_eq!(
        flattened,
        vec![
            (0, 0, vec![10]),
            (0, 1, vec![11]),
            (1, 0, vec![20]),
            (1, 1, vec![21]),
        ]
    );
}

#[test]
fn default_ingress_leader_fanout_scales_up_only_for_large_fast_probes() {
    assert_eq!(
        default_ingress_leader_fanout(4, 256, 8 * 1024 * 1024, true),
        1
    );
    assert_eq!(
        default_ingress_leader_fanout(4, 512, 8 * 1024 * 1024, true),
        2
    );
    assert_eq!(
        default_ingress_leader_fanout(4, 1_024, 8 * 1024 * 1024, true),
        4
    );
    assert_eq!(
        default_ingress_leader_fanout(4, 512, 8 * 1024 * 1024, false),
        1
    );
    assert_eq!(
        default_ingress_leader_fanout(4, 16_384, 8 * 1024 * 1024, false),
        2
    );
}

#[test]
fn default_submit_lead_ms_scales_up_only_for_large_fast_probes() {
    assert_eq!(default_submit_lead_ms(1_000, true, false, 128), 50);
    assert_eq!(default_submit_lead_ms(1_000, true, false, 512), 250);
    assert_eq!(default_submit_lead_ms(1_000, false, true, 512), 75);
    assert_eq!(default_submit_lead_ms(1_000, false, false, 512), 250);
}

#[test]
fn default_warm_first_committed_height_only_applies_to_large_fast_auto_future_genesis_probes() {
    assert!(default_warm_first_committed_height(true, true, 512));
    assert!(!default_warm_first_committed_height(true, true, 256));
    assert!(!default_warm_first_committed_height(true, false, 512));
    assert!(!default_warm_first_committed_height(false, true, 512));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the paper-grade AFT throughput benchmark matrix"]
async fn test_aft_paper_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(benchmark_lane_filter()).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the base-final AFT throughput benchmark matrix"]
async fn test_aft_base_final_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(Some(AftBenchmarkLane::BaseFinal)).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the canonical-ordering AFT throughput benchmark matrix"]
async fn test_aft_canonical_ordering_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(Some(AftBenchmarkLane::CanonicalOrdering)).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the durable-collapse AFT throughput benchmark matrix"]
async fn test_aft_durable_collapse_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(Some(AftBenchmarkLane::DurableCollapse)).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs the sealed-final AFT throughput benchmark matrix"]
async fn test_aft_sealed_final_benchmark_matrix() -> Result<()> {
    run_benchmark_matrix(Some(AftBenchmarkLane::SealedFinal)).await
}
