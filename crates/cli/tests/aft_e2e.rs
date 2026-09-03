// Path: crates/cli/tests/aft_e2e.rs
#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::Result;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_cli::testing::backend::ProcessBackend;
use ioi_cli::testing::{build_test_artifacts, rpc, wait_for_height, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, ActiveKeyRecord, BlockTimingParams, BlockTimingRuntime,
        SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    config::{AftSafetyMode, InitialServiceConfig},
    service_configs::MigrationConfig,
};
use std::collections::HashSet;
use std::ffi::OsString;
use std::time::Duration;

static AFT_E2E_ENV_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
    once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

struct ScopedEnv {
    prior: Vec<(&'static str, Option<OsString>)>,
}

impl ScopedEnv {
    fn set(entries: &[(&'static str, &'static str)]) -> Self {
        let prior = entries
            .iter()
            .map(|(key, value)| {
                let old = std::env::var_os(key);
                std::env::set_var(key, value);
                (*key, old)
            })
            .collect();
        Self { prior }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for (key, value) in self.prior.drain(..).rev() {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

async fn aft_hash_async_metrics(metrics_addr: &str) -> Result<String> {
    let response = reqwest::get(format!("http://{metrics_addr}/metrics")).await?;
    Ok(response.error_for_status()?.text().await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_aft_leader_rotation() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    println!("--- Running Aft deterministic Leader Rotation E2E Test ---");
    build_test_artifacts();

    // 1. Setup a 3-node cluster
    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |builder, keys| {
            let mut validators = Vec::new();
            for key in keys {
                let account_id = builder.add_identity(key);
                let pk = key.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::ED25519, &pk).unwrap();

                validators.push(ValidatorV1 {
                    account_id,
                    weight: 1, // Equal weight for round-robin
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: hash,
                        since_height: 0,
                    },
                });
            }
            // Deterministic sort for stable leader schedule
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: validators.len() as u128,
                    validators,
                },
                next: None,
            };
            builder.set_validators(&vs);

            // Fast blocks for testing
            let timing_params = BlockTimingParams {
                base_interval_secs: 1,
                min_interval_secs: 1,
                max_interval_secs: 5,
                target_gas_per_block: 1_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: timing_params.base_interval_secs,
                ..Default::default()
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        })
        .build()
        .await?;

    // [FIX] Spawn log printers for debugging - Handle closed channels gracefully
    for (i, guard) in cluster.validators.iter().enumerate() {
        let (mut orch_logs, mut work_logs, _) = guard.validator().subscribe_logs();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                     res = orch_logs.recv() => {
                        match res {
                            Ok(line) => println!("[Node {} ORCH] {}", i, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                     }
                     res = work_logs.recv() => {
                        match res {
                            Ok(line) => println!("[Node {} WORK] {}", i, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                     }
                }
            }
        });
    }

    let rpc_addr = &cluster.validators[0].validator().rpc_addr;

    let test_logic = async {
        // 2. Wait for chain progression
        let target_height = 6;
        println!("Waiting for height {}...", target_height);
        wait_for_height(rpc_addr, target_height, Duration::from_secs(30)).await?;

        // 3. Analyze Blocks
        let mut producers = HashSet::new();
        let mut last_height = 0;

        for h in 1..=target_height {
            // [FIX] Add explicit retry loop with logging for the test
            let mut block = None;
            for _ in 0..10 {
                match rpc::get_block_by_height_resilient(rpc_addr, h).await {
                    Ok(Some(b)) => {
                        block = Some(b);
                        break;
                    }
                    Ok(None) => {
                        println!("Block {} not found yet, retrying...", h);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        println!("RPC error for block {}: {}, retrying...", h, e);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            let block =
                block.ok_or_else(|| anyhow::anyhow!("Block {} not found after retries", h))?;

            println!(
                "Block #{}: Producer 0x{}, View {}",
                h,
                hex::encode(&block.header.producer_account_id.0[0..4]),
                block.header.view
            );

            // Verify height continuity
            if block.header.height != last_height + 1 {
                return Err(anyhow::anyhow!("Height gap detected"));
            }
            last_height = block.header.height;

            producers.insert(block.header.producer_account_id);
        }

        // 4. Verify Rotation
        // With 3 validators and 6 blocks, we expect at least 2 unique producers (ideally 3).
        // If only 1 produced all blocks, round-robin failed.
        if producers.len() < 2 {
            return Err(anyhow::anyhow!(
                "Leader rotation failed: observed {:?} unique producers out of 3 validators",
                producers.len()
            ));
        }

        println!("--- Aft deterministic Leader Rotation Test Passed ---");
        Ok(())
    };

    let result = test_logic.await;

    // Always shutdown
    if let Err(e) = cluster.shutdown().await {
        eprintln!("Error shutting down cluster: {}", e);
    }

    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_pq_four_validator_timeout_quorum_and_restart() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let stable = tempfile::tempdir()?;
    let stable_path = stable.path().join("pq-aft-cluster");

    // Normal proposal cadence is safely below the pacemaker timeout. The test
    // forces a genuine timeout by stopping the validator scheduled to lead the
    // next height; the other three validators must then form the exact q=3
    // scoped ML-DSA certificate and continue in the next view. Full-mesh
    // bootstrapping exercises every pairwise ML-KEM/ML-DSA channel.
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "0"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "1000"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
    ]);

    let build_cluster = || {
        TestCluster::builder()
            .with_validators(4)
            .with_consensus_type("Aft")
            .with_aft_safety_mode(AftSafetyMode::ClassicBft)
            .with_pq_consensus_profile()
            .with_state_tree("IAVL")
            .with_chain_id(0xA17)
            .with_state_dir(stable_path.clone())
            .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 0xA17,
                grace_period_blocks: 0,
                accept_staged_during_grace: false,
                allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
                allow_downgrade: false,
            }))
    };

    let mut cluster = build_cluster().build().await?;
    let terminal_finality_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for (index, guard) in cluster.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_finality_errors = terminal_finality_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_finality_errors
                        .lock()
                        .expect("terminal-finality evidence lock poisoned")
                        .push(format!("node {index}: {line}"));
                }
                if ["pq", "timeout", "fallback", "quorum", "error", "failed"]
                    .iter()
                    .any(|needle| normalized.contains(needle))
                {
                    println!("[PQ-AFT node {index}] {line}");
                }
            }
        });
    }
    let first_run = async {
        let mut observed_heights = Vec::with_capacity(cluster.validators.len());
        for guard in &cluster.validators {
            observed_heights.push(rpc::get_status(&guard.validator().rpc_addr).await?.height);
        }
        let baseline = observed_heights.into_iter().max().unwrap_or(1);

        // Fail a leader three heights ahead. The two immediately preceding
        // heights have different round-robin leaders, allowing the three
        // survivors to converge after the process stop before they encounter
        // the missing proposer.
        let timeout_height = baseline + 3;
        let mut validator_order = cluster
            .validators
            .iter()
            .enumerate()
            .map(|(index, guard)| {
                let keypair = guard
                    .validator()
                    .pqc_keypair
                    .as_ref()
                    .expect("strict PQ cluster must retain its ML-DSA validator key");
                let account = account_id_from_key_material(
                    SignatureSuite::ML_DSA_44,
                    &keypair.public_key().to_bytes(),
                )
                .expect("ML-DSA validator account derivation must succeed");
                (account, index)
            })
            .collect::<Vec<_>>();
        validator_order.sort_by_key(|(account, _)| *account);
        let failed_leader_index = validator_order[((timeout_height - 1) as usize) % 4].1;
        let observer_index = if failed_leader_index == 0 { 1 } else { 0 };
        let first_rpc = cluster.validators[observer_index]
            .validator()
            .rpc_addr
            .clone();

        println!(
            "--- PQ AFT fault drill: baseline={baseline}, timeout_height={timeout_height}, failed_leader_index={failed_leader_index}, observer_index={observer_index} ---"
        );

        {
            let backend = cluster.validators[failed_leader_index]
                .validator_mut()
                .backend
                .as_any_mut()
                .downcast_mut::<ProcessBackend>()
                .ok_or_else(|| {
                    anyhow::anyhow!("PQ timeout drill requires the process test backend")
                })?;
            let mut leader = backend
                .orchestration_process
                .take()
                .ok_or_else(|| anyhow::anyhow!("scheduled leader process was not running"))?;
            leader.start_kill()?;
            let _ = leader.wait().await?;
        }

        // A cold debug build verifies three independent ML-DSA timeout votes
        // and a full ML-DSA proposal/QC while repeatedly exercising dead-peer
        // transport. The protocol timeout remains 30 seconds; this outer
        // harness deadline only gives the exact-q recovery enough host budget
        // to finish before teardown on contended CI workers.
        wait_for_height(&first_rpc, timeout_height + 1, Duration::from_secs(240)).await?;

        let mut saw_timeout_certificate = false;
        let mut saw_exact_q_parent = false;
        for height in 1..=timeout_height + 1 {
            let block = rpc::get_block_by_height_resilient(&first_rpc, height)
                .await?
                .ok_or_else(|| anyhow::anyhow!("PQ AFT cluster omitted block {height}"))?;
            if block.header.producer_key_suite != SignatureSuite::ML_DSA_44 {
                return Err(anyhow::anyhow!(
                    "block {height} downgraded producer suite to {:?}",
                    block.header.producer_key_suite
                ));
            }
            if block.header.timeout_certificate.is_some() {
                return Err(anyhow::anyhow!(
                    "block {height} carried legacy unscoped timeout evidence"
                ));
            }
            if let Some(certificate) = block.header.aft_timeout_certificate.as_ref() {
                if certificate.votes.len() != 3 {
                    return Err(anyhow::anyhow!(
                        "block {height} carried {} scoped timeout votes; expected exact q=3",
                        certificate.votes.len()
                    ));
                }
                if certificate.height != timeout_height {
                    return Err(anyhow::anyhow!(
                        "block {height} carried timeout evidence for unexpected height {}",
                        certificate.height
                    ));
                }
                saw_timeout_certificate = true;
            }
            if height > 1 && block.header.parent_qc.signatures.len() == 3 {
                saw_exact_q_parent = true;
            }
        }
        if !saw_timeout_certificate {
            return Err(anyhow::anyhow!(
                "four-validator PQ AFT drill formed no scoped timeout certificate"
            ));
        }
        if !saw_exact_q_parent {
            return Err(anyhow::anyhow!(
                "four-validator PQ AFT drill formed no exact q=3 parent quorum"
            ));
        }
        Ok(rpc::get_status(&first_rpc).await?.height)
    }
    .await;
    let first_shutdown = cluster.shutdown().await;
    let before_restart = first_run?;
    first_shutdown?;

    let resumed = build_cluster().build().await?;
    for (index, guard) in resumed.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_finality_errors = terminal_finality_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_finality_errors
                        .lock()
                        .expect("terminal-finality evidence lock poisoned")
                        .push(format!("restarted node {index}: {line}"));
                }
            }
        });
    }
    let resumed_rpc = resumed.validators[0].validator().rpc_addr.clone();
    let resumed_run = async {
        wait_for_height(&resumed_rpc, before_restart + 2, Duration::from_secs(240)).await?;
        let resumed_block = rpc::get_block_by_height_resilient(&resumed_rpc, before_restart + 1)
            .await?
            .ok_or_else(|| anyhow::anyhow!("PQ AFT cluster did not continue after restart"))?;
        if resumed_block.header.producer_key_suite != SignatureSuite::ML_DSA_44 {
            return Err(anyhow::anyhow!(
                "resumed PQ AFT cluster downgraded its producer suite"
            ));
        }
        Ok(())
    }
    .await;
    let resumed_shutdown = resumed.shutdown().await;
    resumed_run?;
    resumed_shutdown?;
    let terminal_finality_errors = terminal_finality_errors
        .lock()
        .expect("terminal-finality evidence lock poisoned")
        .clone();
    if !terminal_finality_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "PQ AFT drill emitted terminal runtime-finality failures:\n{}",
            terminal_finality_errors.join("\n")
        ));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_aft_pq_hash_fallback_executes_virtual_block() -> Result<()> {
    let _env_lock = AFT_E2E_ENV_LOCK.lock().await;
    build_test_artifacts();
    let stable = tempfile::tempdir()?;
    let stable_path = stable.path().join("pq-hash-fallback");
    let _env = ScopedEnv::set(&[
        ("IOI_TEST_FULL_MESH_BOOTNODES", "1"),
        // Startup readiness may observe one node producing the next block
        // while it samples the others. Exact fallback convergence is checked
        // explicitly below, so requiring a zero-height observation window
        // only makes the cold-restart half race normal forward progress.
        ("IOI_TEST_READY_HEIGHT_LAG_MAX", "1"),
        ("IOI_TEST_ROUND_ROBIN_VIEW_TIMEOUT_SECS", "30"),
        ("IOI_BENCH_BLOCK_INTERVAL_MS", "500"),
        ("IOI_AFT_BLOCK_DIRECT_RELAY", "1"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_ARMED", "1"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_HEIGHT", "4"),
        ("IOI_TEST_AFT_FORCE_HASH_FALLBACK_VIEWS", "3"),
        ("IOI_TEST_AFT_STAGE_OPTIMISTIC_PROJECTION", "1"),
    ]);
    let build_cluster = || {
        TestCluster::builder()
            .with_validators(4)
            .with_consensus_type("Aft")
            .with_aft_safety_mode(AftSafetyMode::ClassicBft)
            .with_pq_consensus_profile()
            .with_state_tree("IAVL")
            .with_chain_id(0xA18)
            .with_state_dir(stable_path.clone())
            .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 0xA18,
                grace_period_blocks: 0,
                accept_staged_during_grace: false,
                allowed_target_suites: vec![SignatureSuite::ML_DSA_44],
                allow_downgrade: false,
            }))
    };
    let cluster = build_cluster().build().await?;

    let terminal_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for (index, guard) in cluster.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_errors = terminal_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_errors
                        .lock()
                        .expect("fallback error lock poisoned")
                        .push(format!("node {index}: {line}"));
                }
                if normalized.contains("hash")
                    || normalized.contains("fallback")
                    || normalized.contains("timeout")
                {
                    if normalized.contains("\"level\":\"debug\"") {
                        continue;
                    } else if normalized.contains("stack backtrace") {
                        println!("[PQ-HASH-FALLBACK node {index}] timeout path returned an error (backtrace elided)");
                    } else {
                        println!("[PQ-HASH-FALLBACK node {index}] {line}");
                    }
                }
            }
        });
    }

    let observer = cluster.validators[0].validator().rpc_addr.clone();
    let run = async {
        wait_for_height(&observer, 3, Duration::from_secs(60)).await?;
        let optimistic_projection = tokio::time::timeout(Duration::from_secs(60), async {
            'wait_for_projection: loop {
                for guard in &cluster.validators {
                    if let Some(block) =
                        rpc::get_block_by_height_resilient(&guard.validator().rpc_addr, 4).await?
                    {
                        if block.header.view == 0 && block.header.signature.is_empty() {
                            break 'wait_for_projection Ok::<_, anyhow::Error>(block);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("normal producer staged no optimistic height-4 projection"))??;
        let optimistic_projection_hash = optimistic_projection.header.hash()?;
        println!(
            "--- observed production-generated speculative workload projection at height 4: {} ---",
            hex::encode(&optimistic_projection_hash)
        );
        // Hash-only agreement plus four independent ML-DSA-heavy offline
        // admission checks is deliberately the pessimistic path. Debug CI on
        // constrained hosts can spend well beyond eight minutes on the
        // complete fallback plus native-child verification, so this
        // wall-clock guard must not masquerade as a protocol timeout. The
        // first optimistic child may use the
        // virtual block's empty-signature canonical reference only while the
        // engine retains the separately typed, fully verified asynchronous
        // predecessor proof. It must never manufacture a native QC.
        wait_for_height(&observer, 5, Duration::from_secs(900)).await?;
        let block = rpc::get_block_by_height_resilient(&observer, 4)
            .await?
            .ok_or_else(|| anyhow::anyhow!("hash fallback omitted virtual block 4"))?;
        if block.header.view != 4
            || !block.header.signature.is_empty()
            || block.header.producer_key_suite != SignatureSuite::ML_DSA_44
            || block.header.aft_timeout_certificate.is_some()
        {
            return Err(anyhow::anyhow!(
                "height 4 is not the canonical hash-fallback virtual envelope: view={}, signature_len={}, suite={:?}, timeout_extension={}",
                block.header.view,
                block.header.signature.len(),
                block.header.producer_key_suite,
                block.header.aft_timeout_certificate.is_some(),
            ));
        }
        if block.header.parent_qc.height != 3 {
            return Err(anyhow::anyhow!(
                "hash fallback virtual block did not bind the exact height-3 high QC"
            ));
        }
        let expected_hash = block.header.hash()?;
        if expected_hash == optimistic_projection_hash {
            return Err(anyhow::anyhow!(
                "hash fallback did not replace the staged optimistic workload projection"
            ));
        }
        for guard in &cluster.validators {
            wait_for_height(
                &guard.validator().rpc_addr,
                5,
                Duration::from_secs(120),
            )
            .await?;
            let peer_block = rpc::get_block_by_height_resilient(&guard.validator().rpc_addr, 4)
                .await?
                .ok_or_else(|| anyhow::anyhow!("peer omitted hash fallback block 4"))?;
            if peer_block.header.hash()? != expected_hash {
                return Err(anyhow::anyhow!(
                    "validators executed different hash-fallback virtual blocks"
                ));
            }
        }
        // Height RPCs expose the workload's live candidate as well as the
        // admitted floor. Wait until every validator has crossed H=5 before
        // asserting the stabilized re-entry header; an earlier same-height
        // candidate may still be inside the bounded replacement window.
        let optimistic_child = rpc::get_block_by_height_resilient(&observer, 5)
            .await?
            .ok_or_else(|| anyhow::anyhow!("optimistic path did not resume at height 5"))?;
        if optimistic_child.header.parent_hash != expected_hash.as_slice()
            || optimistic_child.header.parent_qc.height != 4
            || optimistic_child.header.parent_qc.block_hash != expected_hash.as_slice()
            || !optimistic_child.header.parent_qc.signatures.is_empty()
            || !optimistic_child
                .header
                .parent_qc
                .aggregated_signature
                .is_empty()
            || !optimistic_child.header.parent_qc.signers_bitfield.is_empty()
            || optimistic_child.header.signature.is_empty()
            || optimistic_child.header.producer_key_suite != SignatureSuite::ML_DSA_44
        {
            return Err(anyhow::anyhow!(
                "height 5 did not use the typed async-parent bridge followed by native PQ production: parent_hash_match={}, parent_qc_height={}, parent_qc_hash_match={}, parent_qc_signatures={}, parent_qc_aggregate={}, parent_qc_bitfield={}, child_signature={}, child_suite={:?}",
                optimistic_child.header.parent_hash == expected_hash.as_slice(),
                optimistic_child.header.parent_qc.height,
                optimistic_child.header.parent_qc.block_hash == expected_hash.as_slice(),
                optimistic_child.header.parent_qc.signatures.len(),
                optimistic_child.header.parent_qc.aggregated_signature.len(),
                optimistic_child.header.parent_qc.signers_bitfield.len(),
                optimistic_child.header.signature.len(),
                optimistic_child.header.producer_key_suite,
            ));
        }
        let metrics = aft_hash_async_metrics(
            &cluster.validators[0]
                .validator()
                .orchestration_telemetry_addr,
        )
        .await?;
        for stage in [
            "execution_prepare",
            "workload_execution",
            "runtime_stage",
            "runtime_admission",
            "parent_proof_install",
        ] {
            let needle = format!(
                "ioi_aft_hash_async_stage_duration_seconds_count{{stage=\"{stage}\"}} "
            );
            if !metrics.lines().any(|line| line.starts_with(&needle)) {
                return Err(anyhow::anyhow!(
                    "production fallback metrics omitted stage {stage}"
                ));
            }
        }
        println!("--- AFT hash-async production metrics ---");
        for line in metrics.lines().filter(|line| {
            line.starts_with("ioi_aft_hash_async_messages_total")
                || line.starts_with("ioi_aft_hash_async_bytes_total")
                || line.starts_with("ioi_aft_hash_async_stage_duration_seconds_count")
                || line.starts_with("ioi_aft_hash_async_stage_duration_seconds_sum")
        }) {
            println!("{line}");
        }
        Ok::<_, anyhow::Error>(expected_hash)
    }
    .await;
    let shutdown = cluster.shutdown().await;
    let expected_hash = run?;
    shutdown?;

    // Reopen the exact stable process state. Startup must replay the durable
    // fallback transition, reconstruct the compact terminal session, reinstall
    // the typed async-parent proof, and continue without reopening agreement or
    // manufacturing a native QC for the virtual block.
    let resumed = build_cluster().build().await?;
    for (index, guard) in resumed.validators.iter().enumerate() {
        let (mut orchestration, _, _) = guard.validator().subscribe_logs();
        let terminal_errors = terminal_errors.clone();
        tokio::spawn(async move {
            while let Ok(line) = orchestration.recv().await {
                let normalized = line.to_ascii_lowercase();
                if normalized.contains("terminal runtime finality")
                    || normalized.contains("node frozen")
                {
                    terminal_errors
                        .lock()
                        .expect("fallback error lock poisoned")
                        .push(format!("restarted node {index}: {line}"));
                }
            }
        });
    }
    let resumed_rpc = resumed.validators[0].validator().rpc_addr.clone();
    let resumed_run = async {
        wait_for_height(&resumed_rpc, 7, Duration::from_secs(240)).await?;
        let recovered_virtual = rpc::get_block_by_height_resilient(&resumed_rpc, 4)
            .await?
            .ok_or_else(|| anyhow::anyhow!("restart omitted hash-fallback block 4"))?;
        if recovered_virtual.header.hash()? != expected_hash {
            return Err(anyhow::anyhow!(
                "restart changed the admitted hash-fallback block"
            ));
        }
        let resumed_child = rpc::get_block_by_height_resilient(&resumed_rpc, 6)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("hash-fallback cluster did not advance after restart")
            })?;
        if resumed_child.header.signature.is_empty()
            || resumed_child.header.producer_key_suite != SignatureSuite::ML_DSA_44
        {
            return Err(anyhow::anyhow!(
                "post-restart optimistic production downgraded or lost authentication"
            ));
        }
        Ok(())
    }
    .await;
    let resumed_shutdown = resumed.shutdown().await;
    resumed_run?;
    resumed_shutdown?;
    let terminal_errors = terminal_errors
        .lock()
        .expect("fallback error lock poisoned")
        .clone();
    if !terminal_errors.is_empty() {
        return Err(anyhow::anyhow!(
            "PQ hash-fallback drill emitted terminal failures:\n{}",
            terminal_errors.join("\n")
        ));
    }
    Ok(())
}
