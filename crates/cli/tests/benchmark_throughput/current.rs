#![cfg(all(
    feature = "consensus-poa",
    feature = "state-jellyfish",
    feature = "commitment-hash"
))]

use super::support::{
    create_transfer_tx, generate_accounts, print_report, ThroughputBenchmarkReport, BACKOFF_MS,
    BLOCK_TIME_SECS, MAX_RETRIES, NUM_ACCOUNTS, NUM_RPC_CONNECTIONS, TOTAL_TXS, TXS_PER_ACCOUNT,
};
use anyhow::{anyhow, Result};
use ioi_cli::testing::{build_test_artifacts, TestCluster};
use ioi_ipc::public::{public_api_client::PublicApiClient, SubmitTransactionRequest};
use ioi_types::{
    app::{
        ActiveKeyRecord, BlockTimingParams, BlockTimingRuntime, SignatureSuite, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1,
    },
    config::ValidatorRole,
    keys::ACCOUNT_NONCE_PREFIX,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tonic::transport::Channel;
use tonic::Code;

#[tokio::test(flavor = "multi_thread")]
async fn test_benchmark_100k_throughput() -> Result<()> {
    println!("--- Starting IOI Kernel Throughput Benchmark (Current Profile) ---");
    println!("Configuration:");
    println!("  - Consensus: Aft");
    println!("  - State Tree: Jellyfish Merkle Tree");
    println!("  - Execution: Block-STM (Optimistic Parallel)");
    println!("  - Client Strategy: Sequential Per-Account w/ Retry (Gap Healing)");
    println!(
        "  - Workload:  {} Accounts x {} Txs = {} Total",
        NUM_ACCOUNTS, TXS_PER_ACCOUNT, TOTAL_TXS
    );

    println!("Generating {} accounts...", NUM_ACCOUNTS);
    let accounts = generate_accounts(NUM_ACCOUNTS)?;

    build_test_artifacts();

    let accounts_for_genesis = accounts.clone();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Aft")
        .with_state_tree("Jellyfish")
        .with_commitment_scheme("Hash")
        .with_role(0, ValidatorRole::Consensus)
        .with_epoch_size(100_000)
        .with_genesis_modifier(move |builder, keys| {
            let val_key = &keys[0];
            let val_id = builder.add_identity(val_key);

            for (acc_key, _) in &accounts_for_genesis {
                let account_id = builder.add_identity(acc_key);
                builder.insert_typed([ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat(), &0u64);
            }

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id: val_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::ED25519,
                            public_key_hash: val_id.0,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            };
            builder.set_validators(&vs);

            let timing = BlockTimingParams {
                base_interval_secs: BLOCK_TIME_SECS,
                min_interval_secs: 0,
                max_interval_secs: 10,
                target_gas_per_block: 1_000_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let runtime = BlockTimingRuntime {
                effective_interval_secs: BLOCK_TIME_SECS,
                effective_interval_ms: BLOCK_TIME_SECS.saturating_mul(1_000),
                ema_gas_used: 0,
            };
            builder.set_block_timing(&timing, &runtime);
        })
        .build()
        .await?;

    let node = &cluster.validators[0];
    let rpc = node.validator().rpc_addr.clone();

    println!("Pre-signing {} transactions...", TOTAL_TXS);
    let mut account_txs: Vec<Vec<Vec<u8>>> = Vec::with_capacity(NUM_ACCOUNTS);

    for (key, id) in &accounts {
        let mut txs = Vec::with_capacity(TXS_PER_ACCOUNT as usize);
        for nonce in 0..TXS_PER_ACCOUNT {
            let tx = create_transfer_tx(key, *id, *id, 1, nonce, 1);
            let bytes = ioi_types::codec::to_bytes_canonical(&tx).map_err(|e| anyhow!(e))?;
            txs.push(bytes);
        }
        account_txs.push(txs);
    }
    println!("Generation complete.");

    println!("Establishing {} RPC connections...", NUM_RPC_CONNECTIONS);
    let mut channels = Vec::with_capacity(NUM_RPC_CONNECTIONS);
    for _ in 0..NUM_RPC_CONNECTIONS {
        let ch = Channel::from_shared(format!("http://{}", rpc))?
            .connect()
            .await?;
        channels.push(ch);
    }

    let mut status_client = PublicApiClient::new(channels[0].clone());
    let initial_status = status_client
        .get_status(ioi_ipc::blockchain::GetStatusRequest {})
        .await?
        .into_inner();
    let initial_tx_count = initial_status.total_transactions;
    println!("Initial Chain Tx Count: {}", initial_tx_count);

    println!(
        "Injecting transactions ({} accounts parallel, sequential within account)...",
        NUM_ACCOUNTS
    );

    let injection_start = Instant::now();
    let accepted_txs = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for (i, txs) in account_txs.into_iter().enumerate() {
        let channel = channels[i % NUM_RPC_CONNECTIONS].clone();
        let accepted_counter = accepted_txs.clone();

        handles.push(tokio::spawn(async move {
            let mut client = PublicApiClient::new(channel);

            for tx_bytes in txs {
                let mut retries = 0;
                loop {
                    let req = tonic::Request::new(SubmitTransactionRequest {
                        transaction_bytes: tx_bytes.clone(),
                    });

                    match client.submit_transaction(req).await {
                        Ok(_) => {
                            accepted_counter.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        Err(status) => {
                            let should_retry = match status.code() {
                                Code::ResourceExhausted => true,
                                Code::Unavailable => true,
                                Code::Internal => true,
                                Code::InvalidArgument => {
                                    let msg = status.message();
                                    if msg.contains("Nonce") || msg.contains("Mempool") {
                                        accepted_counter.fetch_add(1, Ordering::Relaxed);
                                        false
                                    } else {
                                        return;
                                    }
                                }
                                _ => false,
                            };

                            if should_retry {
                                retries += 1;
                                if retries > MAX_RETRIES {
                                    return;
                                }
                                sleep(Duration::from_millis(BACKOFF_MS)).await;
                            } else if status.code() == Code::InvalidArgument {
                                break;
                            } else {
                                return;
                            }
                        }
                    }
                }
            }
        }));
    }

    let monitor_handle = tokio::spawn({
        let accepted = accepted_txs.clone();
        async move {
            let mut last_accepted = 0;
            while last_accepted < TOTAL_TXS {
                sleep(Duration::from_secs(1)).await;
                let current = accepted.load(Ordering::Relaxed);
                last_accepted = current;
            }
        }
    });

    for h in handles {
        let _ = h.await;
    }
    monitor_handle.abort();

    let injection_duration = injection_start.elapsed();
    let total_accepted = accepted_txs.load(Ordering::SeqCst) as u64;
    let injection_tps = total_accepted as f64 / injection_duration.as_secs_f64();

    println!(
        "Injection complete in {:.2}s. Accepted {} / {} transactions.",
        injection_duration.as_secs_f64(),
        total_accepted,
        TOTAL_TXS
    );
    println!(">> INJECTION TPS: {:.2} <<", injection_tps);

    println!("Waiting for transactions to be committed...");
    let mut last_processed = 0;
    let mut stall_counter = 0;
    let processed_total = loop {
        let status_res = status_client
            .get_status(ioi_ipc::blockchain::GetStatusRequest {})
            .await;

        if let Ok(resp) = status_res {
            let status = resp.into_inner();
            let observed_tx_count = status.total_transactions;
            let processed = observed_tx_count.saturating_sub(initial_tx_count);

            if processed >= total_accepted {
                println!("All accepted transactions committed!");
                break processed;
            }

            if processed > last_processed {
                println!(
                    "Processed: {} / {} (Height: {})",
                    processed, total_accepted, status.height
                );
                last_processed = processed;
                stall_counter = 0;
            } else {
                stall_counter += 1;
                if stall_counter >= 10 {
                    println!(
                        "\n!!! STALL DETECTED !!!\nProcessed: {} / {} stuck at Height {}.",
                        processed, total_accepted, status.height
                    );
                    println!("Possible causes: Mempool dropped pending nonce, consensus deadlock, or execution panic.");
                    break processed;
                }
            }
        }

        sleep(Duration::from_secs(1)).await;
    };

    let e2e_duration = Instant::now().duration_since(injection_start);
    let e2e_tps = processed_total as f64 / e2e_duration.as_secs_f64();

    print_report(ThroughputBenchmarkReport {
        attempted: TOTAL_TXS,
        accepted: total_accepted,
        committed: processed_total,
        injection_tps,
        e2e_tps,
    });

    if processed_total < total_accepted {
        panic!(
            "Benchmark failed: Dropped {} transactions (Stall)",
            total_accepted - processed_total
        );
    }

    cluster.shutdown().await?;
    Ok(())
}
