// Path: crates/forge/tests/benchmark_throughput.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "state-jellyfish",
    feature = "commitment-hash"
))]

use anyhow::{anyhow, Result};
use ioi_forge::testing::{build_test_artifacts, TestCluster};
use ioi_ipc::public::{public_api_client::PublicApiClient, SubmitTransactionRequest};
use tonic::transport::Channel;
use tonic::Code;

use ioi_types::{
    app::ApplicationTransaction,
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    config::ValidatorRole,
};
use libp2p::identity::Keypair;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

// --- Configuration ---
// High concurrency: 500 accounts running in parallel.
// Total Load: 100,000 Transactions.
const NUM_ACCOUNTS: usize = 500;
const TXS_PER_ACCOUNT: u64 = 200;
const TOTAL_TXS: usize = NUM_ACCOUNTS * TXS_PER_ACCOUNT as usize;

// Tuning Parameters for High Throughput
const NUM_RPC_CONNECTIONS: usize = 16;
const BACKOFF_MS: u64 = 50; // Retry backoff
const MAX_RETRIES: usize = 100; // Give up eventually if system is dead

const BLOCK_TIME_SECS: u64 = 1;

/// Helper to create a signed native Account transaction.
fn create_transfer_tx(
    sender_key: &Keypair,
    sender_id: AccountId,
    _recipient: AccountId,
    _amount: u64,
    nonce: u64,
    chain_id: u32,
) -> ChainTransaction {
    let public_key = sender_key.public().encode_protobuf();

    let header = SignHeader {
        account_id: sender_id,
        nonce,
        chain_id: chain_id.into(),
        tx_version: 1,
    };

    let app_tx = ApplicationTransaction::CallContract {
        header,
        address: vec![0xAA; 32],
        input_data: vec![1, 2, 3],
        gas_limit: 100_000,
        signature_proof: SignatureProof::default(),
    };

    let payload_bytes = app_tx.to_sign_bytes().unwrap();
    let signature = sender_key.sign(&payload_bytes).unwrap();

    let app_tx_signed = match app_tx {
        ApplicationTransaction::CallContract {
            header,
            address,
            input_data,
            gas_limit,
            ..
        } => ApplicationTransaction::CallContract {
            header,
            address,
            input_data,
            gas_limit,
            signature_proof: SignatureProof {
                // FIX: Use ED25519 constant
                suite: SignatureSuite::ED25519,
                public_key,
                signature,
            },
        },
        _ => unreachable!(),
    };

    ChainTransaction::Application(app_tx_signed)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_benchmark_100k_throughput() -> Result<()> {
    // 0. Environment Setup
    println!("--- Starting IOI SDK Throughput Benchmark (Corrected) ---");
    println!("Configuration:");
    println!("  - Consensus: ProofOfAuthority");
    println!("  - State Tree: Jellyfish Merkle Tree");
    println!("  - Execution: Block-STM (Optimistic Parallel)");
    println!("  - Client Strategy: Sequential Per-Account w/ Retry (Gap Healing)");
    println!(
        "  - Workload:  {} Accounts x {} Txs = {} Total",
        NUM_ACCOUNTS, TXS_PER_ACCOUNT, TOTAL_TXS
    );

    // Generate keys
    println!("Generating {} accounts...", NUM_ACCOUNTS);
    let mut accounts = Vec::with_capacity(NUM_ACCOUNTS);
    for _ in 0..NUM_ACCOUNTS {
        let key = Keypair::generate_ed25519();
        let pk = key.public().encode_protobuf();
        // FIX: Use ED25519 constant
        let id = AccountId(account_id_from_key_material(SignatureSuite::ED25519, &pk)?);
        accounts.push((key, id));
    }

    // 1. Cluster Setup
    build_test_artifacts();

    let accounts_for_genesis = accounts.clone();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("Jellyfish")
        .with_commitment_scheme("Hash")
        .with_role(0, ValidatorRole::Consensus)
        .with_epoch_size(100_000)
        .with_genesis_modifier(move |builder, keys| {
            let val_key = &keys[0];
            let val_id = builder.add_identity(val_key);

            for (acc_key, _) in &accounts_for_genesis {
                builder.add_identity(acc_key);
            }

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id: val_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            // FIX: Use ED25519 constant
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
                ema_gas_used: 0,
            };
            builder.set_block_timing(&timing, &runtime);
        })
        .build()
        .await?;

    let node = &cluster.validators[0];
    let rpc = node.validator().rpc_addr.clone();

    // 2. Pre-Generate Transactions
    // We pre-generate to ensure we measure network/consensus throughput, not signing speed.
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

    // Create channel pool
    println!("Establishing {} RPC connections...", NUM_RPC_CONNECTIONS);
    let mut channels = Vec::with_capacity(NUM_RPC_CONNECTIONS);
    for _ in 0..NUM_RPC_CONNECTIONS {
        let ch = Channel::from_shared(format!("http://{}", rpc))?
            .connect()
            .await?;
        channels.push(ch);
    }

    // Check initial state
    let mut status_client = PublicApiClient::new(channels[0].clone());
    let initial_status = status_client
        .get_status(ioi_ipc::blockchain::GetStatusRequest {})
        .await?
        .into_inner();
    let initial_tx_count = initial_status.total_transactions;
    println!("Initial Chain Tx Count: {}", initial_tx_count);

    // 3. Injection Phase (Sequential per Account)
    println!(
        "Injecting transactions ({} accounts parallel, sequential within account)...",
        NUM_ACCOUNTS
    );

    let injection_start = Instant::now();
    let accepted_txs = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    // Spawn one task per account
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
                            break; // Success, move to next nonce
                        }
                        Err(status) => {
                            let should_retry = match status.code() {
                                Code::ResourceExhausted => true, // Queue full, backoff
                                Code::Unavailable => true,       // Network blip
                                Code::Internal => true,          // Server busy
                                Code::InvalidArgument => {
                                    // Special handling for re-submission races
                                    // If "nonce too low" or "already exists", we consider it a success
                                    // because it means we (or a previous retry) already got it in.
                                    let msg = status.message();
                                    if msg.contains("Nonce") || msg.contains("Mempool") {
                                        // Treat as success
                                        accepted_counter.fetch_add(1, Ordering::Relaxed);
                                        false // Break loop, next tx
                                    } else {
                                        // Genuine invalid arg, abort this account
                                        return;
                                    }
                                }
                                _ => false, // Fatal error
                            };

                            if should_retry {
                                retries += 1;
                                if retries > MAX_RETRIES {
                                    // Too many failures, abort account
                                    return;
                                }
                                sleep(Duration::from_millis(BACKOFF_MS)).await;
                            } else if status.code() == Code::InvalidArgument {
                                break; // Handled as success above
                            } else {
                                return; // Fatal
                            }
                        }
                    }
                }
            }
        }));
    }

    // Monitor Injection Progress
    let monitor_handle = tokio::spawn({
        let accepted = accepted_txs.clone();
        async move {
            let mut last_accepted = 0;
            while last_accepted < TOTAL_TXS {
                sleep(Duration::from_secs(1)).await;
                let current = accepted.load(Ordering::Relaxed);
                if current == last_accepted && current < TOTAL_TXS {
                    // Just logging, not failing yet
                }
                last_accepted = current;
                // println!("Accepted: {} / {}", current, TOTAL_TXS);
            }
        }
    });

    // Wait for all injection tasks
    for h in handles {
        let _ = h.await;
    }
    monitor_handle.abort(); // Stop monitoring injection

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

    // 4. Execution Measurement (Wait for Commit)
    // We now have a filled mempool with no gaps.
    let benchmark_start = Instant::now();
    println!("Waiting for transactions to be committed...");

    let mut last_processed = 0;
    let mut stall_counter = 0;
    let mut final_tx_count = 0;

    loop {
        let status_res = status_client
            .get_status(ioi_ipc::blockchain::GetStatusRequest {})
            .await;

        if let Ok(resp) = status_res {
            let status = resp.into_inner();
            final_tx_count = status.total_transactions;
            let processed = final_tx_count.saturating_sub(initial_tx_count);

            if processed >= total_accepted {
                println!("All accepted transactions committed!");
                break;
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
                    // 10 seconds without a single commit -> STALL DETECTED
                    println!(
                        "\n!!! STALL DETECTED !!!\nProcessed: {} / {} stuck at Height {}.",
                        processed, total_accepted, status.height
                    );
                    println!("Possible causes: Mempool dropped pending nonce, consensus deadlock, or execution panic.");
                    break;
                }
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    let e2e_duration = Instant::now().duration_since(injection_start);
    let processed_total = final_tx_count.saturating_sub(initial_tx_count);
    let e2e_tps = processed_total as f64 / e2e_duration.as_secs_f64();

    println!("\n--- Benchmark Results ---");
    println!("Total Attempted:   {}", TOTAL_TXS);
    println!("Total Accepted:    {}", total_accepted);
    println!("Total Committed:   {}", processed_total);
    println!("-------------------------");
    println!("Injection Rate:    {:.2} TPS (Client Push)", injection_tps);
    println!("End-to-End TPS:    {:.2} TPS (Sustained)", e2e_tps);
    println!("-------------------------");

    if processed_total < total_accepted {
        panic!(
            "Benchmark failed: Dropped {} transactions (Stall)",
            total_accepted - processed_total
        );
    }

    cluster.shutdown().await?;
    Ok(())
}
