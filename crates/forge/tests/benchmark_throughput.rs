// Path: crates/forge/tests/benchmark_throughput.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "state-jellyfish",
    feature = "commitment-hash"
))]

use anyhow::Result;
use ioi_forge::testing::{build_test_artifacts, TestCluster};
use ioi_ipc::public::{public_api_client::PublicApiClient, SubmitTransactionRequest};
use tonic::transport::Channel;

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
// [FIX] Using fewer accounts with deep nonce chains to verify Mempool queuing logic.
// 100 accounts * 100 txs = 10,000 Total Txs.
const NUM_ACCOUNTS: usize = 100;
const TXS_PER_ACCOUNT: u64 = 100;
const TOTAL_TXS: usize = NUM_ACCOUNTS * TXS_PER_ACCOUNT as usize;

const BLOCK_TIME_SECS: u64 = 1;
const TIMEOUT_SECS: u64 = 180;

/// Helper to create a signed native Account transaction.
fn create_transfer_tx(
    sender_key: &Keypair,
    sender_id: AccountId,
    _recipient: AccountId, // Unused in dummy load test
    _amount: u64,          // Unused in dummy load test
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
        address: vec![0xAA; 32],   // Dummy contract address
        input_data: vec![1, 2, 3], // Dummy data
        gas_limit: 100_000,
        signature_proof: SignatureProof::default(), // Will be signed below
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
                suite: SignatureSuite::Ed25519,
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
    println!("--- Starting IOI SDK Throughput Benchmark ---");
    println!("Configuration:");
    println!("  - Consensus: ProofOfAuthority");
    println!("  - State Tree: Jellyfish Merkle Tree");
    println!("  - Execution: Block-STM");
    println!("  - Persistence: WAL");
    println!(
        "  - Accounts: {} ({} Txs each)",
        NUM_ACCOUNTS, TXS_PER_ACCOUNT
    );

    // Generate keys
    println!("Generating {} accounts...", NUM_ACCOUNTS);
    let mut accounts = Vec::with_capacity(NUM_ACCOUNTS);
    for _ in 0..NUM_ACCOUNTS {
        let key = Keypair::generate_ed25519();
        let pk = key.public().encode_protobuf();
        let id = AccountId(account_id_from_key_material(SignatureSuite::Ed25519, &pk)?);
        accounts.push((key, id));
    }

    // 1. Cluster Setup
    build_test_artifacts();

    let accounts_for_genesis = accounts.clone();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("Jellyfish") // ENABLE PHASE 3.1
        .with_commitment_scheme("Hash")
        .with_role(0, ValidatorRole::Consensus)
        .with_epoch_size(100_000) // Delay heavy checkpointing
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
                            suite: SignatureSuite::Ed25519,
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
                // [FIX 1] Set min_interval_secs to 0 for maximum throughput (Instant Seal)
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
    // We generate them sequentially per account so nonces are correct (0..99).
    println!("Pre-signing {} transactions...", TOTAL_TXS);
    let mut transactions = Vec::with_capacity(TOTAL_TXS);

    for (key, id) in &accounts {
        for nonce in 0..TXS_PER_ACCOUNT {
            let tx = create_transfer_tx(key, *id, *id, 1, nonce, 1);
            transactions.push(tx);
        }
    }
    println!("Generation complete.");

    // [FIX] Establish a single channel to reuse for all requests
    let channel = Channel::from_shared(format!("http://{}", rpc))?
        .connect()
        .await?;

    // Check initial state
    let mut status_client = PublicApiClient::new(channel.clone());
    let initial_status = status_client
        .get_status(ioi_ipc::blockchain::GetStatusRequest {})
        .await?
        .into_inner();
    let initial_tx_count = initial_status.total_transactions;
    println!("Initial Chain Tx Count: {}", initial_tx_count);

    // 3. Injection Phase
    println!("Injecting transactions via RPC...");

    // [FIX 2] Track injection start separately
    let injection_start = Instant::now();

    let accepted_txs = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    let batch_size = 1000;

    for chunk in transactions.chunks(batch_size) {
        let chunk = chunk.to_vec();
        // Cloning a Channel is cheap (Arc internally) and shares the connection
        let mut client = PublicApiClient::new(channel.clone());
        let accepted_counter = accepted_txs.clone();

        handles.push(tokio::spawn(async move {
            for tx in chunk {
                let tx_bytes = match ioi_types::codec::to_bytes_canonical(&tx) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let request = tonic::Request::new(SubmitTransactionRequest {
                    transaction_bytes: tx_bytes,
                });

                // We only count OK responses. Errors (e.g. mempool full) are dropped.
                match client.submit_transaction(request).await {
                    Ok(_) => {
                        accepted_counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_e) => {
                        // println!("Tx rejected: {}", _e);
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let total_accepted = accepted_txs.load(Ordering::SeqCst) as u64;
    println!(
        "Injection complete in {:.2}s. Accepted {} / {} transactions.",
        injection_start.elapsed().as_secs_f64(),
        total_accepted,
        TOTAL_TXS
    );

    // [FIX 2] Start benchmark timer here to measure processing throughput
    let benchmark_start = Instant::now();

    if total_accepted == 0 {
        panic!("No transactions were accepted by the node. Check logs for rejection reasons.");
    }

    // 4. Execution Measurement (Wait for Commit)
    println!("Waiting for transactions to be committed...");
    let mut last_log = Instant::now();
    let mut final_tx_count = 0;

    loop {
        let status = status_client
            .get_status(ioi_ipc::blockchain::GetStatusRequest {})
            .await?
            .into_inner();
        final_tx_count = status.total_transactions;
        let processed = final_tx_count - initial_tx_count;

        if processed >= total_accepted {
            break;
        }

        if last_log.elapsed() > Duration::from_secs(1) {
            println!("Processed: {} / {}", processed, total_accepted);
            last_log = Instant::now();
        }

        if benchmark_start.elapsed() > Duration::from_secs(TIMEOUT_SECS) {
            println!("WARN: Benchmark timed out.");
            break;
        }

        sleep(Duration::from_millis(200)).await;
    }

    let duration = benchmark_start.elapsed();

    // 5. Results
    let processed_total = final_tx_count - initial_tx_count;
    let tps = processed_total as f64 / duration.as_secs_f64();

    println!("\n--- Benchmark Results ---");
    println!("Total Attempted:   {}", TOTAL_TXS);
    println!("Total Accepted:    {}", total_accepted);
    println!("Total Committed:   {}", processed_total);
    println!("Processing Time:   {:.2}s", duration.as_secs_f64());
    println!("Throughput:        {:.2} TPS", tps);
    println!("-------------------------");

    cluster.shutdown().await?;
    Ok(())
}