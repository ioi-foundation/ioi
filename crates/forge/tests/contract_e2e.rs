// Path: crates/forge/tests/contract_e2e.rs
//! End-to-End Test: Smart Contract Execution Lifecycle

use anyhow::{anyhow, Result};
use ioi_client::WorkloadClient;
use ioi_crypto::algorithms::hash::sha256;
use ioi_forge::testing::{
    build_test_artifacts, submit_transaction, wait_for_contract_deployment, wait_for_height,
    TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ApplicationTransaction, ChainId,
        ChainTransaction, SignHeader, SignatureProof, SignatureSuite, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1,
    },
    config::InitialServiceConfig,
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use std::path::Path;
use std::time::{Duration, Instant};

// Helper function to create a signed transaction with proper nonce and account_id
fn create_signed_app_tx(
    keypair: &Keypair,
    mut tx: ApplicationTransaction,
    nonce: u64,
    chain_id: ChainId,
) -> ChainTransaction {
    let public_key = keypair.public().encode_protobuf();

    // Use the canonical function to derive the account ID
    let account_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &public_key).unwrap();
    let account_id = ioi_types::app::AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    // Set header before creating sign bytes
    match &mut tx {
        ApplicationTransaction::DeployContract { header: h, .. } => *h = header,
        ApplicationTransaction::CallContract { header: h, .. } => *h = header,
        _ => panic!("Unsupported tx type"),
    }

    let payload_bytes = tx.to_sign_bytes().unwrap();
    let signature = keypair.sign(&payload_bytes).unwrap();

    let proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key,
        signature,
    };

    // Set signature proof after signing
    match &mut tx {
        ApplicationTransaction::DeployContract {
            signature_proof, ..
        } => *signature_proof = proof,
        ApplicationTransaction::CallContract {
            signature_proof, ..
        } => *signature_proof = proof,
        _ => panic!("Unsupported tx type"),
    }

    ChainTransaction::Application(tx)
}

static INIT: std::sync::Once = std::sync::Once::new();

fn init_logger() {
    INIT.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

#[tokio::test]
async fn test_contract_deployment_and_execution_lifecycle() -> Result<()> {
    init_logger();

    // 1. SETUP & BUILD
    build_test_artifacts();
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().and_then(|p| p.parent()).unwrap();

    let wasm_path = workspace_root.join("target/wasm32-wasip1/release/counter_contract.wasm");

    let counter_wasm = std::fs::read(&wasm_path).map_err(|e| {
        anyhow!(
            "Failed to read contract artifact at {:?}: {}. Ensure `build_test_artifacts()` ran correctly.",
            wasm_path,
            e
        )
    })?;
    let mut nonce = 0;

    // 2. SETUP NETWORK
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        // --- UPDATED: Using GenesisBuilder API ---
        .with_genesis_modifier(|builder, keys| {
            let keypair = &keys[0];
            let suite = SignatureSuite::Ed25519;
            let pk_bytes = keypair.public().encode_protobuf();

            // A. Register Identity using the builder helper
            // This handles Credentials, ActiveKeyRecord, and PubKey mapping automatically.
            let account_id = builder.add_identity(keypair);

            // Manually get the hash for constructing the ValidatorV1 record
            let account_id_hash = account_id.0;

            // B. Set Canonical Validator Set
            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite,
                            public_key_hash: account_id_hash,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            };

            builder.set_validators(&vs);
        })
        .build()
        .await?;

    let node = cluster.validators[0].validator();
    let rpc_addr = node.rpc_addr.clone();
    let keypair = node.keypair.clone();
    let certs_path = node.certs_dir_path.clone();
    let ipc_addr = node.workload_ipc_addr.clone();

    // --- Spawn a background task to continuously drain logs ---
    let (mut orch_logs, _, _) = node.subscribe_logs();
    let (tx_stop, rx_stop) = tokio::sync::oneshot::channel::<()>();
    let log_task = tokio::spawn(async move {
        tokio::select! {
            _ = async {
                while let Ok(line) = orch_logs.recv().await {
                    println!("[LOGS-Orchestration] {}", line);
                }
            } => {},
            _ = rx_stop => {
                println!("[LOGS-Orchestration] Log draining task stopped.");
            }
        }
    });

    let test_result: Result<()> = async move {
        let workload_client = WorkloadClient::new(
            &ipc_addr,
            &certs_path.join("ca.pem").to_string_lossy(),
            &certs_path.join("orchestration.pem").to_string_lossy(),
            &certs_path.join("orchestration.key").to_string_lossy(),
        )
        .await?;

        // Wait for node to be ready
        wait_for_height(&rpc_addr, 1, Duration::from_secs(20)).await?;

        // 3. DEPLOY CONTRACT
        let deployer_pubkey = keypair.public().encode_protobuf();
        let contract_address =
            sha256([deployer_pubkey.as_slice(), counter_wasm.as_slice()].concat()).unwrap();
        let contract_address_hex = hex::encode(&contract_address);

        let deploy_tx_unsigned = ApplicationTransaction::DeployContract {
            header: Default::default(),
            code: counter_wasm.clone(),
            signature_proof: Default::default(),
        };
        let deploy_tx = create_signed_app_tx(&keypair, deploy_tx_unsigned, nonce, 1.into());
        // nonce must be updated manually since we are using local variables
        let next_nonce = nonce + 1;

        println!("Attempting to submit DEPLOY transaction to {}", rpc_addr);
        submit_transaction(&rpc_addr, &deploy_tx).await?;
        println!("Successfully submitted DEPLOY transaction.");

        // 4. WAIT FOR DEPLOYMENT to be confirmed in state
        wait_for_contract_deployment(&rpc_addr, &contract_address, Duration::from_secs(20)).await?;
        println!(
            "Contract deployed and found in state at address: {}",
            contract_address_hex
        );

        // 5. QUERY INITIAL STATE
        let get_input = vec![0]; // ABI for get()
        let query_context = ioi_api::vm::ExecutionContext {
            caller: vec![],
            block_height: 0,
            gas_limit: 1_000_000_000,
            contract_address: vec![],
        };
        let query_output = workload_client
            .query_contract(
                contract_address.to_vec(),
                get_input.clone(),
                query_context.clone(),
            )
            .await?;
        assert_eq!(
            query_output.return_data,
            vec![0],
            "Initial count should be 0"
        );

        // 6. CALL INCREMENT
        let increment_input = vec![1]; // ABI for increment()
        let call_tx_unsigned = ApplicationTransaction::CallContract {
            header: Default::default(),
            address: contract_address.to_vec(),
            input_data: increment_input,
            gas_limit: 1_000_000,
            signature_proof: Default::default(),
        };
        let call_tx = create_signed_app_tx(&keypair, call_tx_unsigned, next_nonce, 1.into());
        println!("Attempting to submit CALL transaction to {}", rpc_addr);
        submit_transaction(&rpc_addr, &call_tx).await?;
        println!("Successfully submitted CALL transaction.");

        // 7. VERIFY FINAL STATE by polling the contract result directly
        let deadline = Instant::now() + Duration::from_secs(20); // 20-second timeout
        loop {
            let current_query_output = workload_client
                .query_contract(
                    contract_address.to_vec(),
                    get_input.clone(),
                    query_context.clone(),
                )
                .await?;

            if current_query_output.return_data == vec![1] {
                println!("--- Counter is 1. Verification successful. ---");
                break;
            }

            if Instant::now() >= deadline {
                anyhow::bail!(
                    "Timeout waiting for counter to be 1. Current value: {:?}",
                    current_query_output.return_data
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        println!("--- E2E Contract Test Successful ---");
        Ok(())
    }
    .await;

    // Clean up the background task
    let _ = tx_stop.send(());
    let _ = log_task.await;

    // Explicitly shut down the cluster to prevent ValidatorGuard panic, even if test failed
    cluster.shutdown().await?;

    test_result
}
