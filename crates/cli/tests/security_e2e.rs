// Path: crates/cli/tests/security_e2e.rs
#![cfg(all(feature = "validator-bins"))]

// --- Common Imports ---
use anyhow::{anyhow, Result};
use ioi_cli::testing::build_test_artifacts;

// --- Imports for Local Binary Integrity Test ---
#[cfg(feature = "validator-bins")]
use dcrypt::algorithms::hash::{HashFunction, Sha256};
#[cfg(feature = "validator-bins")]
use std::io::Write; // REMOVED: Read
#[cfg(feature = "validator-bins")]
use std::path::PathBuf;
#[cfg(feature = "validator-bins")]
use tempfile::tempdir;

// --- Imports for On-Chain Attestation Test ---
#[cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]
use ioi_api::state::service_namespace_prefix;
#[cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]
use ioi_cli::testing::{
    rpc::{query_state_key, submit_transaction},
    wait_for_height, TestCluster,
};
#[cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BinaryMeasurement,
        BlockTimingParams, BlockTimingRuntime, BootAttestation, ChainId, ChainTransaction,
        SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::{InitialServiceConfig, ServicePolicy},
    service_configs::{MethodPermission, MigrationConfig},
};
#[cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]
use libp2p::identity::Keypair;
#[cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]
use std::collections::BTreeMap;
#[cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// -----------------------------------------------------------------------------
// HELPER: Create Attestation Transaction
// -----------------------------------------------------------------------------

#[cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]
fn create_attestation_tx(
    keypair: &Keypair,
    attestation: BootAttestation,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    // FIX: Map string error to anyhow
    let payload_bytes = codec::to_bytes_canonical(&attestation).map_err(|e| anyhow!(e))?;

    let payload = SystemPayload::CallService {
        service_id: "identity_hub".to_string(),
        method: "register_attestation@v1".to_string(),
        params: payload_bytes,
    };

    let public_key = keypair.public().encode_protobuf();
    let account_id_hash =
        account_id_from_key_material(SignatureSuite::ED25519, &public_key).unwrap();
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature,
    };

    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

// -----------------------------------------------------------------------------
// HELPER: Binary Path Resolution
// -----------------------------------------------------------------------------

#[cfg(feature = "validator-bins")]
fn get_binary_path(name: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    let path = root.join("target/release").join(name);
    if !path.exists() {
        panic!(
            "Binary {} not found at {:?}. Run 'cargo build --release' first.",
            name, path
        );
    }
    path
}

// -----------------------------------------------------------------------------
// TEST 1: Local Binary Integrity Enforcement
// -----------------------------------------------------------------------------

#[tokio::test]
#[cfg(feature = "validator-bins")]
async fn test_guardian_binary_integrity_enforcement() -> Result<()> {
    // 0. Rebuild Validator Binaries to ensure they have the latest code changes
    println!("--- Rebuilding Guardian Binary ---");
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "ioi-node",
            "--bin",
            "guardian",
            "--features",
            "validator-bins",
        ])
        .status()
        .expect("Failed to execute cargo build for guardian");
    assert!(status.success(), "Failed to rebuild guardian binary");

    // 1. Setup artifacts
    build_test_artifacts(); // Ensures binaries exist
    let temp_dir = tempdir()?;
    let bin_dir = temp_dir.path().to_path_buf();

    // 2. Copy binaries to temp dir to simulate a deployment
    let orch_src = get_binary_path("orchestration");
    let work_src = get_binary_path("workload");

    let orch_dst = bin_dir.join("orchestration");
    let work_dst = bin_dir.join("workload");

    std::fs::copy(&orch_src, &orch_dst)?;
    std::fs::copy(&work_src, &work_dst)?;

    // 3. Compute Hashes
    let orch_bytes = std::fs::read(&orch_dst)?;
    let work_bytes = std::fs::read(&work_dst)?;
    let orch_hash = hex::encode(Sha256::digest(&orch_bytes)?);
    let work_hash = hex::encode(Sha256::digest(&work_bytes)?);

    // 4. Test Case: Valid Configuration
    let guard_src = get_binary_path("guardian");
    let guard_dst = bin_dir.join("guardian");
    std::fs::copy(&guard_src, &guard_dst)?;

    // Create valid config
    let valid_config_path = bin_dir.join("guardian.toml");
    let valid_config = format!(
        r#"
        signature_policy = "Fixed"
        enforce_binary_integrity = true
        approved_orchestrator_hash = "{}"
        approved_workload_hash = "{}"
        binary_dir_override = "{}"
        "#,
        orch_hash,
        work_hash,
        bin_dir.to_string_lossy()
    );
    std::fs::write(&valid_config_path, valid_config)?;

    // Spawn Guardian
    let mut valid_proc = std::process::Command::new(&guard_dst)
        .arg("--config-dir")
        .arg(&bin_dir)
        .arg("--agentic-model-path")
        .arg("dummy_model.bin") // Dummy path
        .env("CERTS_DIR", bin_dir.to_string_lossy().as_ref())
        .env("TELEMETRY_ADDR", "127.0.0.1:0") // Random port
        .env("GUARDIAN_LISTEN_ADDR", "127.0.0.1:0")
        .spawn()?;

    // Give it a moment. If it crashes immediately, it failed.
    std::thread::sleep(std::time::Duration::from_millis(1000));
    if let Ok(Some(status)) = valid_proc.try_wait() {
        panic!("Valid guardian process exited unexpectedly with {}", status);
    }
    valid_proc.kill()?;
    let _ = valid_proc.wait(); // Ensure resources are released

    // 5. Test Case: Tampered Binary
    // Append a byte to orchestration
    let mut f = std::fs::OpenOptions::new().append(true).open(&orch_dst)?;
    f.write_all(b"\0")?;
    f.sync_all()?; // Force write to disk
    drop(f);

    // Debug: Verify the hash actually changed
    let tampered_bytes = std::fs::read(&orch_dst)?;
    let tampered_hash = hex::encode(Sha256::digest(&tampered_bytes)?);
    assert_ne!(
        orch_hash, tampered_hash,
        "Test setup error: Orchestration binary modification failed to change hash!"
    );

    // Spawn again
    let mut tampered_proc = std::process::Command::new(&guard_dst)
        .arg("--config-dir")
        .arg(&bin_dir)
        .arg("--agentic-model-path")
        .arg("dummy_model.bin")
        .env("CERTS_DIR", bin_dir.to_string_lossy().as_ref())
        .env("TELEMETRY_ADDR", "127.0.0.1:0")
        .env("GUARDIAN_LISTEN_ADDR", "127.0.0.1:0")
        .env("RUST_LOG", "info") // Make sure we get info logs
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(status)) = tampered_proc.try_wait() {
            // Process exited, check the output
            let output = tampered_proc.wait_with_output()?;
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(
                !status.success(),
                "Tampered guardian should exit with error code"
            );
            assert!(
                stderr.contains("SECURITY VIOLATION") || stderr.contains("hash mismatch"),
                "Guardian did not detect tampered binary. Stderr: {}",
                stderr
            );
            break;
        }

        if start.elapsed() > std::time::Duration::from_secs(5) {
            let _ = tampered_proc.kill();

            // To consume stderr we would need to read it, but since we are panicking
            // and `Read` trait was causing warnings, we omit complex reading logic here.
            panic!("Guardian failed to detect binary tampering (process continued running).");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// TEST 2: On-Chain Binary Attestation Flow
// -----------------------------------------------------------------------------

#[tokio::test]
#[cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]
async fn test_binary_integrity_attestation_flow() -> Result<()> {
    println!("--- Running On-Chain Attestation E2E Test ---");
    build_test_artifacts();

    // [FIX] Define custom policy for IdentityHub
    let mut id_methods = BTreeMap::new();
    id_methods.insert("rotate_key@v1".into(), MethodPermission::User);
    id_methods.insert("register_attestation@v1".into(), MethodPermission::User);

    let id_policy = ServicePolicy {
        methods: id_methods,
        allowed_system_prefixes: vec![
            "system::validators::".to_string(),
            "identity::pubkey::".to_string(), // <--- ADDED: Allow access to global pubkey registry
        ],
    };

    let cluster = TestCluster::builder()
        // [FIX] Inject policy
        .with_service_policy("identity_hub", id_policy)
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        // --- UPDATED: Using GenesisBuilder API ---
        .with_genesis_modifier(move |builder, keys| {
            let keypair = &keys[0];

            // 1. Register Identity
            let account_id = builder.add_identity(keypair);
            let account_id_hash = account_id.0;

            // 2. Validator Set
            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::ED25519,
                            public_key_hash: account_id_hash,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            };
            builder.set_validators(&vs);

            // 3. Block Timing
            let timing_params = BlockTimingParams {
                base_interval_secs: 2, // Fast blocks
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

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;

        wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

        // 1. Construct a valid BootAttestation
        let public_key = keypair.public().encode_protobuf();
        let account_id_hash =
            account_id_from_key_material(SignatureSuite::ED25519, &public_key).unwrap();
        let account_id = AccountId(account_id_hash);

        let dummy_meas = BinaryMeasurement {
            name: "test".to_string(),
            sha256: [0xAA; 32],
            size: 12345,
        };

        let mut attestation = BootAttestation {
            validator_account_id: account_id,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            guardian: dummy_meas.clone(),
            orchestration: dummy_meas.clone(),
            workload: dummy_meas.clone(),
            build_metadata: env!("CARGO_PKG_VERSION").to_string(),
            signature: Vec::new(),
        };

        // Sign the attestation payload
        let sign_bytes = attestation.to_sign_bytes()?;
        let signature = keypair.sign(&sign_bytes)?;
        attestation.signature = signature;

        // 2. Wrap in Transaction
        // Nonce 0 because it's the first tx for this validator
        let tx = create_attestation_tx(keypair, attestation.clone(), 0, 1.into())?;

        // 3. Submit
        println!("Submitting binary attestation transaction...");
        submit_transaction(rpc_addr, &tx).await?;

        // 4. Verify State
        wait_for_height(rpc_addr, 2, Duration::from_secs(20)).await?;

        // FIX: Construct the namespaced key.
        // IdentityHub stores data in its private namespace: _service_data::identity_hub::
        // The service logic appends b"identity::attestation::" + account_id.
        let ns = service_namespace_prefix("identity_hub");
        let key = [
            ns.as_slice(),
            b"identity::attestation::",
            account_id.as_ref(),
        ]
        .concat();

        let stored_bytes = query_state_key(rpc_addr, &key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Attestation not found in state"))?;

        // FIX: Map string error to anyhow
        let stored_attestation: BootAttestation =
            codec::from_bytes_canonical(&stored_bytes).map_err(|e| anyhow!(e))?;

        assert_eq!(
            stored_attestation.validator_account_id, account_id,
            "Stored Account ID mismatch"
        );
        assert_eq!(
            stored_attestation.guardian.sha256, [0xAA; 32],
            "Stored hash mismatch"
        );
        assert_eq!(
            stored_attestation.signature, attestation.signature,
            "Stored signature mismatch"
        );

        println!("SUCCESS: Binary attestation verified on-chain.");
        Ok(())
    }
    .await;

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result
}
