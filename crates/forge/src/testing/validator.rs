// Path: crates/forge/src/testing/validator.rs

use super::{
    assert::{assert_log_contains, LOG_CHANNEL_CAPACITY},
    backend::{DockerBackend, DockerBackendConfig, LogStream, ProcessBackend, TestBackend},
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_client::WorkloadClient;
use ioi_crypto::sign::dilithium::{DilithiumKeyPair, DilithiumScheme};
use ioi_state::primitives::kzg::KZGParams;
use ioi_types::config::{
    CommitmentSchemeType, ConsensusType, InitialServiceConfig, OrchestrationConfig, StateTreeType,
    VmFuelCosts, WorkloadConfig,
};
use ioi_validator::common::generate_certificates_if_needed;
use libp2p::{identity, Multiaddr, PeerId};
use std::any::Any;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::process::Command as TokioCommand;
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Duration;

const WORKLOAD_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Represents a complete, logical validator node, abstracting over its execution backend.
pub struct TestValidator {
    pub keypair: identity::Keypair,
    pub pqc_keypair: Option<DilithiumKeyPair>,
    pub peer_id: PeerId,
    pub rpc_addr: String,
    pub workload_ipc_addr: String,
    pub orchestration_telemetry_addr: String,
    pub workload_telemetry_addr: String,
    pub p2p_addr: Multiaddr,
    pub certs_dir_path: PathBuf,
    _temp_dir: Arc<TempDir>,
    pub backend: Box<dyn TestBackend>,
    orch_log_tx: broadcast::Sender<String>,
    workload_log_tx: broadcast::Sender<String>,
    guardian_log_tx: Option<broadcast::Sender<String>>,
    log_drain_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

struct NullBackend;
#[async_trait]
impl TestBackend for NullBackend {
    async fn launch(&mut self) -> Result<()> {
        Ok(())
    }
    fn get_addresses(&self) -> (String, Multiaddr) {
        ("".into(), "/ip4/127.0.0.1/tcp/0".parse().unwrap())
    }
    fn get_log_streams(&mut self) -> Result<(LogStream, LogStream, Option<LogStream>)> {
        Err(anyhow!("null backend"))
    }
    async fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl Drop for TestValidator {
    fn drop(&mut self) {
        // Take ownership of the backend to ensure it's cleaned up.
        let mut backend = std::mem::replace(&mut self.backend, Box::new(NullBackend));
        let handles = self.log_drain_handles.clone();

        let cleanup_future = async move {
            // Abort log draining tasks first to prevent them from interfering.
            for handle in handles.lock().await.iter() {
                handle.abort();
            }
            // Now, cleanup the backend which kills the processes/containers.
            if let Err(e) = backend.cleanup().await {
                // Use eprintln! because logging might not be available during panic unwinding.
                eprintln!("[WARN] Failed to cleanup test validator backend: {}", e);
            }
        };

        // If we are in an async context, spawn the task without blocking.
        // This is the common case when a test finishes without panicking.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(cleanup_future);
        } else {
            // If `try_current()` fails, we are likely in a drop during a panic
            // where the test runtime is being torn down.
            // Create a new, simple runtime just for our cleanup task and BLOCK on it.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("Failed to create temporary runtime for cleanup");
            rt.block_on(cleanup_future);
        }
    }
}

impl TestValidator {
    /// Subscribes to the non-blocking log streams for this validator's containers.
    ///
    /// This method should be called once at the beginning of a test. The returned
    /// receivers will receive log lines from the moment of subscription. Slow consumption
    /// of these receivers will cause logs to be dropped, but will not block the
    /// underlying validator process.
    pub fn subscribe_logs(
        &self,
    ) -> (
        broadcast::Receiver<String>,
        broadcast::Receiver<String>,
        Option<broadcast::Receiver<String>>,
    ) {
        (
            self.orch_log_tx.subscribe(),
            self.workload_log_tx.subscribe(),
            self.guardian_log_tx.as_ref().map(|tx| tx.subscribe()),
        )
    }

    /// Explicitly shuts down the validator and all its associated resources.
    /// This is the preferred way to tear down a validator in a controlled test,
    /// as it avoids the unpredictable timing of `Drop`.
    pub async fn shutdown(&mut self) -> Result<()> {
        // Abort this validator's log drainers first.
        // This prevents them from holding any resources or panicking during backend cleanup.
        let handles = self.log_drain_handles.lock().await;
        for handle in handles.iter() {
            handle.abort();
        }
        drop(handles); // Release lock

        // Now, trigger the backend cleanup for just this node.
        self.backend.cleanup().await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn launch(
        keypair: identity::Keypair,
        genesis_content: String,
        base_port: u16,
        chain_id: ioi_types::app::ChainId,
        bootnode_addrs: Option<&[Multiaddr]>,
        consensus_type: &str,
        state_tree_type: &str,
        commitment_scheme_type: &str,
        ibc_gateway_addr: Option<&str>,
        agentic_model_path: Option<&str>,
        use_docker: bool,
        initial_services: Vec<InitialServiceConfig>,
        use_malicious_workload: bool,
        light_readiness_check: bool,
        // [+] MODIFIED: Use a generic slice of strings for features
        extra_features: &[String],
    ) -> Result<Self> {
        // --- NEW: Per-validator build step with corrected feature names ---
        let consensus_feature = match consensus_type {
            "ProofOfAuthority" => "consensus-poa",
            "ProofOfStake" => "consensus-pos",
            _ => {
                return Err(anyhow!(
                    "Unsupported test consensus type: {}",
                    consensus_type
                ))
            }
        };
        let tree_feature = match state_tree_type {
            "IAVL" => "tree-iavl",
            "SparseMerkle" => "tree-sparse-merkle",
            "Verkle" => "tree-verkle",
            _ => return Err(anyhow!("Unsupported test state tree: {}", state_tree_type)),
        };
        let primitive_feature = match commitment_scheme_type {
            "Hash" => "primitive-hash",
            "Pedersen" => "primitive-pedersen",
            "KZG" => "primitive-kzg",
            "Lattice" => "primitive-lattice",
            _ => {
                return Err(anyhow!(
                    "Unsupported commitment scheme: {}",
                    commitment_scheme_type
                ))
            }
        };

        // [+] MODIFIED: Dynamically construct the features string.
        let mut features = format!(
            "validator-bins,{},{},{},vm-wasm{}",
            consensus_feature,
            tree_feature,
            primitive_feature,
            if use_malicious_workload {
                ",malicious-bin"
            } else {
                ""
            }
        );

        if !extra_features.is_empty() {
            features.push(',');
            features.push_str(&extra_features.join(","));
        }

        println!("--- Building node binaries with features: {} ---", features);
        let status_node = Command::new("cargo")
            .args([
                "build",
                "-p",
                "ioi-node",
                "--release",
                "--no-default-features",
                "--features",
                &features,
            ])
            .status()
            .expect("Failed to execute cargo build for node");
        if !status_node.success() {
            panic!("Node binary build failed for features: {}", features);
        }
        // --- END MODIFIED BUILD STEP ---

        let peer_id = keypair.public().to_peer_id();
        let temp_dir = Arc::new(tempfile::tempdir()?);
        let certs_dir_path = temp_dir.path().join("certs");
        std::fs::create_dir_all(&certs_dir_path)?;

        let pqc_keypair = Some(
            DilithiumScheme::new(ioi_crypto::security::SecurityLevel::Level2).generate_keypair(),
        )
        .transpose()?; // This handles the Result correctly.

        let p2p_port = portpicker::pick_unused_port().unwrap_or(base_port);
        let rpc_port = portpicker::pick_unused_port().unwrap_or(base_port + 1);
        let p2p_addr_str = format!("/ip4/127.0.0.1/tcp/{}", p2p_port);
        let p2p_addr: Multiaddr = p2p_addr_str.parse()?;
        let rpc_addr = format!("127.0.0.1:{}", rpc_port);

        let keypair_path = temp_dir.path().join("identity.key");
        std::fs::write(&keypair_path, keypair.to_protobuf_encoding()?)?;

        let genesis_path = temp_dir.path().join("genesis.json");
        std::fs::write(&genesis_path, genesis_content)?;

        let config_dir_path = temp_dir.path().to_path_buf();

        // Persist PQC keypair for the orchestrator binary to load.
        let pqc_key_path = config_dir_path.join("pqc_key.json");
        if let Some(kp) = pqc_keypair.as_ref() {
            let pub_hex = hex::encode(SigningKeyPair::public_key(kp).to_bytes());
            let priv_hex = hex::encode(SigningKeyPair::private_key(kp).to_bytes());
            let body = serde_json::json!({ "public": pub_hex, "private": priv_hex }).to_string();
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .mode(0o600)
                    .open(&pqc_key_path)?;
                f.write_all(body.as_bytes())?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&pqc_key_path, body)?;
            }
        }

        let consensus_enum = match consensus_type {
            "ProofOfAuthority" => ConsensusType::ProofOfAuthority,
            "ProofOfStake" => ConsensusType::ProofOfStake,
            _ => return Err(anyhow!("Unsupported consensus type: {}", consensus_type)),
        };

        let state_tree_enum = match state_tree_type {
            "IAVL" => StateTreeType::IAVL,
            "SparseMerkle" => StateTreeType::SparseMerkle,
            "Verkle" => StateTreeType::Verkle,
            _ => return Err(anyhow!("Unsupported state tree type: {}", state_tree_type)),
        };

        let commitment_scheme_enum = match commitment_scheme_type {
            "Hash" => CommitmentSchemeType::Hash,
            "Pedersen" => CommitmentSchemeType::Pedersen,
            "KZG" => CommitmentSchemeType::KZG,
            "Lattice" => CommitmentSchemeType::Lattice,
            _ => {
                return Err(anyhow!(
                    "Unsupported commitment scheme: {}",
                    commitment_scheme_type
                ))
            }
        };

        let orch_config_path = config_dir_path.join("orchestration.toml");
        let orchestration_config = OrchestrationConfig {
            chain_id,
            config_schema_version: 0,
            consensus_type: consensus_enum,
            rpc_listen_address: if use_docker {
                "0.0.0.0:9999".to_string()
            } else {
                rpc_addr.clone()
            },
            rpc_hardening: Default::default(),
            initial_sync_timeout_secs: 180, // avoid premature “no peers” timeouts in CI
            block_production_interval_secs: 5,
            round_robin_view_timeout_secs: 20,
            default_query_gas_limit: 1_000_000_000,
            ibc_gateway_listen_address: ibc_gateway_addr.map(String::from),
        };
        std::fs::write(&orch_config_path, toml::to_string(&orchestration_config)?)?;

        let workload_config_path = config_dir_path.join("workload.toml");
        let workload_state_file = temp_dir.path().join("workload_state.json");
        let mut workload_config = WorkloadConfig {
            runtimes: vec!["WASM".to_string()],
            state_tree: state_tree_enum,
            commitment_scheme: commitment_scheme_enum,
            consensus_type: consensus_enum,
            genesis_file: if use_docker {
                "/tmp/test-data/genesis.json".to_string()
            } else {
                genesis_path.to_string_lossy().replace('\\', "/")
            },
            state_file: if use_docker {
                "/tmp/test-data/workload_state.json".to_string()
            } else {
                workload_state_file.to_string_lossy().replace('\\', "/")
            },
            srs_file_path: None,
            fuel_costs: VmFuelCosts::default(),
            initial_services,
            min_finality_depth: 1000,
            keep_recent_heights: 100_000,
            epoch_size: 50_000,
        };

        if state_tree_type == "Verkle" {
            let srs_path = temp_dir.path().join("srs.bin");
            println!("Generating Verkle SRS, this may take a moment...");
            let params = KZGParams::new_insecure_for_testing(12345, 255);
            params.save_to_file(&srs_path).map_err(|e| anyhow!(e))?;
            println!("SRS generation complete.");
            workload_config.srs_file_path = Some(if use_docker {
                "/tmp/test-data/srs.bin".to_string()
            } else {
                srs_path.to_string_lossy().to_string()
            });
        }

        std::fs::write(&workload_config_path, toml::to_string(&workload_config)?)?;

        let guardian_config = r#"signature_policy = "FollowChain""#.to_string();
        std::fs::write(config_dir_path.join("guardian.toml"), guardian_config)?;

        let (orch_log_tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);
        let (workload_log_tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);
        let (guardian_log_tx, mut guardian_sub) = {
            let (tx, rx) = broadcast::channel(LOG_CHANNEL_CAPACITY);
            (Some(tx), Some(rx))
        };

        let mut log_drain_handles = Vec::new();

        let workload_ipc_addr;
        let orchestration_telemetry_addr;
        let workload_telemetry_addr;

        let mut backend: Box<dyn TestBackend> = if use_docker {
            let docker_config = DockerBackendConfig {
                rpc_addr: rpc_addr.clone(),
                p2p_addr: p2p_addr.clone(),
                agentic_model_path: agentic_model_path.map(PathBuf::from),
                temp_dir: temp_dir.clone(),
                config_dir_path: config_dir_path.clone(),
                certs_dir_path: certs_dir_path.clone(),
            };
            let mut docker_backend = DockerBackend::new(docker_config).await?;
            docker_backend.launch().await?; // Just starts containers
            workload_ipc_addr = "127.0.0.1:8555".to_string();
            orchestration_telemetry_addr = format!("127.0.0.1:{}", rpc_port + 100); // Placeholder
            workload_telemetry_addr = format!("127.0.0.1:{}", rpc_port + 200); // Placeholder
            Box::new(docker_backend)
        } else {
            generate_certificates_if_needed(&certs_dir_path)?;

            let ipc_port_workload = portpicker::pick_unused_port().unwrap_or(base_port + 2);
            let guardian_addr = format!(
                "127.0.0.1:{}",
                portpicker::pick_unused_port().unwrap_or(base_port + 3)
            );
            workload_ipc_addr = format!("127.0.0.1:{}", ipc_port_workload);
            workload_telemetry_addr = format!(
                "127.0.0.1:{}",
                portpicker::pick_unused_port().unwrap_or(base_port + 4)
            );
            orchestration_telemetry_addr = format!(
                "127.0.0.1:{}",
                portpicker::pick_unused_port().unwrap_or(base_port + 5)
            );

            let node_binary_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("target/release/");

            let mut pb = ProcessBackend::new(
                rpc_addr.clone(),
                p2p_addr.clone(),
                node_binary_path.clone(),
                workload_config_path.clone(),
                workload_ipc_addr.clone(),
                certs_dir_path.clone(),
            );
            pb.orchestration_telemetry_addr = Some(orchestration_telemetry_addr.clone());
            pb.workload_telemetry_addr = Some(workload_telemetry_addr.clone());

            // --- Spawn Guardian ---
            if let Some(model_path) = agentic_model_path {
                let telemetry_addr_guard = format!(
                    "127.0.0.1:{}",
                    portpicker::pick_unused_port().unwrap_or(base_port + 6)
                );
                let process = TokioCommand::new(node_binary_path.join("guardian"))
                    .args([
                        "--config-dir",
                        &config_dir_path.to_string_lossy(),
                        "--agentic-model-path",
                        model_path,
                    ])
                    .env("TELEMETRY_ADDR", &telemetry_addr_guard)
                    .env("GUARDIAN_LISTEN_ADDR", &guardian_addr)
                    .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()?;
                pb.guardian_process = Some(process);
            }

            // --- Spawn Workload ---
            let workload_binary_name = if use_malicious_workload {
                "malicious-workload"
            } else {
                "workload"
            };
            let mut workload_cmd = TokioCommand::new(node_binary_path.join(workload_binary_name));
            workload_cmd
                .args(["--config", &workload_config_path.to_string_lossy()])
                .env("TELEMETRY_ADDR", &workload_telemetry_addr)
                .env("IPC_SERVER_ADDR", &workload_ipc_addr)
                .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if agentic_model_path.is_some() {
                workload_cmd.env("GUARDIAN_ADDR", &guardian_addr);
            }
            pb.workload_process = Some(workload_cmd.spawn()?);

            // --- Spawn Orchestration ---
            let mut orch_args = vec![
                "--config".to_string(),
                orch_config_path.to_string_lossy().to_string(),
                "--identity-key-file".to_string(),
                keypair_path.to_string_lossy().to_string(),
                "--listen-address".to_string(),
                p2p_addr_str.clone(),
            ];
            if let Some(addrs) = bootnode_addrs {
                for addr in addrs {
                    orch_args.push("--bootnode".to_string());
                    orch_args.push(addr.to_string());
                }
            }
            if pqc_keypair.is_some() {
                orch_args.push("--pqc-key-file".to_string());
                orch_args.push(pqc_key_path.to_string_lossy().to_string());
            }
            let mut orch_cmd = TokioCommand::new(node_binary_path.join("orchestration"));
            orch_cmd
                .args(&orch_args)
                .env("RUST_BACKTRACE", "1") // Add backtrace for debugging
                .env("TELEMETRY_ADDR", &orchestration_telemetry_addr)
                .env("WORKLOAD_IPC_ADDR", &workload_ipc_addr)
                .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if agentic_model_path.is_some() {
                orch_cmd.env("GUARDIAN_ADDR", &guardian_addr);
            }
            pb.orchestration_process = Some(orch_cmd.spawn()?);

            Box::new(pb)
        };

        // --- START LOG DRAINING AND READINESS CHECKS ---
        let (mut orch_logs, mut workload_logs, guardian_logs_opt) = backend.get_log_streams()?;

        let orch_tx_clone = orch_log_tx.clone();
        log_drain_handles.push(tokio::spawn(async move {
            while let Some(Ok(line)) = orch_logs.next().await {
                let _ = orch_tx_clone.send(line);
            }
        }));

        let work_tx_clone = workload_log_tx.clone();
        log_drain_handles.push(tokio::spawn(async move {
            while let Some(Ok(line)) = workload_logs.next().await {
                let _ = work_tx_clone.send(line);
            }
        }));

        if let (Some(mut guardian_logs), Some(tx)) = (guardian_logs_opt, guardian_log_tx.as_ref()) {
            let tx_clone = tx.clone();
            log_drain_handles.push(tokio::spawn(async move {
                while let Some(Ok(line)) = guardian_logs.next().await {
                    let _ = tx_clone.send(line);
                }
            }));
        }

        let mut orch_sub = orch_log_tx.subscribe();
        let mut workload_sub = workload_log_tx.subscribe();

        if agentic_model_path.is_some() {
            assert_log_contains(
                "Guardian",
                guardian_sub.as_mut().unwrap(),
                &format!("GUARDIAN_IPC_LISTENING_ON_"),
            )
            .await?;
        }

        assert_log_contains(
            "Workload",
            &mut workload_sub,
            &format!("WORKLOAD_IPC_LISTENING_ON_{}", workload_ipc_addr),
        )
        .await?;

        if !use_docker {
            // Only probe genesis for process backend; docker backend has network delays
            let temp_workload_client = WorkloadClient::new(
                &workload_ipc_addr,
                &certs_dir_path.join("ca.pem").to_string_lossy(),
                &certs_dir_path.join("orchestration.pem").to_string_lossy(),
                &certs_dir_path.join("orchestration.key").to_string_lossy(),
            )
            .await?;
            super::assert::wait_for(
                "workload genesis to be ready",
                Duration::from_millis(250),
                WORKLOAD_READY_TIMEOUT,
                || async {
                    match temp_workload_client.get_genesis_status().await {
                        Ok(status) if status.ready => Ok(Some(())),
                        _ => Ok(None),
                    }
                },
            )
            .await?;
        }

        assert_log_contains(
            "Orchestration",
            &mut orch_sub,
            &format!("ORCHESTRATION_RPC_LISTENING_ON_{}", rpc_addr),
        )
        .await?;

        if !light_readiness_check {
            assert_log_contains(
                "Orchestration",
                &mut orch_sub,
                "ORCHESTRATION_STARTUP_COMPLETE",
            )
            .await?;
        } else {
            log::info!("[Forge] Light readiness check complete. Bypassing wait for startup-complete signal.");
        }

        // --- END READINESS CHECKS ---

        Ok(TestValidator {
            keypair,
            pqc_keypair,
            peer_id,
            rpc_addr,
            workload_ipc_addr,
            orchestration_telemetry_addr,
            workload_telemetry_addr,
            p2p_addr,
            certs_dir_path,
            _temp_dir: temp_dir,
            backend,
            orch_log_tx,
            workload_log_tx,
            guardian_log_tx,
            log_drain_handles: Arc::new(Mutex::new(log_drain_handles)),
        })
    }
}