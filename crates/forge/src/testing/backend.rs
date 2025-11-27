// Path: crates/forge/src/testing/backend.rs

use super::docker::{ensure_docker_image_exists, DOCKER_BUILD_CHECK, DOCKER_IMAGE_TAG};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bollard::{
    models::{ContainerCreateBody, HostConfig, NetworkCreateRequest},
    query_parameters::{
        CreateContainerOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptionsBuilder,
        StartContainerOptions, StopContainerOptionsBuilder,
    },
    Docker,
};
use futures_util::stream::{self, Stream, StreamExt};
use ioi_validator::common::generate_certificates_if_needed;
use libp2p::Multiaddr;
use std::any::Any;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncBufReadExt;
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing;

/// A type alias for a stream that yields lines of text, abstracting over the log source.
pub type LogStream = Pin<Box<dyn Stream<Item = Result<String, io::Error>> + Send>>;

/// A trait for abstracting the execution backend for a test validator (local process vs. Docker).
#[async_trait]
pub trait TestBackend: Send {
    /// Launches the components of a validator node.
    async fn launch(&mut self) -> Result<()>;

    /// Returns the RPC and P2P addresses for the launched node.
    fn get_addresses(&self) -> (String, Multiaddr);

    /// Provides streams for the container logs.
    fn get_log_streams(&mut self) -> Result<(LogStream, LogStream, Option<LogStream>)>;

    /// Cleans up all resources (processes, containers, temp files).
    async fn cleanup(&mut self) -> Result<()>;

    /// Restarts the workload process. Only implemented for `ProcessBackend`.
    async fn restart_workload_process(
        &mut self,
        log_tx: broadcast::Sender<String>,
        log_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    ) -> Result<()>;

    /// Kills the workload process. Only implemented for `ProcessBackend`.
    async fn kill_workload_process(&mut self) -> Result<()>;

    /// Provides access to the concrete backend type for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Provides mutable access to the concrete backend type for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

// --- ProcessBackend Implementation ---
#[derive(Debug)]
pub struct ProcessBackend {
    pub orchestration_process: Option<Child>,
    pub workload_process: Option<Child>,
    pub guardian_process: Option<Child>,
    pub rpc_addr: String,
    pub p2p_addr: Multiaddr,
    pub orchestration_telemetry_addr: Option<String>,
    pub workload_telemetry_addr: Option<String>,
    binary_path: PathBuf,
    workload_config_path: PathBuf,
    /// Pinned workload IPC address (never :0 after constructor runs).
    pub workload_ipc_addr: String,
    certs_dir_path: PathBuf,
}

impl ProcessBackend {
    pub fn new(
        rpc_addr: String,
        p2p_addr: Multiaddr,
        binary_path: PathBuf,
        workload_config_path: PathBuf,
        mut workload_ipc_addr: String,
        certs_dir_path: PathBuf,
    ) -> Self {
        // Normalize ":0" to a concrete free port so the address is stable across restarts.
        if workload_ipc_addr.ends_with(":0") {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("failed to allocate a free port for workload IPC");
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            workload_ipc_addr = format!("127.0.0.1:{port}");
            tracing::info!(
                target: "forge",
                "Pinned workload IPC address to {} (replaces :0)",
                workload_ipc_addr
            );
        }
        Self {
            orchestration_process: None,
            workload_process: None,
            guardian_process: None,
            rpc_addr,
            p2p_addr,
            orchestration_telemetry_addr: None,
            workload_telemetry_addr: None,
            binary_path,
            workload_config_path,
            workload_ipc_addr,
            certs_dir_path,
        }
    }
}

#[async_trait]
impl TestBackend for ProcessBackend {
    async fn launch(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_addresses(&self) -> (String, Multiaddr) {
        (self.rpc_addr.clone(), self.p2p_addr.clone())
    }

    fn get_log_streams(&mut self) -> Result<(LogStream, LogStream, Option<LogStream>)> {
        let orch_stderr = self
            .orchestration_process
            .as_mut()
            .and_then(|p| p.stderr.take())
            .ok_or_else(|| anyhow!("Failed to take orchestration stderr"))?;
        let work_stderr = self
            .workload_process
            .as_mut()
            .and_then(|p| p.stderr.take())
            .ok_or_else(|| anyhow!("Failed to take workload stderr"))?;

        let orch_lines = tokio::io::BufReader::new(orch_stderr).lines();
        let orch_stream: LogStream = Box::pin(stream::unfold(orch_lines, |mut lines| async {
            match lines.next_line().await {
                Ok(Some(line)) => Some((Ok(line), lines)),
                Ok(None) => None,
                Err(e) => Some((Err(e), lines)),
            }
        }));

        let work_lines = tokio::io::BufReader::new(work_stderr).lines();
        let work_stream: LogStream = Box::pin(stream::unfold(work_lines, |mut lines| async {
            match lines.next_line().await {
                Ok(Some(line)) => Some((Ok(line), lines)),
                Ok(None) => None,
                Err(e) => Some((Err(e), lines)),
            }
        }));

        let guard_stream = self
            .guardian_process
            .as_mut()
            .and_then(|p| p.stderr.take())
            .map(|stderr| {
                let lines = tokio::io::BufReader::new(stderr).lines();
                let stream: LogStream = Box::pin(stream::unfold(lines, |mut lines| async {
                    match lines.next_line().await {
                        Ok(Some(line)) => Some((Ok(line), lines)),
                        Ok(None) => None,
                        Err(e) => Some((Err(e), lines)),
                    }
                }));
                stream
            });

        Ok((orch_stream, work_stream, guard_stream))
    }

    async fn cleanup(&mut self) -> Result<()> {
        if let Some(mut child) = self.orchestration_process.take() {
            child.kill().await?;
        }
        if let Some(mut child) = self.workload_process.take() {
            child.kill().await?;
        }
        if let Some(mut child) = self.guardian_process.take() {
            child.kill().await?;
        }
        Ok(())
    }

    async fn restart_workload_process(
        &mut self,
        log_tx: broadcast::Sender<String>,
        log_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    ) -> Result<()> {
        // Best-effort cleanup of stale DB artifacts (only if present).
        // We parse the workload config to discover the <state_file> prefix.
        // Then remove common leftover lock/journal files if they exist.
        let cfg_str = std::fs::read_to_string(&self.workload_config_path)?;
        let cfg: ioi_types::config::WorkloadConfig = toml::from_str(&cfg_str)?;
        let db_prefix = std::path::Path::new(&cfg.state_file).with_extension("db");
        for suffix in [".lock", ".lck", ".LOCK", ".journal"] {
            let p = db_prefix.with_extension(format!("db{}", suffix));
            if p.exists() {
                tracing::warn!(target: "forge", "Removing stale DB artifact: {}", p.display());
                let _ = std::fs::remove_file(&p);
            }
        }

        if self.workload_process.is_some() {
            return Err(anyhow!("Workload process is already running."));
        }

        tracing::info!(
            target: "forge",
            "Re-launching workload with IPC_SERVER_ADDR={}",
            self.workload_ipc_addr
        );
        let mut workload_cmd = TokioCommand::new(self.binary_path.join("workload"));
        workload_cmd
            .args(["--config", &self.workload_config_path.to_string_lossy()])
            .env(
                "TELEMETRY_ADDR",
                self.workload_telemetry_addr.as_ref().unwrap(),
            )
            .env("IPC_SERVER_ADDR", &self.workload_ipc_addr)
            .env("CERTS_DIR", self.certs_dir_path.to_string_lossy().as_ref())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = workload_cmd.spawn()?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("Failed to take stderr from restarted workload"))?;

        let log_tx_clone = log_tx.clone();
        let handle = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = log_tx_clone.send(line);
            }
        });
        log_handles.lock().await.push(handle);

        self.workload_process = Some(child);

        // Wait until the restarted workload announces its IPC server.
        // This avoids racing the orchestrator’s reconnect loop.
        let mut rx = log_tx.subscribe();
        tokio::time::timeout(Duration::from_secs(30), async move {
            tracing::info!(
                target: "forge",
                "Waiting for restarted workload to announce its IPC listener..."
            );
            while let Ok(line) = rx.recv().await {
                if line.contains("WORKLOAD_IPC_LISTENING_ON_") {
                    return Ok::<(), anyhow::Error>(());
                }
            }
            Err(anyhow!("Workload did not announce IPC listening in time"))
        })
        .await??;

        Ok(())
    }

    async fn kill_workload_process(&mut self) -> Result<()> {
        if let Some(mut child) = self.workload_process.take() {
            tracing::info!(target: "forge", "Killing workload process (handle-based)...");
            child.start_kill()?;
            // Wait for the process to actually exit to ensure resources/ports are released
            // and to prevent zombie processes.
            let status = child.wait().await?;
            tracing::info!(target: "forge", "Workload process exited with: {}", status);
        } else {
            tracing::warn!(target: "forge", "kill_workload_process called but no process handle found.");
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// --- DockerBackend Implementation ---
pub struct DockerBackendConfig {
    pub rpc_addr: String,
    pub p2p_addr: Multiaddr,
    pub agentic_model_path: Option<PathBuf>,
    pub temp_dir: Arc<TempDir>,
    pub config_dir_path: PathBuf,
    pub certs_dir_path: PathBuf,
}

pub struct DockerBackend {
    docker: Docker,
    network_id: String,
    container_ids: Vec<String>,
    rpc_addr: String,
    p2p_addr: Multiaddr,
    agentic_model_path: Option<PathBuf>,
    _temp_dir: Arc<TempDir>,
    config_dir_path: PathBuf,
    certs_dir_path: PathBuf,
    orch_stream: Option<LogStream>,
    work_stream: Option<LogStream>,
    guard_stream: Option<LogStream>,
}

impl DockerBackend {
    pub async fn new(config: DockerBackendConfig) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        let network_name = format!("ioi-e2e-{}", uuid::Uuid::new_v4());
        let network = docker
            .create_network(NetworkCreateRequest {
                name: network_name,
                ..Default::default()
            })
            .await?;
        let network_id = {
            let id = network.id;
            if id.is_empty() {
                return Err(anyhow!("Failed to create network and get ID"));
            }
            id
        };

        Ok(Self {
            docker,
            network_id,
            container_ids: Vec::new(),
            rpc_addr: config.rpc_addr,
            p2p_addr: config.p2p_addr,
            agentic_model_path: config.agentic_model_path,
            _temp_dir: config.temp_dir,
            config_dir_path: config.config_dir_path,
            certs_dir_path: config.certs_dir_path,
            orch_stream: None,
            work_stream: None,
            guard_stream: None,
        })
    }

    async fn launch_container(
        &mut self,
        name: &str,
        cmd: Vec<String>,
        env: Vec<String>,
        binds: Vec<String>,
    ) -> Result<()> {
        let options = Some(CreateContainerOptionsBuilder::default().name(name).build());
        let host_config = HostConfig {
            network_mode: Some(self.network_id.clone()),
            binds: Some(binds),
            ..Default::default()
        };

        let cmd_strs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        let env_strs: Vec<&str> = env.iter().map(|s| s.as_str()).collect();

        let config = ContainerCreateBody {
            image: Some(DOCKER_IMAGE_TAG.to_string()),
            cmd: Some(cmd_strs.into_iter().map(String::from).collect()),
            env: Some(env_strs.into_iter().map(String::from).collect()),
            host_config: Some(host_config),
            ..Default::default()
        };

        let id = self.docker.create_container(options, config).await?.id;
        self.docker
            .start_container(&id, None::<StartContainerOptions>)
            .await?;
        self.container_ids.push(id);
        Ok(())
    }
}

#[async_trait]
impl TestBackend for DockerBackend {
    async fn launch(&mut self) -> Result<()> {
        DOCKER_BUILD_CHECK
            .get_or_try_init(ensure_docker_image_exists)
            .await?;

        generate_certificates_if_needed(&self.certs_dir_path)?;

        let container_data_dir = "/tmp/test-data";
        let container_certs_dir = "/tmp/certs";
        let container_workload_config = "/tmp/test-data/workload.toml";
        let container_orch_config = "/tmp/test-data/orchestration.toml";
        let container_identity_key = "/tmp/test-data/identity.key";

        let base_binds = vec![
            format!(
                "{}:{}",
                self.config_dir_path.to_string_lossy(),
                container_data_dir
            ),
            format!(
                "{}:{}",
                self.certs_dir_path.to_string_lossy(),
                container_certs_dir
            ),
        ];

        let certs_env_str = format!("CERTS_DIR={}", container_certs_dir);
        let guardian_addr_env_str = "GUARDIAN_ADDR=guardian:8443".to_string();
        let workload_addr_env_str = "WORKLOAD_IPC_ADDR=workload:8555".to_string();

        if let Some(model_path) = &self.agentic_model_path {
            let model_dir = model_path.parent().unwrap().to_string_lossy();
            let model_file_name = model_path.file_name().unwrap().to_string_lossy();
            let container_model_path = format!("/models/{}", model_file_name);

            let mut guardian_binds = base_binds.clone();
            guardian_binds.push(format!("{}:/models", model_dir));

            let guardian_cmd = vec![
                "guardian".to_string(),
                "--config-dir".to_string(),
                container_data_dir.to_string(),
                "--agentic-model-path".to_string(),
                container_model_path,
            ];

            // FIX: Ensure Guardian binds to 0.0.0.0 so it's reachable by other containers
            let guardian_env: Vec<String> = vec![
                certs_env_str.clone(),
                "GUARDIAN_LISTEN_ADDR=0.0.0.0:8443".to_string(),
            ];
            self.launch_container("guardian", guardian_cmd, guardian_env, guardian_binds)
                .await?;
        }

        let workload_cmd = vec![
            "workload".to_string(),
            "--config".to_string(),
            container_workload_config.to_string(),
        ];
        let mut workload_env = vec![
            "IPC_SERVER_ADDR=0.0.0.0:8555".to_string(),
            certs_env_str.clone(),
        ];
        if self.agentic_model_path.is_some() {
            workload_env.push(guardian_addr_env_str.clone());
        }
        self.launch_container("workload", workload_cmd, workload_env, base_binds.clone())
            .await?;

        let orch_cmd = vec![
            "orchestration".to_string(),
            "--config".to_string(),
            container_orch_config.to_string(),
            "--identity-key-file".to_string(),
            container_identity_key.to_string(),
            "--listen-address".to_string(),
            "/ip4/0.0.0.0/tcp/9000".to_string(),
        ];
        let mut orch_env: Vec<String> = vec![workload_addr_env_str.clone(), certs_env_str.clone()];
        if self.agentic_model_path.is_some() {
            orch_env.push(guardian_addr_env_str.clone());
        }
        self.launch_container("orchestration", orch_cmd, orch_env, base_binds)
            .await?;

        let ready_timeout = Duration::from_secs(45);
        let log_options = Some(
            LogsOptionsBuilder::default()
                .follow(true)
                .stderr(true)
                .stdout(true)
                .build(),
        );

        fn convert_stream<S>(s: S) -> LogStream
        where
            S: Stream<Item = Result<bollard::container::LogOutput, bollard::errors::Error>>
                + Send
                + 'static,
        {
            Box::pin(s.map(|res| match res {
                Ok(log_output) => Ok(log_output.to_string()),
                Err(e) => Err(io::Error::other(e)),
            }))
        }

        let mut orch_stream: LogStream =
            convert_stream(self.docker.logs("orchestration", log_options.clone()));
        self.work_stream = Some(convert_stream(
            self.docker.logs("workload", log_options.clone()),
        ));

        if self.agentic_model_path.is_some() {
            let mut guard_stream: LogStream =
                convert_stream(self.docker.logs("guardian", log_options));
            let guard_stream_after_wait = timeout(ready_timeout, async {
                while let Some(Ok(log)) = guard_stream.next().await {
                    if log.contains("Guardian container started") {
                        return Ok(guard_stream);
                    }
                }
                Err(anyhow!("Guardian did not become ready in time"))
            })
            .await??;
            self.guard_stream = Some(guard_stream_after_wait);
        }

        let orch_stream_after_wait = timeout(ready_timeout, async {
            let ready_signal = "ORCHESTRATION_RPC_LISTENING_ON_0.0.0.0:9999";
            while let Some(Ok(log)) = orch_stream.next().await {
                if log.contains(ready_signal) {
                    return Ok(orch_stream);
                }
            }
            Err(anyhow!("Orchestration did not become ready in time"))
        })
        .await??;

        self.orch_stream = Some(orch_stream_after_wait);
        Ok(())
    }

    fn get_addresses(&self) -> (String, Multiaddr) {
        (self.rpc_addr.clone(), self.p2p_addr.clone())
    }

    fn get_log_streams(&mut self) -> Result<(LogStream, LogStream, Option<LogStream>)> {
        let orch = self
            .orch_stream
            .take()
            .ok_or_else(|| anyhow!("Orchestration stream already taken"))?;
        let work = self
            .work_stream
            .take()
            .ok_or_else(|| anyhow!("Workload stream already taken"))?;
        let guard = self.guard_stream.take();
        Ok((orch, work, guard))
    }

    async fn cleanup(&mut self) -> Result<()> {
        let futures = self.container_ids.iter().map(|id| {
            let docker = self.docker.clone();
            let id = id.clone();
            async move {
                docker
                    .stop_container(
                        &id,
                        Some(StopContainerOptionsBuilder::default().t(5).build()),
                    )
                    .await
                    .ok();
                docker
                    .remove_container(
                        &id,
                        Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                    )
                    .await
                    .ok();
            }
        });
        futures_util::future::join_all(futures).await;

        self.docker.remove_network(&self.network_id).await?;
        Ok(())
    }

    async fn restart_workload_process(
        &mut self,
        _log_tx: broadcast::Sender<String>,
        _log_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    ) -> Result<()> {
        Err(anyhow!(
            "Restarting a single container is not supported in the Docker backend"
        ))
    }

    async fn kill_workload_process(&mut self) -> Result<()> {
        Err(anyhow!(
            "Killing single container not supported in the Docker backend"
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}