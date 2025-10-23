// Path: crates/forge/src/testing/backend.rs

use super::{ensure_docker_image_exists, DOCKER_BUILD_CHECK, DOCKER_IMAGE_TAG};
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
use depin_sdk_validator::common::generate_certificates_if_needed;
use futures_util::stream::{self, Stream, StreamExt};
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
use tokio::time::timeout;

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
    // [+] Store paths needed for restart
    binary_path: PathBuf,
    workload_config_path: PathBuf,
    workload_ipc_addr: String,
    certs_dir_path: PathBuf,
}

impl ProcessBackend {
    // [+] Update constructor signature
    pub fn new(
        rpc_addr: String,
        p2p_addr: Multiaddr,
        binary_path: PathBuf,
        workload_config_path: PathBuf,
        workload_ipc_addr: String,
        certs_dir_path: PathBuf,
    ) -> Self {
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

    // [+] Add the restart method here, in its proper home.
    pub async fn restart_workload_process(&mut self) -> Result<()> {
        if self.workload_process.is_some() {
            return Err(anyhow!("Workload process is already running."));
        }

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

        self.workload_process = Some(workload_cmd.spawn()?);
        Ok(())
    }
}

#[async_trait]
impl TestBackend for ProcessBackend {
    async fn launch(&mut self) -> Result<()> {
        // The actual process spawning is handled in TestValidator::launch
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

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// --- DockerBackend Implementation ---

/// Configuration struct to hold parameters for initializing the DockerBackend.
pub struct DockerBackendConfig {
    pub rpc_addr: String,
    pub p2p_addr: Multiaddr,
    pub agentic_model_path: Option<PathBuf>,
    pub temp_dir: Arc<TempDir>,
    pub config_dir_path: PathBuf,
    pub certs_dir_path: PathBuf,
}

/// Backend that launches validator components as Docker containers.
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
        let network_name = format!("depin-e2e-{}", uuid::Uuid::new_v4());
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

        // Define paths as they will appear inside the containers
        let container_data_dir = "/tmp/test-data";
        let container_certs_dir = "/tmp/certs";
        let container_workload_config = "/tmp/test-data/workload.toml";
        let container_orch_config = "/tmp/test-data/orchestration.toml";
        let container_identity_key = "/tmp/test-data/identity.key";

        // Base volume mount for all generated configs and keys
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

            let guardian_env: Vec<String> = vec![certs_env_str.clone()];
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

        let mut orch_stream =
            convert_stream(self.docker.logs("orchestration", log_options.clone()));
        self.work_stream = Some(convert_stream(
            self.docker.logs("workload", log_options.clone()),
        ));

        if self.agentic_model_path.is_some() {
            let mut guard_stream = convert_stream(self.docker.logs("guardian", log_options));
            timeout(ready_timeout, async {
                while let Some(Ok(log)) = guard_stream.next().await {
                    if log.contains("Guardian container started") {
                        return Ok(());
                    }
                }
                Err(anyhow!("Guardian did not become ready in time"))
            })
            .await??;
            self.guard_stream = Some(guard_stream);
        }

        timeout(ready_timeout, async {
            let ready_signal = "ORCHESTRATION_RPC_LISTENING_ON_0.0.0.0:9999";
            while let Some(Ok(log)) = orch_stream.next().await {
                if log.contains(ready_signal) {
                    return Ok(());
                }
            }
            Err(anyhow!("Orchestration did not become ready in time"))
        })
        .await??;

        self.orch_stream = Some(orch_stream);
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

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
