// crates/forge/src/testing/backend.rs

use super::{ensure_docker_image_exists, DOCKER_BUILD_CHECK, DOCKER_IMAGE_TAG};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bollard::container::{
    Config, CreateContainerOptions, LogsOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::models::HostConfig;
use bollard::network::CreateNetworkOptions;
use bollard::Docker;
use futures_util::stream::{self, Stream, StreamExt};
use libp2p::Multiaddr;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncBufReadExt;
use tokio::process::Child;
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
}

// --- ProcessBackend Implementation ---
pub struct ProcessBackend {
    pub orchestration_process: Option<Child>,
    pub workload_process: Option<Child>,
    pub guardian_process: Option<Child>,
    pub rpc_addr: String,
    pub p2p_addr: Multiaddr,
}

impl ProcessBackend {
    pub fn new(rpc_addr: String, p2p_addr: Multiaddr) -> Self {
        Self {
            orchestration_process: None,
            workload_process: None,
            guardian_process: None,
            rpc_addr,
            p2p_addr,
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
}

// --- DockerBackend Implementation ---

/// Backend that launches validator components as Docker containers.
pub struct DockerBackend {
    docker: Docker,
    network_id: String,
    container_ids: Vec<String>,
    rpc_addr: String,
    p2p_addr: Multiaddr,
    semantic_model_path: Option<PathBuf>,
    _temp_dir: Arc<TempDir>,
    _keypair_path: PathBuf,
    _genesis_path: PathBuf,
    config_dir_path: PathBuf,
    orch_stream: Option<LogStream>,
    work_stream: Option<LogStream>,
    guard_stream: Option<LogStream>,
}

impl DockerBackend {
    pub async fn new(
        rpc_addr: String,
        p2p_addr: Multiaddr,
        semantic_model_path: Option<PathBuf>,
        temp_dir: Arc<TempDir>,
        keypair_path: PathBuf,
        genesis_path: PathBuf,
        config_dir_path: PathBuf,
    ) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()?;
        let network_name = format!("depin-e2e-{}", uuid::Uuid::new_v4());
        let network = docker
            .create_network(CreateNetworkOptions {
                name: network_name,
                ..Default::default()
            })
            .await?;
        let network_id = network.id.ok_or(anyhow!("Failed to create network"))?;

        Ok(Self {
            docker,
            network_id,
            container_ids: Vec::new(),
            rpc_addr,
            p2p_addr,
            semantic_model_path,
            _temp_dir: temp_dir,
            _keypair_path: keypair_path,
            _genesis_path: genesis_path,
            config_dir_path,
            orch_stream: None,
            work_stream: None,
            guard_stream: None,
        })
    }

    async fn launch_container<'a>(
        &mut self,
        name: &str,
        cmd: Vec<&'a str>,
        env: Vec<&'a str>,
        binds: Vec<String>,
    ) -> Result<()> {
        let options = Some(CreateContainerOptions {
            name: name.to_string(),
            ..Default::default()
        });
        let host_config = HostConfig {
            network_mode: Some(self.network_id.clone()),
            binds: Some(binds),
            ..Default::default()
        };
        let config: Config<&str> = Config {
            image: Some(DOCKER_IMAGE_TAG),
            cmd: Some(cmd),
            env: Some(env),
            host_config: Some(host_config),
            ..Default::default()
        };

        let id = self.docker.create_container(options, config).await?.id;
        self.docker.start_container::<String>(&id, None).await?;
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

        let container_config_dir = "/tmp/test-data/config";
        let container_genesis_path = "/tmp/test-data/genesis.json";
        let container_state_path = "/tmp/test-data/state.json";

        let base_binds = vec![format!(
            "{}:/tmp/test-data",
            self.config_dir_path.parent().unwrap().to_string_lossy()
        )];

        if let Some(model_path) = &self.semantic_model_path {
            let model_dir = model_path.parent().unwrap().to_string_lossy();
            let model_file_name = model_path.file_name().unwrap().to_string_lossy();
            let container_model_path = format!("/models/{}", model_file_name);
            let mut guardian_binds = base_binds.clone();
            guardian_binds.push(format!("{}:/models", model_dir));

            let guardian_cmd = vec![
                "guardian",
                "--config-dir",
                container_config_dir,
                "--semantic-model-path",
                &container_model_path,
            ];
            let guardian_env = vec![];
            self.launch_container("guardian", guardian_cmd, guardian_env, guardian_binds)
                .await?;
        }
        let workload_cmd = vec![
            "workload",
            "--genesis-file",
            container_genesis_path,
            "--state-file",
            "/tmp/test-data/workload_state.json",
        ];
        let mut workload_env = vec!["IPC_SERVER_ADDR=0.0.0.0:8555"];
        if self.semantic_model_path.is_some() {
            workload_env.push("GUARDIAN_ADDR=guardian:8443");
        }
        self.launch_container("workload", workload_cmd, workload_env, base_binds.clone())
            .await?;

        let orch_cmd = vec![
            "orchestration",
            "--state-file",
            container_state_path,
            "--config-dir",
            container_config_dir,
            "--listen-address",
            "/ip4/0.0.0.0/tcp/9000",
            "--rpc-listen-address",
            "0.0.0.0:9999",
        ];
        let mut orch_env = vec!["WORKLOAD_IPC_ADDR=workload:8555"];
        if self.semantic_model_path.is_some() {
            orch_env.push("GUARDIAN_ADDR=guardian:8443");
        }
        self.launch_container("orchestration", orch_cmd, orch_env, base_binds)
            .await?;

        let ready_timeout = Duration::from_secs(45);
        let log_options = Some(LogsOptions::<String> {
            follow: true,
            stderr: true,
            stdout: true,
            ..Default::default()
        });

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

        if self.semantic_model_path.is_some() {
            let mut guard_stream = convert_stream(self.docker.logs("guardian", log_options));
            timeout(ready_timeout, async {
                while let Some(Ok(log)) = guard_stream.next().await {
                    if log.contains("Guardian container started (mock).") {
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
                    .stop_container(&id, Some(StopContainerOptions { t: 5 }))
                    .await
                    .ok();
                docker
                    .remove_container(
                        &id,
                        Some(RemoveContainerOptions {
                            force: true,
                            ..Default::default()
                        }),
                    )
                    .await
                    .ok();
            }
        });
        futures_util::future::join_all(futures).await;

        self.docker.remove_network(&self.network_id).await?;
        Ok(())
    }
}
