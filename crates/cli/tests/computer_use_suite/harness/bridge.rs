use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::process::{Child, Command};
use tokio::time::sleep;

use super::support::repo_root;
use super::workflow_backend::{WorkflowBridgeClient, WorkflowBridgeProcess};
use crate::computer_use_suite::types::{BridgeState, ComputerUseCase, SuiteConfig, TaskSet};

#[derive(Debug, Deserialize)]
pub(super) struct BridgeCreateResponse {
    pub session_id: String,
    pub url: String,
    pub state: BridgeState,
}

#[derive(Clone)]
pub(super) enum BridgeClient {
    Miniwob { http: Client, base_url: String },
    Workflow(WorkflowBridgeClient),
}

impl BridgeClient {
    fn new_miniwob(base_url: String) -> Result<Self> {
        Ok(Self::Miniwob {
            http: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .context("build bridge client")?,
            base_url,
        })
    }

    async fn health(&self) -> Result<Value> {
        match self {
            Self::Miniwob { http, base_url } => {
                let response = http
                    .get(format!("{}/health", base_url))
                    .send()
                    .await
                    .context("bridge health request")?
                    .error_for_status()
                    .context("bridge health status")?;
                Ok(response
                    .json::<Value>()
                    .await
                    .context("bridge health json")?)
            }
            Self::Workflow(_) => Ok(json!({ "ok": true })),
        }
    }

    pub(super) async fn create_session(
        &self,
        case: &ComputerUseCase,
    ) -> Result<BridgeCreateResponse> {
        match self {
            Self::Miniwob { http, base_url } => {
                let response = http
                    .post(format!("{}/session/create", base_url))
                    .json(&json!({
                        "env_id": &case.env_id,
                        "seed": case.seed,
                        "data_mode": "train",
                    }))
                    .send()
                    .await
                    .context("bridge create session")?
                    .error_for_status()
                    .context("bridge create session status")?;
                response
                    .json::<BridgeCreateResponse>()
                    .await
                    .context("bridge create session json")
            }
            Self::Workflow(client) => {
                let response = client.create_session(case).await?;
                Ok(BridgeCreateResponse {
                    session_id: response.session_id,
                    url: response.url,
                    state: response.state,
                })
            }
        }
    }

    pub(super) async fn state(&self, session_id: &str) -> Result<BridgeState> {
        match self {
            Self::Miniwob { http, base_url } => {
                let response = http
                    .get(format!("{}/session/{}/state", base_url, session_id))
                    .send()
                    .await
                    .context("bridge state request")?
                    .error_for_status()
                    .context("bridge state status")?;
                response
                    .json::<BridgeState>()
                    .await
                    .context("bridge state json")
            }
            Self::Workflow(client) => client.state(session_id).await,
        }
    }

    pub(super) async fn close(&self, session_id: &str) -> Result<()> {
        match self {
            Self::Miniwob { http, base_url } => {
                let _ = http
                    .post(format!("{}/session/{}/close", base_url, session_id))
                    .json(&json!({}))
                    .send()
                    .await
                    .context("bridge close session request")?;
                Ok(())
            }
            Self::Workflow(client) => client.close(session_id).await,
        }
    }
}

pub(super) enum BridgeProcess {
    Miniwob {
        child: Child,
        client: BridgeClient,
        _log_dir: tempfile::TempDir,
    },
    Workflow(WorkflowBridgeProcess),
}

fn tail_log(path: &PathBuf) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let lines = contents.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(40);
    let tail = lines[start..].join("\n").trim().to_string();
    (!tail.is_empty()).then_some(tail)
}

fn bridge_startup_error(
    summary: &str,
    stdout_path: &PathBuf,
    stderr_path: &PathBuf,
    exit_status: Option<ExitStatus>,
) -> anyhow::Error {
    let mut details = vec![format!("ERROR_CLASS=bridge_startup_failure {}", summary)];
    if let Some(status) = exit_status {
        details.push(format!("bridge_exit_status={status}"));
    }
    details.push(format!("bridge_stdout_log={}", stdout_path.display()));
    details.push(format!("bridge_stderr_log={}", stderr_path.display()));
    if let Some(stderr_tail) = tail_log(stderr_path) {
        details.push(format!("bridge_stderr_tail:\n{stderr_tail}"));
    }
    if let Some(stdout_tail) = tail_log(stdout_path) {
        details.push(format!("bridge_stdout_tail:\n{stdout_tail}"));
    }
    anyhow!(details.join("\n"))
}

impl BridgeProcess {
    pub(super) async fn start(config: &SuiteConfig) -> Result<Self> {
        if matches!(
            config.task_set,
            TaskSet::Workflow
                | TaskSet::WorkflowRich
                | TaskSet::WorkflowAudit
                | TaskSet::WorkflowMutation
                | TaskSet::WorkflowReorder
        ) {
            return Ok(Self::Workflow(WorkflowBridgeProcess::start().await?));
        }

        let port =
            portpicker::pick_unused_port().ok_or_else(|| anyhow!("no unused port for bridge"))?;
        let base_url = format!("http://127.0.0.1:{}", port);
        let mut command = Command::new(&config.python_bin);
        command
            .arg("tools/miniwob/bridge.py")
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .kill_on_drop(true)
            .current_dir(repo_root());
        if let Some(source_dir) = &config.bridge_source_dir {
            command.env("COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR", source_dir);
        }
        let log_dir = tempdir().context("create MiniWoB bridge log dir")?;
        let stdout_path = log_dir.path().join("stdout.log");
        let stderr_path = log_dir.path().join("stderr.log");
        let stdout = fs::File::create(&stdout_path).context("create MiniWoB bridge stdout log")?;
        let stderr = fs::File::create(&stderr_path).context("create MiniWoB bridge stderr log")?;
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut child = command.spawn().context("spawn MiniWoB bridge")?;
        let client = BridgeClient::new_miniwob(base_url)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().context("poll MiniWoB bridge status")? {
                return Err(bridge_startup_error(
                    "MiniWoB bridge exited before responding to health checks",
                    &stdout_path,
                    &stderr_path,
                    Some(status),
                ));
            }
            match client.health().await {
                Ok(_) => break,
                Err(err) => {
                    if Instant::now() >= deadline {
                        return Err(bridge_startup_error(
                            &format!("MiniWoB bridge did not become healthy within 10s: {}", err),
                            &stdout_path,
                            &stderr_path,
                            None,
                        ));
                    }
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Ok(Self::Miniwob {
            child,
            client,
            _log_dir: log_dir,
        })
    }

    pub(super) fn client(&self) -> BridgeClient {
        match self {
            Self::Miniwob { client, .. } => client.clone(),
            Self::Workflow(process) => BridgeClient::Workflow(process.client()),
        }
    }

    pub(super) async fn stop(&mut self) {
        match self {
            Self::Miniwob { child, .. } => {
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
            Self::Workflow(process) => process.stop().await,
        }
    }
}
