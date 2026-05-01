use crate::models::{AgentPhase, AgentTask, AppState, ChatMessage};
use crate::orchestrator;
use hex;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::GetSessionHistoryRequest;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use tonic::transport::{Channel, Endpoint};
use url::Url;

const DEFAULT_KERNEL_RPC_URL: &str = "http://127.0.0.1:9000";
const DEFAULT_KERNEL_RPC_CONNECT_TIMEOUT_MS: u64 = 1200;
const LOCAL_DEV_RPC_CONNECT_RETRIES: usize = 8;
const LOCAL_DEV_RPC_CONNECT_RETRY_DELAY_MS: u64 = 350;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRpcTarget {
    pub url: String,
    pub source_label: String,
    pub configured: bool,
    pub remote_hint: bool,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn update_task_state<F>(app: &AppHandle, mut f: F)
where
    F: FnMut(&mut AgentTask),
{
    let state = app.state::<Mutex<AppState>>();
    let mut task_clone: Option<AgentTask> = None;
    let mut memory_runtime = None;

    if let Ok(mut s) = state.lock() {
        memory_runtime = s.memory_runtime.clone();
        if let Some(ref mut task) = s.current_task {
            f(task);
            if let Some(runtime) = memory_runtime.as_ref() {
                if let Err(error) =
                    crate::kernel::runtime_parity::sync_planning_artifacts(app, runtime, task)
                {
                    eprintln!("[Autopilot] Failed to sync planning artifacts: {}", error);
                }
            }
            task.sync_runtime_views();
            task_clone = Some(task.clone());
        }
    }

    if let Some(t) = task_clone {
        // Persist task state on important updates
        if let Some(memory_runtime) = memory_runtime.as_ref() {
            orchestrator::save_local_task_state(memory_runtime, &t);
        }

        let event_name = if t.phase == AgentPhase::Complete
            && !crate::kernel::events::is_waiting_prompt_active(&t)
        {
            "task-completed"
        } else {
            "task-updated"
        };
        let _ = app.emit(event_name, &t);
        let app_clone = app.clone();
        let refresh_history =
            t.phase == AgentPhase::Complete && !crate::kernel::events::is_waiting_prompt_active(&t);
        tauri::async_runtime::spawn(async move {
            crate::kernel::session::emit_session_projection_update(&app_clone, refresh_history)
                .await;
        });
    }
}

pub async fn get_rpc_client(
    state: &State<'_, Mutex<AppState>>,
) -> Result<PublicApiClient<Channel>, String> {
    let cached_client = {
        let s = state.lock().map_err(|_| "Failed to lock state")?;
        s.rpc_client.clone()
    };

    if let Some(c) = cached_client {
        Ok(c)
    } else {
        let new_client = connect_public_api().await?;

        {
            if let Ok(mut s) = state.lock() {
                if s.rpc_client.is_none() {
                    s.rpc_client = Some(new_client.clone());
                }
            }
        }
        Ok(new_client)
    }
}

pub fn kernel_rpc_target() -> KernelRpcTarget {
    if let Ok(explicit_url) = std::env::var("AUTOPILOT_KERNEL_RPC_URL") {
        let trimmed = explicit_url.trim();
        if !trimmed.is_empty() {
            let url = normalize_kernel_rpc_url(trimmed);
            return KernelRpcTarget {
                remote_hint: kernel_rpc_target_is_remote(&url),
                url,
                source_label: "AUTOPILOT_KERNEL_RPC_URL".to_string(),
                configured: true,
            };
        }
    }

    if let Ok(listen_addr) = std::env::var("ORCHESTRATION_RPC_LISTEN_ADDRESS") {
        let trimmed = listen_addr.trim();
        if !trimmed.is_empty() {
            let url = format!("http://{}", kernel_rpc_client_authority(trimmed));
            return KernelRpcTarget {
                remote_hint: kernel_rpc_target_is_remote(&url),
                url,
                source_label: "ORCHESTRATION_RPC_LISTEN_ADDRESS".to_string(),
                configured: true,
            };
        }
    }

    let url = DEFAULT_KERNEL_RPC_URL.to_string();
    KernelRpcTarget {
        remote_hint: kernel_rpc_target_is_remote(&url),
        url,
        source_label: "Default localhost kernel".to_string(),
        configured: false,
    }
}

pub fn kernel_rpc_url() -> String {
    kernel_rpc_target().url
}

pub async fn connect_public_api() -> Result<PublicApiClient<Channel>, String> {
    let rpc_url = kernel_rpc_url();
    let retries = if should_retry_kernel_connect() {
        LOCAL_DEV_RPC_CONNECT_RETRIES
    } else {
        1
    };

    let mut last_error = None;
    for attempt in 0..retries {
        let endpoint = Endpoint::from_shared(rpc_url.clone())
            .map_err(|error| format!("Invalid Kernel RPC URL '{}': {}", rpc_url, error))?
            .connect_timeout(std::time::Duration::from_millis(
                DEFAULT_KERNEL_RPC_CONNECT_TIMEOUT_MS,
            ));

        match endpoint.connect().await {
            Ok(channel) => return Ok(PublicApiClient::new(channel)),
            Err(error) => {
                last_error = Some(error.to_string());
                if attempt + 1 < retries {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        LOCAL_DEV_RPC_CONNECT_RETRY_DELAY_MS,
                    ))
                    .await;
                }
            }
        }
    }

    Err(format!(
        "Failed to connect to Kernel: {}",
        last_error.unwrap_or_else(|| "transport error".to_string())
    ))
}

fn should_retry_kernel_connect() -> bool {
    if crate::is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV") {
        return true;
    }

    matches!(
        std::env::var("AUTOPILOT_DATA_PROFILE")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("desktop-localgpu")
    )
}

fn normalize_kernel_rpc_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    format!("http://{}", kernel_rpc_client_authority(trimmed))
}

fn kernel_rpc_client_authority(raw: &str) -> String {
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        let normalized_ip = match addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        return SocketAddr::new(normalized_ip, addr.port()).to_string();
    }

    raw.to_string()
}

fn kernel_rpc_target_is_remote(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };

    let Some(host) = url
        .host_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };

    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }

    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);

    host.parse::<IpAddr>()
        .map(|ip| !ip.is_loopback())
        .unwrap_or(true)
}

fn normalize_kernel_history_message(role: String, content: String, timestamp: u64) -> ChatMessage {
    if role == "tool" {
        let trimmed = content.trim();
        if trimmed.len() >= "replied:".len()
            && trimmed[.."replied:".len()].eq_ignore_ascii_case("replied:")
        {
            let reply = trimmed["replied:".len()..].trim();
            if !reply.is_empty() {
                return ChatMessage {
                    role: "agent".to_string(),
                    text: reply.to_string(),
                    timestamp,
                };
            }
        }
    }

    ChatMessage {
        role,
        text: content,
        timestamp,
    }
}

pub async fn hydrate_session_history(
    client: &mut PublicApiClient<Channel>,
    session_id_hex: &str,
) -> Result<Vec<ChatMessage>, String> {
    let normalized_session = session_id_hex
        .trim()
        .trim_start_matches("0x")
        .replace('-', "");
    let _ = hex::decode(&normalized_session).map_err(|e| e.to_string())?;

    let req = tonic::Request::new(GetSessionHistoryRequest {
        session_id_hex: normalized_session,
        limit: 0,
        ascending: true,
    });

    let resp = client
        .get_session_history(req)
        .await
        .map_err(|e| e.to_string())?
        .into_inner();

    Ok(resp
        .messages
        .into_iter()
        .map(|m| {
            let timestamp = if m.timestamp == 0 { now() } else { m.timestamp };
            normalize_kernel_history_message(m.role, m.content, timestamp)
        })
        .collect())
}

#[cfg(test)]
#[path = "state/tests.rs"]
mod tests;
