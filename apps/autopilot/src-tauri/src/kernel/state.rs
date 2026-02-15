use crate::models::{AgentPhase, AgentTask, AppState, ChatMessage};
use crate::orchestrator;
use hex;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::GetSessionHistoryRequest;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use tonic::transport::Channel;

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
    let mut scs_handle = None;

    if let Ok(mut s) = state.lock() {
        scs_handle = s.studio_scs.clone();
        if let Some(ref mut task) = s.current_task {
            f(task);
            task_clone = Some(task.clone());
        }
    }

    if let Some(t) = task_clone {
        // Persist task state on important updates
        if let Some(scs) = scs_handle {
            orchestrator::save_local_task_state(&scs, &t);
        }

        let event_name = match t.phase {
            AgentPhase::Complete => "task-completed",
            _ => "task-updated",
        };
        let _ = app.emit(event_name, &t);
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
        // Default to local kernel port
        let channel = Channel::from_static("http://127.0.0.1:9000")
            .connect()
            .await
            .map_err(|e| format!("Failed to connect to Kernel: {}", e))?;
        let new_client = PublicApiClient::new(channel);

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
        .map(|m| ChatMessage {
            role: m.role,
            text: m.content,
            timestamp: if m.timestamp == 0 { now() } else { m.timestamp },
        })
        .collect())
}
