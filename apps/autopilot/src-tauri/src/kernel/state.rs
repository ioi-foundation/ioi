use crate::models::{AgentPhase, AgentTask, AppState, ChatMessage};
use crate::orchestrator;
use hex;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
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
    let session_id_bytes = hex::decode(session_id_hex).map_err(|e| e.to_string())?;

    let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
    let state_prefix = b"agent::state::";

    let key = [
        ns_prefix.as_slice(),
        state_prefix,
        &session_id_bytes,
    ]
    .concat();

    let req = tonic::Request::new(QueryRawStateRequest { key });

    let resp = client
        .query_raw_state(req)
        .await
        .map_err(|e| e.to_string())?
        .into_inner();

    if resp.found && !resp.value.is_empty() {
        return Ok(vec![ChatMessage {
            role: "system".to_string(),
            text: "Session history is archived in SCS (Offline Hydration pending).".to_string(),
            timestamp: now(),
        }]);
    }

    Ok(vec![])
}