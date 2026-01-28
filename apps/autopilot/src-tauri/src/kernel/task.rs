// apps/autopilot/src-tauri/src/kernel/task.rs
use crate::kernel::state::{get_rpc_client, now, update_task_state};
use crate::models::{AgentPhase, AgentTask, AppState, ChatMessage, SessionSummary};
use crate::orchestrator;
use crate::windows;
use ioi_ipc::public::{DraftTransactionRequest, SubmitTransactionRequest};
use ioi_ipc::public::public_api_client::PublicApiClient;
use std::collections::HashSet;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};

#[tauri::command]
pub fn start_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    intent: String,
    mode: String, 
) -> Result<AgentTask, String> {
    let history = vec![ChatMessage {
        role: "user".to_string(),
        text: intent.clone(),
        timestamp: now(),
    }];

    let task_id = uuid::Uuid::new_v4().to_string();
    
    // We treat task_id as session_id for local context unless provided otherwise
    let task = AgentTask {
        id: task_id.clone(),
        session_id: Some(task_id.clone()),
        intent: intent.clone(),
        agent: if mode == "Chat" { "Chat Assistant".to_string() } else { "General Agent".to_string() },
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 10,
        current_step: "Initializing...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None, 
        pending_request_hash: None,
        history, 
        processed_steps: HashSet::new(), 
        swarm_tree: Vec::new(), 
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };

    let mut scs_handle = None;

    {
        let mut app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.current_task = Some(task.clone());
        app_state.gate_response = None;
        scs_handle = app_state.studio_scs.clone();
    }

    // Persist Initial Session State Locally
    if let Some(scs) = scs_handle {
        let summary = SessionSummary {
            session_id: task_id.clone(),
            title: if intent.len() > 30 { format!("{}...", &intent[0..27]) } else { intent.clone() },
            timestamp: now(),
        };
        orchestrator::save_local_session_summary(&scs, summary);
        orchestrator::save_local_task_state(&scs, &task);
    }

    let _ = app.emit("task-started", &task);
    
    windows::show_pill(app.clone());

    let app_clone = app.clone();
    let intent_clone = intent.clone();
    
    let effective_intent = if mode == "Chat" {
        format!("MODE:CHAT {}", intent_clone)
    } else {
        // Prepend SESSION:<hex_id> so IntentResolver can extract it
        // This ensures the backend uses THIS session ID instead of generating a new one
        let session_hex = hex::encode(uuid::Uuid::parse_str(&task_id).unwrap().as_bytes());
        format!("SESSION:{} {}", session_hex, intent_clone)
    };

    // Async submission to Kernel
    tauri::async_runtime::spawn(async move {
        let mut client = match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[Autopilot] Kernel offline: {}", e);
                update_task_state(&app_clone, |t| {
                    t.current_step = "Kernel Unreachable. Simulating offline response...".to_string();
                });
                return;
            }
        };

        let draft_req = tonic::Request::new(DraftTransactionRequest {
            intent: effective_intent,
            address_book: Default::default(),
        });

        match client.draft_transaction(draft_req).await {
            Ok(resp) => {
                let draft = resp.into_inner();
                let submit_req = tonic::Request::new(SubmitTransactionRequest {
                    transaction_bytes: draft.transaction_bytes,
                });

                if let Err(e) = client.submit_transaction(submit_req).await {
                    update_task_state(&app_clone, |t| {
                        t.phase = AgentPhase::Failed;
                        t.current_step = format!("Submission Error: {}", e);
                    });
                }
            }
            Err(e) => {
                update_task_state(&app_clone, |t| {
                    t.phase = AgentPhase::Failed;
                    t.current_step = format!("Drafting Error: {}", e);
                });
            }
        }
    });

    Ok(task)
}

#[tauri::command]
pub fn update_task(_state: State<Mutex<AppState>>, app: AppHandle, task: AgentTask) -> Result<(), String> {
    update_task_state(&app, |t| *t = task.clone());
    Ok(())
}

#[tauri::command]
pub fn complete_task(_state: State<Mutex<AppState>>, app: AppHandle, success: bool) -> Result<(), String> {
    update_task_state(&app, |t| {
        t.phase = if success { AgentPhase::Complete } else { AgentPhase::Failed };
    });
    Ok(())
}

#[tauri::command]
pub fn dismiss_task(state: State<Mutex<AppState>>, app: AppHandle) -> Result<(), String> {
    if let Ok(mut app_state) = state.lock() {
        app_state.current_task = None;
        app_state.gate_response = None;
    }
    windows::hide_pill(app.clone());
    windows::hide_gate(app.clone());
    let _ = app.emit("task-dismissed", ());
    Ok(())
}

#[tauri::command]
pub fn get_current_task(state: State<Mutex<AppState>>) -> Option<AgentTask> {
    state.lock().ok().and_then(|s| s.current_task.clone())
}