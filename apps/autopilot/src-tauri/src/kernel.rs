// apps/autopilot/src-tauri/src/kernel.rs

use crate::models::*;
use crate::windows; 
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::{HashSet, HashMap};
use tauri::{AppHandle, Emitter, Manager, State};

// Import local modules
use crate::execution;
use crate::orchestrator::{self, GraphPayload};

// Kernel Integration
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    DraftTransactionRequest, GetContextBlobRequest,
    SubmitTransactionRequest, SubscribeEventsRequest,
    chain_event::Event as ChainEventEnum
};
use ioi_ipc::blockchain::QueryRawStateRequest;
use tonic::transport::Channel;

// Crypto & Types
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_types::app::action::{ApprovalToken, ApprovalScope}; 
use ioi_types::app::SignatureSuite;
use ioi_types::app::agentic::ResumeAgentParams;
use ioi_types::app::{ChainTransaction, SignHeader, SignatureProof, SystemPayload, SystemTransaction};
use ioi_types::app::{AccountId, ChainId, account_id_from_key_material}; 
use ioi_types::codec;
use ioi_types::app::agentic::LlmToolDefinition;

// [NEW] Imports for Inference Runtime Setup
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn update_task_state<F>(app: &AppHandle, mut f: F)
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

async fn get_rpc_client(state: &State<'_, Mutex<AppState>>) -> Result<PublicApiClient<Channel>, String> {
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

async fn hydrate_session_history(
    client: &mut PublicApiClient<Channel>,
    session_id_hex: &str,
) -> Result<Vec<ChatMessage>, String> {
    let session_id_bytes = hex::decode(session_id_hex).map_err(|e| e.to_string())?;
    
    let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
    let state_prefix = b"agent::state::"; 
    
    let key = [ns_prefix.as_slice(), state_prefix, &session_id_bytes].concat();

    let req = tonic::Request::new(QueryRawStateRequest { key });

    let resp = client.query_raw_state(req).await.map_err(|e| e.to_string())?.into_inner();

    if resp.found && !resp.value.is_empty() {
        return Ok(vec![ChatMessage {
            role: "system".to_string(),
            text: "Session history is archived in SCS (Offline Hydration pending).".to_string(),
            timestamp: now(),
        }]);
    }

    Ok(vec![])
}

// -------------------------------------------------------------------------
// Exposed Commands
// -------------------------------------------------------------------------

#[tauri::command]
pub async fn run_studio_graph(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    payload: GraphPayload,
) -> Result<(), String> {
    println!("[Studio] Received Graph with {} nodes. Starting local execution...", payload.nodes.len());
    
    let (scs, inference) = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        let s = guard.studio_scs.clone().ok_or("Studio SCS not initialized")?;
        let i = guard.inference_runtime.clone().ok_or("Inference runtime not initialized")?;
        (s, i)
    };

    let app_handle = app.clone();
    
    tauri::async_runtime::spawn(async move {
        // [MODIFIED] Pass inference to run_local_graph
        let result = orchestrator::run_local_graph(scs, inference, payload, move |event| {
            let _ = app_handle.emit("graph-event", event);
        }).await;

        if let Err(e) = result {
            eprintln!("[Studio] Orchestrator Runtime Error: {}", e);
        } else {
            println!("[Studio] Graph execution completed successfully.");
        }
    });

    Ok(())
}

#[tauri::command]
pub async fn test_node_execution(
    state: State<'_, Mutex<AppState>>,
    node_type: String,
    config: serde_json::Value,
    input: serde_json::Value,
    node_id: Option<String>,
    session_id: Option<String>,
) -> Result<serde_json::Value, String> {
    println!("[Studio] Running Ephemeral Execution: {} (Session: {:?})", node_type, session_id);

    // [MODIFIED] Unwrap both SCS and InferenceRuntime
    let (scs, inference) = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        let s = guard.studio_scs.clone().ok_or("Studio SCS not initialized")?;
        let i = guard.inference_runtime.clone().ok_or("Inference runtime not initialized")?;
        (s, i)
    };

    let input_str = if let Some(s) = input.as_str() { s.to_string() } else { input.to_string() };

    // [MODIFIED] Pass arguments to execution
    match execution::execute_ephemeral_node(
        &node_type, 
        &config, 
        &input_str, 
        session_id, 
        scs.clone(), 
        inference
    ).await {
        Ok(result) => {
            if result.status == "success" {
                if let Some(nid) = node_id {
                    orchestrator::inject_execution_result(&scs, nid, config, input_str, result.clone());
                }
            }
            serde_json::to_value(result).map_err(|e| e.to_string())
        },
        Err(e) => {
            eprintln!("[Studio] Execution Error: {}", e);
            Ok(serde_json::json!({
                "status": "error",
                "output": format!("Execution Logic Failed: {}", e),
                "data": null,
                "metrics": { "latency_ms": 0 }
            }))
        }
    }
}

#[tauri::command]
pub async fn check_node_cache(
    state: State<'_, Mutex<AppState>>,
    node_id: String,
    config: serde_json::Value,
    input: String,
) -> Result<Option<execution::ExecutionResult>, String> {
    let scs = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        guard.studio_scs.clone().ok_or("Studio SCS not initialized")?
    };

    Ok(orchestrator::query_cache(&scs, node_id, config, input))
}

#[tauri::command]
pub async fn get_available_tools() -> Result<Vec<LlmToolDefinition>, String> {
    Ok(execution::get_active_mcp_tools().await)
}

// --- Session Management ---

#[tauri::command]
pub async fn get_session_history(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<SessionSummary>, String> {
    let mut all_sessions = Vec::new();

    // 1. Fetch Local Sessions from SCS
    if let Ok(guard) = state.lock() {
        if let Some(scs) = &guard.studio_scs {
            let local_sessions = orchestrator::get_local_sessions(scs);
            all_sessions.extend(local_sessions);
        }
    }

    // 2. Fetch Remote Sessions from Kernel (if connected)
    match get_rpc_client(&state).await {
        Ok(mut client) => {
            let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
            let key = [ns_prefix.as_slice(), b"agent::history"].concat();
            let req = tonic::Request::new(QueryRawStateRequest { key });
            
            if let Ok(resp) = client.query_raw_state(req).await {
                let inner = resp.into_inner();
                if inner.found && !inner.value.is_empty() {
                    if let Ok(raw_history) = codec::from_bytes_canonical::<Vec<ioi_services::agentic::desktop::types::SessionSummary>>(&inner.value) {
                        let remote_sessions: Vec<SessionSummary> = raw_history.into_iter().map(|s| SessionSummary {
                            session_id: hex::encode(s.session_id),
                            title: s.title,
                            timestamp: s.timestamp,
                        }).collect();
                        
                        // Merge avoiding duplicates (prefer remote if duplicate)
                        for r in remote_sessions {
                            if let Some(pos) = all_sessions.iter().position(|l| l.session_id == r.session_id) {
                                all_sessions[pos] = r;
                            } else {
                                all_sessions.push(r);
                            }
                        }
                    }
                }
            }
        },
        Err(e) => {
            eprintln!("[Kernel] RPC client unavailable for history: {}", e);
        }
    }

    // 3. Sort Descending
    all_sessions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok(all_sessions)
}

#[tauri::command]
pub async fn load_session(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
) -> Result<AgentTask, String> {
    let mut loaded_task: Option<AgentTask> = None;

    // 1. Try Local Load
    {
        let guard = state.lock().map_err(|_| "Lock fail")?;
        if let Some(scs) = &guard.studio_scs {
            loaded_task = orchestrator::load_local_task(scs, &session_id);
        }
    }

    // 2. If not found locally, try Remote
    if loaded_task.is_none() {
        println!("[Kernel] Session {} not found locally, attempting remote hydrate...", session_id);
        if let Ok(mut client) = get_rpc_client(&state).await {
            let history = hydrate_session_history(&mut client, &session_id).await.unwrap_or_default();
            if !history.is_empty() {
                loaded_task = Some(AgentTask {
                    id: session_id.clone(),
                    intent: history.first().map(|m| m.text.clone()).unwrap_or("Restored Session".into()),
                    agent: "Restored".into(),
                    phase: AgentPhase::Complete,
                    progress: history.len() as u32,
                    total_steps: history.len() as u32,
                    current_step: "Session loaded from Kernel.".into(),
                    gate_info: None,
                    receipt: None,
                    visual_hash: None,
                    pending_request_hash: None,
                    session_id: Some(session_id.clone()),
                    history,
                    processed_steps: HashSet::new(),
                    swarm_tree: Vec::new(), 
                });
            }
        }
    }

    // 3. Finalize Load
    if let Some(task) = loaded_task {
        {
            let mut app_state = state.lock().map_err(|_| "Lock fail")?;
            app_state.current_task = Some(task.clone());
        }
        let _ = app.emit("task-started", &task);
        return Ok(task);
    }

    Err(format!("Session {} not found locally or remotely", session_id))
}

#[tauri::command]
pub async fn delete_session(
    state: State<'_, Mutex<AppState>>,
    session_id: String,
) -> Result<(), String> {
    // 1. Local Delete (Simulate by removing from index)
    if let Ok(guard) = state.lock() {
        if let Some(scs) = &guard.studio_scs {
            let mut sessions = orchestrator::get_local_sessions(scs);
            if let Some(pos) = sessions.iter().position(|s| s.session_id == session_id) {
                sessions.remove(pos);
                // Rewrite index
                if let Ok(bytes) = serde_json::to_vec(&sessions) {
                    if let Ok(mut store) = scs.lock() {
                        let _ = store.append_frame(
                            ioi_scs::FrameType::System,
                            &bytes,
                            0,
                            [0u8; 32],
                            orchestrator::SESSION_INDEX_KEY
                        );
                    }
                }
            }
        }
    }

    // 2. Remote Delete
    if let Ok(_client) = get_rpc_client(&state).await {
        let session_bytes = hex::decode(&session_id).unwrap_or_default();
        if !session_bytes.is_empty() {
             // ... construct and submit delete transaction ...
             // Omitted for brevity as mock
        }
    }
    
    Ok(())
}

// --- Task Lifecycle ---

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
    };

    let mut scs_handle = None;

    {
        let mut app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.current_task = Some(task.clone());
        app_state.gate_response = None;
        scs_handle = app_state.studio_scs.clone();
    }

    // [NEW] Persist Initial Session State Locally
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
        intent_clone
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
pub fn update_task(state: State<Mutex<AppState>>, app: AppHandle, task: AgentTask) -> Result<(), String> {
    update_task_state(&app, |t| *t = task.clone());
    Ok(())
}

#[tauri::command]
pub fn complete_task(state: State<Mutex<AppState>>, app: AppHandle, success: bool) -> Result<(), String> {
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

#[tauri::command]
pub fn get_gate_response(state: State<Mutex<AppState>>) -> Option<GateResponse> {
    state.lock().ok().and_then(|s| s.gate_response.clone())
}

#[tauri::command]
pub fn clear_gate_response(state: State<Mutex<AppState>>) -> Result<(), String> {
    if let Ok(mut app_state) = state.lock() {
        app_state.gate_response = None;
    }
    Ok(())
}

#[tauri::command]
pub async fn gate_respond(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    approved: bool,
) -> Result<(), String> {
    let mut session_id_hex = None;
    let mut request_hash_hex = None;

    {
        if let Ok(mut s) = state.lock() {
            s.gate_response = Some(GateResponse { responded: true, approved });
            if let Some(task) = &s.current_task {
                session_id_hex = task.session_id.clone();
                request_hash_hex = task.pending_request_hash.clone();
            }
        }
    }
    
    windows::hide_gate(app.clone());
    let _ = app.emit("gate-response", approved);

    if approved {
        if let (Some(sid_hex), Some(hash_hex)) = (session_id_hex, request_hash_hex) {
            println!("[Autopilot] Processing approval for Session {} / Hash {}", sid_hex, hash_hex);

            let session_id_bytes = hex::decode(&sid_hex).map_err(|e| e.to_string())?;
            let mut session_id_arr = [0u8; 32];
            if session_id_bytes.len() != 32 { return Err("Invalid session ID len".into()); }
            session_id_arr.copy_from_slice(&session_id_bytes);

            let request_hash_bytes = hex::decode(&hash_hex).map_err(|e| e.to_string())?;
            let mut request_hash_arr = [0u8; 32];
            request_hash_arr.copy_from_slice(&request_hash_bytes);

            let approver_kp = Ed25519KeyPair::generate().map_err(|e| e.to_string())?;
            let approver_pub = approver_kp.public_key();
            
            let token = ApprovalToken {
                request_hash: request_hash_arr,
                scope: ApprovalScope {
                    expires_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600,
                    max_usages: Some(1),
                },
                approver_sig: vec![], 
                approver_suite: SignatureSuite::ED25519,
            };
            
            let mut token_for_signing = token.clone();
            let token_bytes = codec::to_bytes_canonical(&token_for_signing).map_err(|e| e.to_string())?;
            let sig = approver_kp.sign(&token_bytes).map_err(|e| e.to_string())?;
            
            token_for_signing.approver_sig = sig.to_bytes();
            token_for_signing.approver_suite = SignatureSuite::ED25519; 

            let resume_params = ResumeAgentParams {
                session_id: session_id_arr,
                approval_token: Some(token_for_signing),
            };
            let params_bytes = codec::to_bytes_canonical(&resume_params).map_err(|e| e.to_string())?;

            let sys_payload = SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "resume@v1".to_string(),
                params: params_bytes,
            };

            let mut client = get_rpc_client(&state).await?;

            let header = SignHeader {
                account_id: AccountId(account_id_from_key_material(SignatureSuite::ED25519, &approver_pub.to_bytes()).unwrap()),
                nonce: 0, 
                chain_id: ChainId(0),
                tx_version: 1,
                session_auth: None,
            };
            
            let mut tx = SystemTransaction {
                header,
                payload: sys_payload,
                signature_proof: SignatureProof::default(),
            };
            
            let tx_sign_bytes = tx.to_sign_bytes().map_err(|e| e.to_string())?;
            let tx_sig = approver_kp.sign(&tx_sign_bytes).map_err(|e| e.to_string())?;
            
            tx.signature_proof = SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: approver_pub.to_bytes(),
                signature: tx_sig.to_bytes(),
            };
            
            let final_tx = ChainTransaction::System(Box::new(tx));
            let final_tx_bytes = codec::to_bytes_canonical(&final_tx).map_err(|e| e.to_string())?;

            let request = tonic::Request::new(SubmitTransactionRequest {
                transaction_bytes: final_tx_bytes,
            });

            match client.submit_transaction(request).await {
                Ok(resp) => {
                    let tx_hash = resp.into_inner().tx_hash;
                    println!("[Autopilot] Approval transaction submitted: {}", tx_hash);
                    
                    // Simple wait for commit (for better UX, could be improved)
                    let mut attempts = 0;
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        attempts += 1;
                        if attempts > 20 { 
                            println!("[Autopilot] Timeout waiting for approval tx commit");
                            break;
                        }

                        let status_req = tonic::Request::new(
                            ioi_ipc::public::GetTransactionStatusRequest { tx_hash: tx_hash.clone() }
                        );
                        
                        if let Ok(status_resp) = client.get_transaction_status(status_req).await {
                            let status = status_resp.into_inner().status;
                            if status == 3 { // Committed
                                println!("[Autopilot] Approval transaction committed!");
                                break;
                            } else if status == 4 { // Rejected
                                return Err(format!("Approval transaction rejected"));
                            }
                        }
                    }
                    
                    update_task_state(&app, |t| {
                        t.phase = AgentPhase::Running;
                        t.gate_info = None;
                        t.pending_request_hash = None;
                        t.current_step = "Approval granted. Resuming agent...".to_string();
                        t.history.push(ChatMessage {
                            role: "system".to_string(),
                            text: "✅ Approval Granted. Resuming...".to_string(),
                            timestamp: now(),
                        });
                    });
                },
                Err(e) => {
                    eprintln!("[Autopilot] Failed to submit approval transaction: {}", e);
                    return Err(format!("Failed to submit approval: {}", e));
                }
            }
        } else {
            eprintln!("[Autopilot] Missing session_id or request_hash in state. Cannot approve.");
        }
    } else {
        update_task_state(&app, |t| {
            t.phase = AgentPhase::Failed;
            t.current_step = "Action blocked by user".to_string();
            t.gate_info = None;
             t.history.push(ChatMessage {
                role: "system".to_string(),
                text: "❌ Action Denied by User.".to_string(),
                timestamp: now(),
            });
        });
    }
    Ok(())
}

#[tauri::command]
pub async fn get_context_blob(
    state: State<'_, Mutex<AppState>>,
    hash: String,
) -> Result<ContextBlob, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let mut client = get_rpc_client(&state).await?;

    let request = tonic::Request::new(GetContextBlobRequest { blob_hash: hash });

    let response = client
        .get_context_blob(request)
        .await
        .map_err(|e| format!("RPC error: {}", e))?
        .into_inner();

    let data_base64 = STANDARD.encode(&response.data);

    let mime_type = if response.mime_type == "application/octet-stream" {
        if response.data.starts_with(b"\x89PNG") {
            "image/png".to_string()
        } else if response.data.starts_with(b"<") || response.data.starts_with(b"<?xml") {
            "text/xml".to_string() 
        } else if response.data.starts_with(b"{") || response.data.starts_with(b"[") {
            "application/json".to_string()
        } else {
            "text/plain".to_string()
        }
    } else {
        response.mime_type
    };

    Ok(ContextBlob {
        data_base64, 
        mime_type,
    })
}

// [NEW] Monitor Kernel Events (Moved from lib.rs)
pub async fn monitor_kernel_events(app: tauri::AppHandle) {
    let mut client = loop {
        match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => {
                println!("[Autopilot] Connected to Kernel Event Stream at :9000");
                break c;
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    let request = tonic::Request::new(SubscribeEventsRequest {});
    let mut stream = match client.subscribe_events(request).await {
        Ok(s) => s.into_inner(),
        Err(e) => {
            eprintln!("[Autopilot] Failed to subscribe to events: {}", e);
            return;
        }
    };

    let state_handle = app.state::<Mutex<AppState>>();

    println!("[Autopilot] Listening for events...");
    while let Ok(Some(event_msg)) = stream.message().await {
        if let Some(event_enum) = event_msg.event {
            match event_enum {
                ChainEventEnum::Thought(thought) => {
                    update_task_state(&app, |t| {
                        if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == thought.session_id) {
                            agent.current_thought = Some(thought.content.clone());
                            agent.status = "running".to_string();
                        } else {
                            t.current_step = thought.content.clone();
                        }
                        
                        t.phase = AgentPhase::Running;
                        t.progress += 1;
                        if !thought.visual_hash.is_empty() {
                            t.visual_hash = Some(thought.visual_hash.clone());
                        }
                        if !thought.session_id.is_empty() {
                            t.session_id = Some(thought.session_id.clone());
                        }
                    });
                }
                ChainEventEnum::ActionResult(res) => {
                    update_task_state(&app, |t| {
                        let dedup_key = format!("{}:{}", res.step_index, res.tool_name);

                        if t.processed_steps.contains(&dedup_key) {
                            return;
                        }
                        t.processed_steps.insert(dedup_key);

                        t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
                        if !res.session_id.is_empty() {
                            t.session_id = Some(res.session_id.clone());
                        }
                        
                        if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                            agent.artifacts_produced += 1;
                        }

                        if res.tool_name == "agent__complete" || res.tool_name == "system::max_steps_reached" || res.tool_name == "system::auto_complete" {
                             t.phase = AgentPhase::Complete;
                             
                             if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                                 agent.status = "completed".to_string();
                             }

                             t.receipt = Some(Receipt {
                                 duration: "Done".to_string(), 
                                 actions: t.progress,
                                 cost: Some("$0.00".to_string()),
                             });
                             let msg = format!("Task Completed: {}", res.output);
                             if t.history.last().map(|m| m.text != msg).unwrap_or(true) {
                                 t.history.push(ChatMessage { role: "system".into(), text: msg, timestamp: now() });
                             }
                        }
                        
                        if res.tool_name == "chat::reply" {
                             t.phase = AgentPhase::Complete;
                             t.current_step = res.output.clone(); 
                             t.receipt = Some(Receipt {
                                 duration: "Done".to_string(), 
                                 actions: 1,
                                 cost: Some("$0.00".to_string()),
                             });
                             
                             let duplicate = t.history.last().map(|m| m.text == res.output).unwrap_or(false);
                             if !duplicate {
                                 t.history.push(ChatMessage {
                                     role: "agent".to_string(),
                                     text: res.output.clone(),
                                     timestamp: now(),
                                 });
                             }
                        } else if res.tool_name != "agent__complete" && res.tool_name != "system::max_steps_reached" && res.tool_name != "system::auto_complete" {
                             t.history.push(ChatMessage {
                                 role: "tool".to_string(),
                                 text: format!("Tool Output ({}): {}", res.tool_name, res.output),
                                 timestamp: now(),
                             });
                        }
                    });
                }
                ChainEventEnum::Ghost(input) => {
                    let payload = GhostInputEvent {
                        device: input.device.clone(),
                        description: input.description.clone(),
                    };
                    let _ = app.emit("ghost-input", &payload);
                    update_task_state(&app, |t| {
                        if matches!(t.phase, AgentPhase::Running) {
                             t.current_step = format!("User Input: {}", input.description);
                             t.history.push(ChatMessage {
                                 role: "user".to_string(),
                                 text: format!("[Ghost] {}", input.description),
                                 timestamp: now(),
                             });
                        }
                    });
                }
                ChainEventEnum::Action(action) => {
                    if action.verdict == "REQUIRE_APPROVAL" {
                        let already_gating = {
                            if let Ok(guard) = state_handle.lock() {
                                if let Some(task) = &guard.current_task {
                                    task.phase == AgentPhase::Gate && task.pending_request_hash.as_deref() == Some(action.reason.as_str())
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };

                        if !already_gating {
                            println!("[Autopilot] Policy Gate Triggered for {}", action.target);
                            
                            update_task_state(&app, |t| {
                                t.phase = AgentPhase::Gate;
                                t.current_step = "Policy Gate: Approval Required".to_string();
                                
                                t.gate_info = Some(GateInfo {
                                    title: "Restricted Action Intercepted".to_string(),
                                    description: format!("The agent is attempting to execute: {}", action.target),
                                    risk: "high".to_string(), 
                                });
                                
                                t.pending_request_hash = Some(action.reason.clone());

                                if !action.session_id.is_empty() {
                                    t.session_id = Some(action.session_id.clone());
                                }
                                
                                t.history.push(ChatMessage {
                                    role: "system".to_string(),
                                    text: format!("🛑 Policy Gate triggered for action: {}", action.target),
                                    timestamp: now(),
                                });

                                if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == action.session_id) {
                                    agent.status = "paused".to_string();
                                }
                            });
                            
                            if let Some(w) = app.get_webview_window("spotlight") {
                                if w.is_visible().unwrap_or(false) {
                                    let _ = w.set_focus();
                                }
                            }
                        }
                    } 
                    else if action.verdict == "BLOCK" {
                        update_task_state(&app, |t| {
                             t.current_step = format!("⛔ Action Blocked: {}", action.target);
                             t.phase = AgentPhase::Failed;
                             
                             if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == action.session_id) {
                                 agent.status = "failed".to_string();
                             }

                             t.history.push(ChatMessage {
                                 role: "system".to_string(),
                                 text: format!("⛔ Blocked action: {}", action.target),
                                 timestamp: now(),
                             });
                        });
                    }
                }
                ChainEventEnum::Spawn(spawn) => {
                    update_task_state(&app, |t| {
                        let agent = SwarmAgent {
                            id: spawn.new_session_id.clone(),
                            parent_id: if spawn.parent_session_id.is_empty() { None } else { Some(spawn.parent_session_id.clone()) },
                            name: spawn.name.clone(),
                            role: spawn.role.clone(),
                            status: "running".to_string(), 
                            budget_used: 0.0,
                            budget_cap: spawn.budget as f64,
                            current_thought: Some(format!("Initialized goal: {}", spawn.goal)),
                            artifacts_produced: 0,
                            estimated_cost: 0.0,
                            policy_hash: "".to_string(), 
                        };
                        
                        if let Some(pos) = t.swarm_tree.iter().position(|a| a.id == agent.id) {
                            t.swarm_tree[pos] = agent;
                        } else {
                            t.swarm_tree.push(agent);
                        }
                    });
                }
                _ => {}
            }
        }
    }
}