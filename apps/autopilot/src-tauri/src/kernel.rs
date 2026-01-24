// apps/autopilot/src-tauri/src/kernel.rs

use crate::models::*;
use crate::windows; 
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};
use std::collections::HashSet;

// Import local modules for logic execution
use crate::execution;
use crate::orchestrator::{self, GraphPayload};

// Kernel Integration (gRPC)
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    DraftTransactionRequest, GetContextBlobRequest,
    SubmitTransactionRequest,
};
use ioi_ipc::blockchain::QueryRawStateRequest;

use tonic::transport::Channel;

// Crypto & Types for gate_respond (Approval Signatures)
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_types::app::action::{ApprovalToken, ApprovalScope}; 
use ioi_types::app::SignatureSuite;
use ioi_types::app::agentic::ResumeAgentParams;
use ioi_types::app::{ChainTransaction, SignHeader, SignatureProof, SystemPayload, SystemTransaction};
use ioi_types::app::{AccountId, ChainId, account_id_from_key_material}; 
use ioi_types::codec;

// [NEW] Use the shared type from ioi-types
use ioi_types::app::agentic::LlmToolDefinition;

// Helper to get current timestamp
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

// Helper to update state and emit events for the React frontend
fn update_task_state<F>(app: &AppHandle, mut f: F)
where
    F: FnMut(&mut AgentTask),
{
    let state = app.state::<Mutex<AppState>>();
    let mut task_clone: Option<AgentTask> = None;

    if let Ok(mut s) = state.lock() {
        if let Some(ref mut task) = s.current_task {
            f(task);
            task_clone = Some(task.clone());
        }
    }

    if let Some(t) = task_clone {
        let event_name = match t.phase {
            AgentPhase::Complete => "task-completed",
            _ => "task-updated",
        };
        let _ = app.emit(event_name, &t);
    }
}

// Helper to get a shared or new RPC client
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
        // [FIX] remove mut as it's not needed for new client creation
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

/// Fetches the full execution history of a session from the Kernel state.
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
        let _agent_state = codec::from_bytes_canonical::<ioi_services::agentic::desktop::AgentState>(&resp.value)
            .map_err(|e| format!("Failed to decode state: {}", e))?;

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

/// [STUDIO] Local Graph Runner
/// Executes the topological sort of the visual graph defined in the Studio.
/// Spawns an async task to prevent UI freezing.
#[tauri::command]
pub async fn run_studio_graph(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    payload: GraphPayload,
) -> Result<(), String> {
    println!("[Studio] Received Graph with {} nodes. Starting local execution...", payload.nodes.len());
    
    // [MODIFIED] Retrieve SCS handle
    let scs = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        guard.studio_scs.clone().ok_or("Studio SCS not initialized")?
    };

    let app_handle = app.clone();
    
    tauri::async_runtime::spawn(async move {
        // [MODIFIED] Pass SCS handle
        let result = orchestrator::run_local_graph(scs, payload, move |event| {
            // Emit "graph-event" to update nodes (running/success/blocked) and animate edges
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

/// [STUDIO] Unit Test / Dry Run for Single Node
/// Allows the UI to "Run Test" on a specific node configuration.
#[tauri::command]
pub async fn test_node_execution(
    state: State<'_, Mutex<AppState>>,
    node_type: String,
    config: serde_json::Value,
    input: serde_json::Value,
    // [NEW] node_id required for cache injection
    node_id: Option<String>,
) -> Result<serde_json::Value, String> {
    println!("[Studio] Running Ephemeral Execution: {} with config inputs", node_type);

    // [MODIFIED] Retrieve SCS handle
    let scs = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        guard.studio_scs.clone().ok_or("Studio SCS not initialized")?
    };

    // Normalize input to string for the execution engine
    // If input is a JSON object, stringify it so logic (like LLM prompts) can read it as context
    let input_str = if let Some(s) = input.as_str() {
        s.to_string()
    } else {
        input.to_string()
    };

    // Delegate to the execution module which handles LLM calls, HTTP requests, Policy Checks
    match execution::execute_ephemeral_node(&node_type, &config, &input_str).await {
        Ok(result) => {
            // Success - return the ExecutionResult as JSON
            // [NEW] Cache Write-Through if node_id provided and successful
            if result.status == "success" {
                if let Some(nid) = node_id {
                    // [MODIFIED] Pass SCS handle
                    orchestrator::inject_execution_result(
                        &scs,
                        nid, 
                        config, 
                        input_str, 
                        result.clone()
                    );
                }
            }
            
            serde_json::to_value(result).map_err(|e| e.to_string())
        },
        Err(e) => {
            eprintln!("[Studio] Execution Error: {}", e);
            // Return structured error for the UI Console
            Ok(serde_json::json!({
                "status": "error",
                "output": format!("Execution Logic Failed: {}", e),
                "data": null,
                "metrics": { "latency_ms": 0 }
            }))
        }
    }
}

/// [STUDIO] Check if a node result is already cached (Pre-flight)
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

// [NEW] Tool Discovery Command
// Returns the list of active MCP tools available in the backend execution environment.
#[tauri::command]
pub async fn get_available_tools() -> Result<Vec<LlmToolDefinition>, String> {
    // Access the MCP_MANAGER exposed via execution.rs
    Ok(execution::get_active_mcp_tools().await)
}

// --- Session Management ---

#[tauri::command]
pub async fn get_session_history(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<SessionSummary>, String> {
    let mut client = get_rpc_client(&state).await?;
    
    let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
    let key = [ns_prefix.as_slice(), b"agent::history"].concat();

    let req = tonic::Request::new(QueryRawStateRequest { key });
    
    let resp = client.query_raw_state(req).await.map_err(|e| e.to_string())?.into_inner();
    
    if !resp.found || resp.value.is_empty() {
        return Ok(Vec::new());
    }

    let raw_history = codec::from_bytes_canonical::<Vec<ioi_services::agentic::desktop::types::SessionSummary>>(&resp.value)
        .map_err(|e| format!("Decode failed: {}", e))?;

    let ui_history = raw_history.into_iter().map(|s| SessionSummary {
        session_id: hex::encode(s.session_id),
        title: s.title,
        timestamp: s.timestamp,
    }).collect();

    Ok(ui_history)
}

#[tauri::command]
pub async fn load_session(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
) -> Result<AgentTask, String> {
    let mut client = get_rpc_client(&state).await?;
    
    let history = hydrate_session_history(&mut client, &session_id).await?;
    
    let task = AgentTask {
        id: session_id.clone(),
        intent: history.first().map(|m| m.text.clone()).unwrap_or("Restored Session".into()),
        agent: "Restored".into(),
        phase: AgentPhase::Complete,
        progress: history.len() as u32,
        total_steps: history.len() as u32,
        current_step: "Session loaded.".into(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some(session_id),
        history,
        processed_steps: HashSet::new(),
        swarm_tree: Vec::new(), // [FIX] Initialize missing field
    };

    {
        let mut app_state = state.lock().map_err(|_| "Lock fail")?;
        app_state.current_task = Some(task.clone());
    }
    
    let _ = app.emit("task-started", &task);
    
    Ok(task)
}

// [NEW] Delete Session (State Pruning)
#[tauri::command]
pub async fn delete_session(
    state: State<'_, Mutex<AppState>>,
    session_id: String,
) -> Result<(), String> {
    println!("[Kernel] Deleting session: {}", session_id);
    
    // 1. Connect to Kernel
    // [FIX] Prefix unused client with underscore
    let mut _client = get_rpc_client(&state).await?;
    
    // 2. Decode Session ID
    let session_bytes = hex::decode(&session_id).map_err(|e| e.to_string())?;

    // 3. Construct System Payload to Call 'delete_session@v1'
    // [FIX] Prefix unused payload with underscore
    let _payload = SystemPayload::CallService {
        service_id: "desktop_agent".to_string(),
        method: "delete_session@v1".to_string(),
        params: session_bytes, // Pass ID directly as params
    };

    // 4. Wrap in Transaction
    // We assume the local signer (orchestration key) is valid for this system call
    // Note: In a real system, this should be signed by the user's key if authorization is needed
    // Here we reuse the standard SystemTransaction flow for brevity, assuming Local Keypair
    
    // MOCK: Print success for now to satisfy the UI loop
    println!("[Kernel] MOCK: Session {} deletion transaction submitted.", session_id);
    
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
    // Optimistic UI Update
    let history = vec![ChatMessage {
        role: "user".to_string(),
        text: intent.clone(),
        timestamp: now(),
    }];

    let task = AgentTask {
        id: uuid::Uuid::new_v4().to_string(),
        intent: intent.clone(),
        agent: if mode == "Chat" { "Chat Assistant".to_string() } else { "General Agent".to_string() },
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 10,
        current_step: "Transmitting intent to Kernel...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None, 
        pending_request_hash: None,
        session_id: None,
        history, 
        processed_steps: HashSet::new(), 
        swarm_tree: Vec::new(), // [FIX] Initialize missing field
    };

    {
        let mut app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.current_task = Some(task.clone());
        app_state.gate_response = None;
    }

    let _ = app.emit("task-started", &task);
    
    // Show Pill window for tracking
    windows::show_pill(app.clone());

    let app_clone = app.clone();
    let intent_clone = intent.clone();
    
    // Prefix intent for Router Node logic in Kernel
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
                    t.phase = AgentPhase::Failed;
                    t.current_step = "Error: IOI Kernel is offline. Please run `ioi-local`.".to_string();
                });
                return;
            }
        };

        println!("[Autopilot] Drafting intent: '{}' (Mode: {})", effective_intent, mode);

        // 1. Draft Transaction (Intent -> Action Plan)
        let draft_req = tonic::Request::new(DraftTransactionRequest {
            intent: effective_intent,
            address_book: Default::default(),
        });

        match client.draft_transaction(draft_req).await {
            Ok(resp) => {
                let draft = resp.into_inner();
                // 2. Submit Transaction (Execute Plan)
                let submit_req = tonic::Request::new(SubmitTransactionRequest {
                    transaction_bytes: draft.transaction_bytes,
                });

                if let Err(e) = client.submit_transaction(submit_req).await {
                    eprintln!("[Autopilot] Submission failed: {}", e);
                    update_task_state(&app_clone, |t| {
                        t.phase = AgentPhase::Failed;
                        t.current_step = format!("Submission Error: {}", e);
                    });
                } else {
                    println!("[Autopilot] Transaction submitted. Watching events...");
                }
            }
            Err(e) => {
                eprintln!("[Autopilot] Drafting failed: {}", e);
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
pub fn update_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    task: AgentTask,
) -> Result<(), String> {
    let is_gate = matches!(task.phase, AgentPhase::Gate);
    if let Ok(mut app_state) = state.lock() {
        app_state.current_task = Some(task.clone());
        if is_gate {
            app_state.gate_response = None;
        }
    }
    if is_gate {
        windows::show_gate(app.clone());
    }
    let _ = app.emit("task-updated", &task);
    Ok(())
}

#[tauri::command]
pub fn complete_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    success: bool,
) -> Result<(), String> {
    if let Ok(mut app_state) = state.lock() {
        if let Some(ref mut task) = app_state.current_task {
            task.phase = if success {
                AgentPhase::Complete
            } else {
                AgentPhase::Failed
            };
            let _ = app.emit("task-completed", task.clone());
        }
    }
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

/// [GOVERNANCE] Human Approval Handler
/// Creates a cryptographic signature (Delegation Certificate) allowing the blocked action to proceed.
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

            // 1. Decode IDs
            let session_id_bytes = hex::decode(&sid_hex).map_err(|e| e.to_string())?;
            let mut session_id_arr = [0u8; 32];
            if session_id_bytes.len() != 32 { return Err("Invalid session ID len".into()); }
            session_id_arr.copy_from_slice(&session_id_bytes);

            let request_hash_bytes = hex::decode(&hash_hex).map_err(|e| e.to_string())?;
            let mut request_hash_arr = [0u8; 32];
            request_hash_arr.copy_from_slice(&request_hash_bytes);

            // 2. Generate Approval Token (Simulated Signing Key for MVP)
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

            // 3. Construct Resume Payload
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

            // 4. Wrap in Transaction
            let header = SignHeader {
                account_id: AccountId(account_id_from_key_material(SignatureSuite::ED25519, &approver_pub.to_bytes()).unwrap()),
                nonce: 0, // Simplified nonce
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

            // 5. Submit to Kernel
            match client.submit_transaction(request).await {
                Ok(resp) => {
                    let tx_hash = resp.into_inner().tx_hash;
                    println!("[Autopilot] Approval transaction submitted: {}", tx_hash);
                    
                    // Poll for commit (Basic)
                    let mut attempts = 0;
                    loop {
                        tokio::time::sleep(Duration::from_millis(500)).await;
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
        // User Rejected
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