// apps/autopilot/src-tauri/src/kernel.rs
use crate::models::*;
use crate::windows; 
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

// Kernel Integration
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, DraftTransactionRequest, GetContextBlobRequest,
    SubmitTransactionRequest, SubscribeEventsRequest,
};
use tonic::transport::Channel;

// Crypto & Types for gate_respond
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_types::app::action::{ApprovalToken, ApprovalScope}; 
use ioi_types::app::SignatureSuite;
use ioi_types::app::agentic::ResumeAgentParams;
use ioi_types::app::{ChainTransaction, SignHeader, SignatureProof, SystemPayload, SystemTransaction};
use ioi_types::app::{AccountId, ChainId, account_id_from_key_material}; 
use ioi_types::codec;

// Helper to update state and emit events
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

// -------------------------------------------------------------------------
// Kernel Monitor
// -------------------------------------------------------------------------

async fn monitor_kernel_events(app: AppHandle) {
    let mut client = loop {
        match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => {
                println!("[Autopilot] Connected to Kernel Event Stream at :9000");
                break c;
            }
            Err(_) => {
                // Retry loop for connection
                tokio::time::sleep(Duration::from_secs(2)).await;
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

    while let Ok(Some(event_msg)) = stream.message().await {
        if let Some(event_enum) = event_msg.event {
            match event_enum {
                ChainEventEnum::Thought(thought) => {
                    update_task_state(&app, |t| {
                        t.current_step = thought.content.clone();
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
                        t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
                        if !res.session_id.is_empty() {
                            t.session_id = Some(res.session_id.clone());
                        }
                        if res.tool_name == "agent__complete" || res.tool_name == "system::max_steps_reached" {
                             t.phase = AgentPhase::Complete;
                             t.receipt = Some(Receipt {
                                 duration: "Done".to_string(), 
                                 actions: t.progress,
                                 cost: Some("$0.00".to_string()),
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
                        }
                    });
                }
                ChainEventEnum::Action(action) => {
                    if action.verdict == "REQUIRE_APPROVAL" {
                        update_task_state(&app, |t| {
                            t.phase = AgentPhase::Gate;
                            t.current_step = "Policy Gate: Approval Required".to_string();
                            t.gate_info = Some(GateInfo {
                                title: "Restricted Action Intercepted".to_string(),
                                description: format!("Agent attempting: {}", action.target),
                                risk: "medium".to_string(), 
                            });
                            t.pending_request_hash = Some(action.reason.clone());
                            
                            if !action.session_id.is_empty() {
                                t.session_id = Some(action.session_id.clone());
                            }
                        });
                        windows::show_gate(app.clone());
                    } else if action.verdict == "BLOCK" {
                        update_task_state(&app, |t| {
                            t.phase = AgentPhase::Failed;
                            t.current_step = format!("Blocked by Firewall: {}", action.reason);
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

// -------------------------------------------------------------------------
// Exposed Commands
// -------------------------------------------------------------------------

#[tauri::command]
pub fn start_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    intent: String,
) -> Result<AgentTask, String> {
    let task = AgentTask {
        id: uuid::Uuid::new_v4().to_string(),
        intent: intent.clone(),
        agent: "General Agent".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 10,
        current_step: "Transmitting intent to Kernel...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None, 
        pending_request_hash: None,
        session_id: None,
    };

    {
        let mut app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.current_task = Some(task.clone());
        app_state.gate_response = None;
    }

    let _ = app.emit("task-started", &task);
    windows::show_pill(app.clone());

    let app_clone = app.clone();
    let intent_clone = intent.clone();

    tauri::async_runtime::spawn(async move {
        // [MODIFIED] Removed simulation fallback. Errors are now reported directly.
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

        println!("[Autopilot] Drafting intent: '{}'", intent_clone);

        let draft_req = tonic::Request::new(DraftTransactionRequest {
            intent: intent_clone,
            address_book: Default::default(),
        });

        match client.draft_transaction(draft_req).await {
            Ok(resp) => {
                let draft = resp.into_inner();
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
                    // Success: Start monitoring for events
                    monitor_kernel_events(app_clone).await;
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

            // In production, we would use a stored high-security key (e.g., from Secure Enclave or Ledger)
            // For now, we generate a fresh key to simulate the "Approver" signature
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

            let mut client = {
                let maybe_client = state.lock().map_err(|_| "Failed to lock state")?.rpc_client.clone();
                
                if let Some(c) = maybe_client {
                    c
                } else {
                    println!("[Autopilot] RPC client not ready. Connecting now...");
                    let channel = Channel::from_static("http://127.0.0.1:9000")
                        .connect()
                        .await
                        .map_err(|e| format!("Failed to connect to Kernel: {}", e))?;
                    let new_client = PublicApiClient::new(channel);
                    
                    if let Ok(mut s) = state.lock() {
                        s.rpc_client = Some(new_client.clone());
                    }
                    new_client
                }
            };

            // FIX: Use nonce 0 for ephemeral/bootstrap accounts.
            // The kernel accepts unknown accounts only if nonce is 0.
            let tx_nonce = 0;

            let header = SignHeader {
                account_id: AccountId(account_id_from_key_material(SignatureSuite::ED25519, &approver_pub.to_bytes()).unwrap()),
                nonce: tx_nonce,
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
                    
                    // Wait for transaction to be committed before returning
                    let mut attempts = 0;
                    loop {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        attempts += 1;
                        if attempts > 20 { // 10 seconds timeout
                            println!("[Autopilot] Timeout waiting for approval tx commit");
                            break;
                        }

                        let status_req = tonic::Request::new(
                            ioi_ipc::public::GetTransactionStatusRequest { tx_hash: tx_hash.clone() }
                        );
                        
                        if let Ok(status_resp) = client.get_transaction_status(status_req).await {
                            let status = status_resp.into_inner().status;
                            // 3 = COMMITTED
                            if status == 3 {
                                println!("[Autopilot] Approval transaction committed!");
                                break;
                            } else if status == 4 { // REJECTED
                                return Err(format!("Approval transaction rejected"));
                            }
                        }
                    }
                    
                    update_task_state(&app, |t| {
                        t.phase = AgentPhase::Running;
                        t.gate_info = None;
                        t.pending_request_hash = None;
                        t.current_step = "Approval granted. Resuming agent...".to_string();
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

    let cached_client = {
        let s = state.lock().map_err(|_| "Failed to lock state")?;
        s.rpc_client.clone()
    };

    let mut client = if let Some(c) = cached_client {
        c
    } else {
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
        new_client
    };

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