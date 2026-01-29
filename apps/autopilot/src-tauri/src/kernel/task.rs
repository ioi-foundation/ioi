// apps/autopilot/src-tauri/src/kernel/task.rs
use crate::kernel::state::{get_rpc_client, now, update_task_state};
use crate::models::{AgentPhase, AgentTask, AppState, ChatMessage, SessionSummary};
use crate::orchestrator;
use crate::windows;
use ioi_ipc::public::{DraftTransactionRequest, SubmitTransactionRequest, GetTransactionStatusRequest};
use ioi_ipc::public::public_api_client::PublicApiClient;
use std::collections::HashSet;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};

// [NEW] Imports for continue_task
use ioi_services::agentic::desktop::types::PostMessageParams;
use ioi_scs::FrameType;
use dcrypt::algorithms::ByteSerializable;
use ioi_types::codec;
use ioi_types::app::{
    account_id_from_key_material, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction, AccountId
};
use ioi_ipc::blockchain::QueryRawStateRequest;

#[tauri::command]
pub fn start_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    intent: String,
    // [REMOVED] mode: String, -- Unified Interface
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
        // [MODIFIED] Unified Agent Name
        agent: "Autopilot".to_string(),
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

    let scs_handle;

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
    
    // [MODIFIED] Unified Intent Construction
    // We no longer prepend MODE:CHAT. The backend IntentResolver defaults to 'AgentMode::Agent',
    // which allows the Cognitive Router (step/mod.rs) to decide per-step whether to chat or act.
    let session_hex = hex::encode(uuid::Uuid::parse_str(&task_id).unwrap().as_bytes());
    let effective_intent = format!("SESSION:{} {}", session_hex, intent_clone);

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

// [UPDATED] Command: Continue Task with Convergent Nonce Logic
// Sends a new user message to the Kernel via `post_message@v1`.
#[tauri::command]
pub async fn continue_task(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
    user_input: String,
) -> Result<(), String> {
    
    // 1. Optimistic UI Update
    let user_msg_ui = ChatMessage {
        role: "user".to_string(),
        text: user_input.clone(),
        timestamp: crate::kernel::state::now(),
    };
    
    update_task_state(&app, move |t| {
        t.history.push(user_msg_ui.clone()); 
        t.current_step = "Sending message...".to_string();
        t.phase = crate::models::AgentPhase::Running;
    });

    // --- FIX START: Sanitize UUID string ---
    // Remove hyphens if present to support UUID string format from UI
    let clean_session_id = session_id.replace("-", "");
    let session_bytes = hex::decode(&clean_session_id).map_err(|_| "Invalid session ID hex")?;
    // --- FIX END ---

    let mut session_arr = [0u8; 32];
    
    // Ensure we handle potential length mismatches
    if session_bytes.len() > 32 {
         return Err("Session ID too long".into());
    }
    
    // Copy bytes, zero-padding if shorter than 32 (e.g. 16-byte UUID)
    session_arr[..session_bytes.len()].copy_from_slice(&session_bytes);

    let params = PostMessageParams {
        session_id: session_arr,
        role: "user".to_string(),
        content: user_input,
    };
    
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    
    // 3. Async Kernel Call with Backoff Retry
    let app_clone = app.clone();
    
    tauri::async_runtime::spawn(async move {
        let mut client = match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[Autopilot] Failed to connect for continue_task: {}", e);
                return;
            }
        };
        
        // Identity Load
        let data_dir = app_clone.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("./ioi-data"));
        let key_path = data_dir.join("identity.key");
        if std::env::var("IOI_GUARDIAN_KEY_PASS").is_err() {
             unsafe { std::env::set_var("IOI_GUARDIAN_KEY_PASS", "local-mode"); }
        }
        
        let raw_key = match ioi_validator::common::GuardianContainer::load_encrypted_file(&key_path) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[Autopilot] Failed to load identity key: {}", e);
                update_task_state(&app_clone, |t| {
                    t.phase = crate::models::AgentPhase::Failed;
                    t.current_step = format!("Identity Error: {}", e);
                });
                return;
            }
        };

        let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&raw_key).unwrap();
        let pk_bytes = keypair.public().encode_protobuf();
        let account_id = AccountId(
             account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes).unwrap()
        );
        
        // --- CONVERGENT RETRY LOOP ---
        let mut attempts = 0;
        let max_retries = 8;
        let mut backoff_ms = 100;
        let mut nonce_offset = 0;
        let mut last_state_nonce: Option<u64> = None;
        let mut success = false; // [FIX] Defined flag
        let mut last_error: Option<String> = None;

        while attempts < max_retries {
            // 1. Fetch State Nonce (Base)
            let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
            let state_nonce = match client.query_raw_state(tonic::Request::new(QueryRawStateRequest { key: nonce_key })).await {
                 Ok(resp) => {
                     let val = resp.into_inner().value;
                     if val.is_empty() { 0 } else {
                         codec::from_bytes_canonical::<u64>(&val).unwrap_or(0)
                     }
                 },
                 Err(_) => 0,
            };
            
            // If block committed and state advanced, reset our offset logic to avoid overshooting
            if last_state_nonce.map(|n| state_nonce > n).unwrap_or(false) {
                 nonce_offset = 0;
                 backoff_ms = 100; // Reset backoff on progress
            }
            last_state_nonce = Some(state_nonce);

            // Calculate candidate nonce based on offset strategy
            let nonce = state_nonce + nonce_offset;

            // ... (Payload construction and signing) ...
            let payload = SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "post_message@v1".to_string(),
                params: params_bytes.clone(),
            };
            
            let mut sys_tx = SystemTransaction {
                header: SignHeader {
                    account_id,
                    nonce,
                    chain_id: ChainId(0),
                    tx_version: 1,
                    session_auth: None,
                },
                payload,
                signature_proof: SignatureProof::default(),
            };
            
            let sign_bytes = sys_tx.to_sign_bytes().unwrap();
            let sig = keypair.sign(&sign_bytes).unwrap();
            
            sys_tx.signature_proof = SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: pk_bytes.clone(),
                signature: sig,
            };
            
            let tx = ChainTransaction::System(Box::new(sys_tx));
            let tx_bytes = codec::to_bytes_canonical(&tx).unwrap();
            
            // Submit
            match client.submit_transaction(tonic::Request::new(
                 ioi_ipc::public::SubmitTransactionRequest { transaction_bytes: tx_bytes }
            )).await {
                Ok(_) => {
                    println!("[Autopilot] Message sent successfully (Nonce: {})", nonce);
                    success = true; // [FIX] Set flag
                    break; 
                }
                Err(e) => {
                    attempts += 1;
                    let msg = e.message();
                    last_error = Some(msg.to_string());
                    
                    // Specific Error Matching
                    if msg.contains("already exists") || msg.contains("too low") {
                        // Collision: Increment and retry
                        println!("[Autopilot] Nonce {} collision/low. Incrementing...", nonce);
                        // [FIX] Explicit saturating add and clamp
                        nonce_offset = nonce_offset.saturating_add(1);
                        
                        // [FIX] Cap offset and force reset/backoff if we hit ceiling
                        if nonce_offset >= 32 {
                            nonce_offset = 0;
                            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                            backoff_ms = (backoff_ms * 2).min(2000);
                        }
                    } else if msg.contains("too high") || msg.contains("gap") || msg.contains("expected") {
                        // Gap: We are too far ahead. Reset offset and wait.
                        println!("[Autopilot] Nonce {} gap/high. Resetting offset and backing off.", nonce);
                        nonce_offset = 0;
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(2000);
                    } else if msg.contains("Ingestion queue full") {
                        // Transient load: Backoff
                         tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                         backoff_ms = (backoff_ms * 2).min(2000);
                    } else {
                        eprintln!("[Autopilot] Fatal submission error: {}", msg);
                        break;
                    }
                }
            }
        }

        if !success {
             let err_msg = last_error.unwrap_or_else(|| "Network busy (Nonce Lock)".to_string());
             update_task_state(&app_clone, move |t| {
                t.phase = crate::models::AgentPhase::Failed;
                t.current_step = format!("Failed to send message: {}", err_msg);
            });
        }
    });

    Ok(())
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