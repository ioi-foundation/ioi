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

// [NEW] Imports for continue_task
use ioi_services::agentic::desktop::types::PostMessageParams; // [FIX] Updated import
use ioi_scs::FrameType;
use dcrypt::algorithms::ByteSerializable;
use ioi_types::codec;
// [FIX] Import KernelChatMessage to resolve Encode trait issue
use ioi_types::app::agentic::ChatMessage as KernelChatMessage;
use ioi_types::app::{
    account_id_from_key_material, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction, AccountId
};

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

// [NEW] Command: Continue Task (Inbox Pattern)
// Sends a new user message to the Kernel via `post_message@v1`.
#[tauri::command]
pub async fn continue_task(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
    user_input: String,
) -> Result<(), String> {
    
    // 1. Optimistic UI Update
    // We update the local UI state immediately for responsiveness, but do NOT write to local SCS.
    // The Kernel will stream back the definitive history update shortly.
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

    // 2. Prepare Transaction Data
    let session_bytes = hex::decode(&session_id).map_err(|_| "Invalid session ID hex")?;
    let mut session_arr = [0u8; 32];
    session_arr.copy_from_slice(&session_bytes);

    let params = PostMessageParams {
        session_id: session_arr,
        role: "user".to_string(),
        content: user_input,
    };
    
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| e.to_string())?;
    
    // 3. Async Kernel Call
    let app_clone = app.clone();
    
    tauri::async_runtime::spawn(async move {
        // Re-acquire client in async context
        let mut client = match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[Autopilot] Failed to connect for continue_task: {}", e);
                return;
            }
        };
        
        // Load Key (Same logic as delete_session)
        let data_dir = app_clone.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("./ioi-data"));
        let key_path = data_dir.join("identity.key");
        if std::env::var("IOI_GUARDIAN_KEY_PASS").is_err() {
             unsafe { std::env::set_var("IOI_GUARDIAN_KEY_PASS", "local-mode"); }
        }
        
        let raw_key = match ioi_validator::common::GuardianContainer::load_encrypted_file(&key_path) {
            Ok(k) => k,
            Err(e) => { eprintln!("[Autopilot] Failed to load key: {}", e); return; }
        };
        
        let keypair = match libp2p::identity::Keypair::from_protobuf_encoding(&raw_key) {
            Ok(k) => k,
            Err(e) => { eprintln!("[Autopilot] Invalid key: {}", e); return; }
        };
        
        let pk_bytes = keypair.public().encode_protobuf();
        let account_id = AccountId(
             account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes).unwrap()
        );
        
        // Fetch Nonce
        let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
        let nonce = match client.query_raw_state(tonic::Request::new(ioi_ipc::blockchain::QueryRawStateRequest { key: nonce_key })).await {
             Ok(resp) => {
                 let val = resp.into_inner().value;
                 if val.is_empty() { 0 } else {
                     codec::from_bytes_canonical::<u64>(&val).unwrap_or(0)
                 }
             },
             Err(_) => 0,
        };

        // Construct Transaction
        // [FIX] Use post_message@v1
        let payload = SystemPayload::CallService {
            service_id: "desktop_agent".to_string(),
            method: "post_message@v1".to_string(),
            params: params_bytes,
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
            public_key: pk_bytes,
            signature: sig,
        };
        
        let tx = ChainTransaction::System(Box::new(sys_tx));
        let tx_bytes = codec::to_bytes_canonical(&tx).unwrap();
        
        // Submit
        if let Err(e) = client.submit_transaction(tonic::Request::new(
             ioi_ipc::public::SubmitTransactionRequest { transaction_bytes: tx_bytes }
        )).await {
             eprintln!("[Autopilot] Failed to submit message tx: {}", e);
             update_task_state(&app_clone, |t| {
                t.phase = AgentPhase::Failed;
                t.current_step = format!("Message Error: {}", e);
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