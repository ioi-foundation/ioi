use crate::identity;
use crate::kernel::notifications;
use crate::kernel::state::update_task_state;
use crate::models::{
    AgentEvent, AgentPhase, AgentTask, AppState, ChatMessage, EventStatus, EventType,
    SessionSummary,
};
use crate::orchestrator;
use crate::windows;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{DraftTransactionRequest, SubmitTransactionRequest};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};

fn input_probe_logging_enabled() -> bool {
    std::env::var("AUTOPILOT_INPUT_PROBE_LOG")
        .map(|v| {
            let t = v.trim();
            t == "1"
                || t.eq_ignore_ascii_case("true")
                || t.eq_ignore_ascii_case("yes")
                || t.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn generate_session_id_hex() -> String {
    let mut session_bytes = [0u8; 32];
    session_bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    session_bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    hex::encode(session_bytes)
}

fn build_user_input_event(thread_id: &str, step_index: u32, text: &str) -> AgentEvent {
    AgentEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: now_iso(),
        thread_id: thread_id.to_string(),
        step_index,
        event_type: EventType::InfoNote,
        title: "User request".to_string(),
        digest: json!({
            "query": text,
        }),
        details: json!({
            "kind": "user_input",
            "text": text,
        }),
        artifact_refs: Vec::new(),
        receipt_ref: None,
        input_refs: Vec::new(),
        status: EventStatus::Success,
        duration_ms: None,
    }
}

#[derive(Encode, Decode)]
struct PostMessageParams {
    pub session_id: [u8; 32],
    pub role: String,
    pub content: String,
}

fn normalize_session_id(session_id: &str) -> Result<[u8; 32], String> {
    let clean_session_id = session_id.replace('-', "");
    let session_bytes = hex::decode(&clean_session_id).map_err(|_| "Invalid session ID hex")?;
    if session_bytes.len() > 32 {
        return Err("Session ID too long".into());
    }

    let mut session_arr = [0u8; 32];
    session_arr[..session_bytes.len()].copy_from_slice(&session_bytes);
    Ok(session_arr)
}

fn encode_post_message_params(session_id: [u8; 32], content: String) -> Result<Vec<u8>, String> {
    let params = PostMessageParams {
        session_id,
        role: "user".to_string(),
        content,
    };
    codec::to_bytes_canonical(&params).map_err(|e| e.to_string())
}

fn build_post_message_tx_bytes(
    account_id: AccountId,
    nonce: u64,
    public_key: Vec<u8>,
    keypair: &libp2p::identity::Keypair,
    params_bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
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

    let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| e.to_string())?;
    let signature = keypair.sign(&sign_bytes).map_err(|e| e.to_string())?;

    sys_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature,
    };

    let tx = ChainTransaction::System(Box::new(sys_tx));
    codec::to_bytes_canonical(&tx).map_err(|e| e.to_string())
}

async fn query_account_nonce(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    account_id: &AccountId,
) -> u64 {
    let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
    match client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key: nonce_key }))
        .await
    {
        Ok(resp) => {
            let val = resp.into_inner().value;
            if val.is_empty() {
                0
            } else {
                codec::from_bytes_canonical::<u64>(&val).unwrap_or(0)
            }
        }
        Err(_) => 0,
    }
}

async fn submit_post_message_with_nonce_retry(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    keypair: &libp2p::identity::Keypair,
    account_id: AccountId,
    public_key: Vec<u8>,
    params_bytes: Vec<u8>,
) -> Result<(), String> {
    let mut attempts = 0;
    let max_retries = 8;
    let mut backoff_ms = 100;
    let mut nonce_offset = 0;
    let mut last_state_nonce: Option<u64> = None;
    let mut last_error: Option<String> = None;

    while attempts < max_retries {
        let state_nonce = query_account_nonce(client, &account_id).await;

        if last_state_nonce.map(|n| state_nonce > n).unwrap_or(false) {
            nonce_offset = 0;
            backoff_ms = 100;
        }
        last_state_nonce = Some(state_nonce);

        let nonce = state_nonce + nonce_offset;

        let tx_bytes = build_post_message_tx_bytes(
            account_id.clone(),
            nonce,
            public_key.clone(),
            keypair,
            params_bytes.clone(),
        )?;

        match client
            .submit_transaction(tonic::Request::new(SubmitTransactionRequest {
                transaction_bytes: tx_bytes,
            }))
            .await
        {
            Ok(_) => {
                println!("[Autopilot] Message sent successfully (Nonce: {})", nonce);
                return Ok(());
            }
            Err(e) => {
                attempts += 1;
                let msg = e.message().to_string();
                last_error = Some(msg.clone());

                if msg.contains("already exists") || msg.contains("too low") {
                    println!("[Autopilot] Nonce {} collision/low. Incrementing...", nonce);
                    nonce_offset = nonce_offset.saturating_add(1);

                    if nonce_offset >= 32 {
                        nonce_offset = 0;
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(2000);
                    }
                } else if msg.contains("too high")
                    || msg.contains("gap")
                    || msg.contains("expected")
                {
                    println!(
                        "[Autopilot] Nonce {} gap/high. Resetting offset and backing off.",
                        nonce
                    );
                    nonce_offset = 0;
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(2000);
                } else if msg.contains("Ingestion queue full") {
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(2000);
                } else {
                    return Err(msg);
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "Network busy (Nonce Lock)".to_string()))
}

async fn submit_continue_via_ephemeral_post_message(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    params_bytes: Vec<u8>,
) -> Result<(), String> {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| e.to_string())?,
    );

    let tx_bytes = build_post_message_tx_bytes(account_id, 0, public_key, &keypair, params_bytes)?;

    client
        .submit_transaction(tonic::Request::new(SubmitTransactionRequest {
            transaction_bytes: tx_bytes,
        }))
        .await
        .map_err(|e| format!("Submission Error: {}", e))?;

    Ok(())
}

async fn submit_continue_authenticated(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    app: &AppHandle,
    params_bytes: Vec<u8>,
) -> Result<(), String> {
    let keypair = identity::load_identity_keypair_for_app(app)?;
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| e.to_string())?,
    );

    submit_post_message_with_nonce_retry(client, &keypair, account_id, public_key, params_bytes)
        .await
}

pub(crate) async fn send_message_to_session(
    app: &AppHandle,
    session_id: &str,
    user_input: String,
) -> Result<(), String> {
    let session_arr = normalize_session_id(session_id)?;
    let params_bytes = encode_post_message_params(session_arr, user_input.clone())?;
    let fallback_params_bytes = params_bytes.clone();
    let mut client = PublicApiClient::connect("http://127.0.0.1:9000")
        .await
        .map_err(|error| format!("Failed to connect for session message: {}", error))?;

    if let Err(base_err) = submit_continue_authenticated(&mut client, app, params_bytes).await {
        eprintln!(
            "[Autopilot] post_message@v1 session message did not converge. Falling back to ephemeral post_message flow: {}",
            base_err
        );
        submit_continue_via_ephemeral_post_message(&mut client, fallback_params_bytes)
            .await
            .map_err(|fallback_err| {
                format!(
                    "Failed to send message to session {}: {} | fallback: {}",
                    session_id, base_err, fallback_err
                )
            })?;
    }

    Ok(())
}

#[tauri::command]
pub fn start_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    intent: String,
) -> Result<AgentTask, String> {
    if input_probe_logging_enabled() {
        println!(
            "[Autopilot][InputProbe] start_task intent_len={} intent='{}'",
            intent.chars().count(),
            intent
        );
    }

    let history = vec![ChatMessage {
        role: "user".to_string(),
        text: intent.clone(),
        timestamp: crate::kernel::state::now(),
    }];

    let task_id = generate_session_id_hex();

    let mut task = AgentTask {
        id: task_id.clone(),
        session_id: Some(task_id.clone()),
        intent: intent.clone(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 20,
        current_step: "Initializing...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        credential_request: None,
        clarification_request: None,
        history,
        events: vec![build_user_input_event(&task_id, 0, &intent)],
        artifacts: Vec::new(),
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        swarm_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };

    let memory_runtime = {
        let app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.memory_runtime.clone()
    };

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        let run_bundle =
            crate::kernel::artifacts::create_run_bundle(memory_runtime, &task_id, &task_id, vec![]);
        task.run_bundle_id = Some(run_bundle.artifact_id.clone());
        task.artifacts.push(run_bundle.clone());
        let summary = SessionSummary {
            session_id: task_id.clone(),
            title: if intent.len() > 30 {
                format!("{}...", &intent[0..27])
            } else {
                intent.clone()
            },
            timestamp: crate::kernel::state::now(),
        };
        orchestrator::save_local_session_summary(memory_runtime, summary);
        orchestrator::save_local_task_state(memory_runtime, &task);
    }

    {
        let mut app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.current_task = Some(task.clone());
        app_state.gate_response = None;
    }

    let _ = app.emit("task-started", &task);
    crate::windows::show_spotlight(app.clone());

    let app_clone = app.clone();
    let effective_intent = format!("SESSION:{} {}", task_id, intent);

    tauri::async_runtime::spawn(async move {
        let mut client = match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[Autopilot] Kernel offline: {}", e);
                update_task_state(&app_clone, |t| {
                    t.current_step =
                        "Kernel Unreachable. Simulating offline response...".to_string();
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
pub async fn continue_task(
    _state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
    user_input: String,
) -> Result<(), String> {
    if input_probe_logging_enabled() {
        println!(
            "[Autopilot][InputProbe] continue_task input_len={} input='{}' session_id='{}'",
            user_input.chars().count(),
            user_input,
            session_id
        );
    }

    let user_msg_ui = ChatMessage {
        role: "user".to_string(),
        text: user_input.clone(),
        timestamp: crate::kernel::state::now(),
    };
    let user_input_for_event = user_input.clone();

    update_task_state(&app, move |t| {
        t.processed_steps.clear();
        t.history.push(user_msg_ui.clone());
        t.credential_request = None;
        t.clarification_request = None;
        let thread_id = t.session_id.clone().unwrap_or_else(|| t.id.clone());
        let step_index = t.progress;
        t.events.push(build_user_input_event(
            &thread_id,
            step_index,
            &user_input_for_event,
        ));
        t.current_step = "Sending message...".to_string();
        t.phase = AgentPhase::Running;
    });

    let session_arr = normalize_session_id(&session_id)?;
    let normalized_session_id = hex::encode(session_arr);
    notifications::resolve_intervention_by_dedupe_prefix(
        &app,
        &format!("clarification:{}:", session_id),
    );
    notifications::resolve_intervention_by_dedupe_prefix(
        &app,
        &format!("clarification:{}:", normalized_session_id),
    );
    let user_input_for_send = user_input.clone();

    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) =
            send_message_to_session(&app_clone, &normalized_session_id, user_input_for_send).await
        {
            update_task_state(&app_clone, move |t| {
                t.phase = AgentPhase::Failed;
                t.current_step = format!("Failed to send message: {}", error);
            });
        }
    });

    Ok(())
}

#[tauri::command]
pub fn update_task(
    _state: State<Mutex<AppState>>,
    app: AppHandle,
    task: AgentTask,
) -> Result<(), String> {
    update_task_state(&app, |t| *t = task.clone());
    Ok(())
}

#[tauri::command]
pub fn complete_task(
    _state: State<Mutex<AppState>>,
    app: AppHandle,
    success: bool,
) -> Result<(), String> {
    update_task_state(&app, |t| {
        t.phase = if success {
            AgentPhase::Complete
        } else {
            AgentPhase::Failed
        };
    });
    Ok(())
}

#[tauri::command]
pub fn dismiss_task(state: State<Mutex<AppState>>, app: AppHandle) -> Result<(), String> {
    if let Ok(mut app_state) = state.lock() {
        app_state.current_task = None;
        app_state.gate_response = None;
    }
    windows::hide_spotlight(app.clone());
    windows::hide_gate(app.clone());
    let _ = app.emit("task-dismissed", ());
    Ok(())
}

#[tauri::command]
pub fn get_current_task(state: State<Mutex<AppState>>) -> Option<AgentTask> {
    state.lock().ok().and_then(|s| s.current_task.clone())
}
