// apps/autopilot/src-tauri/src/kernel/session.rs
use crate::kernel::state::get_rpc_client;
use crate::models::{AppState, SessionSummary};
use crate::orchestrator;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_scs::{FrameType, RetentionClass}; // [FIX] Import RetentionClass
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};

use ioi_types::app::{
    account_id_from_key_material, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction,
};

// [FIX] Local definition to avoid dependency on private/missing service types
#[derive(Decode, Encode)]
struct RemoteSessionSummary {
    pub session_id: Vec<u8>,
    pub title: String,
    pub timestamp: u64,
}

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
                    // [FIX] Use local RemoteSessionSummary struct
                    if let Ok(raw_history) =
                        codec::from_bytes_canonical::<Vec<RemoteSessionSummary>>(&inner.value)
                    {
                        let remote_sessions: Vec<SessionSummary> = raw_history
                            .into_iter()
                            .map(|s| SessionSummary {
                                session_id: hex::encode(s.session_id),
                                title: s.title,
                                timestamp: s.timestamp,
                            })
                            .collect();

                        // Merge avoiding duplicates (prefer remote if duplicate)
                        for r in remote_sessions {
                            if let Some(pos) = all_sessions
                                .iter()
                                .position(|l| l.session_id == r.session_id)
                            {
                                all_sessions[pos] = r;
                            } else {
                                all_sessions.push(r);
                            }
                        }
                    }
                }
            }
        }
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
) -> Result<crate::models::AgentTask, String> {
    use crate::kernel::state::hydrate_session_history;
    use crate::models::{AgentPhase, AgentTask};
    use std::collections::HashSet;
    use tauri::Emitter;

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
        println!(
            "[Kernel] Session {} not found locally, attempting remote hydrate...",
            session_id
        );
        if let Ok(mut client) = get_rpc_client(&state).await {
            let history = hydrate_session_history(&mut client, &session_id)
                .await
                .unwrap_or_default();
            if !history.is_empty() {
                loaded_task = Some(AgentTask {
                    id: session_id.clone(),
                    intent: history
                        .first()
                        .map(|m| m.text.clone())
                        .unwrap_or("Restored Session".into()),
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
                    events: Vec::new(),
                    artifacts: Vec::new(),
                    run_bundle_id: None,
                    processed_steps: HashSet::new(),
                    swarm_tree: Vec::new(),
                    // [FIX] Initialize missing evolutionary fields
                    generation: 0,
                    lineage_id: "unknown-remote".to_string(),
                    fitness_score: 0.0,
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

    Err(format!(
        "Session {} not found locally or remotely",
        session_id
    ))
}

#[tauri::command]
pub async fn delete_session(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
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
                            FrameType::System,
                            &bytes,
                            0,
                            [0u8; 32],
                            orchestrator::SESSION_INDEX_KEY,
                            RetentionClass::Archival, // [FIX] Add retention
                        );
                    }
                }
            }
        }
    }

    // 2. Remote Delete
    if let Ok(mut client) = get_rpc_client(&state).await {
        let session_bytes = hex::decode(&session_id).unwrap_or_default();
        if !session_bytes.is_empty() {
            // A. Load Identity Key
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("./ioi-data"));
            let key_path = data_dir.join("identity.key");

            // Ensure password env var is set for dev mode (default fallback)
            if std::env::var("IOI_GUARDIAN_KEY_PASS").is_err() {
                unsafe {
                    std::env::set_var("IOI_GUARDIAN_KEY_PASS", "local-mode");
                }
            }

            // Load and decrypt key
            let raw_key = ioi_validator::common::GuardianContainer::load_encrypted_file(&key_path)
                .map_err(|e| format!("Failed to load identity key: {}", e))?;

            let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&raw_key)
                .map_err(|e| e.to_string())?;

            let pk_bytes = keypair.public().encode_protobuf();
            let account_id = ioi_types::app::AccountId(
                account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
                    .map_err(|e| e.to_string())?,
            );

            // B. Fetch Nonce from Chain
            let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
            let nonce = match client
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
            };

            // C. Build Transaction
            let payload = SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "delete_session@v1".to_string(),
                params: session_bytes,
            };

            let mut sys_tx = SystemTransaction {
                header: SignHeader {
                    account_id,
                    nonce,
                    chain_id: ChainId(0), // Assume local chain ID 0
                    tx_version: 1,
                    session_auth: None,
                },
                payload,
                signature_proof: SignatureProof::default(),
            };

            // D. Sign Transaction
            let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| e.to_string())?;

            let sig = keypair.sign(&sign_bytes).map_err(|e| e.to_string())?;

            sys_tx.signature_proof = SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: pk_bytes,
                signature: sig,
            };

            let tx = ChainTransaction::System(Box::new(sys_tx));
            let tx_bytes = codec::to_bytes_canonical(&tx).map_err(|e| e.to_string())?;

            // E. Submit to Kernel
            client
                .submit_transaction(tonic::Request::new(
                    ioi_ipc::public::SubmitTransactionRequest {
                        transaction_bytes: tx_bytes,
                    },
                ))
                .await
                .map_err(|e| e.to_string())?;

            println!(
                "[Kernel] Remote delete transaction submitted for session {}",
                session_id
            );
        }
    }

    Ok(())
}
