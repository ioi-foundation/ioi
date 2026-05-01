#[tauri::command]
pub async fn get_session_history(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<SessionSummary>, String> {
    Ok(refresh_cached_session_history(&state).await)
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

    let mut loaded_task = {
        let guard = state.lock().map_err(|_| "Lock fail")?;
        guard
            .memory_runtime
            .as_ref()
            .and_then(|memory_runtime| orchestrator::load_local_task(memory_runtime, &session_id))
    };

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
                let mut task = AgentTask {
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
                    credential_request: None,
                    clarification_request: None,
                    session_checklist: Vec::new(),
                    background_tasks: Vec::new(),
                    history,
                    events: Vec::new(),
                    artifacts: Vec::new(),
                    chat_session: None,
                    chat_outcome: None,
                    renderer_session: None,
                    build_session: None,
                    run_bundle_id: None,
                    processed_steps: HashSet::new(),
                    work_graph_tree: Vec::new(),
                    generation: 0,
                    lineage_id: "unknown-remote".to_string(),
                    fitness_score: 0.0,
                };
                task.sync_runtime_views();
                loaded_task = Some(task);
            }
        }
    }

    if let Some(mut task) = loaded_task {
        task.sync_runtime_views();
        {
            let mut app_state = state.lock().map_err(|_| "Lock fail")?;
            app_state.current_task = Some(task.clone());
        }
        let _ = app.emit("task-started", &task);
        emit_session_projection_update(&app, true).await;
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
    if let Ok(guard) = state.lock() {
        if let Some(memory_runtime) = guard.memory_runtime.as_ref() {
            orchestrator::delete_local_session_summary(memory_runtime, &session_id);
        }
    }

    if let Ok(mut client) = get_rpc_client(&state).await {
        let session_bytes = hex::decode(&session_id).unwrap_or_default();
        if !session_bytes.is_empty() {
            let keypair = identity::load_identity_keypair_for_app(&app)?;
            let pk_bytes = keypair.public().encode_protobuf();
            let account_id = ioi_types::app::AccountId(
                account_id_from_key_material(SignatureSuite::ED25519, &pk_bytes)
                    .map_err(|e| e.to_string())?,
            );

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

            let payload = SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "delete_session@v1".to_string(),
                params: session_bytes,
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
            let sig = keypair.sign(&sign_bytes).map_err(|e| e.to_string())?;

            sys_tx.signature_proof = SignatureProof {
                suite: SignatureSuite::ED25519,
                public_key: pk_bytes,
                signature: sig,
            };

            let tx = ChainTransaction::System(Box::new(sys_tx));
            let tx_bytes = codec::to_bytes_canonical(&tx).map_err(|e| e.to_string())?;

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

    emit_session_projection_update(&app, true).await;
    Ok(())
}
