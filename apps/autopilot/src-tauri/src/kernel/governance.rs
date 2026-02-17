use crate::kernel::state::{get_rpc_client, now, update_task_state};
use crate::models::{AgentPhase, AppState, ChatMessage, EventType, GateResponse};
use crate::windows;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    GetTransactionStatusRequest, SetRuntimeSecretRequest, SubmitTransactionRequest,
};
use ioi_services::agentic::desktop::keys as desktop_keys;
use ioi_services::agentic::desktop::AgentState;
use ioi_services::agentic::desktop::service::step::incident::IncidentState;
use ioi_types::app::action::{ApprovalScope, ApprovalToken, PiiApprovalAction};
use ioi_types::app::agentic::ResumeAgentParams;
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};
use tonic::transport::Channel;

fn decode_session_id_hex(session_id_hex: &str) -> Result<[u8; 32], String> {
    let normalized = session_id_hex
        .trim()
        .trim_start_matches("0x")
        .replace('-', "");
    let bytes = hex::decode(normalized).map_err(|e| e.to_string())?;
    let mut session_id = [0u8; 32];
    match bytes.len() {
        32 => {
            session_id.copy_from_slice(&bytes);
            Ok(session_id)
        }
        16 => {
            session_id[..16].copy_from_slice(&bytes);
            Ok(session_id)
        }
        _ => Err("Invalid session ID length".to_string()),
    }
}

async fn wait_for_gate_ready(
    client: &mut PublicApiClient<Channel>,
    session_id: [u8; 32],
    expected_request_hash: [u8; 32],
) -> Result<(), String> {
    // Race fix: the UI can receive REQUIRE_APPROVAL before the agent state (pending_tool_hash/jcs)
    // is committed on-chain. Submitting a resume tx too early is rejected by the validator.
    let ns_prefix = service_namespace_prefix("desktop_agent");
    let agent_state_key_local = desktop_keys::get_state_key(&session_id);
    let agent_state_key = [ns_prefix.as_slice(), agent_state_key_local.as_slice()].concat();
    let incident_key_local = desktop_keys::get_incident_key(&session_id);
    let incident_key = [ns_prefix.as_slice(), incident_key_local.as_slice()].concat();

    let poll_ms = 150u64;
    let timeout_ms = 5_000u64;
    let mut waited_ms = 0u64;

    loop {
        let resp = client
            .query_raw_state(tonic::Request::new(QueryRawStateRequest {
                key: agent_state_key.clone(),
            }))
            .await
            .map_err(|e| format!("Failed to query agent state for gate readiness: {}", e))?
            .into_inner();

        if resp.found && !resp.value.is_empty() {
            if let Ok(agent_state) = codec::from_bytes_canonical::<AgentState>(&resp.value) {
                // Not ready until both pending_tool_hash and pending_tool_jcs are committed.
                if let (Some(pending_tool_hash), Some(_pending_tool_jcs)) =
                    (agent_state.pending_tool_hash, agent_state.pending_tool_jcs.as_ref())
                {
                    // Policy gates bind directly to the pending tool hash.
                    if pending_tool_hash == expected_request_hash {
                        return Ok(());
                    }

                    // PII gates bind to an incident pending gate hash (decision hash), which can differ
                    // from the pending tool hash. Check incident state for a matching pending gate.
                    let incident_resp = client
                        .query_raw_state(tonic::Request::new(QueryRawStateRequest {
                            key: incident_key.clone(),
                        }))
                        .await
                        .map_err(|e| {
                            format!("Failed to query incident state for gate readiness: {}", e)
                        })?
                        .into_inner();

                    if incident_resp.found && !incident_resp.value.is_empty() {
                        if let Ok(incident) =
                            codec::from_bytes_canonical::<IncidentState>(&incident_resp.value)
                        {
                            let pending_gate_hash = incident
                                .pending_gate
                                .as_ref()
                                .and_then(|pending| {
                                    let normalized = pending
                                        .request_hash
                                        .trim()
                                        .trim_start_matches("0x")
                                        .to_string();
                                    hex::decode(normalized).ok().and_then(|bytes| {
                                        if bytes.len() == 32 {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(&bytes);
                                            Some(arr)
                                        } else {
                                            None
                                        }
                                    })
                                });

                            if pending_gate_hash == Some(expected_request_hash) {
                                return Ok(());
                            }

                            if let Some(pending_gate_hash) = pending_gate_hash {
                                return Err(format!(
                                    "Approval request mismatch: expected {}, pending_gate {} (pending_tool {})",
                                    hex::encode(expected_request_hash),
                                    hex::encode(pending_gate_hash),
                                    hex::encode(pending_tool_hash)
                                ));
                            }
                        }
                    }
                }
            }
        }

        if waited_ms >= timeout_ms {
            return Err(format!(
                "Gate not ready yet (pending action not committed after {}ms). Please try again.",
                timeout_ms
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
        waited_ms = waited_ms.saturating_add(poll_ms);
    }
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
    action: Option<String>,
) -> Result<(), String> {
    let mut session_id_hex = None;
    let mut request_hash_hex = None;
    let mut visual_hash_hex = None; // [NEW] Capture visual hash
    let mut is_pii_gate = false;
    let action_label = action;

    {
        if let Ok(mut s) = state.lock() {
            s.gate_response = Some(GateResponse {
                responded: true,
                approved,
            });
            if let Some(task) = &s.current_task {
                is_pii_gate = task
                    .gate_info
                    .as_ref()
                    .and_then(|info| info.pii.as_ref())
                    .is_some();
                session_id_hex = task.session_id.clone().or_else(|| Some(task.id.clone()));
                request_hash_hex = task.pending_request_hash.clone().or_else(|| {
                    task.events.iter().rev().find_map(|event| {
                        if event.event_type != EventType::Warning {
                            return None;
                        }
                        let verdict = event
                            .digest
                            .get("verdict")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        if !verdict.eq_ignore_ascii_case("REQUIRE_APPROVAL") {
                            return None;
                        }
                        event
                            .digest
                            .get("request_hash")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    })
                });
                visual_hash_hex = task.visual_hash.clone(); // [NEW] Capture visual hash
            }
        }
    }

    // Default gate action depends on whether the gate is PII-review bound or a normal policy gate.
    let mut action_label = action_label.unwrap_or_else(|| {
        if approved {
            if is_pii_gate {
                "approve_transform".to_string()
            } else {
                "approve".to_string()
            }
        } else if is_pii_gate {
            "deny".to_string()
        } else {
            "cancel".to_string()
        }
    });

    // Back-compat: older UI always sent approve_transform even for policy gates.
    if !is_pii_gate && action_label == "approve_transform" {
        action_label = "approve".to_string();
    }

    // Policy gate "cancel" means: don't submit anything; keep the agent paused.
    if !is_pii_gate && action_label == "cancel" {
        println!(
            "[Autopilot] Gate action 'cancel' for policy gate (no-op; agent remains paused)."
        );
        return Ok(());
    }

    let pii_action = match action_label.as_str() {
        "approve" => None,
        "approve_transform" => Some(PiiApprovalAction::ApproveTransform),
        "deny" => Some(PiiApprovalAction::Deny),
        "grant_scoped_exception" => Some(PiiApprovalAction::GrantScopedException),
        _ => {
            return Err(format!(
                "Unsupported gate action '{}'. Expected approve|approve_transform|deny|grant_scoped_exception|cancel.",
                action_label
            ));
        }
    };

    if !is_pii_gate
        && matches!(
            pii_action,
            Some(PiiApprovalAction::ApproveTransform) | Some(PiiApprovalAction::GrantScopedException)
        )
    {
        return Err(format!(
            "Unsupported gate action '{}' for policy gate. Expected 'approve' (or cancel).",
            action_label
        ));
    }

    let (Some(sid_hex), Some(hash_hex)) = (session_id_hex, request_hash_hex) else {
        return Err("Missing session_id or request_hash in state. Cannot submit gate response.".to_string());
    };

    println!(
        "[Autopilot] Processing gate action '{}' for Session {} / Hash {}",
        action_label, sid_hex, hash_hex
    );

    let session_id_arr = decode_session_id_hex(&sid_hex)?;
    let request_hash_bytes = hex::decode(&hash_hex).map_err(|e| e.to_string())?;
    if request_hash_bytes.len() != 32 {
        return Err("Invalid request hash length".to_string());
    }
    let mut request_hash_arr = [0u8; 32];
    request_hash_arr.copy_from_slice(&request_hash_bytes);

    // Ensure the pending approval state is actually committed before submitting a resume tx.
    // This prevents "approved" cards re-appearing due to validator rejection races.
    let mut client = get_rpc_client(&state).await?;
    wait_for_gate_ready(&mut client, session_id_arr, request_hash_arr).await?;

    // [NEW] Decode visual hash if present
    let visual_hash_arr = if let Some(v_hex) = visual_hash_hex {
        if let Ok(v_bytes) = hex::decode(&v_hex) {
            if v_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v_bytes);
                Some(arr)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let approver_kp = Ed25519KeyPair::generate().map_err(|e| e.to_string())?;
    let approver_pub = approver_kp.public_key();

    let token = ApprovalToken {
        request_hash: request_hash_arr,
        scope: ApprovalScope {
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            max_usages: Some(1),
        },
        visual_hash: visual_hash_arr,
        pii_action: pii_action.clone(),
        scoped_exception: None,
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

    let header = SignHeader {
        account_id: AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &approver_pub.to_bytes())
                .unwrap(),
        ),
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
            println!("[Autopilot] Gate action transaction submitted: {}", tx_hash);

            let mut attempts = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                attempts += 1;
                if attempts > 20 {
                    return Err(
                        "Timed out waiting for gate action transaction commit".to_string(),
                    );
                }

                let status_req = tonic::Request::new(GetTransactionStatusRequest {
                    tx_hash: tx_hash.clone(),
                });

                if let Ok(status_resp) = client.get_transaction_status(status_req).await {
                    let status_body = status_resp.into_inner();
                    let status = status_body.status;
                    if status == 3 {
                        println!("[Autopilot] Gate action transaction committed!");
                        break;
                    } else if status == 4 {
                        if status_body.error_message.trim().is_empty() {
                            return Err("Gate action transaction rejected".to_string());
                        }
                        return Err(format!(
                            "Gate action transaction rejected: {}",
                            status_body.error_message
                        ));
                    }
                }
            }

            update_task_state(&app, |t| {
                t.phase = AgentPhase::Running;
                t.gate_info = None;
                t.pending_request_hash = None;
                t.credential_request = None;
                t.clarification_request = None;
                t.current_step = match pii_action {
                    Some(PiiApprovalAction::Deny) => {
                        "Deny submitted. Failing current step...".to_string()
                    }
                    Some(PiiApprovalAction::GrantScopedException) => {
                        "Scoped exception granted. Resuming agent...".to_string()
                    }
                    Some(PiiApprovalAction::ApproveTransform) => {
                        "Transform approved. Resuming agent...".to_string()
                    }
                    None => "Approved. Resuming agent...".to_string(),
                };
                t.history.push(ChatMessage {
                    role: "system".to_string(),
                    text: match pii_action {
                        Some(PiiApprovalAction::Deny) => {
                            "❌ Deny submitted. Current step will fail closed.".to_string()
                        }
                        Some(PiiApprovalAction::GrantScopedException) => {
                            "✅ Scoped exception granted.".to_string()
                        }
                        Some(PiiApprovalAction::ApproveTransform) => {
                            "✅ Transform approved.".to_string()
                        }
                        None => "✅ Approved.".to_string(),
                    },
                    timestamp: now(),
                });
            });
            windows::hide_gate(app.clone());
            let _ = app.emit("gate-response", approved);
        }
        Err(e) => {
            eprintln!("[Autopilot] Failed to submit gate action transaction: {}", e);
            return Err(format!("Failed to submit gate action: {}", e));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn submit_runtime_password(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
    password: String,
) -> Result<(), String> {
    if password.trim().is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    let session_id_arr = decode_session_id_hex(&session_id)?;
    let session_id_hex = hex::encode(session_id_arr);
    let mut client = get_rpc_client(&state).await?;

    let secret_resp = client
        .set_runtime_secret(tonic::Request::new(SetRuntimeSecretRequest {
            session_id_hex: session_id_hex.clone(),
            secret_kind: "sudo_password".to_string(),
            secret_value: password,
            one_time: true,
            ttl_seconds: 120,
        }))
        .await
        .map_err(|e| format!("Failed to set runtime secret: {}", e))?
        .into_inner();

    if !secret_resp.accepted {
        return Err("Runtime secret was rejected".to_string());
    }

    let resume_params = ResumeAgentParams {
        session_id: session_id_arr,
        approval_token: None,
    };
    let params_bytes = codec::to_bytes_canonical(&resume_params).map_err(|e| e.to_string())?;
    let payload = SystemPayload::CallService {
        service_id: "desktop_agent".to_string(),
        method: "resume@v1".to_string(),
        params: params_bytes,
    };

    let approver_kp = Ed25519KeyPair::generate().map_err(|e| e.to_string())?;
    let approver_pub = approver_kp.public_key();
    let header = SignHeader {
        account_id: AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &approver_pub.to_bytes())
                .unwrap(),
        ),
        nonce: 0,
        chain_id: ChainId(0),
        tx_version: 1,
        session_auth: None,
    };
    let mut tx = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx.to_sign_bytes().map_err(|e| e.to_string())?;
    let sig = approver_kp.sign(&sign_bytes).map_err(|e| e.to_string())?;
    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: approver_pub.to_bytes(),
        signature: sig.to_bytes(),
    };

    let tx_bytes = codec::to_bytes_canonical(&ChainTransaction::System(Box::new(tx)))
        .map_err(|e| e.to_string())?;
    let submit_resp = client
        .submit_transaction(tonic::Request::new(SubmitTransactionRequest {
            transaction_bytes: tx_bytes,
        }))
        .await
        .map_err(|e| format!("Failed to submit resume transaction: {}", e))?
        .into_inner();

    let mut attempts = 0;
    let mut committed = false;
    let mut last_status: Option<i32> = None;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        attempts += 1;
        if attempts > 20 {
            break;
        }
        let status_resp = client
            .get_transaction_status(tonic::Request::new(GetTransactionStatusRequest {
                tx_hash: submit_resp.tx_hash.clone(),
            }))
            .await;
        if let Ok(status_resp) = status_resp {
            let status_body = status_resp.into_inner();
            let status = status_body.status;
            last_status = Some(status);
            if status == 3 {
                committed = true;
                break;
            }
            if status == 4 {
                let base = "Resume transaction was rejected by the chain";
                if status_body.error_message.trim().is_empty() {
                    return Err(base.to_string());
                }
                return Err(format!("{}: {}", base, status_body.error_message));
            }
        }
    }

    if !committed {
        return Err(format!(
            "Timed out waiting for resume transaction commit (last_status={})",
            last_status.unwrap_or_default()
        ));
    }

    update_task_state(&app, |t| {
        t.phase = AgentPhase::Running;
        t.gate_info = None;
        t.pending_request_hash = None;
        t.credential_request = None;
        t.clarification_request = None;
        t.current_step = "Retrying install with provided sudo password...".to_string();
        t.history.push(ChatMessage {
            role: "system".to_string(),
            text: "Retrying installation with provided sudo password.".to_string(),
            timestamp: now(),
        });
    });

    Ok(())
}
