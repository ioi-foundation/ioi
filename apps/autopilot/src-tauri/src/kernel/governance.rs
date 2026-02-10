use crate::kernel::state::{get_rpc_client, now, update_task_state};
use crate::models::{AgentPhase, AppState, ChatMessage, GateResponse};
use crate::windows;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_ipc::public::{GetTransactionStatusRequest, SubmitTransactionRequest};
use ioi_types::app::action::{ApprovalScope, ApprovalToken};
use ioi_types::app::agentic::ResumeAgentParams;
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};

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
    let mut visual_hash_hex = None; // [NEW] Capture visual hash

    {
        if let Ok(mut s) = state.lock() {
            s.gate_response = Some(GateResponse {
                responded: true,
                approved,
            });
            if let Some(task) = &s.current_task {
                session_id_hex = task.session_id.clone();
                request_hash_hex = task.pending_request_hash.clone();
                visual_hash_hex = task.visual_hash.clone(); // [NEW] Capture visual hash
            }
        }
    }

    windows::hide_gate(app.clone());
    let _ = app.emit("gate-response", approved);

    if approved {
        if let (Some(sid_hex), Some(hash_hex)) = (session_id_hex, request_hash_hex) {
            println!(
                "[Autopilot] Processing approval for Session {} / Hash {}",
                sid_hex, hash_hex
            );

            let session_id_bytes = hex::decode(&sid_hex).map_err(|e| e.to_string())?;
            let mut session_id_arr = [0u8; 32];
            if session_id_bytes.len() != 32 {
                return Err("Invalid session ID len".into());
            }
            session_id_arr.copy_from_slice(&session_id_bytes);

            let request_hash_bytes = hex::decode(&hash_hex).map_err(|e| e.to_string())?;
            let mut request_hash_arr = [0u8; 32];
            request_hash_arr.copy_from_slice(&request_hash_bytes);

            // [NEW] Decode visual hash if present
            let visual_hash_arr = if let Some(v_hex) = visual_hash_hex {
                if let Ok(v_bytes) = hex::decode(&v_hex) {
                     if v_bytes.len() == 32 {
                         let mut arr = [0u8; 32];
                         arr.copy_from_slice(&v_bytes);
                         Some(arr)
                     } else { None }
                } else { None }
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
                visual_hash: visual_hash_arr, // [FIX] Added visual_hash
                approver_sig: vec![],
                approver_suite: SignatureSuite::ED25519,
            };

            let mut token_for_signing = token.clone();
            let token_bytes =
                codec::to_bytes_canonical(&token_for_signing).map_err(|e| e.to_string())?;
            let sig = approver_kp
                .sign(&token_bytes)
                .map_err(|e| e.to_string())?;

            token_for_signing.approver_sig = sig.to_bytes();
            token_for_signing.approver_suite = SignatureSuite::ED25519;

            let resume_params = ResumeAgentParams {
                session_id: session_id_arr,
                approval_token: Some(token_for_signing),
            };
            let params_bytes =
                codec::to_bytes_canonical(&resume_params).map_err(|e| e.to_string())?;

            let sys_payload = SystemPayload::CallService {
                service_id: "desktop_agent".to_string(),
                method: "resume@v1".to_string(),
                params: params_bytes,
            };

            let mut client = get_rpc_client(&state).await?;

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
            let final_tx_bytes =
                codec::to_bytes_canonical(&final_tx).map_err(|e| e.to_string())?;

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

                        let status_req = tonic::Request::new(GetTransactionStatusRequest {
                            tx_hash: tx_hash.clone(),
                        });

                        if let Ok(status_resp) = client.get_transaction_status(status_req).await {
                            let status = status_resp.into_inner().status;
                            if status == 3 {
                                // Committed
                                println!("[Autopilot] Approval transaction committed!");
                                break;
                            } else if status == 4 {
                                // Rejected
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
                }
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