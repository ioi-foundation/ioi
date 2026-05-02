use crate::kernel::notifications;
use crate::kernel::state::{get_rpc_client, now, update_task_state};
use crate::models::{AgentPhase, AppState, ChatMessage, EventType, GateResponse};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    GetTransactionStatusRequest, SetRuntimeSecretRequest, SubmitTransactionRequest,
};
use ioi_services::agentic::policy::augment_workspace_filesystem_policy;
use ioi_services::agentic::rules::ActionRules;
use ioi_services::agentic::runtime::keys as runtime_keys;
use ioi_services::agentic::runtime::service::decision_loop::helpers::default_safe_policy;
use ioi_services::agentic::runtime::service::recovery::incident::IncidentState;
use ioi_services::agentic::runtime::types::RegisterApprovalAuthorityParams;
use ioi_services::agentic::runtime::{AgentState, DenyAgentParams, ResumeAgentParams};
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant, PiiApprovalAction};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use std::sync::Mutex;
use tauri::{AppHandle, State};
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

fn decode_hash_hex32(input: &str) -> Option<[u8; 32]> {
    let normalized = input.trim().trim_start_matches("0x").replace('-', "");
    let bytes = hex::decode(normalized).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

async fn query_committed_agent_state(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<AgentState>, String> {
    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .map_err(|e| format!("Failed to query committed agent state: {}", e))?
        .into_inner();

    if !resp.found || resp.value.is_empty() {
        return Ok(None);
    }

    Ok(codec::from_bytes_canonical::<AgentState>(&resp.value).ok())
}

async fn query_committed_incident_state(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<IncidentState>, String> {
    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .map_err(|e| format!("Failed to query committed incident state: {}", e))?
        .into_inner();

    if !resp.found || resp.value.is_empty() {
        return Ok(None);
    }

    Ok(codec::from_bytes_canonical::<IncidentState>(&resp.value).ok())
}

async fn query_raw_state_value(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .map_err(|e| format!("Failed to query committed state: {}", e))?
        .into_inner();

    if !resp.found || resp.value.is_empty() {
        return Ok(None);
    }

    Ok(Some(resp.value))
}

fn desktop_agent_state_key(local_key: &[u8]) -> Vec<u8> {
    let ns_prefix = service_namespace_prefix("desktop_agent");
    [ns_prefix.as_slice(), local_key].concat()
}

fn desktop_agent_action_policy_key(session_id: &[u8; 32]) -> Vec<u8> {
    desktop_agent_state_key(&[runtime_keys::AGENT_POLICY_PREFIX, session_id.as_slice()].concat())
}

fn desktop_agent_approval_policy_hash_key(
    session_id: &[u8; 32],
    request_hash: &[u8; 32],
) -> Vec<u8> {
    desktop_agent_state_key(&runtime_keys::get_approval_policy_hash_key(
        session_id,
        request_hash,
    ))
}

async fn query_action_rules_for_session(
    client: &mut PublicApiClient<Channel>,
    session_id: [u8; 32],
) -> Result<ActionRules, String> {
    let query_timeout = std::time::Duration::from_millis(750);
    let session_policy_key = desktop_agent_action_policy_key(&session_id);
    match tokio::time::timeout(
        query_timeout,
        query_raw_state_value(client, session_policy_key),
    )
    .await
    {
        Ok(Ok(Some(bytes))) => {
            if let Ok(rules) = codec::from_bytes_canonical::<ActionRules>(&bytes) {
                return Ok(rules);
            }
        }
        Ok(Ok(None)) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            println!(
                "[Autopilot] Session policy lookup timed out for Session {}. Falling back to global/default policy hash.",
                hex::encode(session_id)
            );
        }
    }

    let global_policy_key = desktop_agent_action_policy_key(&[0u8; 32]);
    match tokio::time::timeout(
        query_timeout,
        query_raw_state_value(client, global_policy_key),
    )
    .await
    {
        Ok(Ok(Some(bytes))) => {
            if let Ok(rules) = codec::from_bytes_canonical::<ActionRules>(&bytes) {
                return Ok(rules);
            }
        }
        Ok(Ok(None)) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            println!(
                "[Autopilot] Global policy lookup timed out for Session {}. Falling back to default policy hash.",
                hex::encode(session_id)
            );
        }
    }

    Ok(default_safe_policy())
}

fn install_denial_chat_message() -> &'static str {
    "Install approval denied. No host changes were made."
}

fn policy_hash_for_rules(rules: &ActionRules) -> Result<[u8; 32], String> {
    let canonical = serde_jcs::to_vec(rules).map_err(|e| e.to_string())?;
    let digest = sha256(&canonical).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn short_hash(hash: &[u8; 32]) -> String {
    hex::encode(&hash[..6])
}

async fn policy_hash_for_committed_execution_context(
    client: &mut PublicApiClient<Channel>,
    session_id: [u8; 32],
    request_hash: [u8; 32],
    rules: &ActionRules,
) -> Result<[u8; 32], String> {
    let committed_policy_hash_key =
        desktop_agent_approval_policy_hash_key(&session_id, &request_hash);
    if let Some(bytes) = query_raw_state_value(client, committed_policy_hash_key).await? {
        if bytes.len() == 32 {
            let mut committed = [0u8; 32];
            committed.copy_from_slice(&bytes);
            println!(
                "[Autopilot] Approval policy hash context session={} request_hash={} source=cec_pending_policy_hash policy_hash={}",
                hex::encode(&session_id[..4]),
                short_hash(&request_hash),
                short_hash(&committed),
            );
            return Ok(committed);
        }
    }

    let ns_prefix = service_namespace_prefix("desktop_agent");
    let agent_state_key_local = runtime_keys::get_state_key(&session_id);
    let agent_state_key = [ns_prefix.as_slice(), agent_state_key_local.as_slice()].concat();
    let committed_agent_state = query_committed_agent_state(client, agent_state_key).await?;
    let effective_rules = if let Some(agent_state) = committed_agent_state.as_ref() {
        augment_workspace_filesystem_policy(rules, Some(agent_state.working_directory.as_str()))
    } else {
        rules.clone()
    };
    let raw_hash = policy_hash_for_rules(rules)?;
    let effective_hash = policy_hash_for_rules(&effective_rules)?;
    println!(
        "[Autopilot] Approval policy hash context session={} policy_id={} defaults={:?} rule_count={} cwd={} raw_hash={} effective_hash={}",
        hex::encode(&session_id[..4]),
        rules.policy_id,
        rules.defaults,
        rules.rules.len(),
        committed_agent_state
            .as_ref()
            .map(|agent| agent.working_directory.as_str())
            .unwrap_or("<missing-agent-state>"),
        short_hash(&raw_hash),
        short_hash(&effective_hash),
    );
    Ok(effective_hash)
}

async fn wait_for_committed_gate_ready(
    client: &mut PublicApiClient<Channel>,
    session_id: [u8; 32],
    expected_request_hash: [u8; 32],
) -> Result<(), String> {
    // Race fix: the UI can receive REQUIRE_APPROVAL before the agent state (pending_tool_hash/jcs)
    // is committed on-chain. Submitting a resume tx too early is rejected by the validator.
    // This path intentionally polls committed raw state rather than runtime checkpoints because
    // validator approval logic binds to chain-visible pending hashes, not local mirrors.
    let ns_prefix = service_namespace_prefix("desktop_agent");
    let agent_state_key_local = runtime_keys::get_state_key(&session_id);
    let agent_state_key = [ns_prefix.as_slice(), agent_state_key_local.as_slice()].concat();
    let incident_key_local = runtime_keys::get_incident_key(&session_id);
    let incident_key = [ns_prefix.as_slice(), incident_key_local.as_slice()].concat();

    let poll_ms = 150u64;
    let query_timeout_ms = 750u64;
    let timeout_ms = 3_000u64;
    let mut waited_ms = 0u64;

    loop {
        let agent_state_result = tokio::time::timeout(
            std::time::Duration::from_millis(query_timeout_ms),
            query_committed_agent_state(client, agent_state_key.clone()),
        )
        .await;

        if let Ok(agent_state_result) = agent_state_result {
            if let Some(agent_state) = agent_state_result? {
                // Not ready until both pending_tool_hash and pending_tool_jcs are committed.
                if let (Some(pending_tool_hash), Some(_pending_tool_jcs)) = (
                    agent_state.pending_tool_hash,
                    agent_state.pending_tool_jcs.as_ref(),
                ) {
                    // Policy gates bind directly to the pending tool hash.
                    if pending_tool_hash == expected_request_hash {
                        return Ok(());
                    }

                    // PII gates bind to an incident pending gate hash (decision hash), which can differ
                    // from the pending tool hash. Check committed incident state for a matching pending gate.
                    let incident_result = tokio::time::timeout(
                        std::time::Duration::from_millis(query_timeout_ms),
                        query_committed_incident_state(client, incident_key.clone()),
                    )
                    .await;
                    if let Ok(incident_result) = incident_result {
                        if let Some(incident) = incident_result? {
                            let pending_gate_hash = incident
                                .pending_gate
                                .as_ref()
                                .and_then(|pending| decode_hash_hex32(&pending.request_hash));

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
            println!(
                "[Autopilot] Gate readiness probe did not converge after {}ms for Session {} / Hash {}. Proceeding; resume transaction validation remains authoritative.",
                timeout_ms,
                hex::encode(session_id),
                hex::encode(expected_request_hash)
            );
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
        waited_ms = waited_ms.saturating_add(poll_ms);
    }
}

fn build_service_call_transaction(
    signer: &Ed25519KeyPair,
    method: &str,
    params: Vec<u8>,
    nonce: u64,
) -> Result<ChainTransaction, String> {
    let signer_pub = signer.public_key();
    let account_id = account_id_from_key_material(SignatureSuite::ED25519, &signer_pub.to_bytes())
        .map_err(|e| e.to_string())?;
    let header = SignHeader {
        account_id: AccountId(account_id),
        nonce,
        chain_id: ChainId(0),
        tx_version: 1,
        session_auth: None,
    };
    let payload = SystemPayload::CallService {
        service_id: "desktop_agent".to_string(),
        method: method.to_string(),
        params,
    };
    let mut tx = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx.to_sign_bytes().map_err(|e| e.to_string())?;
    let sig = signer.sign(&sign_bytes).map_err(|e| e.to_string())?;
    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: signer_pub.to_bytes(),
        signature: sig.to_bytes(),
    };
    Ok(ChainTransaction::System(Box::new(tx)))
}

async fn submit_desktop_agent_call(
    client: &mut PublicApiClient<Channel>,
    method: &str,
    params: Vec<u8>,
    signer: &Ed25519KeyPair,
    nonce: u64,
) -> Result<String, String> {
    let tx = build_service_call_transaction(signer, method, params, nonce)?;
    let tx_bytes = codec::to_bytes_canonical(&tx).map_err(|e| e.to_string())?;
    let submit_resp = client
        .submit_transaction(tonic::Request::new(SubmitTransactionRequest {
            transaction_bytes: tx_bytes,
        }))
        .await
        .map_err(|e| format!("Failed to submit {method} transaction: {e}"))?
        .into_inner();
    Ok(submit_resp.tx_hash)
}

async fn wait_for_transaction_commit(
    client: &mut PublicApiClient<Channel>,
    tx_hash: String,
    label: &str,
) -> Result<(), String> {
    let mut attempts = 0;
    let mut last_status: Option<i32> = None;
    let status_timeout = std::time::Duration::from_millis(750);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        attempts += 1;
        if attempts > 20 {
            break;
        }
        let status_resp = tokio::time::timeout(
            status_timeout,
            client.get_transaction_status(tonic::Request::new(GetTransactionStatusRequest {
                tx_hash: tx_hash.clone(),
            })),
        )
        .await;
        match status_resp {
            Ok(Ok(status_resp)) => {
                let status_body = status_resp.into_inner();
                let status = status_body.status;
                last_status = Some(status);
                if status == 3 {
                    return Ok(());
                }
                if status == 4 {
                    let base = format!("{label} transaction was rejected by the chain");
                    if status_body.error_message.trim().is_empty() {
                        return Err(base);
                    }
                    return Err(format!("{}: {}", base, status_body.error_message));
                }
            }
            Ok(Err(error)) => {
                println!(
                    "[Autopilot] {} transaction status query failed for {} on attempt {}: {}",
                    label, tx_hash, attempts, error
                );
            }
            Err(_) => {
                println!(
                    "[Autopilot] {} transaction status query timed out for {} on attempt {}",
                    label, tx_hash, attempts
                );
            }
        }
    }

    Err(format!(
        "Timed out waiting for {label} transaction commit (last_status={})",
        last_status.unwrap_or_default()
    ))
}

fn build_approval_artifacts(
    session_id: [u8; 32],
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    now_ms: u64,
) -> Result<(Ed25519KeyPair, ApprovalAuthority, ApprovalGrant), String> {
    let keypair = Ed25519KeyPair::generate().map_err(|e| e.to_string())?;
    let public_key = keypair.public_key().to_bytes();
    let authority_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)
        .map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&request_hash);
    let expires_at = now_ms.saturating_add(120_000);
    let authority = ApprovalAuthority {
        schema_version: 1,
        authority_id,
        public_key: public_key.clone(),
        signature_suite: SignatureSuite::ED25519,
        expires_at,
        revoked: false,
        scope_allowlist: vec!["desktop_agent.resume".to_string()],
    };
    let mut grant = ApprovalGrant {
        schema_version: 1,
        authority_id,
        request_hash,
        policy_hash,
        audience: session_id,
        nonce,
        counter: 1,
        expires_at,
        max_usages: Some(1),
        window_id: None,
        pii_action: None,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: public_key,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let signing_bytes = grant.signing_bytes().map_err(|e| e.to_string())?;
    grant.approver_sig = keypair
        .sign(&signing_bytes)
        .map_err(|e| e.to_string())?
        .to_bytes()
        .to_vec();
    authority.verify().map_err(|e| e.to_string())?;
    grant.verify().map_err(|e| e.to_string())?;
    Ok((keypair, authority, grant))
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
    request_hash: Option<String>,
) -> Result<(), String> {
    let mut session_id_hex = None;
    let mut request_hash_hex = None;
    let mut visual_hash_hex = None; // Capture visual hash
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
                request_hash_hex = request_hash.clone().or_else(|| {
                    task.pending_request_hash.clone().or_else(|| {
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
                    })
                });
                visual_hash_hex = task.visual_hash.clone(); // Capture visual hash
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
        println!("[Autopilot] Gate action 'cancel' for policy gate (no-op; agent remains paused).");
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
            Some(PiiApprovalAction::ApproveTransform)
                | Some(PiiApprovalAction::GrantScopedException)
        )
    {
        return Err(format!(
            "Unsupported gate action '{}' for policy gate. Expected 'approve' (or cancel).",
            action_label
        ));
    }

    let (Some(sid_hex), Some(hash_hex)) = (session_id_hex, request_hash_hex) else {
        return Err(
            "Missing session_id or request_hash in state. Cannot submit gate response.".to_string(),
        );
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
    println!(
        "[Autopilot] Waiting for committed gate readiness for Session {} / Hash {}",
        sid_hex, hash_hex
    );
    wait_for_committed_gate_ready(&mut client, session_id_arr, request_hash_arr).await?;
    println!(
        "[Autopilot] Gate readiness probe finished for Session {} / Hash {}",
        sid_hex, hash_hex
    );

    if !is_pii_gate && action_label == "deny" {
        let deny_params = DenyAgentParams {
            session_id: session_id_arr,
            request_hash: Some(request_hash_arr),
            reason: "Denied from chat approval card.".to_string(),
        };
        let deny_params_bytes =
            codec::to_bytes_canonical(&deny_params).map_err(|e| e.to_string())?;
        let tx_signer = Ed25519KeyPair::generate().map_err(|e| e.to_string())?;

        update_task_state(&app, |t| {
            t.phase = AgentPhase::Complete;
            t.gate_info = None;
            t.pending_request_hash = None;
            t.credential_request = None;
            t.clarification_request = None;
            t.current_step = "Install approval denied.".to_string();
            t.history.push(ChatMessage {
                role: "assistant".to_string(),
                text: install_denial_chat_message().to_string(),
                timestamp: now(),
            });
        });
        notifications::resolve_intervention_by_dedupe_prefix(
            &app,
            &format!("approval:{}:", sid_hex),
        );
        let app_for_reconcile = app.clone();
        tauri::async_runtime::spawn(async move {
            match submit_desktop_agent_call(
                &mut client,
                "deny@v1",
                deny_params_bytes,
                &tx_signer,
                0,
            )
            .await
            {
                Ok(tx_hash) => {
                    if let Err(error) =
                        wait_for_transaction_commit(&mut client, tx_hash, "Deny").await
                    {
                        eprintln!(
                            "[Autopilot] Deny transaction did not commit before returning local denial state: {}",
                            error
                        );
                    }
                }
                Err(error) => {
                    eprintln!(
                        "[Autopilot] Failed to submit deny transaction after local denial state: {}",
                        error
                    );
                }
            }
            crate::kernel::task::spawn_session_state_reconciler(app_for_reconcile, session_id_arr);
        });
        return Ok(());
    }

    // Decode visual hash if present
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

    let _ = visual_hash_arr;

    if !is_pii_gate && action_label == "approve" {
        println!(
            "[Autopilot] Resolving policy hash for approval grant for Session {}",
            sid_hex
        );
        let rules = query_action_rules_for_session(&mut client, session_id_arr).await?;
        let policy_hash = policy_hash_for_committed_execution_context(
            &mut client,
            session_id_arr,
            request_hash_arr,
            &rules,
        )
        .await?;
        let (authority_signer, authority, approval_grant) =
            build_approval_artifacts(session_id_arr, request_hash_arr, policy_hash, now())?;
        let register_params = RegisterApprovalAuthorityParams { authority };
        println!(
            "[Autopilot] Submitting approval authority transaction for Session {}",
            sid_hex
        );
        let register_tx_hash = submit_desktop_agent_call(
            &mut client,
            "register_approval_authority@v1",
            codec::to_bytes_canonical(&register_params).map_err(|e| e.to_string())?,
            &authority_signer,
            0,
        )
        .await?;
        println!(
            "[Autopilot] Approval authority tx submitted for Session {}: {}",
            sid_hex, register_tx_hash
        );
        wait_for_transaction_commit(&mut client, register_tx_hash, "Approval authority").await?;
        println!(
            "[Autopilot] Approval authority committed for Session {}",
            sid_hex
        );

        let resume_params = ResumeAgentParams {
            session_id: session_id_arr,
            approval_grant: Some(approval_grant),
        };
        let resume_signer = Ed25519KeyPair::generate().map_err(|e| e.to_string())?;
        println!(
            "[Autopilot] Submitting resume transaction for Session {}",
            sid_hex
        );
        let resume_tx_hash = submit_desktop_agent_call(
            &mut client,
            "resume@v1",
            codec::to_bytes_canonical(&resume_params).map_err(|e| e.to_string())?,
            &resume_signer,
            0,
        )
        .await?;
        println!(
            "[Autopilot] Resume tx submitted for Session {}: {}",
            sid_hex, resume_tx_hash
        );
        wait_for_transaction_commit(&mut client, resume_tx_hash, "Resume").await?;
        println!("[Autopilot] Resume committed for Session {}", sid_hex);

        crate::kernel::task::trigger_agent_step_for_session(
            &mut client,
            &app,
            session_id_arr,
            None,
        )
        .await
        .map_err(|error| format!("Failed to trigger approved install step: {}", error))?;
        crate::kernel::task::spawn_session_state_reconciler(app.clone(), session_id_arr);

        update_task_state(&app, |t| {
            t.phase = AgentPhase::Running;
            t.gate_info = None;
            t.pending_request_hash = None;
            t.credential_request = None;
            t.clarification_request = None;
            t.current_step = "Install approval granted. Resuming execution...".to_string();
            t.history.push(ChatMessage {
                role: "system".to_string(),
                text: "Install approval granted. Resuming execution.".to_string(),
                timestamp: now(),
            });
        });
        notifications::resolve_intervention_by_dedupe_prefix(
            &app,
            &format!("approval:{}:", sid_hex),
        );
        return Ok(());
    }

    Err(format!(
        "Unsupported gate action '{}' for this gate.",
        action_label
    ))
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
        approval_grant: None,
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

    crate::kernel::task::trigger_agent_step_for_session(&mut client, &app, session_id_arr, None)
        .await
        .map_err(|error| format!("Failed to trigger resumed install step: {}", error))?;
    crate::kernel::task::spawn_session_state_reconciler(app.clone(), session_id_arr);

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
    notifications::resolve_intervention_by_dedupe_prefix(
        &app,
        &format!("credential:{}:sudo_password", session_id),
    );
    notifications::resolve_intervention_by_dedupe_prefix(
        &app,
        &format!("credential:{}:sudo_password", session_id_hex),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_artifact_binds_chat_gate_request_to_desktop_resume_scope() {
        let session_id = [7u8; 32];
        let request_hash = [9u8; 32];
        let policy_hash = policy_hash_for_rules(&ActionRules::default()).expect("policy hash");
        let (_signer, authority, grant) =
            build_approval_artifacts(session_id, request_hash, policy_hash, 1_000)
                .expect("approval artifacts");

        assert_eq!(grant.request_hash, request_hash);
        assert_eq!(grant.policy_hash, policy_hash);
        assert_eq!(grant.audience, session_id);
        assert_eq!(authority.authority_id, grant.authority_id);
        assert_eq!(
            authority.scope_allowlist,
            vec!["desktop_agent.resume".to_string()]
        );
        grant.verify().expect("grant verifies");
        authority.verify().expect("authority verifies");
    }

    #[test]
    fn policy_gate_deny_submits_deny_method_not_resume_grant() {
        let session_id = [3u8; 32];
        let request_hash = [4u8; 32];
        let deny_params = DenyAgentParams {
            session_id,
            request_hash: Some(request_hash),
            reason: "Denied from chat approval card.".to_string(),
        };
        let bytes = codec::to_bytes_canonical(&deny_params).expect("encode deny params");
        let decoded: DenyAgentParams =
            codec::from_bytes_canonical(&bytes).expect("decode deny params");

        assert_eq!(decoded.session_id, session_id);
        assert_eq!(decoded.request_hash, Some(request_hash));
        assert!(decoded.reason.contains("chat approval card"));
    }

    #[test]
    fn approval_policy_hash_uses_executor_effective_workspace_policy() {
        let rules = ActionRules {
            policy_id: "local-dev".to_string(),
            defaults: ioi_services::agentic::rules::DefaultPolicy::AllowAll,
            ..ActionRules::default()
        };

        let raw_hash = policy_hash_for_rules(&rules).expect("raw policy hash");
        let effective = augment_workspace_filesystem_policy(&rules, Some("/workspace/project"));
        let effective_hash = policy_hash_for_rules(&effective).expect("effective policy hash");

        assert_ne!(
            raw_hash, effective_hash,
            "approval grants must bind to the same workspace-augmented policy hash used by CEC"
        );
    }

    #[test]
    fn approval_policy_lookup_uses_desktop_agent_namespace() {
        let session_id = [8u8; 32];
        let namespaced = desktop_agent_action_policy_key(&session_id);
        let root_policy_key = [runtime_keys::AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
        let expected = [
            service_namespace_prefix("desktop_agent").as_slice(),
            runtime_keys::AGENT_POLICY_PREFIX,
            session_id.as_slice(),
        ]
        .concat();

        assert_eq!(namespaced, expected);
        assert_ne!(
            namespaced, root_policy_key,
            "approval grants must be signed against the same namespaced policy source CEC loads"
        );
    }

    #[test]
    fn approval_policy_hash_fallback_uses_runtime_default_safe_policy() {
        let ui_fallback_hash = policy_hash_for_rules(&default_safe_policy()).expect("ui fallback");
        let executor_fallback_hash =
            policy_hash_for_rules(&default_safe_policy()).expect("executor fallback");
        let action_rules_default_hash =
            policy_hash_for_rules(&ActionRules::default()).expect("plain default");

        assert_eq!(ui_fallback_hash, executor_fallback_hash);
        assert_ne!(
            ui_fallback_hash, action_rules_default_hash,
            "approval fallback must match the executor policy loader, not ActionRules::default()"
        );
    }

    #[test]
    fn install_denial_message_is_visible_assistant_copy() {
        assert_eq!(
            install_denial_chat_message(),
            "Install approval denied. No host changes were made."
        );
        assert!(!install_denial_chat_message().contains("request_hash"));
    }
}
