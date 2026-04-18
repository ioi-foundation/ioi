use crate::identity;
use crate::kernel::notifications;
use crate::kernel::state::{hydrate_session_history, update_task_state};
use crate::models::{
    AgentEvent, AgentPhase, AgentTask, AppState, ChatMessage, CredentialRequest, EventStatus,
    EventType,
};
use crate::orchestrator;
use crate::windows;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{GetTransactionStatusRequest, SubmitTransactionRequest, TxStatus};
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::runtime::keys::get_state_key;
use ioi_services::agentic::runtime::{
    AgentMode, AgentState, AgentStatus, StartAgentParams, StepAgentParams,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use serde_json::json;
use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use tauri::{AppHandle, Emitter, Manager, Runtime, State};
use tokio::time::{sleep, timeout, Duration, Instant};

const TX_SUBMIT_TIMEOUT_MS: u64 = 8_000;
const SESSION_START_CONVERGENCE_TIMEOUT_MS: u64 = 15_000;
const CONTINUE_TASK_SEND_TIMEOUT_MS: u64 = 30_000;
const SESSION_START_CONVERGENCE_POLL_MS: u64 = 250;
const SESSION_STATE_RECONCILE_TIMEOUT_MS: u64 = 90_000;
const SESSION_STATE_RECONCILE_POLL_MS: u64 = 750;
const SESSION_BOOTSTRAP_STEP_RETRY_GRACE_MS: u64 = 2_000;
const SESSION_BOOTSTRAP_STEP_RETRY_INTERVAL_MS: u64 = 2_000;
const SESSION_BOOTSTRAP_STEP_MAX_RETRIES: usize = 4;
const AMBIENT_KNOWLEDGE_TIMEOUT_MS: u64 = 1_500;

static ACTIVE_SESSION_RECONCILERS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn active_session_reconcilers() -> &'static Mutex<HashSet<String>> {
    ACTIVE_SESSION_RECONCILERS.get_or_init(|| Mutex::new(HashSet::new()))
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

fn normalize_session_id_string(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("0x")
        .replace('-', "")
        .to_ascii_lowercase()
}

fn session_hex_matches_task(task: &AgentTask, session_id_hex: &str) -> bool {
    let task_session = task.session_id.as_deref().unwrap_or(task.id.as_str());
    normalize_session_id_string(task_session) == normalize_session_id_string(session_id_hex)
}

fn task_should_continue_through_kernel(task: &AgentTask) -> bool {
    !crate::kernel::studio::task_requires_studio_primary_execution(task)
}

fn apply_studio_route_handoff_to_runtime_input(task: &AgentTask, input: &str) -> String {
    crate::kernel::studio::runtime_handoff_prompt_prefix_for_task(task)
        .map(|prefix| format!("{prefix}\nUSER REQUEST:\n{input}"))
        .unwrap_or_else(|| input.to_string())
}

fn hydrate_requested_session_for_continue(
    state: &State<'_, Mutex<AppState>>,
    session_id: &str,
) -> Result<Option<AgentTask>, String> {
    let mut guard = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?;

    if let Some(current_task) = guard.current_task.as_ref() {
        if session_hex_matches_task(current_task, session_id) {
            return Ok(Some(current_task.clone()));
        }
    }

    let Some(memory_runtime) = guard.memory_runtime.as_ref() else {
        return Ok(guard.current_task.clone());
    };

    let Some(mut loaded_task) = orchestrator::load_local_task(memory_runtime, session_id) else {
        return Ok(guard.current_task.clone());
    };

    loaded_task.sync_runtime_views();
    guard.current_task = Some(loaded_task.clone());
    Ok(Some(loaded_task))
}

fn session_bootstrap_commit_delay_should_reconcile(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    normalized.contains("did not commit")
        || normalized.contains("already exists")
        || normalized.contains("inmempool")
        || normalized.contains("too low")
}

fn bootstrap_step_commit_delay_should_reconcile(error: &str) -> bool {
    session_bootstrap_commit_delay_should_reconcile(error)
}

fn workspace_workflow_expansion(
    input: &str,
) -> Result<Option<crate::kernel::workspace_workflows::WorkspaceWorkflowExpansion>, String> {
    crate::kernel::workspace_workflows::expand_workspace_workflow_intent(input)
}

fn app_runtime_resources(
    state: &State<'_, Mutex<AppState>>,
) -> Result<
    (
        Option<Arc<MemoryRuntime>>,
        Option<Arc<dyn ioi_api::vm::inference::InferenceRuntime>>,
    ),
    String,
> {
    let guard = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?;
    Ok((
        guard.memory_runtime.clone(),
        guard.inference_runtime.clone(),
    ))
}

fn maybe_inject_ambient_knowledge_sync(
    state: &State<'_, Mutex<AppState>>,
    app: &AppHandle,
    thread_id: &str,
    intent: &str,
) -> Result<Option<crate::kernel::runtime_parity::AmbientKnowledgeInjection>, String> {
    let (memory_runtime, inference_runtime) = app_runtime_resources(state)?;
    let Some(memory_runtime) = memory_runtime else {
        return Ok(None);
    };
    let Some(inference_runtime) = inference_runtime else {
        return Ok(None);
    };
    Ok(tauri::async_runtime::block_on(
        maybe_inject_ambient_knowledge_best_effort(
            app,
            &memory_runtime,
            &inference_runtime,
            thread_id,
            intent,
        ),
    ))
}

async fn run_best_effort_optional_future<T, F>(label: &str, future: F) -> Option<T>
where
    F: Future<Output = Result<Option<T>, String>>,
{
    match timeout(Duration::from_millis(AMBIENT_KNOWLEDGE_TIMEOUT_MS), future).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            eprintln!(
                "[Autopilot] {} skipped after recoverable failure: {}",
                label, error
            );
            None
        }
        Err(_) => {
            eprintln!(
                "[Autopilot] {} skipped after {}ms timeout",
                label, AMBIENT_KNOWLEDGE_TIMEOUT_MS
            );
            None
        }
    }
}

async fn maybe_inject_ambient_knowledge_best_effort<R: Runtime>(
    app: &AppHandle<R>,
    memory_runtime: &Arc<MemoryRuntime>,
    inference_runtime: &Arc<dyn ioi_api::vm::inference::InferenceRuntime>,
    thread_id: &str,
    intent: &str,
) -> Option<crate::kernel::runtime_parity::AmbientKnowledgeInjection> {
    run_best_effort_optional_future(
        "Ambient knowledge injection",
        crate::kernel::runtime_parity::inject_ambient_knowledge(
            app,
            memory_runtime,
            inference_runtime,
            thread_id,
            intent,
        ),
    )
    .await
}

fn replace_or_insert_task_artifact(task: &mut AgentTask, artifact: crate::models::Artifact) {
    let target_path = artifact
        .metadata
        .get("path")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    if let Some(path) = target_path.as_deref() {
        if let Some(existing) = task.artifacts.iter_mut().find(|candidate| {
            candidate.artifact_type == artifact.artifact_type
                && candidate
                    .metadata
                    .get("path")
                    .and_then(|value| value.as_str())
                    == Some(path)
        }) {
            *existing = artifact;
            return;
        }
    }
    if task
        .artifacts
        .iter()
        .any(|candidate| candidate.artifact_id == artifact.artifact_id)
    {
        return;
    }
    task.artifacts.push(artifact);
}

fn update_task_if_current_matches<F>(app: &AppHandle, expected_task_id: &str, mut f: F)
where
    F: FnMut(&mut AgentTask),
{
    update_task_state(app, |task| {
        if task.id == expected_task_id {
            f(task);
        }
    });
}

fn update_task_if_session_matches<F>(app: &AppHandle, expected_session_id: &str, mut f: F)
where
    F: FnMut(&mut AgentTask),
{
    update_task_state(app, |task| {
        if session_hex_matches_task(task, expected_session_id) {
            f(task);
        }
    });
}

fn replace_current_task_snapshot(
    app: &AppHandle,
    expected_task_id: &str,
    mut next_task: AgentTask,
) -> bool {
    let state = app.state::<Mutex<AppState>>();
    let mut task_clone: Option<AgentTask> = None;
    let mut memory_runtime = None;

    next_task.sync_runtime_views();

    if let Ok(mut app_state) = state.lock() {
        memory_runtime = app_state.memory_runtime.clone();
        if let Some(current_task) = app_state.current_task.as_mut() {
            if current_task.id == expected_task_id {
                if let Some(runtime) = memory_runtime.as_ref() {
                    if let Err(error) = crate::kernel::runtime_parity::sync_planning_artifacts(
                        app,
                        runtime,
                        &mut next_task,
                    ) {
                        eprintln!("[Autopilot] Failed to sync planning artifacts: {}", error);
                    }
                }
                *current_task = next_task;
                task_clone = Some(current_task.clone());
            }
        }
    }

    if let Some(task) = task_clone {
        if let Some(memory_runtime) = memory_runtime.as_ref() {
            orchestrator::save_local_task_state(memory_runtime, &task);
        }

        let event_name = if task.phase == AgentPhase::Complete
            && !crate::kernel::events::is_waiting_prompt_active(&task)
        {
            "task-completed"
        } else {
            "task-updated"
        };
        let _ = app.emit(event_name, &task);
        true
    } else {
        false
    }
}

fn bootstrap_step_label_for_state(agent_state: &AgentState) -> String {
    if agent_state.step_count == 0 {
        "Agent session queued. Waiting for first step...".to_string()
    } else {
        format!("Agent step {} in progress...", agent_state.step_count)
    }
}

fn should_replace_with_reconciled_running_step(current_step: &str) -> bool {
    let normalized = current_step.trim().to_ascii_lowercase();
    normalized.is_empty()
        || normalized == "initializing..."
        || normalized == "connecting to kernel..."
        || normalized == "submitting session start..."
        || normalized == "waiting for session start to commit..."
        || normalized == "waiting for message to commit..."
        || normalized == "scheduling first step..."
        || normalized == "agent session started. running first step..."
        || normalized == "sending message..."
        || normalized.contains("session state is reconciling")
        || normalized.contains("session state is still reconciling")
        || normalized.contains("session start commit is delayed")
        || normalized.contains("bootstrap is continuing in the background")
        || normalized.contains("recovering first step")
        || normalized.contains("bootstrap first-step recovery")
        || normalized.contains("waiting for first step")
        || normalized.contains("session queued")
}

fn bootstrap_state_still_needs_recovery(app: &AppHandle, session_id_hex: &str) -> bool {
    let state = app.state::<Mutex<AppState>>();
    let Ok(app_state) = state.lock() else {
        return true;
    };
    let Some(task) = app_state.current_task.as_ref() else {
        return true;
    };
    if !session_hex_matches_task(task, session_id_hex) {
        return false;
    }
    should_replace_with_reconciled_running_step(&task.current_step)
}

fn task_has_live_session_activity(task: &AgentTask) -> bool {
    !task.history.is_empty() || !task.events.is_empty() || !task.artifacts.is_empty()
}

fn submit_error_indicates_bootstrap_step_already_pending(error: &str) -> bool {
    let normalized = error.trim().to_ascii_lowercase();
    normalized.contains("already exists")
        || normalized.contains("duplicate")
        || normalized.contains("too low")
}

fn bootstrap_step_retry_interval_elapsed(last_bootstrap_retry_at: Option<Instant>) -> bool {
    last_bootstrap_retry_at
        .map(|ts| ts.elapsed() >= Duration::from_millis(SESSION_BOOTSTRAP_STEP_RETRY_INTERVAL_MS))
        .unwrap_or(true)
}

fn bootstrap_step_is_stalled(bootstrap_step_nonce: Option<u64>, agent_state: &AgentState) -> bool {
    bootstrap_step_nonce.is_some()
        && matches!(agent_state.status, AgentStatus::Idle | AgentStatus::Running)
        && agent_state.step_count == 0
}

fn bootstrap_step_should_escalate_pending_recovery(
    bootstrap_step_stalled: bool,
    bootstrap_retry_attempts: usize,
    bootstrap_fallback_attempted: bool,
    bootstrap_retry_window_open: bool,
    bootstrap_retry_interval_elapsed: bool,
) -> bool {
    bootstrap_step_stalled
        && bootstrap_retry_attempts >= SESSION_BOOTSTRAP_STEP_MAX_RETRIES
        && !bootstrap_fallback_attempted
        && bootstrap_retry_window_open
        && bootstrap_retry_interval_elapsed
}

async fn maybe_retry_or_escalate_bootstrap_step(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    app: &AppHandle,
    session_id: [u8; 32],
    session_id_hex: &str,
    bootstrap_step_nonce: Option<u64>,
    bootstrap_step_stalled: bool,
    bootstrap_retry_window_open: bool,
    bootstrap_retry_attempts: &mut usize,
    bootstrap_fallback_attempted: &mut bool,
    last_bootstrap_retry_at: &mut Option<Instant>,
) {
    if !bootstrap_step_stalled {
        return;
    }

    if bootstrap_step_nonce.is_some()
        && *bootstrap_retry_attempts < SESSION_BOOTSTRAP_STEP_MAX_RETRIES
        && bootstrap_retry_window_open
        && bootstrap_step_retry_interval_elapsed(*last_bootstrap_retry_at)
    {
        let nonce = bootstrap_step_nonce.expect("checked is_some");
        *bootstrap_retry_attempts += 1;
        *last_bootstrap_retry_at = Some(Instant::now());

        let step_params = match encode_step_agent_params(session_id) {
            Ok(params) => params,
            Err(error) => {
                eprintln!(
                    "[Autopilot] Bootstrap first-step retry encoding failed for {}: {}",
                    session_id_hex, error
                );
                Vec::new()
            }
        };

        if !step_params.is_empty() {
            match submit_step_authenticated_at_nonce(client, app, step_params, nonce).await {
                Ok(_tx_hash) => {
                    println!(
                        "[Autopilot] Re-submitted first step heartbeat for session {} (attempt {} nonce {}).",
                        session_id_hex, *bootstrap_retry_attempts, nonce
                    );
                }
                Err(error) if submit_error_indicates_bootstrap_step_already_pending(&error) => {
                    println!(
                        "[Autopilot] First step heartbeat for session {} already pending or consumed (attempt {} nonce {}).",
                        session_id_hex, *bootstrap_retry_attempts, nonce
                    );
                }
                Err(error) => {
                    eprintln!(
                        "[Autopilot] First step heartbeat retry failed for {} at nonce {} (attempt {}): {}",
                        session_id_hex, nonce, *bootstrap_retry_attempts, error
                    );
                }
            }
        }
    }

    if bootstrap_step_should_escalate_pending_recovery(
        bootstrap_step_stalled,
        *bootstrap_retry_attempts,
        *bootstrap_fallback_attempted,
        bootstrap_retry_window_open,
        bootstrap_step_retry_interval_elapsed(*last_bootstrap_retry_at),
    ) {
        *bootstrap_fallback_attempted = true;
        update_task_state(app, |task| {
            if session_hex_matches_task(task, session_id_hex) {
                task.phase = AgentPhase::Running;
                task.current_step =
                    "Recovering first step after bootstrap pending stall...".to_string();
            }
        });
        match trigger_agent_step_via_ephemeral_fallback(client, session_id).await {
            Ok(()) => {
                println!(
                    "[Autopilot] Escalated first-step recovery for session {} after {} pending bootstrap retries via ephemeral fallback.",
                    session_id_hex, *bootstrap_retry_attempts
                );
            }
            Err(error) => {
                eprintln!(
                    "[Autopilot] Escalated first-step recovery failed for {} after {} pending bootstrap retries: {}",
                    session_id_hex, *bootstrap_retry_attempts, error
                );
            }
        }
    }
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

fn encode_start_agent_params(session_id: [u8; 32], goal: String) -> Result<Vec<u8>, String> {
    let params = StartAgentParams {
        session_id,
        goal,
        max_steps: 20,
        parent_session_id: None,
        initial_budget: 1000,
        mode: AgentMode::Agent,
    };
    codec::to_bytes_canonical(&params).map_err(|e| e.to_string())
}

fn encode_step_agent_params(session_id: [u8; 32]) -> Result<Vec<u8>, String> {
    codec::to_bytes_canonical(&StepAgentParams { session_id }).map_err(|e| e.to_string())
}

fn build_signed_service_call_tx_bytes(
    account_id: AccountId,
    nonce: u64,
    public_key: Vec<u8>,
    keypair: &libp2p::identity::Keypair,
    service_id: &str,
    method: &str,
    params_bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let payload = SystemPayload::CallService {
        service_id: service_id.to_string(),
        method: method.to_string(),
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

fn build_post_message_tx_bytes(
    account_id: AccountId,
    nonce: u64,
    public_key: Vec<u8>,
    keypair: &libp2p::identity::Keypair,
    params_bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
    build_signed_service_call_tx_bytes(
        account_id,
        nonce,
        public_key,
        keypair,
        "desktop_agent",
        "post_message@v1",
        params_bytes,
    )
}

fn build_start_agent_tx_bytes(
    account_id: AccountId,
    nonce: u64,
    public_key: Vec<u8>,
    keypair: &libp2p::identity::Keypair,
    params_bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
    build_signed_service_call_tx_bytes(
        account_id,
        nonce,
        public_key,
        keypair,
        "desktop_agent",
        "start@v1",
        params_bytes,
    )
}

fn build_step_agent_tx_bytes(
    account_id: AccountId,
    nonce: u64,
    public_key: Vec<u8>,
    keypair: &libp2p::identity::Keypair,
    params_bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
    build_signed_service_call_tx_bytes(
        account_id,
        nonce,
        public_key,
        keypair,
        "desktop_agent",
        "step@v1",
        params_bytes,
    )
}

fn session_state_key(session_id: [u8; 32]) -> Vec<u8> {
    let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
    let local_key = get_state_key(&session_id);
    [ns_prefix.as_slice(), local_key.as_slice()].concat()
}

async fn submit_transaction_with_timeout(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    tx_bytes: Vec<u8>,
) -> Result<ioi_ipc::public::SubmitTransactionResponse, String> {
    let request = tonic::Request::new(SubmitTransactionRequest {
        transaction_bytes: tx_bytes,
    });

    timeout(
        Duration::from_millis(TX_SUBMIT_TIMEOUT_MS),
        client.submit_transaction(request),
    )
    .await
    .map_err(|_| {
        format!(
            "Submission timed out after {}ms while waiting for kernel RPC",
            TX_SUBMIT_TIMEOUT_MS
        )
    })?
    .map_err(|e| format!("Submission Error: {}", e))
    .map(|resp| resp.into_inner())
}

async fn query_account_nonce(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    account_id: &AccountId,
) -> u64 {
    let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
    match timeout(
        Duration::from_millis(TX_SUBMIT_TIMEOUT_MS),
        client.query_raw_state(tonic::Request::new(QueryRawStateRequest { key: nonce_key })),
    )
    .await
    {
        Ok(Ok(resp)) => {
            let val = resp.into_inner().value;
            if val.is_empty() {
                0
            } else {
                codec::from_bytes_canonical::<u64>(&val).unwrap_or(0)
            }
        }
        Ok(Err(error)) => {
            eprintln!(
                "[Autopilot] Failed to query account nonce from kernel RPC. Falling back to nonce 0: {}",
                error
            );
            0
        }
        Err(_) => {
            eprintln!(
                "[Autopilot] Timed out after {}ms while querying account nonce. Falling back to nonce 0.",
                TX_SUBMIT_TIMEOUT_MS
            );
            0
        }
    }
}

async fn submit_service_call_with_nonce_retry(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    keypair: &libp2p::identity::Keypair,
    account_id: AccountId,
    public_key: Vec<u8>,
    tx_builder: fn(
        AccountId,
        u64,
        Vec<u8>,
        &libp2p::identity::Keypair,
        Vec<u8>,
    ) -> Result<Vec<u8>, String>,
    params_bytes: Vec<u8>,
    success_log: &str,
) -> Result<(u64, String), String> {
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

        let tx_bytes = tx_builder(
            account_id.clone(),
            nonce,
            public_key.clone(),
            keypair,
            params_bytes.clone(),
        )?;

        match submit_transaction_with_timeout(client, tx_bytes).await {
            Ok(response) => {
                println!(
                    "[Autopilot] {} (Nonce: {}, TxHash: {})",
                    success_log, nonce, response.tx_hash
                );
                return Ok((nonce, response.tx_hash));
            }
            Err(e) => {
                attempts += 1;
                let msg = e;
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

async fn submit_post_message_with_nonce_retry(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    keypair: &libp2p::identity::Keypair,
    account_id: AccountId,
    public_key: Vec<u8>,
    params_bytes: Vec<u8>,
) -> Result<(u64, String), String> {
    submit_service_call_with_nonce_retry(
        client,
        keypair,
        account_id,
        public_key,
        build_post_message_tx_bytes,
        params_bytes,
        "Message sent successfully",
    )
    .await
}

async fn submit_start_agent_with_nonce_retry(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    keypair: &libp2p::identity::Keypair,
    account_id: AccountId,
    public_key: Vec<u8>,
    params_bytes: Vec<u8>,
) -> Result<(u64, String), String> {
    submit_service_call_with_nonce_retry(
        client,
        keypair,
        account_id,
        public_key,
        build_start_agent_tx_bytes,
        params_bytes,
        "Agent start submitted successfully",
    )
    .await
}

async fn submit_step_with_nonce_retry(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    keypair: &libp2p::identity::Keypair,
    account_id: AccountId,
    public_key: Vec<u8>,
    params_bytes: Vec<u8>,
) -> Result<(u64, String), String> {
    submit_service_call_with_nonce_retry(
        client,
        keypair,
        account_id,
        public_key,
        build_step_agent_tx_bytes,
        params_bytes,
        "Agent step submitted successfully",
    )
    .await
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

    let _ = submit_transaction_with_timeout(client, tx_bytes).await?;

    Ok(())
}

async fn submit_start_via_ephemeral_start_agent(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    params_bytes: Vec<u8>,
) -> Result<(), String> {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| e.to_string())?,
    );

    let tx_bytes = build_start_agent_tx_bytes(account_id, 0, public_key, &keypair, params_bytes)?;

    let _ = submit_transaction_with_timeout(client, tx_bytes).await?;

    Ok(())
}

async fn submit_step_via_ephemeral_agent_step(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    params_bytes: Vec<u8>,
) -> Result<String, String> {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| e.to_string())?,
    );

    let tx_bytes = build_step_agent_tx_bytes(account_id, 0, public_key, &keypair, params_bytes)?;

    let response = submit_transaction_with_timeout(client, tx_bytes).await?;

    Ok(response.tx_hash)
}

async fn trigger_agent_step_via_ephemeral_fallback(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    session_id: [u8; 32],
) -> Result<(), String> {
    let step_params = encode_step_agent_params(session_id)?;
    let tx_hash = submit_step_via_ephemeral_agent_step(client, step_params).await?;
    match wait_for_tx_commit(client, &tx_hash, SESSION_START_CONVERGENCE_TIMEOUT_MS).await {
        Ok(()) => Ok(()),
        Err(error) if bootstrap_step_commit_delay_should_reconcile(&error) => {
            println!(
                "[Autopilot] step@v1 ephemeral tx {} is still pending. Deferring commit confirmation to the reconciler: {}",
                tx_hash, error
            );
            Ok(())
        }
        Err(error) => Err(format!(
            "Triggered session step via ephemeral fallback but tx {} did not commit: {}",
            tx_hash, error
        )),
    }
}

async fn submit_continue_authenticated(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    app: &AppHandle,
    params_bytes: Vec<u8>,
) -> Result<(u64, String), String> {
    let keypair = identity::load_identity_keypair_for_app(app)?;
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| e.to_string())?,
    );

    submit_post_message_with_nonce_retry(client, &keypair, account_id, public_key, params_bytes)
        .await
}

async fn submit_start_authenticated(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    app: &AppHandle,
    params_bytes: Vec<u8>,
) -> Result<(u64, String), String> {
    let keypair = identity::load_identity_keypair_for_app(app)?;
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| e.to_string())?,
    );

    submit_start_agent_with_nonce_retry(client, &keypair, account_id, public_key, params_bytes)
        .await
}

async fn submit_step_authenticated(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    app: &AppHandle,
    params_bytes: Vec<u8>,
) -> Result<(u64, String), String> {
    let keypair = identity::load_identity_keypair_for_app(app)?;
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| e.to_string())?,
    );

    submit_step_with_nonce_retry(client, &keypair, account_id, public_key, params_bytes).await
}

async fn submit_step_authenticated_at_nonce(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    app: &AppHandle,
    params_bytes: Vec<u8>,
    nonce: u64,
) -> Result<String, String> {
    let keypair = identity::load_identity_keypair_for_app(app)?;
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| e.to_string())?,
    );

    let tx_bytes =
        build_step_agent_tx_bytes(account_id, nonce, public_key, &keypair, params_bytes)?;

    let response = submit_transaction_with_timeout(client, tx_bytes).await?;

    println!(
        "[Autopilot] Agent step submitted successfully (Nonce: {}, TxHash: {})",
        nonce, response.tx_hash
    );
    Ok(response.tx_hash)
}

async fn wait_for_tx_commit(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    tx_hash: &str,
    timeout_ms: u64,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut last_status = TxStatus::Unknown;
    let mut last_error = String::new();

    loop {
        let response = timeout(
            Duration::from_millis(TX_SUBMIT_TIMEOUT_MS),
            client.get_transaction_status(tonic::Request::new(GetTransactionStatusRequest {
                tx_hash: tx_hash.to_string(),
            })),
        )
        .await
        .map_err(|_| {
            format!(
                "Timed out while waiting for tx {} status after {}ms",
                tx_hash, TX_SUBMIT_TIMEOUT_MS
            )
        })?
        .map_err(|error| format!("Failed to query tx {} status: {}", tx_hash, error))?
        .into_inner();

        last_status = TxStatus::try_from(response.status).unwrap_or(TxStatus::Unknown);
        last_error = response.error_message;

        match last_status {
            TxStatus::Committed => return Ok(()),
            TxStatus::Rejected => {
                return Err(if last_error.trim().is_empty() {
                    format!("Tx {} was rejected by the kernel.", tx_hash)
                } else {
                    format!(
                        "Tx {} was rejected by the kernel: {}",
                        tx_hash,
                        last_error.trim()
                    )
                });
            }
            _ => {}
        }

        if Instant::now() >= deadline {
            let detail = if last_error.trim().is_empty() {
                format!("last tx status: {:?}", last_status)
            } else {
                format!("last tx status: {:?} ({})", last_status, last_error.trim())
            };
            return Err(format!(
                "Tx {} did not commit within {}ms ({detail}).",
                tx_hash, timeout_ms
            ));
        }

        sleep(Duration::from_millis(SESSION_START_CONVERGENCE_POLL_MS)).await;
    }
}

async fn query_agent_state(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    session_id: [u8; 32],
) -> Result<Option<AgentState>, String> {
    let state_key = session_state_key(session_id);
    let response = timeout(
        Duration::from_millis(TX_SUBMIT_TIMEOUT_MS),
        client.query_raw_state(tonic::Request::new(QueryRawStateRequest { key: state_key })),
    )
    .await
    .map_err(|_| {
        format!(
            "Timed out while reading session state after {}ms",
            TX_SUBMIT_TIMEOUT_MS
        )
    })?
    .map_err(|error| format!("Failed to query session state: {}", error))?
    .into_inner();

    if !response.found || response.value.is_empty() {
        return Ok(None);
    }

    codec::from_bytes_canonical::<AgentState>(&response.value)
        .map(Some)
        .map_err(|error| format!("Failed to decode session state: {}", error))
}

async fn wait_for_session_state_visibility(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    session_id: [u8; 32],
    timeout_ms: u64,
) -> Result<AgentState, String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    loop {
        if let Some(state) = query_agent_state(client, session_id).await? {
            return Ok(state);
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "Session {} did not become visible within {}ms.",
                hex::encode(session_id),
                timeout_ms
            ));
        }

        sleep(Duration::from_millis(SESSION_START_CONVERGENCE_POLL_MS)).await;
    }
}

async fn continue_session_bootstrap_after_visibility_timeout(
    app: AppHandle,
    session_id: [u8; 32],
    next_step_nonce: Option<u64>,
) {
    let session_id_hex = hex::encode(session_id);
    let mut client = match crate::kernel::state::connect_public_api().await {
        Ok(client) => client,
        Err(error) => {
            update_task_state(&app, |t| {
                if session_hex_matches_task(t, &session_id_hex) {
                    t.phase = AgentPhase::Failed;
                    t.current_step = format!(
                        "Session bootstrap recovery could not connect to the kernel: {}",
                        error
                    );
                }
            });
            return;
        }
    };

    match wait_for_session_state_visibility(
        &mut client,
        session_id,
        SESSION_STATE_RECONCILE_TIMEOUT_MS,
    )
    .await
    {
        Ok(_) => {
            update_task_state(&app, |t| {
                if session_hex_matches_task(t, &session_id_hex) {
                    t.current_step = "Scheduling first step...".to_string();
                    t.phase = AgentPhase::Running;
                }
            });

            if let Err(step_error) =
                trigger_agent_step_for_session(&mut client, &app, session_id, next_step_nonce).await
            {
                update_task_state(&app, |t| {
                    if session_hex_matches_task(t, &session_id_hex) {
                        t.phase = AgentPhase::Failed;
                        t.current_step = format!(
                            "Session appeared, but the first step could not be triggered: {}",
                            step_error
                        );
                    }
                });
                return;
            }

            update_task_state(&app, |t| {
                if session_hex_matches_task(t, &session_id_hex) {
                    t.phase = AgentPhase::Running;
                    t.current_step = "Agent session queued. Waiting for first step...".to_string();
                }
            });
            spawn_session_state_reconciler_with_bootstrap_nonce(
                app.clone(),
                session_id,
                next_step_nonce,
            );
        }
        Err(error) => {
            if next_step_nonce.is_some() {
                match trigger_agent_step_for_session(&mut client, &app, session_id, next_step_nonce)
                    .await
                {
                    Ok(()) => {
                        update_task_state(&app, |t| {
                            if session_hex_matches_task(t, &session_id_hex) {
                                t.phase = AgentPhase::Running;
                                t.current_step = "Session state is reconciling, but the first step was queued using the bootstrap nonce.".to_string();
                            }
                        });
                        spawn_session_state_reconciler_with_bootstrap_nonce(
                            app.clone(),
                            session_id,
                            next_step_nonce,
                        );
                        return;
                    }
                    Err(step_error)
                        if bootstrap_step_commit_delay_should_reconcile(&step_error)
                            || submit_error_indicates_bootstrap_step_already_pending(
                                &step_error,
                            ) =>
                    {
                        update_task_state(&app, |t| {
                            if session_hex_matches_task(t, &session_id_hex) {
                                t.phase = AgentPhase::Running;
                                t.current_step = format!(
                                    "Session state is still reconciling, and the optimistic first-step submit could not complete yet. Continuing bootstrap in the background: {} | {}",
                                    error, step_error
                                );
                            }
                        });
                        spawn_session_state_reconciler_with_bootstrap_nonce(
                            app.clone(),
                            session_id,
                            next_step_nonce,
                        );
                        return;
                    }
                    Err(_) => {}
                }
            }

            let mut keep_running = false;
            update_task_state(&app, |t| {
                if session_hex_matches_task(t, &session_id_hex) {
                    if task_has_live_session_activity(t) {
                        keep_running = true;
                        t.phase = AgentPhase::Running;
                        t.current_step = format!(
                            "Session state is still reconciling in the background, but live activity is flowing: {}",
                            error
                        );
                    } else {
                        t.phase = AgentPhase::Failed;
                        t.current_step = format!("Session state did not materialize: {}", error);
                    }
                }
            });
            if keep_running {
                spawn_session_state_reconciler_with_bootstrap_nonce(
                    app.clone(),
                    session_id,
                    next_step_nonce,
                );
            }
        }
    }
}

async fn bootstrap_kernel_session_after_studio_prepare(
    app: AppHandle,
    task_id: String,
    intent: String,
) {
    let session_id = match normalize_session_id(&task_id) {
        Ok(session_id) => session_id,
        Err(error) => {
            update_task_if_current_matches(&app, &task_id, |task| {
                task.phase = AgentPhase::Failed;
                task.current_step = format!("Session bootstrap error: {}", error);
            });
            return;
        }
    };

    let start_params = match encode_start_agent_params(session_id, intent.clone()) {
        Ok(params) => params,
        Err(error) => {
            update_task_if_current_matches(&app, &task_id, |task| {
                task.phase = AgentPhase::Failed;
                task.current_step = format!("Start encoding error: {}", error);
            });
            return;
        }
    };
    let fallback_params = start_params.clone();

    update_task_if_current_matches(&app, &task_id, |task| {
        task.current_step = "Connecting to Kernel...".to_string();
    });

    let mut client = match crate::kernel::state::connect_public_api().await {
        Ok(client) => client,
        Err(error) => {
            eprintln!("[Autopilot] Kernel offline: {}", error);
            update_task_if_current_matches(&app, &task_id, |task| {
                task.current_step =
                    "Kernel Unreachable. Simulating offline response...".to_string();
            });
            return;
        }
    };

    update_task_if_current_matches(&app, &task_id, |task| {
        task.current_step = "Submitting session start...".to_string();
    });

    let (next_step_nonce, start_tx_hash) = match submit_start_authenticated(
        &mut client,
        &app,
        start_params,
    )
    .await
    {
        Ok((nonce, tx_hash)) => (Some(nonce.saturating_add(1)), Some(tx_hash)),
        Err(base_err) => {
            eprintln!(
                    "[Autopilot] start@v1 authenticated submit did not converge. Falling back to ephemeral start flow: {}",
                    base_err
                );
            if let Err(fallback_err) =
                submit_start_via_ephemeral_start_agent(&mut client, fallback_params).await
            {
                update_task_if_current_matches(&app, &task_id, |task| {
                    task.phase = AgentPhase::Failed;
                    task.current_step = format!(
                        "Failed to start session: {} | fallback: {}",
                        base_err, fallback_err
                    );
                });
                return;
            }
            (None, None)
        }
    };

    update_task_if_current_matches(&app, &task_id, |task| {
        task.current_step = "Waiting for session start to commit...".to_string();
    });
    if let Some(start_tx_hash) = start_tx_hash.as_deref() {
        if let Err(error) = wait_for_tx_commit(
            &mut client,
            start_tx_hash,
            SESSION_START_CONVERGENCE_TIMEOUT_MS,
        )
        .await
        {
            if session_bootstrap_commit_delay_should_reconcile(&error) {
                update_task_if_current_matches(&app, &task_id, |task| {
                    task.phase = AgentPhase::Running;
                    task.current_step = format!(
                        "Session start commit is delayed, but bootstrap is continuing in the background: {}",
                        error
                    );
                });
                tauri::async_runtime::spawn(continue_session_bootstrap_after_visibility_timeout(
                    app.clone(),
                    session_id,
                    next_step_nonce,
                ));
                return;
            }
            update_task_if_current_matches(&app, &task_id, |task| {
                if task.phase == AgentPhase::Running
                    && matches!(
                        task.current_step.as_str(),
                        "Submitting session start..." | "Waiting for session start to commit..."
                    )
                {
                    task.phase = AgentPhase::Failed;
                    task.current_step = format!("Session start failed to commit: {}", error);
                }
            });
            return;
        }
    }

    update_task_if_current_matches(&app, &task_id, |task| {
        task.current_step = "Waiting for session state...".to_string();
    });

    if let Err(error) = wait_for_session_state_visibility(
        &mut client,
        session_id,
        SESSION_START_CONVERGENCE_TIMEOUT_MS,
    )
    .await
    {
        update_task_if_current_matches(&app, &task_id, |task| {
            task.phase = AgentPhase::Running;
            task.current_step = format!(
                "Session start committed, but kernel state is taking longer than expected. Continuing bootstrap in the background: {}",
                error
            );
        });

        match trigger_agent_step_for_session(&mut client, &app, session_id, next_step_nonce).await {
            Ok(()) => {
                update_task_if_current_matches(&app, &task_id, |task| {
                    task.phase = AgentPhase::Running;
                    task.current_step =
                        "Session state is reconciling, but the first step was queued using the committed bootstrap nonce.".to_string();
                });
                spawn_session_state_reconciler_with_bootstrap_nonce(
                    app.clone(),
                    session_id,
                    next_step_nonce,
                );
                return;
            }
            Err(step_error) => {
                update_task_if_current_matches(&app, &task_id, |task| {
                    task.phase = AgentPhase::Running;
                    task.current_step = format!(
                        "Session state is still reconciling, and the optimistic first-step submit could not complete yet. Continuing bootstrap in the background: {} | {}",
                        error, step_error
                    );
                });
                tauri::async_runtime::spawn(continue_session_bootstrap_after_visibility_timeout(
                    app.clone(),
                    session_id,
                    next_step_nonce,
                ));
                return;
            }
        }
    }

    update_task_if_current_matches(&app, &task_id, |task| {
        task.current_step = "Scheduling first step...".to_string();
    });

    if let Err(step_error) =
        trigger_agent_step_for_session(&mut client, &app, session_id, next_step_nonce).await
    {
        if bootstrap_step_commit_delay_should_reconcile(&step_error) {
            update_task_if_current_matches(&app, &task_id, |task| {
                task.phase = AgentPhase::Running;
                task.current_step = format!(
                    "First step commit is delayed, but bootstrap is continuing in the background: {}",
                    step_error
                );
            });
            spawn_session_state_reconciler_with_bootstrap_nonce(
                app.clone(),
                session_id,
                next_step_nonce,
            );
            return;
        }
        update_task_if_current_matches(&app, &task_id, |task| {
            task.phase = AgentPhase::Failed;
            task.current_step = format!(
                "Session started, but failed to trigger first step: {}",
                step_error
            );
        });
        return;
    }

    update_task_if_current_matches(&app, &task_id, |task| {
        task.phase = AgentPhase::Running;
        task.current_step = "Agent session queued. Waiting for first step...".to_string();
    });
    spawn_session_state_reconciler_with_bootstrap_nonce(app.clone(), session_id, next_step_nonce);
}

fn sync_task_from_kernel_state(
    app: &AppHandle,
    session_id_hex: &str,
    agent_state: &AgentState,
    kernel_history: Option<Vec<ChatMessage>>,
) {
    let history_terminal_reply = kernel_history.as_ref().and_then(|history| {
        history
            .iter()
            .rev()
            .find(|message| message.role == "agent" && !message.text.trim().is_empty())
            .map(|message| message.text.clone())
    });
    let terminal_reply = match &agent_state.status {
        AgentStatus::Completed(Some(text)) if !text.trim().is_empty() => Some(text.clone()),
        _ => history_terminal_reply,
    };
    let failed_reason = match &agent_state.status {
        AgentStatus::Failed(reason) if !reason.trim().is_empty() => Some(reason.clone()),
        _ => None,
    };

    update_task_state(app, |task| {
        if !session_hex_matches_task(task, session_id_hex) {
            return;
        }

        task.session_id = Some(session_id_hex.to_string());
        task.progress = agent_state.step_count;
        task.total_steps = agent_state.max_steps.max(task.total_steps);

        if let Some(history) = kernel_history.as_ref() {
            if !history.is_empty() {
                task.history = history.clone();
            }
        }

        match &agent_state.status {
            AgentStatus::Idle | AgentStatus::Running => {
                task.phase = AgentPhase::Running;
                task.gate_info = None;
                task.pending_request_hash = None;
                task.credential_request = None;
                if should_replace_with_reconciled_running_step(&task.current_step) {
                    task.current_step = bootstrap_step_label_for_state(agent_state);
                }
            }
            AgentStatus::Completed(_) => {
                task.phase = AgentPhase::Complete;
                task.gate_info = None;
                task.pending_request_hash = None;
                task.credential_request = None;
                if terminal_reply.is_some() {
                    task.current_step = "Ready for input".to_string();
                } else {
                    task.current_step = "Task completed".to_string();
                }
                task.receipt = Some(crate::models::Receipt {
                    duration: "Done".to_string(),
                    actions: agent_state.step_count,
                    cost: Some("$0.00".to_string()),
                });

                if let Some(reply) = terminal_reply.as_ref() {
                    let exists = task
                        .history
                        .iter()
                        .rev()
                        .take(8)
                        .any(|message| message.role == "agent" && message.text == *reply);
                    if !exists {
                        task.history.push(ChatMessage {
                            role: "agent".to_string(),
                            text: reply.clone(),
                            timestamp: crate::kernel::state::now(),
                        });
                    }
                }
            }
            AgentStatus::Paused(reason) => {
                let waiting_for_sudo = reason.eq_ignore_ascii_case("Waiting for sudo password");
                let waiting_for_clarification = reason
                    .trim()
                    .eq_ignore_ascii_case("Waiting for clarification on target identity.")
                    || reason.trim().eq_ignore_ascii_case(
                        "Waiting for user clarification on app/package name.",
                    )
                    || reason
                        .trim()
                        .eq_ignore_ascii_case("Waiting for intent clarification.")
                    || reason
                        .to_ascii_lowercase()
                        .contains("waiting for clarification");
                task.phase = if waiting_for_sudo || waiting_for_clarification {
                    AgentPhase::Running
                } else {
                    AgentPhase::Complete
                };
                task.current_step = reason.clone();
                task.gate_info = None;
                task.pending_request_hash = None;
                if waiting_for_sudo {
                    task.clarification_request = None;
                    task.credential_request = Some(CredentialRequest {
                        kind: "sudo_password".to_string(),
                        prompt: "A one-time sudo password is required to continue the install."
                            .to_string(),
                        one_time: true,
                    });
                } else {
                    task.credential_request = None;
                }
            }
            AgentStatus::Failed(reason) => {
                task.phase = AgentPhase::Failed;
                task.current_step = format!("Task failed: {}", reason);
                task.gate_info = None;
                task.pending_request_hash = None;
                task.credential_request = None;
                if let Some(message) = failed_reason.as_ref() {
                    let exists = task
                        .history
                        .iter()
                        .rev()
                        .take(8)
                        .any(|entry| entry.role == "system" && entry.text.contains(message));
                    if !exists {
                        task.history.push(ChatMessage {
                            role: "system".to_string(),
                            text: format!("Task Failed: {}", message),
                            timestamp: crate::kernel::state::now(),
                        });
                    }
                }
            }
            AgentStatus::Terminated => {
                task.phase = AgentPhase::Failed;
                task.current_step = "Task terminated".to_string();
                task.gate_info = None;
                task.pending_request_hash = None;
                task.credential_request = None;
            }
        }
    });
}

pub(crate) fn spawn_session_state_reconciler(app: AppHandle, session_id: [u8; 32]) {
    spawn_session_state_reconciler_with_bootstrap_nonce(app, session_id, None);
}

fn spawn_session_state_reconciler_with_bootstrap_nonce(
    app: AppHandle,
    session_id: [u8; 32],
    bootstrap_step_nonce: Option<u64>,
) {
    let session_id_hex = hex::encode(session_id);
    let should_spawn = {
        match active_session_reconcilers().lock() {
            Ok(mut active) => active.insert(session_id_hex.clone()),
            Err(_) => true,
        }
    };

    if !should_spawn {
        return;
    }

    tauri::async_runtime::spawn(async move {
        let deadline = Instant::now() + Duration::from_millis(SESSION_STATE_RECONCILE_TIMEOUT_MS);
        let bootstrap_retry_window_opens_at =
            Instant::now() + Duration::from_millis(SESSION_BOOTSTRAP_STEP_RETRY_GRACE_MS);
        let mut bootstrap_retry_attempts = 0usize;
        let mut bootstrap_fallback_attempted = false;
        let mut last_bootstrap_retry_at: Option<Instant> = None;

        let mut client = match crate::kernel::state::connect_public_api().await {
            Ok(client) => client,
            Err(error) => {
                eprintln!(
                    "[Autopilot] Session reconciler could not connect for {}: {}",
                    session_id_hex, error
                );
                if let Ok(mut active) = active_session_reconcilers().lock() {
                    active.remove(&session_id_hex);
                }
                return;
            }
        };

        loop {
            let bootstrap_retry_window_open = Instant::now() >= bootstrap_retry_window_opens_at;
            match query_agent_state(&mut client, session_id).await {
                Ok(Some(agent_state)) => {
                    let terminal =
                        !matches!(agent_state.status, AgentStatus::Idle | AgentStatus::Running);
                    let history = if terminal {
                        hydrate_session_history(&mut client, &session_id_hex)
                            .await
                            .ok()
                    } else {
                        None
                    };
                    sync_task_from_kernel_state(&app, &session_id_hex, &agent_state, history);

                    if terminal {
                        break;
                    }

                    maybe_retry_or_escalate_bootstrap_step(
                        &mut client,
                        &app,
                        session_id,
                        &session_id_hex,
                        bootstrap_step_nonce,
                        bootstrap_step_is_stalled(bootstrap_step_nonce, &agent_state),
                        bootstrap_retry_window_open,
                        &mut bootstrap_retry_attempts,
                        &mut bootstrap_fallback_attempted,
                        &mut last_bootstrap_retry_at,
                    )
                    .await;
                }
                Ok(None) => {
                    let bootstrap_step_invisible_stalled = bootstrap_step_nonce.is_some()
                        && bootstrap_state_still_needs_recovery(&app, &session_id_hex);

                    if bootstrap_step_invisible_stalled {
                        update_task_state(&app, |task| {
                            if session_hex_matches_task(task, &session_id_hex)
                                && should_replace_with_reconciled_running_step(&task.current_step)
                            {
                                task.phase = AgentPhase::Running;
                                task.current_step = "Session state is still reconciling, but bootstrap recovery is continuing in the background.".to_string();
                            }
                        });
                    }

                    maybe_retry_or_escalate_bootstrap_step(
                        &mut client,
                        &app,
                        session_id,
                        &session_id_hex,
                        bootstrap_step_nonce,
                        bootstrap_step_invisible_stalled,
                        bootstrap_retry_window_open,
                        &mut bootstrap_retry_attempts,
                        &mut bootstrap_fallback_attempted,
                        &mut last_bootstrap_retry_at,
                    )
                    .await;
                }
                Err(error) => {
                    eprintln!(
                        "[Autopilot] Session reconciler query failed for {}: {}",
                        session_id_hex, error
                    );
                }
            }

            if Instant::now() >= deadline {
                break;
            }

            sleep(Duration::from_millis(SESSION_STATE_RECONCILE_POLL_MS)).await;
        }

        if let Ok(mut active) = active_session_reconcilers().lock() {
            active.remove(&session_id_hex);
        }
    });
}

pub(crate) async fn trigger_agent_step_for_session(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    app: &AppHandle,
    session_id: [u8; 32],
    preferred_nonce: Option<u64>,
) -> Result<(), String> {
    let step_params = encode_step_agent_params(session_id)?;
    let fallback_step_params = step_params.clone();

    if let Some(nonce) = preferred_nonce {
        match submit_step_authenticated_at_nonce(client, app, step_params.clone(), nonce).await {
            Ok(tx_hash) => {
                match wait_for_tx_commit(client, &tx_hash, SESSION_START_CONVERGENCE_TIMEOUT_MS)
                    .await
                {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        if bootstrap_step_commit_delay_should_reconcile(&error) {
                            println!(
                                "[Autopilot] step@v1 exact-nonce tx {} at nonce {} is still pending. Deferring commit confirmation to the reconciler: {}",
                                tx_hash, nonce, error
                            );
                            return Ok(());
                        }
                        eprintln!(
                            "[Autopilot] step@v1 exact-nonce tx {} at nonce {} did not commit in time. Falling back to retry path: {}",
                            tx_hash, nonce, error
                        );
                    }
                }
            }
            Err(error) => {
                if submit_error_indicates_bootstrap_step_already_pending(&error) {
                    println!(
                        "[Autopilot] step@v1 exact-nonce submit at nonce {} appears already pending or consumed. Deferring confirmation to the reconciler: {}",
                        nonce, error
                    );
                    return Ok(());
                }
                eprintln!(
                    "[Autopilot] step@v1 exact-nonce submit failed at nonce {}. Falling back to retry path: {}",
                    nonce, error
                );
            }
        }
    }

    let authenticated_submit = submit_step_authenticated(client, app, step_params).await;
    if let Err(base_err) = match authenticated_submit {
        Ok((_, tx_hash)) => {
            match wait_for_tx_commit(client, &tx_hash, SESSION_START_CONVERGENCE_TIMEOUT_MS).await {
                Ok(()) => Ok(()),
                Err(error) if bootstrap_step_commit_delay_should_reconcile(&error) => {
                    println!(
                        "[Autopilot] step@v1 authenticated tx {} is still pending. Deferring commit confirmation to the reconciler: {}",
                        tx_hash, error
                    );
                    Ok(())
                }
                Err(error) => Err(format!(
                    "Triggered session step but the authenticated tx {} did not commit: {}",
                    tx_hash, error
                )),
            }
        }
        Err(base_err) => Err(base_err),
    } {
        eprintln!(
            "[Autopilot] step@v1 authenticated submit did not converge. Falling back to ephemeral step flow: {}",
            base_err
        );
        let fallback_tx_hash = submit_step_via_ephemeral_agent_step(client, fallback_step_params)
            .await
            .map_err(|fallback_err| {
                format!(
                    "Failed to trigger session step: {} | fallback: {}",
                    base_err, fallback_err
                )
            })?;
        wait_for_tx_commit(
            client,
            &fallback_tx_hash,
            SESSION_START_CONVERGENCE_TIMEOUT_MS,
        )
        .await
        .map_err(|error| {
            format!(
                "Failed to trigger session step: {} | fallback tx {} did not commit: {}",
                base_err, fallback_tx_hash, error
            )
        })?;
    }

    Ok(())
}

pub(crate) async fn send_message_to_session(
    app: &AppHandle,
    session_id: &str,
    user_input: String,
) -> Result<(), String> {
    crate::kernel::studio::maybe_prepare_current_task_for_studio_turn(app, &user_input)?;
    let routed_user_input = if let Some(task) = app
        .state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.current_task.clone())
    {
        if !task_should_continue_through_kernel(&task) {
            return Ok(());
        }
        apply_studio_route_handoff_to_runtime_input(&task, &user_input)
    } else {
        user_input.clone()
    };

    let session_arr = normalize_session_id(session_id)?;
    let params_bytes = encode_post_message_params(session_arr, routed_user_input)?;
    let fallback_params_bytes = params_bytes.clone();
    let mut client = crate::kernel::state::connect_public_api()
        .await
        .map_err(|error| format!("Failed to connect for session message: {}", error))?;

    let next_step_nonce = match submit_continue_authenticated(&mut client, app, params_bytes).await
    {
        Ok((nonce, tx_hash)) => {
            update_task_state(app, |t| {
                if session_hex_matches_task(t, &hex::encode(session_arr)) {
                    t.current_step = "Waiting for message to commit...".to_string();
                }
            });
            if let Err(error) =
                wait_for_tx_commit(&mut client, &tx_hash, SESSION_START_CONVERGENCE_TIMEOUT_MS)
                    .await
            {
                return Err(format!(
                    "Message submit for session {} did not commit cleanly: {}",
                    session_id, error
                ));
            }
            Some(nonce.saturating_add(1))
        }
        Err(base_err) => {
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
            None
        }
    };

    trigger_agent_step_for_session(&mut client, app, session_arr, next_step_nonce)
        .await
        .map_err(|error| {
            format!(
                "Failed to trigger next step for session {} after sending message: {}",
                session_id, error
            )
        })?;

    spawn_session_state_reconciler(app.clone(), session_arr);

    Ok(())
}

fn should_reuse_running_studio_task_for_duplicate_submit(
    current_task: &AgentTask,
    intent: &str,
    origin_surface: Option<&str>,
) -> bool {
    origin_surface == Some("studio")
        && current_task.phase == AgentPhase::Running
        && current_task.intent.trim() == intent.trim()
}

#[tauri::command]
pub fn start_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    intent: String,
    origin_surface: Option<String>,
) -> Result<AgentTask, String> {
    eprintln!(
        "[Autopilot] start_task invoked origin_surface={} intent_len={}",
        origin_surface.as_deref().unwrap_or("overlay"),
        intent.trim().len()
    );
    {
        let app_state = state.lock().map_err(|_| "Failed to lock state")?;
        if let Some(existing_task) = app_state.current_task.as_ref().filter(|task| {
            should_reuse_running_studio_task_for_duplicate_submit(
                task,
                &intent,
                origin_surface.as_deref(),
            )
        }) {
            eprintln!(
                "[Autopilot] start_task reusing running studio task {} for duplicate seed submit",
                existing_task.id
            );
            return Ok(existing_task.clone());
        }
    }
    let task_id = generate_session_id_hex();
    let workflow_expansion = workspace_workflow_expansion(&intent)?;
    eprintln!(
        "[Autopilot] start_task workflow expansion ready for {}",
        task_id
    );
    let knowledge_injection = maybe_inject_ambient_knowledge_sync(&state, &app, &task_id, &intent)?;
    eprintln!(
        "[Autopilot] start_task knowledge injection ready for {} attached={}",
        task_id,
        knowledge_injection.is_some()
    );
    let base_bootstrap_intent = workflow_expansion
        .as_ref()
        .map(|workflow| workflow.expanded_intent.clone())
        .unwrap_or_else(|| intent.clone());
    let session_bootstrap_intent = knowledge_injection
        .as_ref()
        .map(|knowledge| format!("{}\n\n{}", knowledge.prompt_prefix, base_bootstrap_intent))
        .unwrap_or(base_bootstrap_intent);
    let mut history = vec![ChatMessage {
        role: "user".to_string(),
        text: intent.clone(),
        timestamp: crate::kernel::state::now(),
    }];
    if let Some(workflow) = workflow_expansion.as_ref() {
        history.push(ChatMessage {
            role: "system".to_string(),
            text: workflow.announcement.clone(),
            timestamp: crate::kernel::state::now(),
        });
    }
    if let Some(knowledge) = knowledge_injection.as_ref() {
        history.push(ChatMessage {
            role: "system".to_string(),
            text: knowledge.announcement.clone(),
            timestamp: crate::kernel::state::now(),
        });
    }

    let mut task = AgentTask {
        id: task_id.clone(),
        session_id: Some(task_id.clone()),
        intent: intent.clone(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 20,
        current_step: workflow_expansion
            .as_ref()
            .map(|workflow| workflow.announcement.clone())
            .unwrap_or_else(|| "Initializing...".to_string()),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        credential_request: None,
        clarification_request: None,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history,
        events: vec![build_user_input_event(&task_id, 0, &intent)],
        artifacts: Vec::new(),
        studio_session: None,
        studio_outcome: None,
        renderer_session: None,
        build_session: None,
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        swarm_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };

    task.sync_runtime_views();

    let memory_runtime = {
        let app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.memory_runtime.clone()
    };

    if let Some(memory_runtime) = memory_runtime.as_ref() {
        let run_bundle =
            crate::kernel::artifacts::create_run_bundle(memory_runtime, &task_id, &task_id, vec![]);
        task.run_bundle_id = Some(run_bundle.artifact_id.clone());
        task.artifacts.push(run_bundle.clone());
        if let Some(workflow) = workflow_expansion.as_ref() {
            let workflow_artifact = crate::kernel::artifacts::create_named_file_artifact(
                memory_runtime,
                &task_id,
                &workflow.summary.file_path,
                Some("text/markdown"),
                None,
                workflow.markdown.as_bytes(),
            );
            task.artifacts.push(workflow_artifact);
        }
        if let Some(knowledge) = knowledge_injection.as_ref() {
            replace_or_insert_task_artifact(&mut task, knowledge.summary_artifact.clone());
        }
        if let Err(error) =
            crate::kernel::runtime_parity::sync_planning_artifacts(&app, memory_runtime, &mut task)
        {
            eprintln!("[Autopilot] Failed to sync planning artifacts: {}", error);
        }
        orchestrator::save_local_task_state(memory_runtime, &task);
    }

    {
        let mut app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.current_task = Some(task.clone());
        app_state.gate_response = None;
    }
    eprintln!(
        "[Autopilot] start_task initial task saved {} phase={:?}",
        task_id, task.phase
    );

    let _ = app.emit("task-started", &task);
    let app_for_projection = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_for_projection, true).await;
    });
    match origin_surface
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("studio") => {
            if let Some(window) = app.get_webview_window("spotlight") {
                let _ = window.hide();
            }
            crate::windows::hide_pill(app.clone());
        }
        _ => crate::windows::show_spotlight(app.clone()),
    }
    let app_clone = app.clone();
    let task_id_for_prepare = task_id.clone();
    let intent_for_prepare = session_bootstrap_intent.clone();
    let task_for_prepare = task.clone();

    tauri::async_runtime::spawn(async move {
        let app_for_prepare = app_clone.clone();
        let prepare_outcome = tokio::task::spawn_blocking(move || {
            let mut prepared_task = task_for_prepare;
            crate::kernel::studio::maybe_prepare_task_for_studio(
                &app_for_prepare,
                &mut prepared_task,
                &intent_for_prepare,
            )?;

            let studio_primary =
                crate::kernel::studio::task_requires_studio_primary_execution(&prepared_task);
            if studio_primary {
                crate::kernel::studio::apply_studio_authoritative_status(&mut prepared_task, None);
            }

            Ok::<(AgentTask, bool), String>((prepared_task, studio_primary))
        })
        .await;

        match prepare_outcome {
            Ok(Ok((prepared_task, studio_primary))) => {
                replace_current_task_snapshot(&app_clone, &task_id_for_prepare, prepared_task);
                if !studio_primary {
                    let bootstrap_intent = app_clone
                        .state::<Mutex<AppState>>()
                        .lock()
                        .ok()
                        .and_then(|state| state.current_task.clone())
                        .map(|task| {
                            apply_studio_route_handoff_to_runtime_input(
                                &task,
                                &session_bootstrap_intent,
                            )
                        })
                        .unwrap_or_else(|| session_bootstrap_intent.clone());
                    bootstrap_kernel_session_after_studio_prepare(
                        app_clone.clone(),
                        task_id_for_prepare,
                        bootstrap_intent,
                    )
                    .await;
                }
            }
            Ok(Err(error)) => {
                update_task_if_current_matches(&app_clone, &task_id_for_prepare, |task| {
                    task.phase = AgentPhase::Failed;
                    task.current_step = format!("Studio preparation failed: {}", error);
                });
            }
            Err(error) => {
                update_task_if_current_matches(&app_clone, &task_id_for_prepare, |task| {
                    task.phase = AgentPhase::Failed;
                    task.current_step = format!("Studio preparation task failed to run: {}", error);
                });
            }
        }
    });

    Ok(task)
}

#[tauri::command]
pub async fn continue_task(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    session_id: String,
    user_input: String,
) -> Result<(), String> {
    let hydrated_session_task = hydrate_requested_session_for_continue(&state, &session_id)?;
    if let Some(task) = hydrated_session_task.as_ref() {
        println!(
            "[Autopilot][StudioContinue] hydrated session={} task_session={} studio_backed={}",
            session_id,
            task.session_id.as_deref().unwrap_or(task.id.as_str()),
            task.studio_session.is_some() && task.studio_outcome.is_some()
        );
    }

    let workflow_expansion = workspace_workflow_expansion(&user_input)?;
    let knowledge_injection = {
        let (memory_runtime, inference_runtime) = app_runtime_resources(&state)?;
        match (memory_runtime, inference_runtime) {
            (Some(memory_runtime), Some(inference_runtime)) => {
                maybe_inject_ambient_knowledge_best_effort(
                    &app,
                    &memory_runtime,
                    &inference_runtime,
                    &session_id,
                    &user_input,
                )
                .await
            }
            _ => None,
        }
    };
    let base_user_input_for_send = workflow_expansion
        .as_ref()
        .map(|workflow| workflow.expanded_intent.clone())
        .unwrap_or_else(|| user_input.clone());
    let user_input_for_send = knowledge_injection
        .as_ref()
        .map(|knowledge| {
            format!(
                "{}\n\n{}",
                knowledge.prompt_prefix, base_user_input_for_send
            )
        })
        .unwrap_or(base_user_input_for_send);
    let user_msg_ui = ChatMessage {
        role: "user".to_string(),
        text: user_input.clone(),
        timestamp: crate::kernel::state::now(),
    };
    let user_input_for_event = user_input.clone();
    let knowledge_injection_for_update = knowledge_injection.clone();

    update_task_state(&app, move |t| {
        t.processed_steps.clear();
        t.history.push(user_msg_ui.clone());
        if let Some(workflow) = workflow_expansion.as_ref() {
            t.history.push(ChatMessage {
                role: "system".to_string(),
                text: workflow.announcement.clone(),
                timestamp: crate::kernel::state::now(),
            });
            t.current_step = workflow.announcement.clone();
        }
        if let Some(knowledge) = knowledge_injection_for_update.as_ref() {
            t.history.push(ChatMessage {
                role: "system".to_string(),
                text: knowledge.announcement.clone(),
                timestamp: crate::kernel::state::now(),
            });
            replace_or_insert_task_artifact(t, knowledge.summary_artifact.clone());
        }
        t.credential_request = None;
        t.clarification_request = None;
        let thread_id = t.session_id.clone().unwrap_or_else(|| t.id.clone());
        let step_index = t.progress;
        t.events.push(build_user_input_event(
            &thread_id,
            step_index,
            &user_input_for_event,
        ));
        if workflow_expansion.is_none() {
            t.current_step = "Sending message...".to_string();
        }
        t.phase = AgentPhase::Running;
    });

    let should_continue_via_studio_primary = app
        .state::<Mutex<AppState>>()
        .lock()
        .ok()
        .and_then(|state| state.current_task.clone())
        .map(|task| {
            let session_matches = session_hex_matches_task(&task, &session_id);
            let studio_backed =
                session_matches && task.studio_session.is_some() && task.studio_outcome.is_some();
            println!(
                "[Autopilot][StudioContinue] session={} task_session={} session_matches={} studio_backed={} phase={:?} current_step={}",
                session_id,
                task.session_id.as_deref().unwrap_or(task.id.as_str()),
                session_matches,
                studio_backed,
                task.phase,
                task.current_step
            );
            studio_backed
        })
        .unwrap_or(false);

    if should_continue_via_studio_primary {
        println!(
            "[Autopilot][StudioContinue] preparing studio follow-up for session={} input={}",
            session_id, user_input
        );
        let app_for_prepare = app.clone();
        let user_input_for_prepare = user_input.clone();
        let preparation_result = tauri::async_runtime::spawn_blocking(move || {
            crate::kernel::studio::maybe_prepare_current_task_for_studio_turn(
                &app_for_prepare,
                &user_input_for_prepare,
            )
        })
        .await
        .map_err(|error| format!("Studio follow-up worker failed: {error}"))
        .and_then(|result| result);

        if let Err(error) = preparation_result {
            let failure_message = format!("Studio follow-up failed: {error}");
            update_task_state(&app, |task| {
                task.phase = AgentPhase::Failed;
                task.current_step = failure_message.clone();
                task.history.push(ChatMessage {
                    role: "system".to_string(),
                    text: failure_message.clone(),
                    timestamp: crate::kernel::state::now(),
                });
            });
        } else {
            println!(
                "[Autopilot][StudioContinue] studio follow-up prepared for session={}",
                session_id
            );
        }
        return Ok(());
    }

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
    let app_clone = app.clone();
    let session_for_status = normalized_session_id.clone();
    tauri::async_runtime::spawn(async move {
        let send_result = timeout(
            Duration::from_millis(CONTINUE_TASK_SEND_TIMEOUT_MS),
            send_message_to_session(&app_clone, &normalized_session_id, user_input_for_send),
        )
        .await;

        match send_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                update_task_if_session_matches(&app_clone, &session_for_status, move |task| {
                    task.phase = AgentPhase::Failed;
                    task.current_step = format!("Failed to send message: {}", error);
                });
            }
            Err(_) => {
                let timeout_message = format!(
                    "Message submit timed out after {}s. Retry from Spotlight, Gate, or Pill.",
                    CONTINUE_TASK_SEND_TIMEOUT_MS / 1000
                );
                update_task_if_session_matches(&app_clone, &session_for_status, |task| {
                    task.phase = AgentPhase::Failed;
                    task.current_step = timeout_message.clone();
                    let exists = task
                        .history
                        .iter()
                        .rev()
                        .take(6)
                        .any(|entry| entry.role == "system" && entry.text == timeout_message);
                    if !exists {
                        task.history.push(ChatMessage {
                            role: "system".to_string(),
                            text: timeout_message.clone(),
                            timestamp: crate::kernel::state::now(),
                        });
                    }
                });
            }
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
    let mut session_id: Option<String> = None;
    let mut memory_runtime = None;
    if let Ok(mut app_state) = state.lock() {
        memory_runtime = app_state.memory_runtime.clone();
        session_id = app_state
            .current_task
            .as_ref()
            .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
        app_state.current_task = None;
        app_state.gate_response = None;
    }
    if let (Some(memory_runtime), Some(session_id)) = (memory_runtime.as_ref(), session_id.as_ref())
    {
        orchestrator::clear_local_task_state(memory_runtime, session_id);
    }
    windows::hide_spotlight(app.clone());
    windows::hide_gate(app.clone());
    let _ = app.emit("task-dismissed", ());
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_clone, true).await;
    });
    Ok(())
}

#[tauri::command]
pub fn cancel_task(state: State<Mutex<AppState>>, app: AppHandle) -> Result<(), String> {
    let mut session_id: Option<String> = None;
    let mut memory_runtime = None;
    if let Ok(mut app_state) = state.lock() {
        memory_runtime = app_state.memory_runtime.clone();
        session_id = app_state
            .current_task
            .as_ref()
            .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
        app_state.current_task = None;
        app_state.gate_response = None;
    }
    if let (Some(memory_runtime), Some(session_id)) = (memory_runtime.as_ref(), session_id.as_ref())
    {
        orchestrator::clear_local_task_state(memory_runtime, session_id);
    }
    let _ = app.emit("task-dismissed", ());
    let app_clone = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::kernel::session::emit_session_projection_update(&app_clone, true).await;
    });
    Ok(())
}

#[tauri::command]
pub fn get_current_task(state: State<Mutex<AppState>>) -> Option<AgentTask> {
    state.lock().ok().and_then(|s| {
        s.current_task.clone().map(|mut task| {
            task.sync_runtime_views();
            task
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use std::path::PathBuf;

    fn local_gpu_profile_dir() -> PathBuf {
        let data_root = std::env::var("XDG_DATA_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(PathBuf::from)
                    .map(|home| home.join(".local").join("share"))
            })
            .unwrap_or_else(|| PathBuf::from("/tmp"));

        data_root.join("ai.ioi.autopilot").join("profiles").join(
            std::env::var("AUTOPILOT_DATA_PROFILE")
                .unwrap_or_else(|_| "desktop-localgpu".to_string()),
        )
    }

    async fn wait_for_tx_commit(
        client: &mut PublicApiClient<tonic::transport::Channel>,
        tx_hash: &str,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let response = timeout(
                Duration::from_millis(TX_SUBMIT_TIMEOUT_MS),
                client.get_transaction_status(tonic::Request::new(GetTransactionStatusRequest {
                    tx_hash: tx_hash.to_string(),
                })),
            )
            .await
            .map_err(|_| format!("Timed out while waiting for tx {} status", tx_hash))?
            .map_err(|error| format!("Failed to query tx {} status: {}", tx_hash, error))?
            .into_inner();

            let status = TxStatus::try_from(response.status).unwrap_or(TxStatus::Unknown);
            match status {
                TxStatus::Committed => return Ok(()),
                TxStatus::Rejected => {
                    return Err(if response.error_message.trim().is_empty() {
                        format!("Tx {} was rejected", tx_hash)
                    } else {
                        format!(
                            "Tx {} was rejected: {}",
                            tx_hash,
                            response.error_message.trim()
                        )
                    });
                }
                _ => {}
            }

            if Instant::now() >= deadline {
                return Err(format!(
                    "Tx {} did not commit within 30s (last status: {:?})",
                    tx_hash, status
                ));
            }

            sleep(Duration::from_millis(500)).await;
        }
    }

    #[test]
    fn reconciler_replaces_optimistic_ui_running_steps() {
        assert!(should_replace_with_reconciled_running_step(
            "Sending message..."
        ));
        assert!(should_replace_with_reconciled_running_step(
            "Connecting to Kernel..."
        ));
        assert!(should_replace_with_reconciled_running_step(
            "Scheduling first step..."
        ));
        assert!(should_replace_with_reconciled_running_step(
            "Agent session queued. Waiting for first step..."
        ));
        assert!(should_replace_with_reconciled_running_step(
            "Waiting for message to commit..."
        ));
        assert!(should_replace_with_reconciled_running_step(
            "Session state is reconciling, but the first step was queued using the committed bootstrap nonce."
        ));
        assert!(should_replace_with_reconciled_running_step(
            "Session state is still reconciling, and the optimistic first-step submit could not complete yet. Continuing bootstrap in the background: visibility timeout | already exists"
        ));
        assert!(should_replace_with_reconciled_running_step(
            "Session start commit is delayed, but bootstrap is continuing in the background: Tx abc did not commit within 15000ms."
        ));
        assert!(should_replace_with_reconciled_running_step(
            "Recovering first step after bootstrap pending stall..."
        ));
        assert!(!should_replace_with_reconciled_running_step(
            "Streaming browser::inspect (stdout)"
        ));
    }

    #[test]
    fn session_state_key_targets_desktop_agent_namespace() {
        let session_id = [7u8; 32];
        let key = session_state_key(session_id);
        let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
        let local_key = get_state_key(&session_id);
        assert_eq!(key, [ns_prefix.as_slice(), local_key.as_slice()].concat());
    }

    #[test]
    fn live_activity_prevents_false_session_materialization_failure() {
        let mut task = AgentTask {
            id: "session-a".to_string(),
            intent: "chat".to_string(),
            agent: "autopilot".to_string(),
            phase: AgentPhase::Running,
            progress: 0,
            total_steps: 0,
            current_step: "Waiting for session state...".to_string(),
            gate_info: None,
            receipt: None,
            visual_hash: None,
            pending_request_hash: None,
            session_id: Some("session-a".to_string()),
            credential_request: None,
            clarification_request: None,
            session_checklist: Vec::new(),
            background_tasks: Vec::new(),
            history: Vec::new(),
            events: Vec::new(),
            artifacts: Vec::new(),
            studio_session: None,
            studio_outcome: None,
            renderer_session: None,
            build_session: None,
            run_bundle_id: None,
            processed_steps: HashSet::new(),
            swarm_tree: Vec::new(),
            generation: 0,
            lineage_id: "genesis".to_string(),
            fitness_score: 0.0,
        };

        assert!(!task_has_live_session_activity(&task));
        task.events
            .push(build_user_input_event("thread-a", 0, "hello"));
        assert!(task_has_live_session_activity(&task));
    }

    #[test]
    fn bootstrap_step_commit_delay_reconciles_instead_of_failing() {
        assert!(bootstrap_step_commit_delay_should_reconcile(
            "Triggered session step at nonce 1 but it did not commit: Tx abc did not commit within 15000ms (last tx status: InMempool).",
        ));
        assert!(bootstrap_step_commit_delay_should_reconcile(
            "step submit already exists for nonce 1",
        ));
        assert!(!bootstrap_step_commit_delay_should_reconcile(
            "permission denied",
        ));
    }

    #[test]
    fn session_start_commit_delay_reconciles_instead_of_failing() {
        assert!(session_bootstrap_commit_delay_should_reconcile(
            "Tx abc did not commit within 15000ms (last tx status: InMempool).",
        ));
        assert!(session_bootstrap_commit_delay_should_reconcile(
            "Submission already exists for nonce 0",
        ));
        assert!(!session_bootstrap_commit_delay_should_reconcile(
            "permission denied",
        ));
    }

    #[test]
    fn bootstrap_step_duplicate_submit_is_treated_as_pending() {
        assert!(submit_error_indicates_bootstrap_step_already_pending(
            "step submit already exists for nonce 1",
        ));
        assert!(submit_error_indicates_bootstrap_step_already_pending(
            "nonce too low for account",
        ));
        assert!(!submit_error_indicates_bootstrap_step_already_pending(
            "permission denied",
        ));
    }

    #[test]
    fn bootstrap_pending_step_escalates_after_retry_budget_is_exhausted() {
        assert!(bootstrap_step_should_escalate_pending_recovery(
            true,
            SESSION_BOOTSTRAP_STEP_MAX_RETRIES,
            false,
            true,
            true,
        ));
        assert!(!bootstrap_step_should_escalate_pending_recovery(
            true,
            SESSION_BOOTSTRAP_STEP_MAX_RETRIES - 1,
            false,
            true,
            true,
        ));
        assert!(!bootstrap_step_should_escalate_pending_recovery(
            true,
            SESSION_BOOTSTRAP_STEP_MAX_RETRIES,
            true,
            true,
            true,
        ));
        assert!(!bootstrap_step_should_escalate_pending_recovery(
            false,
            SESSION_BOOTSTRAP_STEP_MAX_RETRIES,
            false,
            true,
            true,
        ));
    }

    #[test]
    fn bootstrap_recovery_stays_enabled_for_delayed_start_placeholders() {
        let task = AgentTask {
            id: "task-1".to_string(),
            intent: "chat".to_string(),
            agent: "autopilot".to_string(),
            phase: AgentPhase::Running,
            progress: 0,
            total_steps: 0,
            current_step: "Session start commit is delayed, but bootstrap is continuing in the background: Tx abc did not commit within 15000ms.".to_string(),
            gate_info: None,
            receipt: None,
            visual_hash: None,
            pending_request_hash: None,
            session_id: Some("task-1".to_string()),
            credential_request: None,
            clarification_request: None,
            session_checklist: Vec::new(),
            background_tasks: Vec::new(),
            history: Vec::new(),
            events: Vec::new(),
            artifacts: Vec::new(),
            studio_session: None,
            studio_outcome: None,
            renderer_session: None,
            build_session: None,
            run_bundle_id: None,
            processed_steps: HashSet::new(),
            swarm_tree: Vec::new(),
            generation: 0,
            lineage_id: "genesis".to_string(),
            fitness_score: 0.0,
        };

        assert!(should_replace_with_reconciled_running_step(
            &task.current_step
        ));
    }

    #[test]
    fn duplicate_studio_seed_submit_reuses_running_task() {
        let running_task = AgentTask {
            id: "task-1".to_string(),
            intent: "Make me a report.".to_string(),
            agent: "autopilot".to_string(),
            phase: AgentPhase::Running,
            progress: 0,
            total_steps: 0,
            current_step: "Initializing...".to_string(),
            gate_info: None,
            receipt: None,
            visual_hash: None,
            pending_request_hash: None,
            session_id: Some("task-1".to_string()),
            credential_request: None,
            clarification_request: None,
            session_checklist: Vec::new(),
            background_tasks: Vec::new(),
            history: Vec::new(),
            events: Vec::new(),
            artifacts: Vec::new(),
            studio_session: None,
            studio_outcome: None,
            renderer_session: None,
            build_session: None,
            run_bundle_id: None,
            processed_steps: HashSet::new(),
            swarm_tree: Vec::new(),
            generation: 0,
            lineage_id: "genesis".to_string(),
            fitness_score: 0.0,
        };

        assert!(should_reuse_running_studio_task_for_duplicate_submit(
            &running_task,
            "Make me a report.",
            Some("studio"),
        ));
        assert!(!should_reuse_running_studio_task_for_duplicate_submit(
            &running_task,
            "Make me a report.",
            Some("overlay"),
        ));
        assert!(!should_reuse_running_studio_task_for_duplicate_submit(
            &running_task,
            "Make me a deck.",
            Some("studio"),
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn best_effort_optional_future_returns_successful_value() {
        let value = run_best_effort_optional_future("test future", async {
            Ok::<_, String>(Some("ready"))
        })
        .await;

        assert_eq!(value, Some("ready"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn best_effort_optional_future_drops_recoverable_failure() {
        let value = run_best_effort_optional_future::<&'static str, _>("test future", async {
            Err::<Option<&'static str>, _>("boom".to_string())
        })
        .await;

        assert_eq!(value, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn best_effort_optional_future_times_out_without_blocking_startup() {
        let value = run_best_effort_optional_future::<&'static str, _>("test future", async {
            sleep(Duration::from_millis(AMBIENT_KNOWLEDGE_TIMEOUT_MS + 50)).await;
            Ok::<_, String>(Some("late"))
        })
        .await;

        assert_eq!(value, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires a running desktop-localgpu kernel companion"]
    async fn authenticated_desktop_agent_session_bootstrap_commits_against_local_kernel() {
        let key_path = local_gpu_profile_dir().join("identity.key");
        let keypair = identity::ensure_identity_keypair_at_path(&key_path)
            .expect("identity key should exist");
        let public_key = keypair.public().encode_protobuf();
        let account_id = AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &public_key)
                .expect("account id should derive"),
        );
        let session_id =
            normalize_session_id(&generate_session_id_hex()).expect("session id should encode");
        let goal = "Reply with exactly one word: hello".to_string();

        let mut client = crate::kernel::state::connect_public_api()
            .await
            .expect("local kernel should be reachable");
        let start_params =
            encode_start_agent_params(session_id, goal).expect("start params should encode");
        let (start_nonce, start_tx_hash) = submit_start_agent_with_nonce_retry(
            &mut client,
            &keypair,
            account_id.clone(),
            public_key.clone(),
            start_params,
        )
        .await
        .expect("start@v1 should submit");

        wait_for_tx_commit(&mut client, &start_tx_hash)
            .await
            .expect("start tx should commit");

        wait_for_session_state_visibility(&mut client, session_id, 30_000)
            .await
            .expect("session state should materialize after start tx commit");

        let step_params = encode_step_agent_params(session_id).expect("step params should encode");
        let step_tx_bytes = build_step_agent_tx_bytes(
            account_id,
            start_nonce.saturating_add(1),
            public_key,
            &keypair,
            step_params,
        )
        .expect("step tx should encode");
        let submit_response = submit_transaction_with_timeout(&mut client, step_tx_bytes)
            .await
            .expect("step@v1 should submit");
        let step_tx_hash = submit_response.tx_hash;
        wait_for_tx_commit(&mut client, &step_tx_hash)
            .await
            .expect("step tx should commit");

        let agent_state = timeout(Duration::from_secs(30), async {
            loop {
                if let Some(state) = query_agent_state(&mut client, session_id)
                    .await
                    .expect("session state query should succeed")
                {
                    if state.step_count > 0
                        || !matches!(state.status, AgentStatus::Idle | AgentStatus::Running)
                    {
                        break state;
                    }
                }
                sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .expect("agent state should advance beyond bootstrap");

        assert!(
            agent_state.step_count > 0
                || matches!(
                    agent_state.status,
                    AgentStatus::Completed(_) | AgentStatus::Paused(_) | AgentStatus::Failed(_)
                ),
            "agent state should advance after the first step commits"
        );
    }
}
