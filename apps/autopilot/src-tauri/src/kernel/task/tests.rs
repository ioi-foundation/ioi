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
        std::env::var("AUTOPILOT_DATA_PROFILE").unwrap_or_else(|_| "desktop-localgpu".to_string()),
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
        chat_session: None,
        chat_outcome: None,
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
        chat_session: None,
        chat_outcome: None,
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
        chat_session: None,
        chat_outcome: None,
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
    let value =
        run_best_effort_optional_future("test future", async { Ok::<_, String>(Some("ready")) })
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
    let keypair =
        identity::ensure_identity_keypair_at_path(&key_path).expect("identity key should exist");
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
