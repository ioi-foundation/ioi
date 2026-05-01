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

fn minimal_chat_outcome_request(raw_prompt: &str) -> crate::models::ChatOutcomeRequest {
    crate::models::ChatOutcomeRequest {
        request_id: "request-1".to_string(),
        raw_prompt: raw_prompt.to_string(),
        active_artifact_id: None,
        outcome_kind: crate::models::ChatOutcomeKind::Conversation,
        execution_strategy: ioi_types::app::ChatExecutionStrategy::SinglePass,
        execution_mode_decision: None,
        confidence: 1.0,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: Vec::new(),
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    }
}

fn minimal_chat_manifest() -> crate::models::ChatArtifactManifest {
    crate::models::ChatArtifactManifest {
        artifact_id: "artifact-session".to_string(),
        title: "Inline answer".to_string(),
        artifact_class: crate::models::ChatArtifactClass::Document,
        renderer: crate::models::ChatRendererKind::Markdown,
        primary_tab: "render".to_string(),
        tabs: Vec::new(),
        files: Vec::new(),
        verification: crate::models::ChatArtifactManifestVerification {
            status: crate::models::ChatArtifactVerificationStatus::Ready,
            lifecycle_state: crate::models::ChatArtifactLifecycleState::Ready,
            summary: "Ready.".to_string(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
        },
        storage: None,
    }
}

fn minimal_chat_session() -> crate::models::ChatArtifactSession {
    crate::models::ChatArtifactSession {
        session_id: "chat-session".to_string(),
        thread_id: "thread-session".to_string(),
        artifact_id: "artifact-session".to_string(),
        origin_prompt_event_id: None,
        title: "Inline answer".to_string(),
        summary: "Ready.".to_string(),
        current_lens: "render".to_string(),
        navigator_backing_mode: "artifact".to_string(),
        navigator_nodes: Vec::new(),
        attached_artifact_ids: Vec::new(),
        available_lenses: Vec::new(),
        materialization: crate::models::ChatArtifactMaterializationContract {
            version: 1,
            request_kind: "conversation".to_string(),
            normalized_intent: "answer".to_string(),
            summary: "Ready.".to_string(),
            artifact_brief: None,
            preparation_needs: None,
            prepared_context_resolution: None,
            skill_discovery_resolution: None,
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
            retrieved_sources: Vec::new(),
            edit_intent: None,
            candidate_summaries: Vec::new(),
            winning_candidate_id: None,
            winning_candidate_rationale: None,
            execution_envelope: None,
            work_graph_plan: None,
            work_graph_execution: None,
            work_graph_worker_receipts: Vec::new(),
            work_graph_change_receipts: Vec::new(),
            work_graph_merge_receipts: Vec::new(),
            work_graph_verification_receipts: Vec::new(),
            render_evaluation: None,
            validation: None,
            output_origin: None,
            production_provenance: None,
            acceptance_provenance: None,
            degraded_path_used: false,
            ux_lifecycle: None,
            failure: None,
            navigator_nodes: Vec::new(),
            file_writes: Vec::new(),
            command_intents: Vec::new(),
            preview_intent: None,
            pipeline_steps: Vec::new(),
            operator_steps: Vec::new(),
            notes: Vec::new(),
        },
        outcome_request: minimal_chat_outcome_request("answer"),
        artifact_manifest: minimal_chat_manifest(),
        verified_reply: crate::models::ChatVerifiedReply {
            status: crate::models::ChatArtifactVerificationStatus::Ready,
            lifecycle_state: crate::models::ChatArtifactLifecycleState::Ready,
            title: "Inline answer".to_string(),
            summary: "Ready.".to_string(),
            evidence: Vec::new(),
            production_provenance: None,
            acceptance_provenance: None,
            failure: None,
            updated_at: now_iso(),
        },
        lifecycle_state: crate::models::ChatArtifactLifecycleState::Ready,
        status: "ready".to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        retrieved_exemplars: Vec::new(),
        retrieved_sources: Vec::new(),
        selected_targets: Vec::new(),
        widget_state: None,
        ux_lifecycle: None,
        active_operator_run: None,
        operator_run_history: Vec::new(),
        created_at: now_iso(),
        updated_at: now_iso(),
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    }
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
fn session_hex_matches_active_chat_session_identifiers() {
    let task = AgentTask {
        id: "task-session".to_string(),
        intent: "chat".to_string(),
        agent: "autopilot".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 0,
        current_step: "Ready.".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some("task-session".to_string()),
        credential_request: None,
        clarification_request: None,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history: Vec::new(),
        events: Vec::new(),
        artifacts: Vec::new(),
        chat_session: Some(minimal_chat_session()),
        chat_outcome: None,
        renderer_session: None,
        build_session: None,
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        work_graph_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };

    assert!(session_hex_matches_task(&task, "task-session"));
    assert!(session_hex_matches_task(&task, "chat-session"));
    assert!(session_hex_matches_task(&task, "thread-session"));
    assert!(session_hex_matches_task(&task, "artifact-session"));
    assert!(!session_hex_matches_task(&task, "unrelated-session"));
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
        work_graph_tree: Vec::new(),
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
        work_graph_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };

    assert!(should_replace_with_reconciled_running_step(
        &task.current_step
    ));
}

#[test]
fn duplicate_chat_seed_submit_reuses_running_task() {
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
        work_graph_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };

    assert!(should_reuse_running_chat_task_for_duplicate_submit(
        &running_task,
        "Make me a report.",
        Some("chat"),
    ));
    assert!(!should_reuse_running_chat_task_for_duplicate_submit(
        &running_task,
        "Make me a report.",
        Some("overlay"),
    ));
    assert!(!should_reuse_running_chat_task_for_duplicate_submit(
        &running_task,
        "Make me a deck.",
        Some("chat"),
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
