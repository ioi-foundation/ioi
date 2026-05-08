use super::{
    canonical_chat_session_title_from_query, clean_chat_session_title_candidate,
    get_local_sessions, get_local_sessions_with_live_tasks, load_artifact_content, load_artifacts,
    load_events, load_local_engine_control_plane, load_local_engine_control_plane_document,
    load_session_file_context, persisted_workspace_root_for_session,
    save_local_engine_control_plane, save_local_engine_control_plane_document,
    save_local_session_summary, save_local_task_state, save_session_file_context,
    session_summary_from_task, thread_storage_key, LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME,
    LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
};
use crate::kernel::file_context::{
    apply_exclude_file_context_path, apply_include_file_context_path,
};
use crate::models::{
    AgentPhase, AgentTask, BuildArtifactSession, ChatCodeWorkerLease, ChatMessage,
    LocalEngineConfigMigrationRecord, LocalEngineControlPlaneDocument, SessionFileContext,
    SessionSummary,
};
use crate::open_or_create_memory_runtime;
use ioi_memory::MemoryRuntime;
use serde::Serialize;
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

fn env_var_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let lock = env_var_test_lock().lock().expect("env var test lock");
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key,
            previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn build_session(workspace_root: &str) -> BuildArtifactSession {
    BuildArtifactSession {
        session_id: "build-session".to_string(),
        chat_session_id: "chat-session".to_string(),
        workspace_root: workspace_root.to_string(),
        entry_document: "src/App.tsx".to_string(),
        preview_url: Some("http://127.0.0.1:4173".to_string()),
        preview_process_id: Some(41),
        scaffold_recipe_id: "workspace_surface".to_string(),
        presentation_variant_id: None,
        package_manager: "npm".to_string(),
        build_status: "ready".to_string(),
        verification_status: "ready".to_string(),
        receipts: Vec::new(),
        current_worker_execution: ChatCodeWorkerLease {
            backend: "local".to_string(),
            planner_authority: "runtime".to_string(),
            allowed_mutation_scope: vec!["workspace".to_string()],
            allowed_command_classes: vec!["build".to_string()],
            execution_state: "complete".to_string(),
            retry_classification: None,
            last_summary: Some("Preview verified.".to_string()),
        },
        current_lens: "render".to_string(),
        available_lenses: vec!["render".to_string()],
        ready_lenses: vec!["render".to_string()],
        retry_count: 0,
        last_failure_summary: None,
    }
}

fn task_with_workspace_root(workspace_root: &str) -> AgentTask {
    let mut task = AgentTask {
        id: "task-id".to_string(),
        intent: "Create a workspace artifact for billing settings".to_string(),
        agent: "Autopilot".to_string(),
        phase: AgentPhase::Complete,
        progress: 4,
        total_steps: 4,
        current_step: "Preview verified and ready".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None,
        pending_request_hash: None,
        session_id: Some("session-123".to_string()),
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
        build_session: Some(build_session(workspace_root)),
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        work_graph_tree: Vec::new(),
        generation: 0,
        lineage_id: "genesis".to_string(),
        fitness_score: 0.0,
    };
    task.sync_runtime_views();
    task
}

fn task_without_workspace_root() -> AgentTask {
    let mut task = task_with_workspace_root("/tmp/unused");
    task.build_session = None;
    task.sync_runtime_views();
    task
}

fn temp_runtime_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("autopilot-store-test-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("temp runtime dir");
    dir
}

#[test]
fn runtime_selector_promotes_default_only_for_enabled_non_mutating_turns() {
    let task = task_without_workspace_root();
    let promoted_readiness = super::runtime_harness_selector_live_promotion_readiness_proof(
        "promotion-session",
        &task,
        "Explain the runtime harness.",
        "verify",
        "objective_satisfied",
        true,
    );
    let promoted = super::runtime_harness_selector_decision_with_default_promotion(
        "promotion-session",
        &task,
        "Explain the runtime harness.",
        "verify",
        "objective_satisfied",
        true,
        Some(&promoted_readiness),
    );
    assert_eq!(
        promoted
            .get("selectedSelector")
            .and_then(|value| value.as_str()),
        Some("blessed_workflow_live_default")
    );
    assert_eq!(
        promoted
            .get("productionDefaultSelector")
            .and_then(|value| value.as_str()),
        Some("blessed_workflow_live_default")
    );
    assert_eq!(
        promoted
            .get("actualRuntimeAuthority")
            .and_then(|value| value.as_str()),
        Some("blessed_workflow_activation_default")
    );
    assert_eq!(
        promoted
            .get("defaultPromotionGate")
            .and_then(|gate| gate.get("eligible"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        promoted
            .get("livePromotionReadinessReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let mutating_task = task_with_workspace_root("/tmp/mutating-workspace");
    let blocked_readiness = super::runtime_harness_selector_live_promotion_readiness_proof(
        "promotion-session",
        &mutating_task,
        "Edit the workspace.",
        "verify",
        "objective_satisfied",
        true,
    );
    let blocked = super::runtime_harness_selector_decision_with_default_promotion(
        "promotion-session",
        &mutating_task,
        "Edit the workspace.",
        "verify",
        "objective_satisfied",
        true,
        Some(&blocked_readiness),
    );
    assert_eq!(
        blocked
            .get("selectedSelector")
            .and_then(|value| value.as_str()),
        Some("legacy_runtime")
    );
    assert_eq!(
        blocked
            .get("defaultPromotionGate")
            .and_then(|gate| gate.get("activationBlockers"))
            .and_then(|value| value.as_array())
            .map(|blockers| {
                blockers
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .contains(&"mutation_evidence_present")
            }),
        Some(true)
    );
}

#[test]
fn runtime_activation_id_gate_click_proof_fails_closed_for_default_dispatch() {
    let valid = super::runtime_harness_default_activation_id_gate_click_proof("gate-session");
    assert_eq!(
        super::runtime_harness_activation_id_gate_click_proof_blockers(
            Some(&valid),
            None,
            ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS,
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        super::runtime_harness_activation_id_gate_click_proof_blockers(
            None,
            None,
            ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS,
        ),
        vec!["activation_id_gate_click_proof_missing".to_string()]
    );

    let mut dry_run_only = valid.clone();
    dry_run_only["passed"] = json!(false);
    dry_run_only["mintedActivation"]["clicked"] = json!(false);
    dry_run_only["mintedActivation"]["applied"] = json!(false);
    dry_run_only["mintedActivation"]["receiptRefs"] = json!([]);
    let dry_run_blockers = super::runtime_harness_activation_id_gate_click_proof_blockers(
        Some(&dry_run_only),
        None,
        ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS,
    );
    assert!(dry_run_blockers.contains(&"activation_id_gate_click_proof_failed".to_string()));
    assert!(dry_run_blockers.contains(&"activation_id_gate_mint_not_clicked".to_string()));
    assert!(dry_run_blockers.contains(&"activation_id_gate_mint_not_applied".to_string()));
    assert!(dry_run_blockers.contains(&"activation_id_gate_mint_receipts_missing".to_string()));

    let mut mismatched = valid.clone();
    mismatched["mintedActivation"]["workerBindingActivationId"] = json!("activation:mismatch");
    let mismatch_blockers = super::runtime_harness_activation_id_gate_click_proof_blockers(
        Some(&mismatched),
        None,
        ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS,
    );
    assert!(
        mismatch_blockers.contains(&"activation_id_gate_mint_worker_binding_mismatch".to_string())
    );
}

#[test]
fn runtime_harness_fork_activation_records_rollback_restore_canaries() {
    let activation = super::runtime_harness_fork_activation(
        "rollback-canary-session",
        &[
            json!({"clusterId": "cognition", "clusterStatus": "passed"}),
            json!({"clusterId": "routing_model", "clusterStatus": "passed"}),
            json!({"clusterId": "verification_completion_output", "clusterStatus": "passed"}),
            json!({"clusterId": "authority_tooling", "clusterStatus": "passed"}),
        ],
    );

    let invalid_canary = activation
        .get("invalidFork")
        .and_then(|fork| fork.get("rollbackRestoreCanary"))
        .expect("invalid fork rollback restore canary");
    assert_eq!(
        invalid_canary
            .get("schemaVersion")
            .and_then(|value| value.as_str()),
        Some("workflow.harness.rollback-restore-canary.v1")
    );
    assert_eq!(
        invalid_canary
            .get("status")
            .and_then(|value| value.as_str()),
        Some("blocked")
    );
    assert_eq!(
        invalid_canary
            .get("revisionSource")
            .and_then(|value| value.as_str()),
        Some("git")
    );
    assert_eq!(
        invalid_canary
            .get("hashVerified")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        invalid_canary
            .get("receiptBindingRef")
            .and_then(|value| value.as_str())
            .map(|value| value.starts_with("workflow_restore_canary:")),
        Some(true)
    );
    let invalid_receipt_ref = invalid_canary
        .get("receiptBindingRef")
        .and_then(|value| value.as_str())
        .expect("invalid canary receipt binding ref");
    assert!(invalid_canary
        .get("evidenceRefs")
        .and_then(|value| value.as_array())
        .expect("invalid canary evidence refs")
        .iter()
        .any(|value| value.as_str() == Some(invalid_receipt_ref)));
    let invalid_audit = activation
        .get("invalidFork")
        .and_then(|fork| fork.get("activationAudit"))
        .and_then(|value| value.as_array())
        .expect("invalid activation audit");
    assert!(invalid_audit.iter().any(|event| {
        event
            .get("receiptRefs")
            .and_then(|value| value.as_array())
            .map(|refs| {
                refs.iter()
                    .any(|value| value.as_str() == Some(invalid_receipt_ref))
            })
            .unwrap_or(false)
    }));
    assert_eq!(
        invalid_canary
            .get("blockers")
            .and_then(|value| value.as_array())
            .map(|blockers| blockers
                .iter()
                .any(|blocker| { blocker.as_str() == Some("rollback_restore_canary_not_run") })),
        Some(true)
    );

    let valid_canary = activation
        .get("validFork")
        .and_then(|fork| fork.get("rollbackRestoreCanary"))
        .expect("valid fork rollback restore canary");
    assert_eq!(
        valid_canary
            .get("schemaVersion")
            .and_then(|value| value.as_str()),
        Some("workflow.harness.rollback-restore-canary.v1")
    );
    assert_eq!(
        valid_canary.get("status").and_then(|value| value.as_str()),
        Some("not_required")
    );
    assert_eq!(
        valid_canary
            .get("revisionSource")
            .and_then(|value| value.as_str()),
        Some("file_hash_only")
    );
    assert_eq!(
        valid_canary
            .get("hashVerified")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        valid_canary
            .get("receiptBindingRef")
            .and_then(|value| value.as_str())
            .map(|value| value.starts_with("workflow_restore_canary:")),
        Some(true)
    );
    let valid_receipt_ref = valid_canary
        .get("receiptBindingRef")
        .and_then(|value| value.as_str())
        .expect("valid canary receipt binding ref");
    assert!(valid_canary
        .get("evidenceRefs")
        .and_then(|value| value.as_array())
        .expect("valid canary evidence refs")
        .iter()
        .any(|value| value.as_str() == Some(valid_receipt_ref)));
    let valid_audit = activation
        .get("validFork")
        .and_then(|fork| fork.get("activationAudit"))
        .and_then(|value| value.as_array())
        .expect("valid activation audit");
    for event_type in [
        "dry_run_mintable",
        "activation_minted",
        "rollback_drill_passed",
        "rollback_executed",
    ] {
        assert!(valid_audit.iter().any(|event| {
            event.get("eventType").and_then(|value| value.as_str()) == Some(event_type)
                && event
                    .get("receiptRefs")
                    .and_then(|value| value.as_array())
                    .map(|refs| {
                        refs.iter()
                            .any(|value| value.as_str() == Some(valid_receipt_ref))
                    })
                    .unwrap_or(false)
        }));
    }
    assert!(activation
        .get("validFork")
        .and_then(|fork| fork.get("activationRollbackExecution"))
        .and_then(|execution| execution.get("restoreReceiptBindingRef"))
        .and_then(|value| value.as_str())
        .map(|value| value == valid_receipt_ref)
        .unwrap_or(false));
    assert_eq!(
        valid_canary
            .get("blockers")
            .and_then(|value| value.as_array())
            .map(|blockers| blockers.is_empty()),
        Some(true)
    );
}

#[test]
fn default_runtime_dispatch_accepts_isolated_output_writer_staged_write_canary() {
    let _provider_gated_visible_output_guard =
        EnvVarGuard::set(super::WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT_ENV, "1");
    let mut task = task_without_workspace_root();
    let sid = "default-dispatch-session";
    let latest_user_turn = "Explain the runtime harness.";
    let latest_agent_turn = "The runtime harness is a read-only workflow substrate.";
    task.history.push(ChatMessage {
        role: "user".to_string(),
        text: latest_user_turn.to_string(),
        timestamp: 100,
    });
    task.history.push(ChatMessage {
        role: "agent".to_string(),
        text: latest_agent_turn.to_string(),
        timestamp: 200,
    });
    let selector = super::runtime_harness_selector_decision_with_default_promotion(
        sid,
        &task,
        latest_user_turn,
        "verify",
        "objective_satisfied",
        true,
        Some(
            &super::runtime_harness_selector_live_promotion_readiness_proof(
                sid,
                &task,
                latest_user_turn,
                "verify",
                "objective_satisfied",
                true,
            ),
        ),
    );
    let shadow = super::runtime_harness_shadow_run(
        &task,
        sid,
        latest_user_turn,
        latest_agent_turn,
        "sha256:prompt",
        "verified_desktop_chat",
        "verify",
        "objective_satisfied",
        true,
        false,
        false,
    );
    let gated = super::runtime_harness_gated_cluster_runs(sid, &shadow);
    let cognition = super::runtime_harness_cognition_canary_execution_boundary(
        sid,
        &task,
        latest_user_turn,
        latest_agent_turn,
        "objective_satisfied",
        true,
        &shadow,
        gated.as_slice(),
        &selector,
    );
    let routing = super::runtime_harness_routing_model_canary_execution_boundary(
        sid,
        &task,
        latest_user_turn,
        latest_agent_turn,
        "objective_satisfied",
        true,
        &shadow,
        gated.as_slice(),
        &selector,
    );
    let verification = super::runtime_harness_verification_output_canary_execution_boundary(
        sid,
        &task,
        latest_user_turn,
        latest_agent_turn,
        "objective_satisfied",
        true,
        &shadow,
        gated.as_slice(),
        &selector,
    );
    let authority_tooling = super::runtime_harness_authority_tooling_canary_execution_boundary(
        sid,
        &task,
        latest_user_turn,
        latest_agent_turn,
        "objective_satisfied",
        true,
        &shadow,
        gated.as_slice(),
        &selector,
    );
    let staged_record = super::workflow_output_writer_staged_transcript_write_record(
        sid,
        &task,
        &super::runtime_prompt_hash(&[latest_agent_turn]),
    );
    let staged_proof = json!({
        "schemaVersion": "workflow.output_writer.transcript-staging-proof.v1",
        "surface": "checkpoint_blobs",
        "checkpointName": super::WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
        "record": staged_record,
        "persisted": true,
        "loadedBeforeRollback": true,
        "visibleBeforeCount": 0,
        "visibleAfterCount": 0,
        "excludedFromVisibleTranscript": true,
        "rollbackAction": "delete_checkpoint_blob",
        "rollbackExecuted": true,
        "rollbackVerified": true,
        "rollbackStatus": "deleted",
    });
    let visible_record = super::workflow_output_writer_visible_transcript_write_record(
        sid,
        &task,
        &super::runtime_prompt_hash(&[latest_agent_turn]),
    )
    .expect("visible transcript record");
    let visible_proof = json!({
        "schemaVersion": "workflow.output_writer.visible-transcript-write-proof.v1",
        "mode": "workflow_visible_transcript_write",
        "target": "checkpoint_transcript_messages",
        "record": visible_record,
        "persisted": true,
        "committed": true,
        "created": true,
        "visible": true,
        "visibleBeforeCount": 1,
        "visibleAfterCount": 2,
        "visibleRowsDelta": 1,
        "existedBefore": false,
        "idempotencyGuard": "session_role_timestamp_order_content_hash_receipt_binding",
        "duplicateSuppressionReady": true,
        "identityCheckpointPersisted": true,
        "rollbackAvailable": true,
        "rollbackMode": "legacy_runtime_fallback_with_idempotent_duplicate_suppression",
    });
    let legacy_fallback = json!({
        "schemaVersion": "workflow.output_writer.legacy-transcript-fallback.v1",
        "phase": "legacy_fallback_after_workflow_output",
        "writeAuthority": "existing_runtime_service",
        "appendedCount": 0,
        "duplicateSuppressedCount": 2,
        "latestAgentDuplicateSuppressed": true,
        "idempotencyGuard": "role_timestamp_content_hash"
    });
    let live_handoff = json!({
        "schemaVersion": "workflow.harness.live-handoff.v1",
        "selector": "blessed_workflow_live_default",
        "productionDefaultSelector": "blessed_workflow_live_default",
        "workflowId": ioi_types::app::DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        "activationId": ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "harnessHash": ioi_types::app::DEFAULT_AGENT_HARNESS_HASH,
        "componentVersionSet": {
            "ioi.agent-harness.planner.v1": "1.0.0",
            "ioi.agent-harness.prompt_assembler.v1": "1.0.0",
            "ioi.agent-harness.task_state.v1": "1.0.0",
            "ioi.agent-harness.model_router.v1": "1.0.0",
            "ioi.agent-harness.model_call.v1": "1.0.0",
            "ioi.agent-harness.policy_gate.v1": "1.0.0",
            "ioi.agent-harness.verifier.v1": "1.0.0",
            "ioi.agent-harness.output_writer.v1": "1.0.0"
        },
        "canaryStatus": "passed",
        "defaultAuthorityTransferred": true,
        "runtimeAuthority": "blessed_workflow_activation_default",
        "rollbackTarget": ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        "rollbackAvailable": true,
        "livePromotionReadinessProof": selector
            .get("livePromotionReadinessProof")
            .cloned()
            .unwrap_or_else(|| json!(null)),
        "livePromotionReadinessReady": true,
        "livePromotionReadinessBlockers": [],
        "livePromotionReadinessPolicyDecision": "allow_default_harness_live_promotion_readiness"
    });
    let activation_id_gate_click_proof =
        super::runtime_harness_default_activation_id_gate_click_proof(sid);
    let canary_boundaries = vec![cognition, routing, verification, authority_tooling];
    let dispatch = super::runtime_harness_default_runtime_dispatch(
        sid,
        &task,
        "verified_desktop_chat",
        "verify",
        latest_agent_turn,
        "sha256:prompt",
        &selector,
        &live_handoff,
        canary_boundaries.as_slice(),
        Some(&activation_id_gate_click_proof),
        Some(&staged_proof),
        Some(&visible_proof),
        Some(&legacy_fallback),
    );
    let binding = super::runtime_harness_default_runtime_binding(
        sid,
        &task,
        &selector,
        &live_handoff,
        &dispatch,
    );

    assert_eq!(
        dispatch.get("status").and_then(|value| value.as_str()),
        Some("accepted"),
        "activation blockers: {}",
        dispatch
            .get("activationBlockers")
            .cloned()
            .unwrap_or_else(|| json!([]))
    );
    assert_eq!(
        dispatch
            .get("runtimeAuthority")
            .and_then(|value| value.as_str()),
        Some("blessed_workflow_activation_default")
    );
    assert_eq!(
        dispatch
            .get("outputAuthority")
            .and_then(|value| value.as_str()),
        Some("blessed_workflow_activation_default")
    );
    assert_eq!(
        dispatch
            .get("drivesRuntimeDecision")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("activationIdGateClickProofPresent")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("activationIdGateClickProofPassed")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("activationIdGateClickProofBlockers")
            .and_then(|value| value.as_array())
            .map(Vec::is_empty),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("defaultDispatchActivationBlockers")
            .and_then(|value| value.as_array())
            .map(Vec::is_empty),
        Some(true)
    );
    let missing_proof_dispatch = super::runtime_harness_default_runtime_dispatch(
        sid,
        &task,
        "verified_desktop_chat",
        "verify",
        latest_agent_turn,
        "sha256:prompt",
        &selector,
        &live_handoff,
        canary_boundaries.as_slice(),
        None,
        Some(&staged_proof),
        Some(&visible_proof),
        Some(&legacy_fallback),
    );
    assert_eq!(
        missing_proof_dispatch
            .get("status")
            .and_then(|value| value.as_str()),
        Some("blocked")
    );
    assert_eq!(
        missing_proof_dispatch
            .get("activationIdGateClickProofPresent")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(missing_proof_dispatch
        .get("defaultDispatchActivationBlockers")
        .and_then(|value| value.as_array())
        .map(|blockers| blockers
            .iter()
            .any(|value| value.as_str() == Some("activation_id_gate_click_proof_missing")))
        .unwrap_or(false));
    let mut mismatched_activation_id_gate_click_proof = activation_id_gate_click_proof.clone();
    mismatched_activation_id_gate_click_proof["mintedActivation"]["workerBindingActivationId"] =
        json!("activation:mismatch");
    let mismatched_proof_dispatch = super::runtime_harness_default_runtime_dispatch(
        sid,
        &task,
        "verified_desktop_chat",
        "verify",
        latest_agent_turn,
        "sha256:prompt",
        &selector,
        &live_handoff,
        canary_boundaries.as_slice(),
        Some(&mismatched_activation_id_gate_click_proof),
        Some(&staged_proof),
        Some(&visible_proof),
        Some(&legacy_fallback),
    );
    assert_eq!(
        mismatched_proof_dispatch
            .get("drivesRuntimeDecision")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(mismatched_proof_dispatch
        .get("activationIdGateClickProofBlockers")
        .and_then(|value| value.as_array())
        .map(|blockers| blockers.iter().any(|value| {
            value.as_str() == Some("activation_id_gate_mint_worker_binding_mismatch")
        }))
        .unwrap_or(false));
    assert_eq!(
        binding
            .get("schemaVersion")
            .and_then(|value| value.as_str()),
        Some("workflow.harness.default-runtime-binding.v1")
    );
    assert_eq!(
        binding.get("workflowId").and_then(|value| value.as_str()),
        Some(ioi_types::app::DEFAULT_AGENT_HARNESS_WORKFLOW_ID)
    );
    assert_eq!(
        binding.get("activationId").and_then(|value| value.as_str()),
        Some(ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
    );
    assert_eq!(
        binding.get("harnessHash").and_then(|value| value.as_str()),
        Some(ioi_types::app::DEFAULT_AGENT_HARNESS_HASH)
    );
    assert_eq!(
        binding
            .get("selectorDecisionId")
            .and_then(|value| value.as_str()),
        selector.get("decisionId").and_then(|value| value.as_str())
    );
    assert_eq!(
        binding
            .get("defaultDispatchId")
            .and_then(|value| value.as_str()),
        dispatch.get("dispatchId").and_then(|value| value.as_str())
    );
    assert_eq!(
        binding
            .get("bindingMatched")
            .and_then(|value| value.as_bool()),
        Some(true),
        "binding authority blockers: {}",
        binding
            .get("workerBindingAuthorityBlockers")
            .cloned()
            .unwrap_or_else(|| json!([]))
    );
    assert_eq!(
        binding
            .get("workerBindingAuthorityReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerBindingAuthorityBlockers")
            .and_then(|value| value.as_array())
            .map(Vec::is_empty),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerBindingRegistryBound")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerBindingRegistryStatus")
            .and_then(|value| value.as_str()),
        Some("bound")
    );
    assert_eq!(
        binding
            .get("workerBindingRegistryBlockers")
            .and_then(|value| value.as_array())
            .map(Vec::is_empty),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerAttachAccepted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerAttachStatus")
            .and_then(|value| value.as_str()),
        Some("bound")
    );
    assert_eq!(
        binding
            .get("workerAttachBlockers")
            .and_then(|value| value.as_array())
            .map(Vec::is_empty),
        Some(true)
    );
    assert_eq!(
        binding
            .get("invalidWorkerAttachBlocked")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("livePromotionReadinessProofIdsMatch")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("invalidForkLiveActivationBlocked")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerBinding")
            .and_then(|value| value.get("authorityBindingReady"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerBinding")
            .and_then(|value| value.get("selectorDecisionId"))
            .and_then(|value| value.as_str()),
        selector.get("decisionId").and_then(|value| value.as_str())
    );
    assert_eq!(
        binding
            .get("workerBinding")
            .and_then(|value| value.get("defaultDispatchId"))
            .and_then(|value| value.as_str()),
        dispatch.get("dispatchId").and_then(|value| value.as_str())
    );
    assert_eq!(
        binding
            .get("workerBindingRegistryRecord")
            .and_then(|value| value.get("bindingStatus"))
            .and_then(|value| value.as_str()),
        Some("bound")
    );
    assert_eq!(
        binding
            .get("workerBindingRegistryRecord")
            .and_then(|value| value.get("readinessProofId"))
            .and_then(|value| value.as_str()),
        selector
            .get("livePromotionReadinessProof")
            .and_then(|value| value.get("proofId"))
            .and_then(|value| value.as_str())
    );
    assert_eq!(
        binding
            .get("workerBindingRegistryRecord")
            .and_then(|value| value.get("workerBinding"))
            .and_then(|value| value.get("harnessActivationId"))
            .and_then(|value| value.as_str()),
        Some(ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
    );
    assert_eq!(
        binding
            .get("workerAttachReceipt")
            .and_then(|value| value.get("registryRecordId"))
            .and_then(|value| value.as_str()),
        binding
            .get("workerBindingRegistryRecord")
            .and_then(|value| value.get("registryRecordId"))
            .and_then(|value| value.as_str())
    );
    assert_eq!(
        binding
            .get("workerAttachReceipt")
            .and_then(|value| value.get("attachStatus"))
            .and_then(|value| value.as_str()),
        Some("bound")
    );
    assert_eq!(
        binding
            .get("workerAttachResumeReceipt")
            .and_then(|value| value.get("attachStatus"))
            .and_then(|value| value.as_str()),
        Some("resumed")
    );
    assert_eq!(
        binding
            .get("workerAttachRollbackReceipt")
            .and_then(|value| value.get("attachStatus"))
            .and_then(|value| value.as_str()),
        Some("rolled_back")
    );
    assert_eq!(
        binding
            .get("workerAttachLifecycleComplete")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    let worker_attach_lifecycle_statuses = binding
        .get("workerAttachLifecycleStatuses")
        .and_then(|value| value.as_array())
        .expect("worker attach lifecycle statuses");
    assert!(worker_attach_lifecycle_statuses
        .iter()
        .any(|value| value.as_str() == Some("bound")));
    assert!(worker_attach_lifecycle_statuses
        .iter()
        .any(|value| value.as_str() == Some("resumed")));
    assert!(worker_attach_lifecycle_statuses
        .iter()
        .any(|value| value.as_str() == Some("rolled_back")));
    assert_eq!(
        binding
            .get("workerSessionStatus")
            .and_then(|value| value.as_str()),
        Some("rollback_ready")
    );
    assert_eq!(
        binding
            .get("workerSessionAccepted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerSessionRecord")
            .and_then(|value| value.get("currentStatus"))
            .and_then(|value| value.as_str()),
        Some("rollback_ready")
    );
    assert_eq!(
        binding
            .get("workerSessionRecord")
            .and_then(|value| value.get("workerId"))
            .and_then(|value| value.as_str()),
        binding
            .get("workerAttachReceipt")
            .and_then(|value| value.get("workerId"))
            .and_then(|value| value.as_str())
    );
    assert!(binding
        .get("workerSessionRecord")
        .and_then(|value| value.get("lifecycleEventIds"))
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 3)
        .unwrap_or(false));
    assert_eq!(
        binding
            .get("workerSessionRecord")
            .and_then(|value| value.get("persistedInRuntimeCheckpoint"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        binding
            .get("workerSessionRecord")
            .and_then(|value| value.get("restoredFromPersistedSession"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(binding
        .get("workerSessionRecord")
        .and_then(|value| value.get("persistenceBlockers"))
        .and_then(|value| value.as_array())
        .map(|items| items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        binding
            .get("workerSessionRecord")
            .and_then(|value| value.get("launchAuthorityReady"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(binding
        .get("workerSessionRecord")
        .and_then(|value| value.get("launchAuthorityBlockers"))
        .and_then(|value| value.as_array())
        .map(|items| items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        binding
            .get("workerSessionRecord")
            .and_then(|value| value.get("rollbackHandoffReady"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(binding
        .get("workerSessionRecord")
        .and_then(|value| value.get("rollbackHandoffBlockers"))
        .and_then(|value| value.as_array())
        .map(|items| items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        binding
            .get("invalidWorkerAttachReceipt")
            .and_then(|value| value.get("accepted"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    let clusters = dispatch
        .get("acceptedClusterIds")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(clusters.contains(&"cognition"));
    assert!(clusters.contains(&"routing_model"));
    assert!(clusters.contains(&"verification_output"));
    assert!(clusters.contains(&"authority_tooling"));
    let components = dispatch
        .get("componentKinds")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(components.contains(&"verifier"));
    assert!(components.contains(&"completion_gate"));
    assert!(components.contains(&"output_writer"));
    assert!(components.contains(&"policy_gate"));
    assert!(components.contains(&"dry_run_simulator"));
    assert!(components.contains(&"approval_gate"));
    assert_eq!(
        dispatch
            .get("routingModelAdapterMode")
            .and_then(|value| value.as_str()),
        Some("workflow_component_adapter_gated")
    );
    let routing_model_component_kinds = dispatch
        .get("routingModelComponentKinds")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(routing_model_component_kinds.contains(&"model_router"));
    assert!(routing_model_component_kinds.contains(&"model_call"));
    assert!(routing_model_component_kinds.contains(&"tool_router"));
    assert_eq!(
        dispatch
            .get("routingModelAdapterResults")
            .and_then(|value| value.as_array())
            .map(|items| items.len()),
        Some(3)
    );
    assert!(dispatch
        .get("routingModelDivergenceClasses")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str())
                .all(|value| value == "none")
        })
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("outputWriterDeferred")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("outputWriterStatus")
            .and_then(|value| value.as_str()),
        Some("visible_write_committed")
    );
    assert_eq!(
        dispatch
            .get("outputWriterHandoffReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterMaterializationMode")
            .and_then(|value| value.as_str()),
        Some("workflow_visible_transcript_write")
    );
    assert_eq!(
        dispatch
            .get("outputWriterMaterializationCanaryReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterMaterializationCommitted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterStagedWriteMode")
            .and_then(|value| value.as_str()),
        Some("isolated_checkpoint_blob")
    );
    assert_eq!(
        dispatch
            .get("outputWriterStagedWriteCanaryReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterStagedWritePersisted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterStagedWriteCommitted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterStagedWriteVisible")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("outputWriterStagedWriteExcludedFromVisibleTranscript")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterStagedWriteRollbackStatus")
            .and_then(|value| value.as_str()),
        Some("deleted")
    );
    assert_eq!(
        dispatch
            .get("outputWriterStagedWriteRollbackVerified")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterVisibleWriteMode")
            .and_then(|value| value.as_str()),
        Some("workflow_visible_transcript_write")
    );
    assert_eq!(
        dispatch
            .get("outputWriterVisibleWriteReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterVisibleWritePersisted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterVisibleWriteCommitted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterVisibleWriteVisible")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputWriterVisibleWriteLegacyDuplicateSuppressed")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("cognitionExecutionMode")
            .and_then(|value| value.as_str()),
        Some("workflow_synchronous_envelope")
    );
    assert_eq!(
        dispatch
            .get("cognitionExecutionReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("promptAssemblyMode")
            .and_then(|value| value.as_str()),
        Some("workflow_synchronous_envelope")
    );
    assert_eq!(
        dispatch
            .get("promptAssemblyPromptHash")
            .and_then(|value| value.as_str()),
        Some("sha256:prompt")
    );
    assert_eq!(
        dispatch
            .get("promptAssemblyPromptHashMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("modelExecutionMode")
            .and_then(|value| value.as_str()),
        Some("workflow_synchronous_envelope")
    );
    assert_eq!(
        dispatch
            .get("modelExecutionEnvelopeReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(dispatch
        .get("modelExecutionBindingId")
        .and_then(|value| value.as_str())
        .map(|value| !value.is_empty())
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("modelExecutionBindingReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("modelExecutionPromptHash")
            .and_then(|value| value.as_str()),
        Some("sha256:prompt")
    );
    assert_eq!(
        dispatch
            .get("modelExecutionPromptHashMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("modelExecutionOutputHash")
            .and_then(|value| value.as_str()),
        dispatch
            .get("actualVisibleOutputHash")
            .and_then(|value| value.as_str())
    );
    assert_eq!(
        dispatch
            .get("modelExecutionOutputHashMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("modelExecutionProviderInvocationMode")
            .and_then(|value| value.as_str()),
        Some("workflow_provider_canary")
    );
    assert_eq!(
        dispatch
            .get("modelExecutionLowLevelInvocationDeferred")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("modelExecutionFallbackSelector")
            .and_then(|value| value.as_str()),
        Some("legacy_runtime_model_invocation")
    );
    assert_eq!(
        dispatch
            .get("modelProviderCanaryMode")
            .and_then(|value| value.as_str()),
        Some("workflow_provider_canary")
    );
    assert_eq!(
        dispatch
            .get("modelProviderCanaryReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("modelProviderCanaryOutputHashMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("modelProviderCanaryTranscriptMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("modelProviderCanaryFallbackRetained")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("modelProviderCanaryRollbackAvailable")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingMode")
            .and_then(|value| value.as_str()),
        Some("workflow_live_dry_run")
    );
    assert_eq!(
        dispatch
            .get("authorityToolingReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingPolicyGateReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingToolRouterReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingDryRunSimulatorReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingApprovalGateReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingReadOnlyAuthorityCanaryReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(dispatch
        .get("authorityToolingReadOnlyComponentKinds")
        .and_then(|value| value.as_array())
        .map(|items| {
            let component_kinds = items
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>();
            component_kinds.contains(&"mcp_provider")
                && component_kinds.contains(&"mcp_tool_call")
                && component_kinds.contains(&"tool_call")
                && component_kinds.contains(&"connector_call")
                && component_kinds.contains(&"wallet_capability")
        })
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingMutationDeferredComponentKinds")
        .and_then(|value| value.as_array())
        .map(|items| {
            let component_kinds = items
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>();
            component_kinds.contains(&"mcp_provider")
                && component_kinds.contains(&"mcp_tool_call")
                && component_kinds.contains(&"tool_call")
                && component_kinds.contains(&"connector_call")
                && component_kinds.contains(&"wallet_capability")
        })
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("authorityToolingReadOnlyRouteAccepted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingDestructiveRouteDenied")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingMutatingToolCallsBlocked")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingSideEffectsExecuted")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingRollbackAvailable")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("legacyTranscriptAuthorityRetained")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("transcriptMaterializationMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("transcriptMaterializationContentHashMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("transcriptMaterializationOrderMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("transcriptMaterializationReceiptBindingMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("transcriptMaterializationDivergenceCount")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        dispatch
            .get("workflowTranscriptWriteCandidate")
            .and_then(|value| value.get("committed"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("stagedTranscriptWriteRecord")
            .and_then(|value| value.get("committed"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("stagedTranscriptWriteRecord")
            .and_then(|value| value.get("visible"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("legacyTranscriptWriteRecord")
            .and_then(|value| value.get("committed"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("legacyTranscriptWriteRecord")
            .and_then(|value| value.get("suppressedByIdempotency"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("workflowTranscriptWriteRecord")
            .and_then(|value| value.get("committed"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("workflowTranscriptWriteRecord")
            .and_then(|value| value.get("visible"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("outputHashDivergence")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        dispatch
            .get("outputHashDivergenceCount")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        dispatch
            .get("stagedTranscriptWriteMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("stagedTranscriptWriteDivergenceCount")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        dispatch
            .get("visibleTranscriptWriteMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("visibleTranscriptWriteDivergenceCount")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        dispatch
            .get("proposedVisibleOutputHash")
            .and_then(|value| value.as_str()),
        dispatch
            .get("actualVisibleOutputHash")
            .and_then(|value| value.as_str())
    );
    assert!(dispatch
        .get("dispatchNodeAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 19)
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("workerAttachLifecycleComplete")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    let dispatch_worker_attach_lifecycle_attempt_ids = dispatch
        .get("workerAttachLifecycleAttemptIds")
        .and_then(|value| value.as_array())
        .expect("dispatch worker attach lifecycle attempt ids");
    assert!(dispatch_worker_attach_lifecycle_attempt_ids.len() >= 3);
    let dispatch_node_attempt_ids = dispatch
        .get("dispatchNodeAttemptIds")
        .and_then(|value| value.as_array())
        .expect("dispatch node attempt ids");
    for attempt_id in dispatch_worker_attach_lifecycle_attempt_ids {
        assert!(dispatch_node_attempt_ids.contains(attempt_id));
    }
    assert_eq!(
        dispatch
            .get("workerSessionRecord")
            .and_then(|value| value.get("currentStatus"))
            .and_then(|value| value.as_str()),
        Some("rollback_ready")
    );
    assert_eq!(
        dispatch
            .get("workerSessionRecord")
            .and_then(|value| value.get("persistedInRuntimeCheckpoint"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("workerSessionRecord")
            .and_then(|value| value.get("restoredFromPersistedSession"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("workerSessionRecord")
            .and_then(|value| value.get("launchAuthorityReady"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("workerSessionRecord")
            .and_then(|value| value.get("rollbackHandoffReady"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(dispatch
        .get("workerSessionRecord")
        .and_then(|value| value.get("lifecycleAttemptIds"))
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 3)
        .unwrap_or(false));
    assert!(dispatch
        .get("cognitionExecutionAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 3)
        .unwrap_or(false));
    assert!(dispatch
        .get("cognitionExecutionReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 3)
        .unwrap_or(false));
    assert!(dispatch
        .get("cognitionExecutionReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 3)
        .unwrap_or(false));
    assert!(dispatch
        .get("modelExecutionAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 3)
        .unwrap_or(false));
    assert!(dispatch
        .get("modelExecutionReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 3)
        .unwrap_or(false));
    assert!(dispatch
        .get("modelExecutionReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 3)
        .unwrap_or(false));
    assert!(dispatch
        .get("modelProviderCanaryAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("modelProviderCanaryReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("modelProviderCanaryReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("outputWriterMaterializationCanaryAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("outputWriterStagedWriteCanaryAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("outputWriterVisibleWriteAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingLiveDryRunAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 10)
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingReadOnlyLiveAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 5)
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingReadOnlyReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 5)
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingReadOnlyReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 5)
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("authorityToolingProviderCatalogLiveReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingProviderCatalogLiveComponentKind")
            .and_then(|value| value.as_str()),
        Some("mcp_provider")
    );
    assert!(dispatch
        .get("authorityToolingProviderCatalogLiveAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingProviderCatalogLiveReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingProviderCatalogLiveReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("authorityToolingMcpToolCatalogLiveReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingMcpToolCatalogLiveComponentKind")
            .and_then(|value| value.as_str()),
        Some("mcp_tool_call")
    );
    assert!(dispatch
        .get("authorityToolingMcpToolCatalogLiveAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingMcpToolCatalogLiveReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingMcpToolCatalogLiveReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("authorityToolingNativeToolCatalogLiveReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingNativeToolCatalogLiveComponentKind")
            .and_then(|value| value.as_str()),
        Some("tool_call")
    );
    assert!(dispatch
        .get("authorityToolingNativeToolCatalogLiveAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingNativeToolCatalogLiveReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingNativeToolCatalogLiveReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("authorityToolingConnectorCatalogLiveReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingConnectorCatalogLiveComponentKind")
            .and_then(|value| value.as_str()),
        Some("connector_call")
    );
    assert!(dispatch
        .get("authorityToolingConnectorCatalogLiveAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingConnectorCatalogLiveReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingConnectorCatalogLiveReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        dispatch
            .get("authorityToolingWalletCapabilityLiveDryRunReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingWalletCapabilityLiveDryRunComponentKind")
            .and_then(|value| value.as_str()),
        Some("wallet_capability")
    );
    assert!(dispatch
        .get("authorityToolingWalletCapabilityLiveDryRunAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingWalletCapabilityLiveDryRunReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("readOnlyAuthorityCanaryReady"))
            .and_then(|value| value.as_bool())
            == Some(true)
    );
    assert!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("providerCatalogLiveReady"))
            .and_then(|value| value.as_bool())
            == Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("providerCatalogLiveComponentKind"))
            .and_then(|value| value.as_str()),
        Some("mcp_provider")
    );
    assert!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("mcpToolCatalogLiveReady"))
            .and_then(|value| value.as_bool())
            == Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("mcpToolCatalogLiveComponentKind"))
            .and_then(|value| value.as_str()),
        Some("mcp_tool_call")
    );
    assert!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("nativeToolCatalogLiveReady"))
            .and_then(|value| value.as_bool())
            == Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("nativeToolCatalogLiveComponentKind"))
            .and_then(|value| value.as_str()),
        Some("tool_call")
    );
    assert!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("connectorCatalogLiveReady"))
            .and_then(|value| value.as_bool())
            == Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("connectorCatalogLiveComponentKind"))
            .and_then(|value| value.as_str()),
        Some("connector_call")
    );
    assert!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("walletCapabilityLiveDryRunReady"))
            .and_then(|value| value.as_bool())
            == Some(true)
    );
    assert_eq!(
        dispatch
            .get("authorityToolingProof")
            .and_then(|proof| proof.get("walletCapabilityLiveDryRunComponentKind"))
            .and_then(|value| value.as_str()),
        Some("wallet_capability")
    );
    assert!(dispatch
        .get("authorityToolingProof")
        .and_then(|proof| proof.get("mutationDeferredComponentKinds"))
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str())
                .any(|value| value == "wallet_capability")
        })
        .unwrap_or(false));
    assert!(dispatch
        .get("authorityToolingDenialReceiptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(dispatch
        .get("acceptedNodeAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| items.len() >= 18)
        .unwrap_or(false));
}

fn save_local_engine_control_plane_value<T: Serialize>(
    memory_runtime: &Arc<MemoryRuntime>,
    value: &T,
) {
    let key = super::global_checkpoint_key(LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME)
        .expect("local engine checkpoint key");
    let bytes = serde_json::to_vec(value).expect("serialize local engine checkpoint value");
    memory_runtime
        .upsert_checkpoint_blob(key, LOCAL_ENGINE_CONTROL_PLANE_CHECKPOINT_NAME, &bytes)
        .expect("persist local engine checkpoint value");
}

#[test]
fn session_summary_from_task_preserves_existing_title_and_timestamp() {
    let task = task_with_workspace_root("/tmp/workspace");
    let existing = SessionSummary {
        session_id: "session-123".to_string(),
        title: "Existing title".to_string(),
        timestamp: 42,
        phase: Some(AgentPhase::Running),
        current_step: Some("Initializing".to_string()),
        resume_hint: None,
        workspace_root: None,
    };

    let summary = session_summary_from_task(&task, Some(&existing));

    assert_eq!(summary.session_id, "session-123");
    assert_eq!(summary.title, "Existing title");
    assert_eq!(summary.timestamp, 42);
    assert_eq!(summary.phase, Some(AgentPhase::Complete));
    assert_eq!(
        summary.current_step.as_deref(),
        Some("Preview verified and ready")
    );
    assert_eq!(summary.resume_hint.as_deref(), Some("Open workspace"));
    assert_eq!(summary.workspace_root.as_deref(), Some("/tmp/workspace"));
}

#[test]
fn session_summary_from_task_derives_title_when_no_summary_exists() {
    let mut task = task_with_workspace_root("/tmp/workspace");
    task.intent = "Create a React app for a property management dashboard".to_string();

    let summary = session_summary_from_task(&task, None);

    assert_eq!(summary.session_id, "session-123");
    assert_eq!(
        summary.title,
        "Create a React app for a property management dashboard"
    );
    assert_eq!(summary.phase, Some(AgentPhase::Complete));
    assert_eq!(summary.resume_hint.as_deref(), Some("Open workspace"));
    assert_eq!(summary.workspace_root.as_deref(), Some("/tmp/workspace"));
}

#[test]
fn canonical_chat_title_is_query_derived_for_install_and_direct_answers() {
    assert_eq!(
        canonical_chat_session_title_from_query("install lmstudio").as_deref(),
        Some("install lmstudio")
    );
    assert_eq!(
        canonical_chat_session_title_from_query("what is 2+2").as_deref(),
        Some("what is 2+2")
    );
}

#[test]
fn canonical_chat_title_rejects_route_and_context_envelopes_as_titles() {
    assert!(clean_chat_session_title_candidate("CHAT ARTIFACT ROUTE CONTRACT:").is_none());
    assert!(clean_chat_session_title_candidate("[Codebase context] Workspace").is_none());
}

#[test]
fn session_summary_from_task_strips_context_envelope_from_title() {
    let mut task = task_with_workspace_root("/tmp/workspace");
    task.intent = "[Codebase context]\nWorkspace: /home/user/project\n\n[User request]\nCreate an interactive HTML artifact that explains quantum computers".to_string();
    let existing = SessionSummary {
        session_id: "session-123".to_string(),
        title: "[Codebase context] Workspace".to_string(),
        timestamp: 42,
        phase: Some(AgentPhase::Running),
        current_step: Some("Initializing".to_string()),
        resume_hint: None,
        workspace_root: None,
    };

    let summary = session_summary_from_task(&task, Some(&existing));

    assert!(!summary.title.contains("[Codebase context]"));
    assert!(summary
        .title
        .starts_with("Create an interactive HTML artifact that explains"));
    assert_eq!(summary.timestamp, 42);
}

#[test]
fn session_summary_from_task_strips_runtime_handoff_envelope_from_title() {
    let mut task = task_with_workspace_root("/tmp/workspace");
    task.intent = "CHAT ARTIFACT ROUTE CONTRACT:\nRoute family: command_execution\n\nUSER REQUEST:\n[Codebase context]\nWorkspace: .\n\n[User request]\ninstall lmstudio".to_string();
    let existing = SessionSummary {
        session_id: "session-123".to_string(),
        title: "CHAT ARTIFACT ROUTE CONTRACT:".to_string(),
        timestamp: 42,
        phase: Some(AgentPhase::Running),
        current_step: Some("Waiting for approval".to_string()),
        resume_hint: None,
        workspace_root: None,
    };

    let summary = session_summary_from_task(&task, Some(&existing));

    assert_eq!(summary.title, "install lmstudio");
    assert_eq!(summary.timestamp, 42);
}

#[test]
fn session_summary_from_task_preserves_existing_workspace_root() {
    let task = task_without_workspace_root();
    let existing = SessionSummary {
        session_id: "session-123".to_string(),
        title: "Existing title".to_string(),
        timestamp: 42,
        phase: Some(AgentPhase::Running),
        current_step: Some("Initializing".to_string()),
        resume_hint: None,
        workspace_root: Some("/tmp/preserved-root".to_string()),
    };

    let summary = session_summary_from_task(&task, Some(&existing));

    assert_eq!(
        summary.workspace_root.as_deref(),
        Some("/tmp/preserved-root")
    );
}

#[test]
fn live_task_summary_appears_even_when_not_retained_in_session_index() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let mut task = task_with_workspace_root("/tmp/live-workspace");
    task.session_id =
        Some("e65b8f5b1a0f4dc9aa424d9d50a792f5378cda656a5a421fb8d154a2060faa54".to_string());
    task.phase = AgentPhase::Gate;
    task.current_step = "Waiting for clarification.".to_string();

    save_local_task_state(&memory_runtime, &task);
    let summaries = get_local_sessions_with_live_tasks(&memory_runtime);

    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].session_id, task.session_id.clone().unwrap());
    assert_eq!(summaries[0].phase, Some(AgentPhase::Gate));
    assert_eq!(
        summaries[0].workspace_root.as_deref(),
        Some("/tmp/live-workspace")
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn save_local_task_state_exports_gui_runtime_evidence_projection() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let mut task = task_without_workspace_root();
    task.session_id = Some("session-runtime-evidence".to_string());
    task.phase = AgentPhase::Complete;
    task.progress = 2;
    task.current_step = "Ready for input".to_string();
    task.history.push(ChatMessage {
        role: "user".to_string(),
        text: "Where is Autopilot chat task state defined? Cite the files you used.".to_string(),
        timestamp: 100,
    });
    task.history.push(ChatMessage {
        role: "agent".to_string(),
        text: "Autopilot chat task state is defined in the task-state module.".to_string(),
        timestamp: 200,
    });

    save_local_task_state(&memory_runtime, &task);
    save_local_task_state(&memory_runtime, &task);

    let thread_key = thread_storage_key("session-runtime-evidence").expect("thread key");
    let transcript = memory_runtime
        .load_transcript_messages(thread_key)
        .expect("transcript projection");
    assert_eq!(transcript.len(), 2);
    assert_eq!(transcript[0].role, "user");
    assert_eq!(
        transcript[1].privacy_metadata.redaction_version,
        "autopilot-runtime-evidence-v1"
    );
    assert!(memory_runtime
        .load_checkpoint_blob(
            thread_key,
            super::WORKFLOW_OUTPUT_WRITER_TRANSCRIPT_STAGING_CHECKPOINT_NAME,
        )
        .expect("staging checkpoint lookup")
        .is_none());

    let artifacts = load_artifacts(&memory_runtime, "session-runtime-evidence");
    let runtime_artifact = artifacts
        .iter()
        .find(|artifact| artifact.title.contains("quality ledger"))
        .expect("runtime evidence artifact");
    assert_eq!(
        runtime_artifact.artifact_type,
        crate::models::ArtifactType::Report
    );
    let content = load_artifact_content(&memory_runtime, &runtime_artifact.artifact_id)
        .expect("runtime evidence content");
    let projection: serde_json::Value =
        serde_json::from_slice(&content).expect("runtime projection json");
    assert_eq!(
        projection
            .get("StopConditionRecord")
            .and_then(|value| value.get("reason"))
            .and_then(|value| value.as_str()),
        Some("objective_satisfied")
    );
    assert!(projection.get("AgentQualityLedger").is_some());
    assert_eq!(
        projection
            .get("PromptAssemblyContract")
            .and_then(|value| value.get("sections"))
            .and_then(|value| value.as_array())
            .map(|sections| !sections.is_empty()),
        Some(true)
    );
    assert_eq!(
        projection
            .get("PromptAssemblyContract")
            .and_then(|value| value.get("policyOverridesBlocked"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(projection.get("TaskStateModel").is_some());
    assert!(projection.get("AgentTurnState").is_some());
    assert!(projection.get("AgentDecisionLoop").is_some());
    assert_eq!(
        projection
            .get("HarnessWorkerBinding")
            .and_then(|value| value.get("executionMode"))
            .and_then(|value| value.as_str()),
        Some("live")
    );
    let selector_decision = projection
        .get("HarnessRuntimeSelectorDecision")
        .expect("runtime selector decision");
    assert_eq!(
        selector_decision
            .get("selectedSelector")
            .and_then(|value| value.as_str()),
        Some("blessed_workflow_live_canary")
    );
    assert_eq!(
        selector_decision
            .get("productionDefaultSelector")
            .and_then(|value| value.as_str()),
        Some("legacy_runtime")
    );
    assert_eq!(
        selector_decision
            .get("canaryEligible")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        selector_decision
            .get("canaryBlockers")
            .and_then(|value| value.as_array())
            .map(Vec::is_empty),
        Some(true)
    );
    assert_eq!(
        selector_decision
            .get("actualRuntimeAuthority")
            .and_then(|value| value.as_str()),
        Some("blessed_workflow_activation_canary")
    );
    let shadow_run = projection
        .get("HarnessShadowRun")
        .expect("harness shadow run projection");
    let shadow_attempts = shadow_run
        .get("nodeAttempts")
        .and_then(|value| value.as_array())
        .expect("harness shadow node attempts");
    assert!(shadow_attempts.len() >= 10);
    assert!(shadow_attempts.iter().any(|attempt| {
        attempt
            .get("componentKind")
            .and_then(|value| value.as_str())
            == Some("prompt_assembler")
    }));
    assert_eq!(
        shadow_run
            .get("promotionBlocked")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        shadow_run
            .get("comparisons")
            .and_then(|value| value.as_array())
            .map(|comparisons| comparisons.len()),
        Some(shadow_attempts.len())
    );
    let gated_clusters = projection
        .get("HarnessGatedClusterRuns")
        .and_then(|value| value.as_array())
        .expect("harness gated cluster runs");
    assert!(gated_clusters.len() >= 4);
    let cognition_gate = gated_clusters
        .iter()
        .find(|run| run.get("clusterId").and_then(|value| value.as_str()) == Some("cognition"))
        .expect("cognition gated cluster");
    let routing_model_gate = gated_clusters
        .iter()
        .find(|run| run.get("clusterId").and_then(|value| value.as_str()) == Some("routing_model"))
        .expect("routing/model gated cluster");
    let verification_output_gate = gated_clusters
        .iter()
        .find(|run| {
            run.get("clusterId").and_then(|value| value.as_str()) == Some("verification_output")
        })
        .expect("verification/output gated cluster");
    let authority_tooling_gate = gated_clusters
        .iter()
        .find(|run| {
            run.get("clusterId").and_then(|value| value.as_str()) == Some("authority_tooling")
        })
        .expect("authority/tooling gated cluster");
    assert_eq!(
        cognition_gate
            .get("executionMode")
            .and_then(|value| value.as_str()),
        Some("gated")
    );
    assert_eq!(
        cognition_gate
            .get("promotionBlocked")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        cognition_gate
            .get("rollbackAvailable")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        cognition_gate
            .get("canaryStatus")
            .and_then(|value| value.as_str()),
        Some("passed")
    );
    assert_eq!(
        routing_model_gate
            .get("executionMode")
            .and_then(|value| value.as_str()),
        Some("gated")
    );
    assert_eq!(
        routing_model_gate
            .get("promotionBlocked")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        routing_model_gate
            .get("canaryStatus")
            .and_then(|value| value.as_str()),
        Some("passed")
    );
    assert_eq!(
        verification_output_gate
            .get("executionMode")
            .and_then(|value| value.as_str()),
        Some("gated")
    );
    assert_eq!(
        verification_output_gate
            .get("promotionBlocked")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        verification_output_gate
            .get("canaryStatus")
            .and_then(|value| value.as_str()),
        Some("passed")
    );
    assert_eq!(
        authority_tooling_gate
            .get("executionMode")
            .and_then(|value| value.as_str()),
        Some("gated")
    );
    assert_eq!(
        authority_tooling_gate
            .get("promotionBlocked")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        authority_tooling_gate
            .get("runtimeAuthority")
            .and_then(|value| value.as_str()),
        Some("existing_runtime_service")
    );
    assert_eq!(
        authority_tooling_gate
            .get("canaryStatus")
            .and_then(|value| value.as_str()),
        Some("passed")
    );
    let canary_boundaries = projection
        .get("HarnessCanaryExecutionBoundaries")
        .and_then(|value| value.as_array())
        .expect("execution-backed canary boundaries");
    assert!(canary_boundaries.len() >= 4);
    let boundary_for = |cluster_id: &str| {
        canary_boundaries
            .iter()
            .find(|boundary| {
                boundary.get("clusterId").and_then(|value| value.as_str()) == Some(cluster_id)
            })
            .unwrap_or_else(|| panic!("missing execution-backed canary boundary for {cluster_id}"))
    };
    for (cluster_id, required_component) in [
        ("cognition", "capability_sequencer"),
        ("routing_model", "tool_router"),
        ("verification_output", "completion_gate"),
        ("authority_tooling", "wallet_capability"),
    ] {
        let minimum_attempts = match cluster_id {
            "routing_model" => 3,
            "authority_tooling" => 8,
            _ => 6,
        };
        let canary_boundary = boundary_for(cluster_id);
        assert_eq!(
            canary_boundary
                .get("schemaVersion")
                .and_then(|value| value.as_str()),
            Some("workflow.harness.canary-execution-boundary.v1")
        );
        assert_eq!(
            canary_boundary
                .get("executionMode")
                .and_then(|value| value.as_str()),
            Some("live")
        );
        assert_eq!(
            canary_boundary
                .get("runtimeAuthority")
                .and_then(|value| value.as_str()),
            Some("blessed_workflow_activation_canary")
        );
        assert_eq!(
            canary_boundary
                .get("executorKind")
                .and_then(|value| value.as_str()),
            Some("workflow_node_executor")
        );
        assert_eq!(
            canary_boundary
                .get("status")
                .and_then(|value| value.as_str()),
            Some("passed")
        );
        assert_eq!(
            canary_boundary
                .get("activationBlockers")
                .and_then(|value| value.as_array())
                .map(Vec::is_empty),
            Some(true)
        );
        assert!(canary_boundary
            .get("nodeAttemptIds")
            .and_then(|value| value.as_array())
            .map(|items| items.len() >= minimum_attempts)
            .unwrap_or(false));
        assert!(canary_boundary
            .get("executedComponentKinds")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .contains(&required_component)
            })
            .unwrap_or(false));
        let rollback_drill = canary_boundary
            .get("rollbackDrill")
            .expect("canary rollback drill");
        assert_eq!(
            rollback_drill
                .get("clusterId")
                .and_then(|value| value.as_str()),
            Some(cluster_id)
        );
        assert_eq!(
            rollback_drill
                .get("failureInjected")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(
            rollback_drill
                .get("observedFailure")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(
            rollback_drill
                .get("rollbackExecuted")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
        assert_eq!(
            rollback_drill
                .get("rollbackSelector")
                .and_then(|value| value.as_str()),
            Some("legacy_runtime")
        );
        assert_eq!(
            rollback_drill
                .get("drillStatus")
                .and_then(|value| value.as_str()),
            Some("passed")
        );
    }
    let canary_boundary = projection
        .get("HarnessCanaryExecutionBoundary")
        .expect("compat execution-backed canary boundary");
    assert_eq!(
        canary_boundary
            .get("clusterId")
            .and_then(|value| value.as_str()),
        Some("verification_output")
    );
    let live_handoff = projection
        .get("HarnessLiveHandoff")
        .expect("blessed live handoff proof");
    assert_eq!(
        live_handoff
            .get("selector")
            .and_then(|value| value.as_str()),
        Some("blessed_workflow_live_canary")
    );
    assert_eq!(
        live_handoff
            .get("productionDefaultSelector")
            .and_then(|value| value.as_str()),
        Some("legacy_runtime")
    );
    assert_eq!(
        live_handoff
            .get("activationId")
            .and_then(|value| value.as_str()),
        Some(ioi_types::app::DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
    );
    assert_eq!(
        live_handoff
            .get("canaryStatus")
            .and_then(|value| value.as_str()),
        Some("passed")
    );
    assert_eq!(
        live_handoff
            .get("canaryTurnRoutedThroughWorkflow")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        live_handoff
            .get("executionBoundaryStatus")
            .and_then(|value| value.as_str()),
        Some("passed")
    );
    let handoff_boundary_clusters = live_handoff
        .get("executionBoundaryClusterIds")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(handoff_boundary_clusters.contains(&"cognition"));
    assert!(handoff_boundary_clusters.contains(&"routing_model"));
    assert!(handoff_boundary_clusters.contains(&"verification_output"));
    assert!(handoff_boundary_clusters.contains(&"authority_tooling"));
    assert_eq!(
        live_handoff
            .get("defaultAuthorityTransferred")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        live_handoff
            .get("rollbackAvailable")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        live_handoff
            .get("activationBlockers")
            .and_then(|value| value.as_array())
            .map(Vec::is_empty),
        Some(true)
    );
    assert!(live_handoff
        .get("nodeTimelineAttemptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(live_handoff
        .get("receiptIds")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    let default_dispatch = projection
        .get("HarnessDefaultRuntimeDispatch")
        .expect("default runtime dispatch proof");
    assert_eq!(
        default_dispatch
            .get("cognitionExecutionMode")
            .and_then(|value| value.as_str()),
        Some("workflow_synchronous_envelope")
    );
    assert!(default_dispatch
        .get("cognitionExecutionProof")
        .and_then(|value| value.get("schemaVersion"))
        .and_then(|value| value.as_str())
        .map(|value| value == "workflow.harness.cognition-execution-envelope.v1")
        .unwrap_or(false));
    assert_eq!(
        default_dispatch
            .get("modelExecutionMode")
            .and_then(|value| value.as_str()),
        Some("workflow_synchronous_envelope")
    );
    assert!(default_dispatch
        .get("modelExecutionProof")
        .and_then(|value| value.get("schemaVersion"))
        .and_then(|value| value.as_str())
        .map(|value| value == "workflow.harness.model-execution-envelope.v1")
        .unwrap_or(false));
    let live_promotion_readiness = default_dispatch
        .get("livePromotionReadinessProof")
        .expect("live promotion readiness proof");
    assert_eq!(
        live_promotion_readiness
            .get("schemaVersion")
            .and_then(|value| value.as_str()),
        Some("workflow.harness.live-promotion-readiness.v1")
    );
    assert_eq!(
        live_promotion_readiness
            .get("defaultLiveActivationReady")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        live_promotion_readiness
            .get("policyDecision")
            .and_then(|value| value.as_str()),
        Some("allow_default_harness_live_promotion_readiness")
    );
    assert!(live_promotion_readiness
        .get("clusterReadiness")
        .and_then(|value| value.as_array())
        .map(|clusters| clusters.len() >= 4
            && clusters.iter().all(|cluster| {
                cluster
                    .get("targetExecutionMode")
                    .and_then(|value| value.as_str())
                    == Some("live")
                    && cluster
                        .get("blockers")
                        .and_then(|value| value.as_array())
                        .map(|items| items.is_empty())
                        .unwrap_or(false)
            }))
        .unwrap_or(false));
    assert_eq!(
        default_dispatch
            .get("outputWriterStagedWriteMode")
            .and_then(|value| value.as_str()),
        Some("isolated_checkpoint_blob")
    );
    assert_eq!(
        default_dispatch
            .get("outputWriterStagedWritePersisted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        default_dispatch
            .get("outputWriterStagedWriteVisible")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        default_dispatch
            .get("outputWriterStagedWriteExcludedFromVisibleTranscript")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        default_dispatch
            .get("outputWriterStagedWriteRollbackStatus")
            .and_then(|value| value.as_str()),
        Some("deleted")
    );
    assert_eq!(
        default_dispatch
            .get("outputWriterStagedWriteRollbackVerified")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        default_dispatch
            .get("stagedTranscriptWriteMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        default_dispatch
            .get("stagedTranscriptWriteDivergenceCount")
            .and_then(|value| value.as_u64()),
        Some(0)
    );
    assert_eq!(
        default_dispatch
            .get("stagedTranscriptWriteRecord")
            .and_then(|value| value.get("stagingSurface"))
            .and_then(|value| value.as_str()),
        Some("checkpoint_blobs")
    );
    assert!(projection.get("SessionTraceBundle").is_some());
    assert!(projection.get("ModelRoutingDecision").is_some());
    assert!(projection.get("RuntimeStrategyRouter").is_some());
    assert!(projection.get("PostconditionSynthesizer").is_some());
    assert!(projection.get("CapabilityDiscovery").is_some());
    assert!(projection.get("ToolSelectionQualityModel").is_some());
    assert!(projection.get("MemoryQualityGate").is_some());
    assert_eq!(
        projection
            .get("SessionTraceBundle")
            .and_then(|value| value.get("reconstructsFinalState"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        projection
            .get("ModelRoutingDecision")
            .and_then(|value| value.get("policyAllowsEgress"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        projection
            .get("WorkflowEnvelopeAdapter")
            .and_then(|value| value.get("usesPublicSubstrateContract"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        projection
            .get("HarnessTraceAdapter")
            .and_then(|value| value.get("importsCompositorUiState"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        projection
            .get("OperatorInterruptionContract")
            .and_then(|value| value.get("preservesObjectiveTaskStateAndAuthority"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let events = load_events(&memory_runtime, "session-runtime-evidence", None, None);
    assert!(events
        .iter()
        .any(|event| event.title == "Runtime trace export"));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn save_session_file_context_backfills_existing_session_summary_root() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    save_local_session_summary(
        &memory_runtime,
        SessionSummary {
            session_id: "session-123".to_string(),
            title: "Existing title".to_string(),
            timestamp: 42,
            phase: Some(AgentPhase::Running),
            current_step: Some("Initializing".to_string()),
            resume_hint: None,
            workspace_root: None,
        },
    );

    save_session_file_context(
        &memory_runtime,
        Some("session-123"),
        &SessionFileContext {
            session_id: Some("session-123".to_string()),
            workspace_root: "/tmp/from-file-context".to_string(),
            pinned_files: Vec::new(),
            recent_files: Vec::new(),
            explicit_includes: Vec::new(),
            explicit_excludes: Vec::new(),
            updated_at_ms: 1,
        },
    );

    let saved = get_local_sessions(&memory_runtime);
    assert_eq!(saved.len(), 1);
    assert_eq!(
        saved[0].workspace_root.as_deref(),
        Some("/tmp/from-file-context")
    );
    assert_eq!(
        persisted_workspace_root_for_session(&memory_runtime, Some("session-123")).as_deref(),
        Some("/tmp/from-file-context")
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn sequential_session_file_context_saves_preserve_existing_scope_entries() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let workspace_root = "/tmp/workspace";

    save_local_session_summary(
        &memory_runtime,
        SessionSummary {
            session_id: "session-123".to_string(),
            title: "Existing title".to_string(),
            timestamp: 42,
            phase: Some(AgentPhase::Running),
            current_step: Some("Initializing".to_string()),
            resume_hint: None,
            workspace_root: Some(workspace_root.to_string()),
        },
    );

    let mut initial =
        load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
    apply_include_file_context_path(&mut initial, "docs").expect("include docs");
    initial.updated_at_ms = 1;
    save_session_file_context(&memory_runtime, Some("session-123"), &initial);

    let mut reloaded =
        load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
    assert_eq!(reloaded.explicit_includes, vec!["docs"]);
    assert!(reloaded.explicit_excludes.is_empty());

    apply_exclude_file_context_path(&mut reloaded, "target").expect("exclude target");
    reloaded.updated_at_ms = 2;
    save_session_file_context(&memory_runtime, Some("session-123"), &reloaded);

    let final_context =
        load_session_file_context(&memory_runtime, Some("session-123"), Some(workspace_root));
    assert_eq!(final_context.explicit_includes, vec!["docs"]);
    assert_eq!(final_context.explicit_excludes, vec!["target"]);
    assert_eq!(final_context.recent_files, vec!["target", "docs"]);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn load_local_engine_control_plane_rejects_legacy_unversioned_payload() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let control_plane = crate::kernel::data::default_local_engine_control_plane();
    let legacy_value = json!({
        "runtime": control_plane.runtime.clone(),
        "storage": control_plane.storage.clone(),
        "watchdog": control_plane.watchdog.clone(),
        "memory": control_plane.memory.clone(),
        "backendPolicy": control_plane.backend_policy.clone(),
        "responses": control_plane.responses.clone(),
        "api": control_plane.api.clone(),
        "galleries": control_plane.galleries.clone(),
        "environment": control_plane.environment.clone()
    });
    save_local_engine_control_plane_value(&memory_runtime, &legacy_value);

    assert!(load_local_engine_control_plane_document(&memory_runtime).is_none());
    assert!(load_local_engine_control_plane(&memory_runtime).is_none());

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn save_local_engine_control_plane_preserves_existing_profile_and_migrations() {
    let dir = temp_runtime_dir();
    let memory_runtime = Arc::new(open_or_create_memory_runtime(&dir).expect("memory runtime"));
    let control_plane = crate::kernel::data::default_local_engine_control_plane();
    save_local_engine_control_plane_document(
        &memory_runtime,
        &LocalEngineControlPlaneDocument {
            schema_version: LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
            profile_id: "custom.profile".to_string(),
            migrations: vec![LocalEngineConfigMigrationRecord {
                migration_id: "legacy.seed".to_string(),
                from_version: 0,
                to_version: 1,
                applied_at_ms: 7,
                summary: "Imported legacy seed profile.".to_string(),
                details: vec!["Preserve this history across later saves.".to_string()],
            }],
            control_plane: control_plane.clone(),
        },
    );

    let mut updated = control_plane;
    updated.runtime.default_model = "gpt-4.1-mini".to_string();
    save_local_engine_control_plane(&memory_runtime, &updated);

    let saved = load_local_engine_control_plane_document(&memory_runtime)
        .expect("saved control plane document");
    assert_eq!(saved.profile_id, "custom.profile");
    assert_eq!(
        saved.schema_version,
        LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION
    );
    assert_eq!(saved.migrations.len(), 1);
    assert_eq!(saved.migrations[0].migration_id, "legacy.seed");
    assert_eq!(saved.control_plane.runtime.default_model, "gpt-4.1-mini");

    let _ = fs::remove_dir_all(dir);
}
