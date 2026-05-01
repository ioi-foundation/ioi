use super::*;
use crate::kernel::chat::content_session::attach_inline_answer_chat_session;
use ioi_api::runtime_harness::{
    ArtifactOperatorPhase, ArtifactOperatorRunStatus, ArtifactOperatorStep,
};

#[test]
fn authoritative_chat_artifact_marks_task_complete_without_kernel_session() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    assert!(task_is_chat_authoritative(&task));

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(
        task.current_step,
        "Chat verified the artifact and is ready for the next request."
    );
}

#[test]
fn authoritative_status_prefers_terminal_operator_run_over_stale_lifecycle_state() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    let chat_session = task.chat_session.as_mut().expect("chat session");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Materializing;
    chat_session.status = "materializing".to_string();
    super::operator_run::start_operator_run_for_session(
        chat_session,
        Some("prompt-evt-1"),
        ioi_api::runtime_harness::ArtifactOperatorRunMode::Create,
    );
    super::operator_run::refresh_active_operator_run_from_session(chat_session, None);

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert!(
        task.current_step.contains("verified"),
        "expected a ready/verified step, got {:?}",
        task.current_step
    );
}

#[test]
fn terminal_operator_run_does_not_promote_partial_manifest_to_ready() {
    let mut task = test_task(ChatArtifactVerificationStatus::Partial);
    let chat_session = task.chat_session.as_mut().expect("chat session");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Materializing;
    chat_session.status = "materializing".to_string();
    super::operator_run::start_operator_run_for_session(
        chat_session,
        Some("prompt-evt-1"),
        ioi_api::runtime_harness::ArtifactOperatorRunMode::Create,
    );
    super::operator_run::refresh_active_operator_run_from_session(chat_session, None);

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert!(
        task.current_step.contains("provisional")
            || task.current_step.contains("partially materialized"),
        "partial verification must remain visible to runtime state, got {:?}",
        task.current_step
    );
    assert!(
        !task.current_step.contains("verified"),
        "operator completion must not override the typed manifest verification result"
    );
}

#[test]
fn authoritative_ready_artifact_mentions_candidates_and_repairs_when_available() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    task.chat_session
        .as_mut()
        .expect("chat session")
        .materialization
        .winning_candidate_id = Some("candidate-2".to_string());
    task.chat_session
        .as_mut()
        .expect("chat session")
        .materialization
        .candidate_summaries = vec![
        ioi_api::chat::ChatArtifactCandidateSummary {
            candidate_id: "candidate-1".to_string(),
            seed: 1,
            model: "fixture".to_string(),
            temperature: 0.4,
            strategy: "initial".to_string(),
            origin: ioi_api::chat::ChatArtifactOutputOrigin::FixtureRuntime,
            provenance: None,
            summary: "Initial".to_string(),
            renderable_paths: vec!["artifact.md".to_string()],
            selected: false,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(ioi_api::chat::ChatArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: None,
                pass_kind: "initial".to_string(),
                pass_index: 0,
                score_total: 10,
                score_delta_from_parent: None,
                terminated_reason: None,
            }),
            render_evaluation: None,
            validation: ioi_api::chat::ChatArtifactValidationResult {
                classification: ioi_api::chat::ChatArtifactValidationStatus::Repairable,
                request_faithfulness: 3,
                concept_coverage: 3,
                interaction_relevance: 2,
                layout_coherence: 2,
                visual_hierarchy: 2,
                completeness: 2,
                generic_shell_detected: false,
                trivial_shell_detected: false,
                deserves_primary_artifact_view: false,
                patched_existing_artifact: None,
                continuity_revision_ux: None,
                issue_classes: Vec::new(),
                repair_hints: Vec::new(),
                strengths: Vec::new(),
                blocked_reasons: Vec::new(),
                file_findings: Vec::new(),
                aesthetic_verdict: "needs_repair".to_string(),
                interaction_verdict: "needs_repair".to_string(),
                truthfulness_warnings: Vec::new(),
                recommended_next_pass: Some("structural_repair".to_string()),
                strongest_contradiction: None,
                rationale: "repair".to_string(),
                ..chat_validation_fixture()
            },
        },
        ioi_api::chat::ChatArtifactCandidateSummary {
            candidate_id: "candidate-2".to_string(),
            seed: 1,
            model: "fixture".to_string(),
            temperature: 0.25,
            strategy: "repair".to_string(),
            origin: ioi_api::chat::ChatArtifactOutputOrigin::LiveInference,
            provenance: None,
            summary: "Winner".to_string(),
            renderable_paths: vec!["artifact.md".to_string()],
            selected: true,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(ioi_api::chat::ChatArtifactCandidateConvergenceTrace {
                lineage_root_id: "candidate-1".to_string(),
                parent_candidate_id: Some("candidate-1".to_string()),
                pass_kind: "structural_repair".to_string(),
                pass_index: 1,
                score_total: 18,
                score_delta_from_parent: Some(8),
                terminated_reason: Some("accepted".to_string()),
            }),
            render_evaluation: None,
            validation: ioi_api::chat::ChatArtifactValidationResult {
                classification: ioi_api::chat::ChatArtifactValidationStatus::Pass,
                request_faithfulness: 5,
                concept_coverage: 4,
                interaction_relevance: 4,
                layout_coherence: 4,
                visual_hierarchy: 4,
                completeness: 4,
                generic_shell_detected: false,
                trivial_shell_detected: false,
                deserves_primary_artifact_view: true,
                patched_existing_artifact: None,
                continuity_revision_ux: None,
                issue_classes: Vec::new(),
                repair_hints: Vec::new(),
                strengths: Vec::new(),
                blocked_reasons: Vec::new(),
                file_findings: Vec::new(),
                aesthetic_verdict: "good".to_string(),
                interaction_verdict: "good".to_string(),
                truthfulness_warnings: Vec::new(),
                recommended_next_pass: None,
                strongest_contradiction: None,
                rationale: "accepted".to_string(),
                ..chat_validation_fixture()
            },
        },
    ];

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(
        task.current_step,
        "Chat verified candidate-2 after 2 candidate(s)."
    );
}

#[test]
fn authoritative_status_prefers_active_operator_step_detail_for_running_artifacts() {
    let mut task = test_task(ChatArtifactVerificationStatus::Blocked);
    let chat_session = task.chat_session.as_mut().expect("chat session");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Materializing;
    chat_session.status = "materializing".to_string();
    super::operator_run::start_operator_run_for_session(
        chat_session,
        Some("prompt-evt-1"),
        ioi_api::runtime_harness::ArtifactOperatorRunMode::Create,
    );
    chat_session
        .materialization
        .operator_steps
        .push(ArtifactOperatorStep {
            step_id: "verify-step-1".to_string(),
            origin_prompt_event_id: "prompt-evt-1".to_string(),
            phase: ArtifactOperatorPhase::VerifyArtifact,
            engine: "browser_verifier".to_string(),
            status: ArtifactOperatorRunStatus::Active,
            label: "Run browser verification".to_string(),
            detail: "Chat is checking the rendered draft for runtime errors.".to_string(),
            started_at_ms: 1,
            finished_at_ms: None,
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        });
    super::operator_run::refresh_active_operator_run_from_session(chat_session, None);

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Running);
    assert_eq!(
        task.current_step,
        "Chat is checking the rendered draft for runtime errors."
    );
}

#[test]
fn authoritative_status_keeps_running_when_active_operator_step_conflicts_with_stale_ready_manifest(
) {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    let chat_session = task.chat_session.as_mut().expect("chat session");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Materializing;
    chat_session.status = "materializing".to_string();
    super::operator_run::start_operator_run_for_session(
        chat_session,
        Some("prompt-evt-1"),
        ioi_api::runtime_harness::ArtifactOperatorRunMode::Create,
    );
    chat_session
        .materialization
        .operator_steps
        .push(ArtifactOperatorStep {
            step_id: "author-step-1".to_string(),
            origin_prompt_event_id: "prompt-evt-1".to_string(),
            phase: ArtifactOperatorPhase::AuthorArtifact,
            engine: "direct_author".to_string(),
            status: ArtifactOperatorRunStatus::Active,
            label: "Write artifact".to_string(),
            detail: "Chat is still writing the strongest artifact draft.".to_string(),
            started_at_ms: 1,
            finished_at_ms: None,
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        });
    super::operator_run::refresh_active_operator_run_from_session(chat_session, None);

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Running);
    assert_eq!(
        task.current_step,
        "Chat is still writing the strongest artifact draft."
    );
}

#[test]
fn authoritative_status_completes_when_ready_manifest_conflicts_with_stale_verify_step() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    let chat_session = task.chat_session.as_mut().expect("chat session");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Ready;
    chat_session.status = "ready".to_string();
    super::operator_run::start_operator_run_for_session(
        chat_session,
        Some("prompt-evt-1"),
        ioi_api::runtime_harness::ArtifactOperatorRunMode::Create,
    );
    chat_session
        .materialization
        .operator_steps
        .push(ArtifactOperatorStep {
            step_id: "verify-step-1".to_string(),
            origin_prompt_event_id: "prompt-evt-1".to_string(),
            phase: ArtifactOperatorPhase::VerifyArtifact,
            engine: "browser_verifier".to_string(),
            status: ArtifactOperatorRunStatus::Active,
            label: "Run browser verification".to_string(),
            detail: "Render evaluation is complete and Chat is surfacing the rendered artifact."
                .to_string(),
            started_at_ms: 1,
            finished_at_ms: None,
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        });
    super::operator_run::refresh_active_operator_run_from_session(chat_session, None);

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(
        task.current_step,
        "Chat verified the artifact and is ready for the next request."
    );
}

#[test]
fn authoritative_status_fails_when_blocked_manifest_conflicts_with_stale_verify_step() {
    let mut task = test_task(ChatArtifactVerificationStatus::Blocked);
    let chat_session = task.chat_session.as_mut().expect("chat session");
    chat_session.lifecycle_state = ChatArtifactLifecycleState::Rendering;
    chat_session.status = "rendering".to_string();
    chat_session.artifact_manifest.verification.summary =
        "Chat materialized files, but acceptance validation blocked the primary presentation."
            .to_string();
    super::operator_run::start_operator_run_for_session(
        chat_session,
        Some("prompt-evt-1"),
        ioi_api::runtime_harness::ArtifactOperatorRunMode::Create,
    );
    chat_session
        .materialization
        .operator_steps
        .push(ArtifactOperatorStep {
            step_id: "verify-step-1".to_string(),
            origin_prompt_event_id: "prompt-evt-1".to_string(),
            phase: ArtifactOperatorPhase::VerifyArtifact,
            engine: "browser_verifier".to_string(),
            status: ArtifactOperatorRunStatus::Active,
            label: "Run browser verification".to_string(),
            detail: "Render evaluation is complete and Chat is surfacing the rendered artifact."
                .to_string(),
            started_at_ms: 1,
            finished_at_ms: None,
            preview: None,
            file_refs: Vec::new(),
            source_refs: Vec::new(),
            verification_refs: Vec::new(),
            attempt: 1,
        });
    super::operator_run::refresh_active_operator_run_from_session(chat_session, None);

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Failed);
    assert_eq!(
        task.current_step,
        "Chat materialized files, but acceptance validation blocked the primary presentation."
    );
}

#[test]
fn authoritative_workspace_artifact_stays_running_until_verification_passes() {
    let mut task = test_task(ChatArtifactVerificationStatus::Blocked);
    task.build_session = Some(test_build_session("preview-starting", "pending"));

    apply_chat_authoritative_status(&mut task, None);
    assert_eq!(task.phase, AgentPhase::Gate);

    task.build_session = Some(test_build_session("preview-ready", "passed"));
    apply_chat_authoritative_status(&mut task, None);
    assert_eq!(task.phase, AgentPhase::Complete);
    assert_eq!(task.current_step, "Chat workspace renderer verified.");
}

#[test]
fn blocked_nonworkspace_artifact_marks_task_failed_without_clarification() {
    let mut task = test_task(ChatArtifactVerificationStatus::Blocked);
    task.chat_session
        .as_mut()
        .expect("chat session")
        .artifact_manifest
        .verification
        .failure = Some(ChatArtifactFailure {
        kind: ChatArtifactFailureKind::RoutingFailure,
        code: "routing_failure".to_string(),
        message: "Chat outcome planning timed out after 45s while routing the request.".to_string(),
    });

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Failed);
    assert_eq!(
        task.current_step,
        "Chat outcome planning timed out after 45s while routing the request."
    );
}

#[test]
fn blocked_nonworkspace_artifact_allows_clarification_without_running_spinner() {
    let mut task = test_task(ChatArtifactVerificationStatus::Blocked);
    task.clarification_request = Some(ClarificationRequest {
        kind: "intent_resolution".to_string(),
        question: "Which approval flow should this diagram cover?".to_string(),
        tool_name: "system::intent_clarification".to_string(),
        failure_class: None,
        evidence_snippet: None,
        context_hint: None,
        options: Vec::new(),
        allow_other: true,
    });

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Gate);
    assert_eq!(
        task.current_step,
        "Chat is waiting for clarification before it can materialize a usable artifact."
    );
}

#[test]
fn ready_nonartifact_route_with_gate_info_marks_task_gate() {
    let mut task = test_task(ChatArtifactVerificationStatus::Ready);
    task.gate_info = Some(GateInfo {
        title: "Approval needed".to_string(),
        description: "Chat needs approval before opening the currentness route.".to_string(),
        risk: "low".to_string(),
        approve_label: Some("Approve".to_string()),
        deny_label: Some("Cancel".to_string()),
        deadline_ms: None,
        surface_label: None,
        scope_label: None,
        operation_label: None,
        target_label: None,
        operator_note: None,
        pii: None,
    });
    task.current_step = "Waiting for approval".to_string();

    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Gate);
    assert_eq!(task.current_step, "Waiting for approval");
}

#[test]
fn current_task_turn_surfaces_inference_unavailable_as_blocked_chat_session() {
    let prompt = "Create an interactive HTML artifact that explains a product rollout with charts";
    let mut task = empty_task(prompt);
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(UnavailableInferenceRuntime::new(
        "Inference is unavailable because no Chat runtime is configured.",
    ));
    let workspace_root_base =
        std::env::temp_dir().join(format!("ioi-chat-proof-workspaces-{}", Uuid::new_v4()));
    fs::create_dir_all(&workspace_root_base).expect("workspace root");

    run_chat_current_task_turn_for_proof(
        &mut task,
        prompt,
        proof_memory_runtime(),
        runtime.clone(),
        runtime,
        &workspace_root_base,
    )
    .expect("proof turn");

    let chat_session = task.chat_session.as_ref().expect("chat session");
    assert_eq!(
        chat_session.lifecycle_state,
        ChatArtifactLifecycleState::Blocked
    );
    assert_eq!(
        chat_session
            .artifact_manifest
            .verification
            .production_provenance
            .as_ref()
            .expect("provenance")
            .kind,
        crate::models::ChatRuntimeProvenanceKind::InferenceUnavailable
    );
    assert_eq!(
        chat_session
            .artifact_manifest
            .verification
            .failure
            .as_ref()
            .expect("failure")
            .code,
        "inference_unavailable"
    );
    assert!(chat_session.artifact_manifest.files.is_empty());
    let _ = fs::remove_dir_all(workspace_root_base);
}

#[test]
fn current_task_turn_surfaces_routing_timeouts_as_blocked_chat_session() {
    let prompt = "Help me reason about a product rollout with charts";
    let mut task = empty_task(prompt);
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(SlowChatOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"artifact",
              "confidence":0.9,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":{
                "artifactClass":"interactive_single_file",
                "deliverableShape":"single_file",
                "renderer":"html_iframe",
                "presentationSurface":"side_panel",
                "persistence":"artifact_scoped",
                "executionSubstrate":"client_sandbox",
                "workspaceRecipeId":null,
                "presentationVariantId":null,
                "scope":{"targetProject":null,"createNewWorkspace":false,"mutationBoundary":["artifact"]},
                "verification":{"requireRender":true,"requireBuild":false,"requirePreview":false,"requireExport":true,"requireDiffReview":false}
              }
            }"#
        .to_string(),
        delay: Duration::from_millis(50),
        provenance: None,
    });
    let workspace_root_base =
        std::env::temp_dir().join(format!("ioi-chat-proof-workspaces-{}", Uuid::new_v4()));
    fs::create_dir_all(&workspace_root_base).expect("workspace root");

    run_chat_current_task_turn_for_proof_with_route_timeout(
        &mut task,
        prompt,
        proof_memory_runtime(),
        runtime.clone(),
        runtime,
        &workspace_root_base,
        Duration::from_millis(5),
    )
    .expect("proof turn");

    let chat_session = task.chat_session.as_ref().expect("chat session");
    assert_eq!(
        chat_session.lifecycle_state,
        ChatArtifactLifecycleState::Blocked
    );
    assert_eq!(
        chat_session
            .artifact_manifest
            .verification
            .failure
            .as_ref()
            .expect("failure")
            .code,
        "routing_failure"
    );
    assert!(chat_session
        .artifact_manifest
        .verification
        .failure
        .as_ref()
        .expect("failure")
        .message
        .contains("timed out"));
    assert!(chat_session.artifact_manifest.files.is_empty());
    let _ = fs::remove_dir_all(workspace_root_base);
}

#[test]
fn current_task_turn_surfaces_inline_answer_routes_as_shared_execution_sessions() {
    let prompt =
        "Talk through whether an AI tools editorial launch page needs a stronger story arc";
    let mut task = empty_task(prompt);
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatOutcomeTestRuntime {
        payload: r#"{
              "outcomeKind":"conversation",
              "confidence":0.41,
              "needsClarification":false,
              "clarificationQuestions":[],
              "artifact":null
            }"#
        .to_string(),
    });
    let workspace_root_base =
        std::env::temp_dir().join(format!("ioi-chat-proof-workspaces-{}", Uuid::new_v4()));
    fs::create_dir_all(&workspace_root_base).expect("workspace root");

    run_chat_current_task_turn_for_proof(
        &mut task,
        prompt,
        proof_memory_runtime(),
        runtime.clone(),
        runtime,
        &workspace_root_base,
    )
    .expect("proof turn");

    let chat_session = task.chat_session.as_ref().expect("chat session");
    assert_eq!(
        chat_session.lifecycle_state,
        ChatArtifactLifecycleState::Ready
    );
    assert!(chat_session
        .artifact_manifest
        .verification
        .failure
        .is_none());
    assert!(chat_session
        .artifact_manifest
        .verification
        .summary
        .contains("routed this request to conversation"));
    assert!(chat_session
        .outcome_request
        .decision_evidence
        .iter()
        .any(|hint| hint == "no_persistent_artifact_requested"));
    assert_eq!(
        chat_session.outcome_request.outcome_kind,
        ChatOutcomeKind::Conversation
    );
    assert!(chat_session.materialization.work_graph_execution.is_some());
    assert_eq!(
        chat_session
            .materialization
            .work_graph_execution
            .as_ref()
            .expect("work graph execution")
            .execution_domain,
        "chat_conversation"
    );
    assert!(chat_session
        .materialization
        .pipeline_steps
        .iter()
        .any(|step| step.id == "reply"));
    assert!(task_is_chat_authoritative(&task));
    let _ = fs::remove_dir_all(workspace_root_base);
}

#[test]
fn authoritative_conversation_route_marks_task_complete_with_shared_summary() {
    let mut task = empty_task("Explain the rollout in chat");
    let outcome_request = ChatOutcomeRequest {
        request_id: "conversation-request".to_string(),
        raw_prompt: "Explain the rollout in chat".to_string(),
        active_artifact_id: None,
        outcome_kind: ChatOutcomeKind::Conversation,
        execution_strategy: ChatExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        decision_evidence: vec![
            "currentness_override".to_string(),
            "shared_answer_surface".to_string(),
        ],
        lane_request: None,
        normalized_request: None,
        source_decision: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    };
    super::content_session::attach_inline_answer_chat_session(
        &mut task,
        "Explain the rollout in chat",
        crate::models::ChatRuntimeProvenance {
            kind: crate::models::ChatRuntimeProvenanceKind::OpaqueRuntime,
            label: "opaque inference runtime".to_string(),
            model: None,
            endpoint: None,
        },
        &outcome_request,
    );

    assert!(task_is_chat_authoritative(&task));
    apply_chat_authoritative_status(&mut task, None);

    assert_eq!(task.phase, AgentPhase::Complete);
    assert!(task.current_step.contains("Currentness pressure"));
}

